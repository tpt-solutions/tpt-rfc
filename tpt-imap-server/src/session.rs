// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-connection IMAP session: protocol state machine, command
//! dispatch, and all command handlers.

use std::collections::HashSet;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;

use crate::command::*;
use crate::error::Result as StoreResult;
use crate::proto::{self, Request, Token};
use crate::store::MailboxStore;
use base64::Engine;
use crate::types::*;

/// Advertised capabilities (RFC 9051 §6.1.1).
pub const CAPABILITIES: &str =
    "IMAP4rev2 IMAP4rev1 AUTH=PLAIN AUTH=LOGIN ID NAMESPACE IDLE";

/// Protocol state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

/// The session's view of a selected mailbox.
struct Selected {
    name: String,
    readonly: bool,
    /// UIDs in mailbox order (1-based sequence number = index + 1).
    uids: Vec<u32>,
}

/// An IMAP session bound to a [`MailboxStore`].
pub struct Session<S: MailboxStore> {
    store: Arc<S>,
    user: Option<String>,
    state: State,
    selected: Option<Selected>,
}

impl<S: MailboxStore> Session<S> {
    /// Create a new (unauthenticated) session over the given store.
    pub fn new(store: Arc<S>) -> Self {
        Session {
            store,
            user: None,
            state: State::NotAuthenticated,
            selected: None,
        }
    }

    /// The authenticated username, or panics if called pre-login (handlers
    /// only call this in Authenticated/Selected states).
    fn user(&self) -> &str {
        self.user.as_deref().expect("session is authenticated")
    }

    /// Run the session to completion: greeting, request loop, BYE on close.
    pub fn run<R, W>(&mut self, mut r: R, mut w: W) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        proto::write_untagged(&mut w, "OK IMAP4rev2 server ready")?;
        w.flush()?;
        loop {
            let req = match proto::read_request(&mut r, &mut w)? {
                Some(req) => req,
                None => break,
            };
            if req.command == "LOGOUT" {
                self.cmd_logout(&mut w, &req.tag)?;
                break;
            }
            self.dispatch(&mut r, &mut w, req)?;
            if self.state == State::Logout {
                break;
            }
        }
        Ok(())
    }

    fn dispatch<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        req: Request,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let tag = req.tag.clone();
        let cmd = req.command.as_str();
        match cmd {
            "CAPABILITY" => return self.cmd_capability(w, &tag),
            "NOOP" => return self.ok(w, &tag, "NOOP completed"),
            "LOGOUT" => return self.cmd_logout(w, &tag),
            "ID" => return self.cmd_id(w, &tag),
            _ => {}
        }
        match self.state {
            State::NotAuthenticated => self.dispatch_unauth(r, w, &tag, cmd, &req.args),
            State::Authenticated => self.dispatch_auth(r, w, &tag, cmd, &req.args),
            State::Selected => self.dispatch_selected(r, w, &tag, cmd, &req.args),
            State::Logout => Ok(()),
        }
    }

    // --- generic response helpers ----------------------------------------

    fn ok<W: Write>(&self, w: &mut W, tag: &str, text: &str) -> std::io::Result<()> {
        proto::write_status(w, tag, "OK", text)?;
        w.flush()
    }

    fn no<W: Write>(&self, w: &mut W, tag: &str, text: &str) -> std::io::Result<()> {
        proto::write_status(w, tag, "NO", text)?;
        w.flush()
    }

    fn bad<W: Write>(&self, w: &mut W, tag: &str, text: &str) -> std::io::Result<()> {
        proto::write_status(w, tag, "BAD", text)?;
        w.flush()
    }

    // --- unauthenticated commands ----------------------------------------

    fn dispatch_unauth<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        tag: &str,
        cmd: &str,
        args: &[Token],
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        match cmd {
            "LOGIN" => self.cmd_login(w, tag, args),
            "AUTHENTICATE" => self.cmd_authenticate(r, w, tag, args),
            "STARTTLS" => self.no(w, tag, "STARTTLS is not supported"),
            _ => self.bad(w, tag, "command not allowed in unauthenticated state"),
        }
    }

    fn cmd_login<W: Write>(
        &mut self,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()> {
        let user = match args.first().and_then(proto::token_str) {
            Some(u) => u.to_string(),
            None => return self.bad(w, tag, "LOGIN requires a user name"),
        };
        let pass = match args.get(1).and_then(proto::token_str) {
            Some(p) => p.to_string(),
            None => return self.bad(w, tag, "LOGIN requires a password"),
        };
        self.do_auth(w, tag, &user, &pass)
    }

    fn cmd_authenticate<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let mech = match args.first().and_then(proto::token_str) {
            Some(m) => m.to_ascii_uppercase(),
            None => return self.bad(w, tag, "AUTHENTICATE requires a mechanism"),
        };
        match mech.as_str() {
            "PLAIN" => self.auth_plain(r, w, tag, args.get(1)),
            "LOGIN" => self.auth_login(r, w, tag),
            _ => self.no(w, tag, "unsupported authentication mechanism"),
        }
    }

    fn auth_plain<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        tag: &str,
        initial: Option<&Token>,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let b64 = match initial {
            Some(t) => match proto::token_str(t) {
                Some(s) => s.to_string(),
                None => return self.bad(w, tag, "invalid AUTHENTICATE PLAIN response"),
            },
            None => {
                proto::write_continuation(w, "")?;
                w.flush()?;
                let line = match proto::read_line(r)? {
                    Some(l) => l,
                    None => return Ok(()),
                };
                String::from_utf8_lossy(&line).trim().to_string()
            }
        };
        let decoded = match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            Ok(d) => d,
            Err(e) => return self.no(w, tag, &format!("base64 error: {e}")),
        };
        let parts: Vec<&[u8]> = decoded.split(|&c| c == 0).collect();
        if parts.len() != 3 {
            return self.no(w, tag, "malformed PLAIN credentials");
        }
        let authcid = String::from_utf8_lossy(parts[1]).to_string();
        let pass = String::from_utf8_lossy(parts[2]).to_string();
        if authcid.is_empty() {
            return self.no(w, tag, "authentication failed");
        }
        self.do_auth(w, tag, &authcid, &pass)
    }

    fn do_auth<W: Write>(
        &mut self,
        w: &mut W,
        tag: &str,
        user: &str,
        pass: &str,
    ) -> std::io::Result<()> {
        match self.store.authenticate(user, pass) {
            Ok(true) => {
                self.user = Some(user.to_string());
                self.state = State::Authenticated;
                proto::write_untagged(w, &format!("CAPABILITY {CAPABILITIES}"))?;
                self.ok(w, tag, "Authenticated")
            }
            Ok(false) => self.no(w, tag, "authentication failed"),
            Err(e) => self.no(w, tag, &format!("authentication error: {e}")),
        }
    }

    // --- authenticated mailbox-management commands ----------------------

    fn dispatch_auth<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        tag: &str,
        cmd: &str,
        args: &[Token],
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        match cmd {
            "SELECT" => self.cmd_select(r, w, tag, args, false),
            "EXAMINE" => self.cmd_select(r, w, tag, args, true),
            "CREATE" => self.cmd_create(w, tag, args),
            "DELETE" => self.cmd_delete(w, tag, args),
            "RENAME" => self.cmd_rename(w, tag, args),
            "LIST" => self.cmd_list(w, tag, args, false),
            "LSUB" => self.cmd_list(w, tag, args, true),
            "SUBSCRIBE" => self.cmd_subscribe(w, tag, args, true),
            "UNSUBSCRIBE" => self.cmd_subscribe(w, tag, args, false),
            "STATUS" => self.cmd_status(w, tag, args),
            "APPEND" => self.cmd_append(w, tag, args),
            "NAMESPACE" => self.cmd_namespace(w, tag),
            "CLOSE" | "CHECK" | "EXPUNGE" | "FETCH" | "STORE" | "COPY" | "SEARCH" | "IDLE" => {
                self.bad(w, tag, "command requires a selected mailbox")
            }
            _ => self.bad(w, tag, "unknown command"),
        }
    }

    fn cmd_namespace<W: Write>(&self, w: &mut W, tag: &str) -> std::io::Result<()> {
        proto::write_untagged(w, "NAMESPACE ((\"\" \"/\")) NIL NIL")?;
        self.ok(w, tag, "NAMESPACE completed")
    }

    fn cmd_select<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        tag: &str,
        args: &[Token],
        readonly: bool,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let _ = r;
        let name = match args.first().and_then(proto::token_str) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "SELECT/EXAMINE requires a mailbox name"),
        };
        let user = self.user().to_string();
        let status = match self.store.mailbox_status(&user, &name) {
            Ok(s) => s,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        let snaps = match self.store.messages(&user, &name) {
            Ok(v) => v,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        let uids: Vec<u32> = snaps.iter().map(|m| m.uid).collect();
        self.selected = Some(Selected {
            name,
            readonly,
            uids,
        });
        self.state = State::Selected;
        proto::write_untagged(w, &format!("{} EXISTS", status.messages))?;
        proto::write_untagged(w, "0 RECENT")?;
        proto::write_untagged(w, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")?;
        proto::write_untagged(
            w,
            &format!("* OK [UIDVALIDITY {}] {}", status.uidvalidity, select_label(readonly)),
        )?;
        self.ok(
            w,
            tag,
            &format!(
                "[UIDVALIDITY {}] {} completed",
                status.uidvalidity,
                select_label(readonly)
            ),
        )
    }

    fn cmd_list<W: Write>(
        &self,
        w: &mut W,
        tag: &str,
        args: &[Token],
        lsub: bool,
    ) -> std::io::Result<()> {
        let reference = args.first().and_then(proto::token_str).unwrap_or("");
        let pattern = args.get(1).and_then(proto::token_str).unwrap_or("");
        let entries: StoreResult<Vec<ListEntry>> = if lsub {
            self.store.lsub(self.user(), reference, pattern)
        } else {
            self.store.list(self.user(), reference, pattern)
        };
        let entries = match entries {
            Ok(v) => v,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        for e in &entries {
            proto::write_untagged(
                w,
                &format!(
                    "LIST ({}) \"{}\" {}",
                    e.attributes.join(" "),
                    e.delimiter,
                    quote_if_needed(&e.name)
                ),
            )?;
        }
        self.ok(w, tag, "LIST completed")
    }

    fn cmd_status<W: Write>(
        &self,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()> {
        let name = match args.first().and_then(proto::token_str) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "STATUS requires a mailbox name"),
        };
        let items = match parse_status_items(&args[1..]) {
            Ok(v) => v,
            Err(_) => return self.bad(w, tag, "invalid STATUS items"),
        };
        let st = match self.store.mailbox_status(self.user(), &name) {
            Ok(s) => s,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        let mut parts = Vec::new();
        for it in &items {
            match it.as_str() {
                "MESSAGES" => parts.push(format!("MESSAGES {}", st.messages)),
                "UIDNEXT" => parts.push(format!("UIDNEXT {}", st.uidnext)),
                "UIDVALIDITY" => parts.push(format!("UIDVALIDITY {}", st.uidvalidity)),
                "UNSEEN" => parts.push(format!("UNSEEN {}", st.unseen)),
                "DELETED" => parts.push(format!("DELETED {}", st.deleted)),
                "RECENT" => parts.push("RECENT 0".to_string()),
                _ => {}
            }
        }
        proto::write_untagged(
            w,
            &format!("STATUS {} ({})", quote_if_needed(&name), parts.join(" ")),
        )?;
        self.ok(w, tag, "STATUS completed")
    }

    fn cmd_create<W: Write>(
        &self,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()> {
        let name = match args.first().and_then(proto::token_str) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "CREATE requires a mailbox name"),
        };
        match self.store.create(self.user(), &name) {
            Ok(()) => self.ok(w, tag, "CREATE completed"),
            Err(e) => self.no(w, tag, &e.to_string()),
        }
    }

    fn cmd_delete<W: Write>(
        &self,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()> {
        let name = match args.first().and_then(proto::token_str) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "DELETE requires a mailbox name"),
        };
        match self.store.delete(self.user(), &name) {
            Ok(()) => self.ok(w, tag, "DELETE completed"),
            Err(e) => self.no(w, tag, &e.to_string()),
        }
    }

    fn cmd_rename<W: Write>(
        &self,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()> {
        let from = match args.first().and_then(proto::token_str) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "RENAME requires a source mailbox"),
        };
        let to = match args.get(1).and_then(proto::token_str) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "RENAME requires a destination mailbox"),
        };
        match self.store.rename(self.user(), &from, &to) {
            Ok(()) => self.ok(w, tag, "RENAME completed"),
            Err(e) => self.no(w, tag, &e.to_string()),
        }
    }

    fn cmd_subscribe<W: Write>(
        &self,
        w: &mut W,
        tag: &str,
        args: &[Token],
        subscribe: bool,
    ) -> std::io::Result<()> {
        let name = match args.first().and_then(proto::token_str) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "SUBSCRIBE requires a mailbox name"),
        };
        let res = if subscribe {
            self.store.subscribe(self.user(), &name)
        } else {
            self.store.unsubscribe(self.user(), &name)
        };
        match res {
            Ok(()) => self.ok(w, tag, "SUBSCRIBE completed"),
            Err(e) => self.no(w, tag, &e.to_string()),
        }
    }

    fn cmd_append<W: Write>(
        &self,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()> {
        if args.is_empty() {
            return self.bad(w, tag, "APPEND requires a mailbox name");
        }
        let name = match proto::token_str(&args[0]) {
            Some(n) => n.to_string(),
            None => return self.bad(w, tag, "APPEND requires a mailbox name"),
        };
        let mut i = 1usize;
        let mut flags: HashSet<Flag> = HashSet::new();
        let mut internal_date: Option<i64> = None;

        // Optional (FLAGS) group.
        if matches!(args.get(i), Some(Token::LParen)) {
            let f = match collect_flags(&args[i..]) {
                Ok(v) => v,
                Err(_) => return self.bad(w, tag, "invalid APPEND flags"),
            };
            flags = f.into_iter().collect();
            let mut depth = 0i32;
            let mut j = i;
            while j < args.len() {
                match &args[j] {
                    Token::LParen => depth += 1,
                    Token::RParen => {
                        depth -= 1;
                        if depth == 0 {
                            i = j + 1;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }

        // Optional internal date.
        if let Some(t) = args.get(i) {
            if let Some(s) = proto::token_str(t) {
                if looks_like_imap_date(s) {
                    internal_date = parse_imap_date(s);
                    i += 1;
                }
            }
        }

        let data = match args.get(i) {
            Some(Token::Literal(d)) => d.clone(),
            _ => return self.bad(w, tag, "APPEND requires a message literal"),
        };

        let msg = AppendMessage {
            data,
            flags,
            internal_date,
        };
        match self.store.append(self.user(), &name, msg) {
            Ok(()) => self.ok(w, tag, "APPEND completed"),
            Err(e) => self.no(w, tag, &e.to_string()),
        }
    }

    // --- selected (message) commands -------------------------------------

    fn dispatch_selected<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        tag: &str,
        cmd: &str,
        args: &[Token],
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        match cmd {
            "FETCH" => self.cmd_fetch(r, w, tag, args, false),
            "STORE" => self.cmd_store(r, w, tag, args, false),
            "COPY" => self.cmd_copy(r, w, tag, args, false),
            "SEARCH" => self.cmd_search(r, w, tag, args, false),
            "EXPUNGE" => self.cmd_expunge(w, tag),
            "CLOSE" => self.cmd_close(w, tag),
            "CHECK" => self.ok(w, tag, "CHECK completed"),
            "IDLE" => self.cmd_idle(r, w, tag),
            "UID" => {
                let sub = args
                    .first()
                    .and_then(proto::token_str)
                    .map(|s| s.to_ascii_uppercase());
                match sub.as_deref() {
                    Some("FETCH") => self.cmd_fetch(r, w, tag, &args[1..], true),
                    Some("STORE") => self.cmd_store(r, w, tag, &args[1..], true),
                    Some("COPY") => self.cmd_copy(r, w, tag, &args[1..], true),
                    Some("SEARCH") => self.cmd_search(r, w, tag, &args[1..], true),
                    Some("EXPUNGE") => self.cmd_uid_expunge(w, tag, &args[1..]),
                    _ => self.bad(w, tag, "unknown UID command"),
                }
            }
            _ => self.dispatch_auth(r, w, tag, cmd, args),
        }
    }

    fn cmd_fetch<R, W>(
        &self,
        _r: &mut R,
        w: &mut W,
        tag: &str,
        args: &[Token],
        uid_mode: bool,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let (set, items) = match parse_fetch(args) {
            Ok(v) => v,
            Err(_) => return self.bad(w, tag, "invalid FETCH arguments"),
        };
        let sel = match &self.selected {
            Some(s) => s,
            None => return self.bad(w, tag, "no mailbox selected"),
        };
        let count = sel.uids.len() as u32;
        let target_uids: Vec<u32> = if uid_mode {
            resolve_uid(&set, &sel.uids)
        } else {
            resolve_sequence(&set, count)
                .iter()
                .map(|s| sel.uids[*s as usize - 1])
                .collect()
        };
        let user = self.user().to_string();
        let name = sel.name.clone();
        let readonly = sel.readonly;
        let snaps = match self.store.messages(&user, &name) {
            Ok(v) => v,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        for &uid in &target_uids {
            let snap = match snaps.iter().find(|m| m.uid == uid) {
                Some(s) => s,
                None => continue,
            };
            let seq = sel.uids.iter().position(|u| *u == uid).unwrap() as u32 + 1;
            self.write_fetch(w, seq, uid, &items, snap, readonly, uid_mode, &user, &name)?;
        }
        self.ok(w, tag, "FETCH completed")
    }

    #[allow(clippy::too_many_arguments)]
    fn write_fetch<W: Write>(
        &self,
        w: &mut W,
        seq: u32,
        uid: u32,
        items: &[FetchItem],
        snap: &MessageSnapshot,
        readonly: bool,
        uid_mode: bool,
        user: &str,
        name: &str,
    ) -> std::io::Result<()> {
        let mut flags = snap.flags.clone();
        let mut needs_seen = false;
        for item in items {
            if let FetchItem::Body { peek, .. } = item {
                if !*peek {
                    needs_seen = true;
                }
            }
        }
        if needs_seen && !readonly && !flags.contains(&Flag::System(SystemFlag::Seen)) {
            if let Ok(new) = self
                .store
                .set_flags(user, name, uid, FlagOp::Add, &[Flag::System(SystemFlag::Seen)])
            {
                flags = new;
            }
        }

        let (headers, body) = split_message(&snap.data);
        let mut parts: Vec<FetchPart> = Vec::new();
        for item in items {
            match item {
                FetchItem::Flags => {
                    parts.push(FetchPart::Text(format!("FLAGS ({})", join_flags(&flags))))
                }
                FetchItem::Uid => parts.push(FetchPart::Text(format!("UID {uid}"))),
                FetchItem::InternalDate => parts.push(FetchPart::Text(format!(
                    "INTERNALDATE \"{}\"",
                    format_internal_date(snap.internal_date)
                ))),
                FetchItem::Size => {
                    parts.push(FetchPart::Text(format!("RFC822.SIZE {}", snap.data.len())))
                }
                FetchItem::Envelope => {
                    parts.push(FetchPart::Text(format!("ENVELOPE {}", build_envelope(&snap.data))))
                }
                FetchItem::BodyStructure => parts.push(FetchPart::Text(format!(
                    "BODYSTRUCTURE {}",
                    build_bodystructure(body, false)
                ))),
                FetchItem::BodyStructureSimple => parts.push(FetchPart::Text(format!(
                    "BODY {}",
                    build_bodystructure(body, true)
                ))),
                FetchItem::Body { peek: _, section } => {
                    let (label, content) = match section {
                        Section::Whole => ("BODY[]".to_string(), snap.data.clone()),
                        Section::Header => ("BODY[HEADER]".to_string(), headers.to_vec()),
                        Section::Text => ("BODY[TEXT]".to_string(), body.to_vec()),
                        Section::HeaderFields(fields) => {
                            let h = extract_header_fields(headers, fields);
                            (
                                format!("BODY[HEADER.FIELDS ({})]", fields.join(" ")),
                                h,
                            )
                        }
                    };
                    parts.push(FetchPart::Text(label));
                    parts.push(FetchPart::Lit(content));
                }
            }
        }
        if uid_mode && !items_have_uid(items) {
            parts.insert(0, FetchPart::Text(format!("UID {uid}")));
        }

        w.write_all(format!("* {seq} FETCH (").as_bytes())?;
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                w.write_all(b" ")?;
            }
            match p {
                FetchPart::Text(t) => w.write_all(t.as_bytes())?,
                FetchPart::Lit(d) => {
                    w.write_all(b" ")?;
                    proto::write_literal(w, d)?;
                }
            }
        }
        w.write_all(b")\r\n")
    }

    fn cmd_store<R, W>(
        &self,
        _r: &mut R,
        w: &mut W,
        tag: &str,
        args: &[Token],
        uid_mode: bool,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let (set, op, silent, flags) = match parse_store(args) {
            Ok(v) => v,
            Err(_) => return self.bad(w, tag, "invalid STORE arguments"),
        };
        let sel = match &self.selected {
            Some(s) => s,
            None => return self.bad(w, tag, "no mailbox selected"),
        };
        if sel.readonly {
            return self.no(w, tag, "mailbox is read-only");
        }
        let count = sel.uids.len() as u32;
        let target_uids: Vec<u32> = if uid_mode {
            resolve_uid(&set, &sel.uids)
        } else {
            resolve_sequence(&set, count)
                .iter()
                .map(|s| sel.uids[*s as usize - 1])
                .collect()
        };
        let user = self.user().to_string();
        let name = sel.name.clone();
        for &uid in &target_uids {
            let new_flags = match self.store.set_flags(&user, &name, uid, op, &flags) {
                Ok(f) => f,
                Err(e) => return self.no(w, tag, &e.to_string()),
            };
            if !silent {
                let seq = sel.uids.iter().position(|u| *u == uid).unwrap() as u32 + 1;
                proto::write_untagged(
                    w,
                    &format!(
                        "{seq} FETCH (UID {uid} FLAGS ({}))",
                        join_flags(&new_flags)
                    ),
                )?;
            }
        }
        self.ok(w, tag, "STORE completed")
    }

    fn cmd_copy<R, W>(
        &self,
        _r: &mut R,
        w: &mut W,
        tag: &str,
        args: &[Token],
        uid_mode: bool,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        if args.len() < 2 {
            return self.bad(w, tag, "COPY requires a sequence set and a mailbox");
        }
        let set = match parse_seqset(&args[0]) {
            Ok(v) => v,
            Err(_) => return self.bad(w, tag, "invalid COPY sequence set"),
        };
        let target = match proto::token_str(args.last().unwrap()) {
            Some(t) => t.to_string(),
            None => return self.bad(w, tag, "COPY requires a destination mailbox"),
        };
        let sel = match &self.selected {
            Some(s) => s,
            None => return self.bad(w, tag, "no mailbox selected"),
        };
        let count = sel.uids.len() as u32;
        let target_uids: Vec<u32> = if uid_mode {
            resolve_uid(&set, &sel.uids)
        } else {
            resolve_sequence(&set, count)
                .iter()
                .map(|s| sel.uids[*s as usize - 1])
                .collect()
        };
        match self
            .store
            .copy_messages(self.user(), &sel.name, &target_uids, &target)
        {
            Ok(()) => self.ok(w, tag, "COPY completed"),
            Err(e) => self.no(w, tag, &e.to_string()),
        }
    }

    fn cmd_search<R, W>(
        &self,
        _r: &mut R,
        w: &mut W,
        tag: &str,
        args: &[Token],
        uid_mode: bool,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let criteria = match parse_search(args, uid_mode) {
            Ok(v) => v,
            Err(_) => return self.bad(w, tag, "invalid SEARCH criteria"),
        };
        let sel = match &self.selected {
            Some(s) => s,
            None => return self.bad(w, tag, "no mailbox selected"),
        };
        let user = self.user().to_string();
        let name = sel.name.clone();
        let snaps = match self.store.messages(&user, &name) {
            Ok(v) => v,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        let count = sel.uids.len() as u32;
        let mut out: Vec<u32> = Vec::new();
        for (idx, m) in snaps.iter().enumerate() {
            if eval_search(&criteria, idx as u32 + 1, count, m) {
                out.push(if uid_mode { m.uid } else { idx as u32 + 1 });
            }
        }
        let list = out
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        proto::write_untagged(w, &format!("SEARCH {list}"))?;
        self.ok(w, tag, "SEARCH completed")
    }

    fn cmd_expunge<W: Write>(&mut self, w: &mut W, tag: &str) -> std::io::Result<()> {
        let (name, readonly, user) = {
            let sel = match &self.selected {
                Some(s) => s,
                None => return self.bad(w, tag, "no mailbox selected"),
            };
            (sel.name.clone(), sel.readonly, self.user().to_string())
        };
        if readonly {
            return self.no(w, tag, "mailbox is read-only");
        }
        let removed = match self.store.expunge(&user, &name) {
            Ok(v) => v,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        if let Some(sel) = &mut self.selected {
            for &uid in &removed {
                if let Some(pos) = sel.uids.iter().position(|u| *u == uid) {
                    proto::write_untagged(w, &format!("{} EXPUNGE", pos + 1))?;
                    sel.uids.remove(pos);
                }
            }
        }
        self.ok(w, tag, "EXPUNGE completed")
    }

    fn cmd_uid_expunge<W: Write>(
        &mut self,
        w: &mut W,
        tag: &str,
        args: &[Token],
    ) -> std::io::Result<()> {
        let set = match args.first().map(|t| parse_seqset(t)) {
            Some(Ok(v)) => v,
            _ => return self.bad(w, tag, "UID EXPUNGE requires a uid set"),
        };
        let (name, readonly, user) = {
            let sel = match &self.selected {
                Some(s) => s,
                None => return self.bad(w, tag, "no mailbox selected"),
            };
            (sel.name.clone(), sel.readonly, self.user().to_string())
        };
        if readonly {
            return self.no(w, tag, "mailbox is read-only");
        }
        let target_uids = {
            let sel = self.selected.as_ref().unwrap();
            resolve_uid(&set, &sel.uids)
        };
        let removed = match self.store.expunge_uids(&user, &name, &target_uids) {
            Ok(v) => v,
            Err(e) => return self.no(w, tag, &e.to_string()),
        };
        if let Some(sel) = &mut self.selected {
            for &uid in &removed {
                if let Some(pos) = sel.uids.iter().position(|u| *u == uid) {
                    proto::write_untagged(w, &format!("{} EXPUNGE", pos + 1))?;
                    sel.uids.remove(pos);
                }
            }
        }
        self.ok(w, tag, "UID EXPUNGE completed")
    }

    fn cmd_close<W: Write>(&mut self, w: &mut W, tag: &str) -> std::io::Result<()> {
        let (name, user) = {
            let sel = match &self.selected {
                Some(s) => s,
                None => return self.bad(w, tag, "no mailbox selected"),
            };
            (sel.name.clone(), self.user().to_string())
        };
        let _ = self.store.expunge(&user, &name);
        self.selected = None;
        self.state = State::Authenticated;
        self.ok(w, tag, "CLOSE completed")
    }

    fn cmd_idle<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        tag: &str,
    ) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        proto::write_continuation(w, "idling")?;
        w.flush()?;
        loop {
            let line = match proto::read_line(r)? {
                Some(l) => l,
                None => break,
            };
            if trim_bytes(&line).eq_ignore_ascii_case(b"DONE") {
                break;
            }
        }
        self.ok(w, tag, "IDLE terminated")
    }

    // --- small per-command helpers ---------------------------------------

    fn cmd_capability<W: Write>(&self, w: &mut W, tag: &str) -> std::io::Result<()> {
        proto::write_untagged(w, &format!("CAPABILITY {CAPABILITIES}"))?;
        self.ok(w, tag, "CAPABILITY completed")
    }

    fn cmd_id<W: Write>(&self, w: &mut W, tag: &str) -> std::io::Result<()> {
        proto::write_untagged(w, "ID NIL")?;
        self.ok(w, tag, "ID completed")
    }

    fn cmd_logout<W: Write>(&mut self, w: &mut W, tag: &str) -> std::io::Result<()> {
        proto::write_untagged(w, "BYE Logging out")?;
        proto::write_status(w, tag, "OK", "Logout completed")?;
        w.flush()?;
        self.state = State::Logout;
        Ok(())
    }
}

// --- AUTHENTICATE LOGIN SASL helper -------------------------------------

impl<S: MailboxStore> Session<S> {
    fn auth_login<R, W>(&mut self, r: &mut R, w: &mut W, tag: &str) -> std::io::Result<()>
    where
        R: BufRead + Read,
        W: Write,
    {
        let enc = base64::engine::general_purpose::STANDARD.encode(b"Username:");
        proto::write_continuation(w, &enc)?;
        w.flush()?;
        let user_line = match proto::read_line(r)? {
            Some(l) => l,
            None => return Ok(()),
        };
        let user = match base64::engine::general_purpose::STANDARD.decode(trim_bytes(&user_line)) {
            Ok(d) => String::from_utf8_lossy(&d).to_string(),
            Err(e) => return self.no(w, tag, &format!("base64 error: {e}")),
        };
        let enc = base64::engine::general_purpose::STANDARD.encode(b"Password:");
        proto::write_continuation(w, &enc)?;
        w.flush()?;
        let pass_line = match proto::read_line(r)? {
            Some(l) => l,
            None => return Ok(()),
        };
        let pass = match base64::engine::general_purpose::STANDARD.decode(trim_bytes(&pass_line)) {
            Ok(d) => String::from_utf8_lossy(&d).to_string(),
            Err(e) => return self.no(w, tag, &format!("base64 error: {e}")),
        };
        self.do_auth(w, tag, &user, &pass)
    }
}

// --- free functions -------------------------------------------------------

fn select_label(readonly: bool) -> &'static str {
    if readonly {
        "Examine"
    } else {
        "Select"
    }
}

fn join_flags(flags: &HashSet<Flag>) -> String {
    let mut v: Vec<String> = flags.iter().map(|f| f.as_str()).collect();
    v.sort();
    v.join(" ")
}

fn items_have_uid(items: &[FetchItem]) -> bool {
    items.iter().any(|i| matches!(i, FetchItem::Uid))
}

fn looks_like_imap_date(s: &str) -> bool {
    // dd-Mon-yyyy or contains a time colon.
    s.contains(':') || (s.len() >= 3 && s.as_bytes()[2] == b'-')
}

fn parse_imap_date(s: &str) -> Option<i64> {
    // dd-Mon-yyyy HH:MM:SS +zzzz  (timezone ignored; treated as UTC)
    let mut parts = s.split_whitespace();
    let date = parts.next()?;
    let time = parts.next()?;
    let dmy: Vec<&str> = date.split('-').collect();
    if dmy.len() != 3 {
        return None;
    }
    let day: i64 = dmy[0].parse().ok()?;
    let mon = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(dmy[1]))? as i64 + 1;
    let year: i64 = dmy[2].parse().ok()?;
    let hms: Vec<i64> = time.split(':').filter_map(|x| x.parse().ok()).collect();
    if hms.len() != 3 {
        return None;
    }
    let days = days_from_civil(year, mon, day);
    Some((days * 86400) + hms[0] * 3600 + hms[1] * 60 + hms[2])
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Inverse of `civil_from_days` (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn extract_header_fields(headers: &[u8], fields: &[String]) -> Vec<u8> {
    let text = String::from_utf8_lossy(headers).into_owned();
    let lowers: Vec<String> = fields.iter().map(|f| f.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some((h, _v)) = line.split_once(':') {
            if lowers.iter().any(|l| l == &h.trim().to_ascii_lowercase()) {
                out.extend_from_slice(line.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    out
}

fn eval_search(
    criteria: &[SearchCriterion],
    seq: u32,
    count: u32,
    msg: &MessageSnapshot,
) -> bool {
    criteria.iter().all(|c| eval_one(c, seq, count, msg))
}

fn eval_one(c: &SearchCriterion, seq: u32, _count: u32, msg: &MessageSnapshot) -> bool {
    match c {
        SearchCriterion::All => true,
        SearchCriterion::SeqSet(set) => in_set(set, seq),
        SearchCriterion::UidSet(set) => in_set(set, msg.uid),
        SearchCriterion::Flag(f) => msg.flags.contains(&Flag::System(*f)),
        SearchCriterion::UnFlag(f) => !msg.flags.contains(&Flag::System(*f)),
        SearchCriterion::Smaller(n) => msg.data.len() as u32 <= *n,
        SearchCriterion::Larger(n) => msg.data.len() as u32 >= *n,
        SearchCriterion::Text(s) => contains_ci(&msg.data, s),
        SearchCriterion::Subject(s) => {
            let (h, _) = split_message(&msg.data);
            match get_header(h, "Subject") {
                Some(v) => contains_ci(v.as_bytes(), s),
                None => false,
            }
        }
        SearchCriterion::From(s) => {
            let (h, _) = split_message(&msg.data);
            match get_header(h, "From") {
                Some(v) => contains_ci(v.as_bytes(), s),
                None => false,
            }
        }
        SearchCriterion::To(s) => {
            let (h, _) = split_message(&msg.data);
            match get_header(h, "To") {
                Some(v) => contains_ci(v.as_bytes(), s),
                None => false,
            }
        }
        SearchCriterion::Or(a, b) => {
            eval_one(a, seq, _count, msg) || eval_one(b, seq, _count, msg)
        }
        SearchCriterion::Not(a) => !eval_one(a, seq, _count, msg),
    }
}

fn contains_ci(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    let hlower: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();
    hlower.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// A piece of a FETCH response body.
enum FetchPart {
    Text(String),
    Lit(Vec<u8>),
}
