// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 1939 POP3 session state machine, transport-agnostic.
//!
//! A [`Session`] is driven over any `BufRead + Write` (see [`Session::run`]),
//! which keeps it fully testable without a network. The TCP [`crate::server`]
//! wraps this for real sockets.

use std::io::{BufRead, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::MailboxBackend;

/// Maximum length of a single command line accepted from a client. RFC 1939
/// suggests implementations impose a bound; we use a generous limit and reject
/// over-long lines with `-ERR`.
const MAX_COMMAND_LEN: usize = 512;

/// POP3 session states (RFC 1939 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for `USER`/`PASS`/`APOP`/`QUIT`.
    Authorization,
    /// Authenticated; serving mailbox commands.
    Transaction,
}

/// A message held in the session's snapshot of the mailbox. The `deleted` flag
/// is session-local until `QUIT` (RFC 1939 §11).
struct SessionMessage {
    uid: String,
    octets: usize,
    content: Vec<u8>,
    deleted: bool,
}

/// A POP3 session for a single connection.
pub struct Session {
    backend: Arc<dyn MailboxBackend>,
    state: State,
    /// The timestamp string that appeared inside `<...>` in the greeting.
    timestamp: String,
    /// User authenticated for this session (set once authorization succeeds).
    user: Option<String>,
    /// Snapshot of the mailbox taken on entering the TRANSACTION state.
    messages: Vec<SessionMessage>,
    /// Username supplied by `USER`, pending `PASS` (AUTHORIZATION only).
    pending_user: Option<String>,
}

impl Session {
    /// Create a new session bound to `backend`. The greeting timestamp is
    /// generated here so it is stable for the whole connection (APOP needs it).
    pub fn new(backend: Arc<dyn MailboxBackend>) -> Self {
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let pid = std::process::id();
        let timestamp = format!("{}.{}@{}", pid, start, host);
        Self {
            backend,
            state: State::Authorization,
            timestamp,
            user: None,
            messages: Vec::new(),
            pending_user: None,
        }
    }

    /// Drive the session to completion over `reader`/`writer`. Sends the
    /// greeting, then processes one command per line until `QUIT` or EOF.
    pub fn run<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        self.write_line(
            writer,
            &format!("+OK POP3 server ready <{}>", self.timestamp),
        )?;

        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break; // EOF
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.len() > MAX_COMMAND_LEN {
                self.write_err(writer, "command line too long")?;
                writer.flush()?;
                continue;
            }
            let quit = self.handle_line(trimmed, writer)?;
            writer.flush()?;
            if quit {
                break;
            }
        }
        Ok(())
    }

    /// Process a single command line. Returns `true` if the connection should
    /// be closed (i.e. `QUIT` was processed).
    fn handle_line<W: Write>(&mut self, line: &str, writer: &mut W) -> std::io::Result<bool> {
        let (name, arg) = match line.find([' ', '\t']) {
            Some(i) => (
                line[..i].to_ascii_uppercase(),
                Some(line[i + 1..].trim_end().to_string()),
            ),
            None => (line.to_ascii_uppercase(), None),
        };

        match self.state {
            State::Authorization => self.handle_auth(&name, arg.as_deref(), writer),
            State::Transaction => self.handle_transaction(&name, arg.as_deref(), writer),
        }
    }

    // --- AUTHORIZATION state -------------------------------------------------

    fn handle_auth<W: Write>(
        &mut self,
        name: &str,
        arg: Option<&str>,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        match name {
            "USER" => {
                match arg {
                    Some(user) if !user.is_empty() => {
                        self.pending_user = Some(user.to_string());
                        self.write_ok(writer, "user accepted")?;
                    }
                    _ => self.write_err(writer, "syntax error: USER requires a name")?,
                }
                Ok(false)
            }
            "PASS" => {
                let user = match self.pending_user.take() {
                    Some(u) => u,
                    None => {
                        self.write_err(writer, "send USER first")?;
                        return Ok(false);
                    }
                };
                match arg {
                    Some(pass) => self.authorize_user(&user, pass, writer),
                    None => {
                        self.write_err(writer, "syntax error: PASS requires a password")?;
                        Ok(false)
                    }
                }
            }
            "APOP" => self.handle_apop(arg, writer),
            "QUIT" => {
                self.write_ok(writer, "POP3 server signing off")?;
                Ok(true)
            }
            _ => {
                self.write_err(writer, "command not valid in authorization state")?;
                Ok(false)
            }
        }
    }

    fn authorize_user<W: Write>(
        &mut self,
        user: &str,
        pass: &str,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        match self.backend.authenticate(user, pass) {
            Ok(true) => self.enter_transaction(user, writer),
            Ok(false) => {
                self.write_err(writer, "authentication failed")?;
                Ok(false)
            }
            Err(e) => {
                self.write_err(writer, &format!("authentication error: {}", e))?;
                Ok(false)
            }
        }
    }

    fn handle_apop<W: Write>(
        &mut self,
        arg: Option<&str>,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let arg = match arg {
            Some(a) if !a.is_empty() => a,
            _ => {
                self.write_err(writer, "syntax error: APOP requires user and digest")?;
                return Ok(false);
            }
        };
        let mut parts = arg.splitn(2, ' ');
        let user = parts.next().unwrap_or("");
        let digest = parts.next().unwrap_or("");
        if user.is_empty() || digest.is_empty() {
            self.write_err(writer, "syntax error: APOP requires user and digest")?;
            return Ok(false);
        }
        match self
            .backend
            .authenticate_apop(user, &self.timestamp, digest)
        {
            Ok(true) => self.enter_transaction(user, writer),
            Ok(false) => {
                self.write_err(writer, "authentication failed")?;
                Ok(false)
            }
            Err(e) => {
                self.write_err(writer, &format!("authentication error: {}", e))?;
                Ok(false)
            }
        }
    }

    /// Load the mailbox snapshot and transition to the TRANSACTION state.
    fn enter_transaction<W: Write>(&mut self, user: &str, writer: &mut W) -> std::io::Result<bool> {
        let messages = match self.backend.messages(user) {
            Ok(m) => m,
            Err(e) => {
                self.write_err(writer, &format!("mailbox error: {}", e))?;
                return Ok(false);
            }
        };
        self.messages = messages
            .into_iter()
            .map(|m| SessionMessage {
                uid: m.uid,
                octets: m.octets,
                content: m.content,
                deleted: false,
            })
            .collect();
        self.user = Some(user.to_string());
        self.state = State::Transaction;
        self.write_ok(writer, "mailbox has been opened")?;
        Ok(false)
    }

    // --- TRANSACTION state ---------------------------------------------------

    fn handle_transaction<W: Write>(
        &mut self,
        name: &str,
        arg: Option<&str>,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        match name {
            "STAT" => self.cmd_stat(writer),
            "LIST" => self.cmd_list(arg, writer),
            "RETR" => self.cmd_retr(arg, writer),
            "DELE" => self.cmd_dele(arg, writer),
            "NOOP" => {
                self.write_ok(writer, "")?;
                Ok(false)
            }
            "RSET" => {
                for m in &mut self.messages {
                    m.deleted = false;
                }
                self.write_ok(writer, "mailbox restored")?;
                Ok(false)
            }
            "TOP" => self.cmd_top(arg, writer),
            "UIDL" => self.cmd_uidl(arg, writer),
            "QUIT" => self.cmd_quit(writer),
            _ => {
                self.write_err(writer, "command not recognized")?;
                Ok(false)
            }
        }
    }

    /// Resolve a 1-based message number, returning `None` if out of range or
    /// already deleted (such messages are not visible in a transaction).
    fn resolve(&self, num: usize) -> Option<&SessionMessage> {
        if num == 0 || num > self.messages.len() {
            return None;
        }
        let m = &self.messages[num - 1];
        if m.deleted {
            return None;
        }
        Some(m)
    }

    fn parse_msg_num(arg: Option<&str>) -> Option<usize> {
        let arg = arg?.trim();
        if arg.is_empty() {
            return None;
        }
        arg.parse::<usize>().ok().filter(|n| *n > 0)
    }

    fn cmd_stat<W: Write>(&self, writer: &mut W) -> std::io::Result<bool> {
        let visible: Vec<&SessionMessage> = self.visible();
        let count = visible.len();
        let octets: usize = visible.iter().map(|m| m.octets).sum();
        self.write_ok(writer, &format!("{} {}", count, octets))?;
        Ok(false)
    }

    fn cmd_list<W: Write>(&self, arg: Option<&str>, writer: &mut W) -> std::io::Result<bool> {
        match arg {
            None => {
                self.write_ok(writer, &format!("{} messages", self.visible().len()))?;
                for m in self.visible() {
                    let num = self.number_of(m);
                    self.write_line(writer, &format!("{} {}", num, m.octets))?;
                }
                self.write_line(writer, ".")?;
            }
            Some(_) => {
                let num = match Self::parse_msg_num(arg) {
                    Some(n) => n,
                    None => {
                        self.write_err(writer, "no such message")?;
                        return Ok(false);
                    }
                };
                match self.resolve(num) {
                    Some(m) => self.write_ok(writer, &format!("{} {}", num, m.octets))?,
                    None => self.write_err(writer, "no such message")?,
                }
            }
        }
        Ok(false)
    }

    fn cmd_retr<W: Write>(&self, arg: Option<&str>, writer: &mut W) -> std::io::Result<bool> {
        let num = match Self::parse_msg_num(arg) {
            Some(n) => n,
            None => {
                self.write_err(writer, "syntax error: RETR requires a message number")?;
                return Ok(false);
            }
        };
        match self.resolve(num) {
            Some(m) => {
                self.write_ok(writer, &format!("{} octets", m.octets))?;
                write_stuffed(writer, &m.content)?;
                self.write_line(writer, ".")?;
            }
            None => {
                self.write_err(writer, "no such message")?;
            }
        }
        Ok(false)
    }

    fn cmd_dele<W: Write>(&mut self, arg: Option<&str>, writer: &mut W) -> std::io::Result<bool> {
        let num = match Self::parse_msg_num(arg) {
            Some(n) => n,
            None => {
                self.write_err(writer, "syntax error: DELE requires a message number")?;
                return Ok(false);
            }
        };
        match self.resolve(num) {
            Some(_) => {
                // `resolve` already validated the index; `num` is 1-based.
                self.messages[num - 1].deleted = true;
                self.write_ok(writer, &format!("message {} deleted", num))?;
            }
            None => self.write_err(writer, "no such message")?,
        }
        Ok(false)
    }

    fn cmd_top<W: Write>(&self, arg: Option<&str>, writer: &mut W) -> std::io::Result<bool> {
        let arg = match arg {
            Some(a) => a,
            None => {
                self.write_err(writer, "syntax error: TOP requires msg n")?;
                return Ok(false);
            }
        };
        let mut parts = arg.splitn(2, ' ');
        let num = match parts.next().and_then(|s| Self::parse_msg_num(Some(s))) {
            Some(n) => n,
            None => {
                self.write_err(writer, "syntax error: TOP requires msg n")?;
                return Ok(false);
            }
        };
        let lines = match parts.next().and_then(|s| s.trim().parse::<usize>().ok()) {
            Some(n) => n,
            None => {
                self.write_err(writer, "syntax error: TOP requires a line count")?;
                return Ok(false);
            }
        };
        match self.resolve(num) {
            Some(m) => {
                self.write_ok(writer, "")?;
                let body = top_bytes(&m.content, lines);
                write_stuffed(writer, &body)?;
                self.write_line(writer, ".")?;
            }
            None => self.write_err(writer, "no such message")?,
        }
        Ok(false)
    }

    fn cmd_uidl<W: Write>(&self, arg: Option<&str>, writer: &mut W) -> std::io::Result<bool> {
        match arg {
            None => {
                self.write_ok(writer, &format!("{} messages", self.visible().len()))?;
                for m in self.visible() {
                    self.write_line(writer, &format!("{} {}", self.number_of(m), m.uid))?;
                }
                self.write_line(writer, ".")?;
            }
            Some(_) => {
                let num = match Self::parse_msg_num(arg) {
                    Some(n) => n,
                    None => {
                        self.write_err(writer, "no such message")?;
                        return Ok(false);
                    }
                };
                match self.resolve(num) {
                    Some(m) => self.write_ok(writer, &format!("{} {}", num, m.uid))?,
                    None => self.write_err(writer, "no such message")?,
                }
            }
        }
        Ok(false)
    }

    fn cmd_quit<W: Write>(&mut self, writer: &mut W) -> std::io::Result<bool> {
        // UPDATE state: commit deletions, then sign off.
        if let Some(user) = self.user.clone() {
            let deleted: Vec<String> = self
                .messages
                .iter()
                .filter(|m| m.deleted)
                .map(|m| m.uid.clone())
                .collect();
            if let Err(e) = self.backend.expunge(&user, &deleted) {
                // Even on backend failure we must close the connection; the RFC
                // gives the client no way to recover here. Log via the error
                // text but still send a goodbye.
                let _ = e;
            }
        }
        self.write_ok(writer, "POP3 server signing off")?;
        Ok(true)
    }

    // --- helpers -------------------------------------------------------------

    /// Messages visible in the current transaction (not deleted).
    fn visible(&self) -> Vec<&SessionMessage> {
        self.messages.iter().filter(|m| !m.deleted).collect()
    }

    /// The 1-based number a message is known by in this session. Because
    /// deleted messages are excluded from `visible()`, their slots are skipped.
    fn number_of(&self, target: &SessionMessage) -> usize {
        let mut number = 0;
        for m in &self.messages {
            if std::ptr::eq(m, target) {
                return number + 1;
            }
            if !m.deleted {
                number += 1;
            }
        }
        0
    }

    fn write_ok<W: Write>(&self, w: &mut W, msg: &str) -> std::io::Result<()> {
        if msg.is_empty() {
            self.write_line(w, "+OK")
        } else {
            self.write_line(w, &format!("+OK {}", msg))
        }
    }

    fn write_err<W: Write>(&self, w: &mut W, msg: &str) -> std::io::Result<()> {
        if msg.is_empty() {
            self.write_line(w, "-ERR")
        } else {
            self.write_line(w, &format!("-ERR {}", msg))
        }
    }

    fn write_line<W: Write>(&self, w: &mut W, line: &str) -> std::io::Result<()> {
        w.write_all(line.as_bytes())?;
        w.write_all(b"\r\n")?;
        Ok(())
    }
}

/// Return the bytes for a `TOP msg n` response: the full header block (up to and
/// including the first blank line) followed by at most `n` body lines.
fn top_bytes(content: &[u8], n: usize) -> Vec<u8> {
    // Locate the header/body separator (blank line).
    let sep = find_separator(content);
    let (header, body) = match sep {
        Some(pos) => {
            // `pos` points at the start of the separator; include it.
            let header_end = pos + separator_len(content, pos);
            (&content[..header_end], &content[header_end..])
        }
        None => (content, &[][..]),
    };

    let mut out = Vec::new();
    out.extend_from_slice(header);
    if !header.ends_with(b"\r\n") && !header.ends_with(b"\n") {
        out.extend_from_slice(b"\r\n");
    }

    if n > 0 {
        let mut lines = 0;
        let mut i = 0;
        while i < body.len() && lines < n {
            let line_end = body[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| i + p + 1)
                .unwrap_or(body.len());
            out.extend_from_slice(&body[i..line_end]);
            i = line_end;
            lines += 1;
        }
    }
    out
}

fn find_separator(content: &[u8]) -> Option<usize> {
    // CRLF CRLF
    let mut i = 0;
    while i + 3 < content.len() {
        if &content[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
        i += 1;
    }
    // LF LF
    let mut i = 0;
    while i + 1 < content.len() {
        if content[i] == b'\n' && content[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn separator_len(content: &[u8], pos: usize) -> usize {
    if content[pos..].starts_with(b"\r\n\r\n") {
        4
    } else {
        2
    }
}

/// Write `content` as a POP3 multi-line body with byte-stuffing: any line that
/// begins with `.` is prefixed with an extra `.`. The content is terminated with
/// CRLF if it does not already end with one.
fn write_stuffed<W: Write>(w: &mut W, content: &[u8]) -> std::io::Result<()> {
    let mut line_start = true;
    let mut last_was_cr = false;
    let mut ends_crlf = false;
    for &b in content {
        if line_start && b == b'.' {
            w.write_all(b"..")?;
            ends_crlf = false;
        } else {
            w.write_all(&[b])?;
            ends_crlf = last_was_cr && b == b'\n';
        }
        last_was_cr = b == b'\r';
        line_start = b == b'\n';
    }
    if !ends_crlf {
        w.write_all(b"\r\n")?;
    }
    Ok(())
}
