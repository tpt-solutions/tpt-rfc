// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference [`MailboxStore`](crate::store::MailboxStore) implementation that
//! keeps all mailboxes and messages in memory. Intended for tests, examples,
//! and as a template for custom backends.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::error::{ImapError, Result};
use crate::store::MailboxStore;
use crate::types::*;

const DELIM: &str = "/";

#[derive(Clone)]
struct StoredMessage {
    uid: u32,
    flags: HashSet<Flag>,
    internal_date: i64,
    data: Vec<u8>,
}

struct Mailbox {
    name: String,
    subscribed: bool,
    uidvalidity: u32,
    uidnext: u32,
    messages: Vec<StoredMessage>,
}

struct Inner {
    users: HashMap<String, String>,
    /// user -> mailbox name -> mailbox
    mailboxes: HashMap<String, HashMap<String, Mailbox>>,
}

/// An in-memory mailbox store. Thread-safe via an internal mutex.
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    /// Create an empty store with no users or mailboxes.
    pub fn new() -> Self {
        InMemoryStore {
            inner: Mutex::new(Inner {
                users: HashMap::new(),
                mailboxes: HashMap::new(),
            }),
        }
    }

    /// Builder: register a user with a password (plaintext, in-memory only).
    pub fn with_user(self, user: &str, password: &str) -> Self {
        self.inner
            .lock()
            .unwrap()
            .users
            .insert(user.to_string(), password.to_string());
        self
    }

    /// Builder / test helper: create an (empty) mailbox for a user.
    pub fn add_mailbox(&self, user: &str, name: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let name = canonical(name);
        let mbs = g.mailboxes.entry(user.to_string()).or_default();
        if mbs.contains_key(&name) {
            return Err(ImapError::MailboxExists);
        }
        let subscribed = name.eq_ignore_ascii_case("INBOX");
        mbs.insert(
            name.clone(),
            Mailbox {
                name,
                subscribed,
                uidvalidity: 1,
                uidnext: 1,
                messages: Vec::new(),
            },
        );
        Ok(())
    }

    /// Builder / test helper: append a pre-built message to a mailbox.
    pub fn add_message(
        &self,
        user: &str,
        name: &str,
        data: Vec<u8>,
        flags: HashSet<Flag>,
        internal_date: i64,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let mb = g
            .mailboxes
            .get_mut(user)
            .and_then(|m| m.get_mut(&canonical(name)))
            .ok_or(ImapError::NoSuchMailbox)?;
        let uid = mb.uidnext;
        mb.uidnext += 1;
        mb.messages.push(StoredMessage {
            uid,
            flags,
            internal_date,
            data,
        });
        Ok(())
    }
}

impl MailboxStore for InMemoryStore {
    fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        let g = self.inner.lock().unwrap();
        Ok(g.users.get(username).map_or(false, |p| p == password))
    }

    fn list(&self, username: &str, reference: &str, pattern: &str) -> Result<Vec<ListEntry>> {
        let g = self.inner.lock().unwrap();
        let mbs = match g.mailboxes.get(username) {
            Some(m) => m,
            None => return Ok(Vec::new()),
        };
        let combined = combine(reference, pattern);
        let mut out: Vec<ListEntry> = mbs
            .values()
            .filter(|mb| match_wildcard(&mb.name, &combined))
            .map(|mb| ListEntry {
                name: mb.name.clone(),
                attributes: attributes(mb),
                delimiter: DELIM.to_string(),
            })
            .collect();

        // RFC 9051: INBOX is always listable, even if not present in storage.
        let inbox_match =
            combined.eq_ignore_ascii_case("INBOX") || match_wildcard("INBOX", &combined);
        if inbox_match && !out.iter().any(|e| e.name.eq_ignore_ascii_case("INBOX")) {
            out.push(ListEntry {
                name: "INBOX".to_string(),
                attributes: vec!["\\Unmarked".to_string()],
                delimiter: DELIM.to_string(),
            });
        }
        Ok(out)
    }

    fn lsub(&self, username: &str, reference: &str, pattern: &str) -> Result<Vec<ListEntry>> {
        let g = self.inner.lock().unwrap();
        let mbs = match g.mailboxes.get(username) {
            Some(m) => m,
            None => return Ok(Vec::new()),
        };
        let combined = combine(reference, pattern);
        let mut out: Vec<ListEntry> = mbs
            .values()
            .filter(|mb| mb.subscribed && match_wildcard(&mb.name, &combined))
            .map(|mb| ListEntry {
                name: mb.name.clone(),
                attributes: attributes(mb),
                delimiter: DELIM.to_string(),
            })
            .collect();
        let inbox_match =
            combined.eq_ignore_ascii_case("INBOX") || match_wildcard("INBOX", &combined);
        if inbox_match
            && !out.iter().any(|e| e.name.eq_ignore_ascii_case("INBOX"))
            && mbs
                .values()
                .any(|mb| mb.name.eq_ignore_ascii_case("INBOX") && mb.subscribed)
        {
            out.push(ListEntry {
                name: "INBOX".to_string(),
                attributes: vec!["\\Subscribed".to_string(), "\\Unmarked".to_string()],
                delimiter: DELIM.to_string(),
            });
        }
        Ok(out)
    }

    fn create(&self, username: &str, name: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let name = canonical(name);
        let mbs = g.mailboxes.entry(username.to_string()).or_default();
        if mbs.contains_key(&name) {
            return Err(ImapError::MailboxExists);
        }
        mbs.insert(
            name.clone(),
            Mailbox {
                name,
                subscribed: false,
                uidvalidity: 1,
                uidnext: 1,
                messages: Vec::new(),
            },
        );
        Ok(())
    }

    fn delete(&self, username: &str, name: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let name = canonical(name);
        let mbs = g
            .mailboxes
            .get_mut(username)
            .ok_or(ImapError::NoSuchMailbox)?;
        if mbs.remove(&name).is_none() {
            return Err(ImapError::NoSuchMailbox);
        }
        Ok(())
    }

    fn rename(&self, username: &str, from: &str, to: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let from = canonical(from);
        let to = canonical(to);
        let mbs = g
            .mailboxes
            .get_mut(username)
            .ok_or(ImapError::NoSuchMailbox)?;
        let mb = mbs.remove(&from).ok_or(ImapError::NoSuchMailbox)?;
        if mbs.contains_key(&to) {
            return Err(ImapError::MailboxExists);
        }
        mbs.insert(to, mb);
        Ok(())
    }

    fn subscribe(&self, username: &str, name: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let name = canonical(name);
        let mb = g
            .mailboxes
            .entry(username.to_string())
            .or_default()
            .entry(name.clone())
            .or_insert(Mailbox {
                name,
                subscribed: false,
                uidvalidity: 1,
                uidnext: 1,
                messages: Vec::new(),
            });
        mb.subscribed = true;
        Ok(())
    }

    fn unsubscribe(&self, username: &str, name: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let name = canonical(name);
        if let Some(mb) = g.mailboxes.get_mut(username).and_then(|m| m.get_mut(&name)) {
            mb.subscribed = false;
        }
        Ok(())
    }

    fn mailbox_status(&self, username: &str, name: &str) -> Result<MailboxStatus> {
        let g = self.inner.lock().unwrap();
        let mb = get_mailbox(&g, username, name)?;
        let messages = mb.messages.len() as u32;
        let unseen = mb
            .messages
            .iter()
            .filter(|m| !m.flags.contains(&Flag::System(SystemFlag::Seen)))
            .count() as u32;
        let deleted = mb
            .messages
            .iter()
            .filter(|m| m.flags.contains(&Flag::System(SystemFlag::Deleted)))
            .count() as u32;
        Ok(MailboxStatus {
            messages,
            uidnext: mb.uidnext,
            uidvalidity: mb.uidvalidity,
            unseen,
            deleted,
        })
    }

    fn messages(&self, username: &str, name: &str) -> Result<Vec<MessageSnapshot>> {
        let g = self.inner.lock().unwrap();
        let mb = get_mailbox(&g, username, name)?;
        Ok(mb
            .messages
            .iter()
            .map(|m| MessageSnapshot {
                uid: m.uid,
                flags: m.flags.clone(),
                internal_date: m.internal_date,
                data: m.data.clone(),
            })
            .collect())
    }

    fn set_flags(
        &self,
        username: &str,
        name: &str,
        uid: u32,
        op: FlagOp,
        flags: &[Flag],
    ) -> Result<HashSet<Flag>> {
        let mut g = self.inner.lock().unwrap();
        let mb = get_mailbox_mut(&mut g, username, name)?;
        let m = mb
            .messages
            .iter_mut()
            .find(|m| m.uid == uid)
            .ok_or(ImapError::NoSuchMailbox)?;
        match op {
            FlagOp::Replace => {
                m.flags = flags.to_vec().into_iter().collect();
            }
            FlagOp::Add => {
                for f in flags {
                    m.flags.insert(f.clone());
                }
            }
            FlagOp::Remove => {
                for f in flags {
                    m.flags.remove(f);
                }
            }
        }
        Ok(m.flags.clone())
    }

    fn expunge_uids(&self, username: &str, name: &str, uids: &[u32]) -> Result<Vec<u32>> {
        let mut g = self.inner.lock().unwrap();
        let mb = get_mailbox_mut(&mut g, username, name)?;
        let target: HashSet<u32> = uids.iter().copied().collect();
        let removed: Vec<u32> = mb
            .messages
            .iter()
            .filter(|m| {
                target.contains(&m.uid) && m.flags.contains(&Flag::System(SystemFlag::Deleted))
            })
            .map(|m| m.uid)
            .collect();
        mb.messages.retain(|m| {
            !(target.contains(&m.uid) && m.flags.contains(&Flag::System(SystemFlag::Deleted)))
        });
        Ok(removed)
    }

    fn append(&self, username: &str, name: &str, msg: AppendMessage) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let mb = get_mailbox_mut(&mut g, username, name)?;
        let uid = mb.uidnext;
        mb.uidnext += 1;
        mb.messages.push(StoredMessage {
            uid,
            flags: msg.flags,
            internal_date: msg.internal_date.unwrap_or_else(now),
            data: msg.data,
        });
        Ok(())
    }

    fn copy_messages(&self, username: &str, from: &str, uids: &[u32], to: &str) -> Result<()> {
        let target: HashSet<u32> = uids.iter().copied().collect();
        let to_copy = {
            let g = self.inner.lock().unwrap();
            let src = get_mailbox(&g, username, from)?;
            src.messages
                .iter()
                .filter(|m| target.contains(&m.uid))
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut g = self.inner.lock().unwrap();
        let dst = get_mailbox_mut(&mut g, username, to)?;
        for mut m in to_copy {
            m.uid = dst.uidnext;
            dst.uidnext += 1;
            dst.messages.push(m);
        }
        Ok(())
    }
}

fn get_mailbox<'a>(g: &'a Inner, user: &str, name: &str) -> Result<&'a Mailbox> {
    let name = canonical(name);
    g.mailboxes
        .get(user)
        .and_then(|m| m.get(&name))
        .ok_or(ImapError::NoSuchMailbox)
}

fn get_mailbox_mut<'a>(g: &'a mut Inner, user: &str, name: &str) -> Result<&'a mut Mailbox> {
    let name = canonical(name);
    g.mailboxes
        .get_mut(user)
        .and_then(|m| m.get_mut(&name))
        .ok_or(ImapError::NoSuchMailbox)
}

/// Canonicalise a mailbox name: INBOX is case-insensitive per RFC 9051.
fn canonical(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") {
        "INBOX".to_string()
    } else {
        name.to_string()
    }
}

fn attributes(mb: &Mailbox) -> Vec<String> {
    let mut a = Vec::new();
    if mb.subscribed {
        a.push("\\Subscribed".to_string());
    }
    a.push("\\Unmarked".to_string());
    a
}

fn combine(reference: &str, pattern: &str) -> String {
    if reference.is_empty() {
        return pattern.to_string();
    }
    if pattern.is_empty() {
        return reference.to_string();
    }
    if reference.ends_with(DELIM) || pattern.starts_with(DELIM) {
        format!("{reference}{pattern}")
    } else {
        format!("{reference}{DELIM}{pattern}")
    }
}

/// Match a mailbox name against a LIST/LSUB pattern with `*` (any, incl.
/// delimiter) and `%` (any except delimiter) wildcards.
fn match_wildcard(name: &str, pattern: &str) -> bool {
    wildcard_match(name.as_bytes(), pattern.as_bytes())
}

fn wildcard_match(s: &[u8], p: &[u8]) -> bool {
    if p.is_empty() {
        return s.is_empty();
    }
    match p[0] {
        b'*' => {
            for i in 0..=s.len() {
                if wildcard_match(&s[i..], &p[1..]) {
                    return true;
                }
            }
            false
        }
        b'%' => {
            if wildcard_match(s, &p[1..]) {
                return true;
            }
            for i in 0..s.len() {
                if s[i] == DELIM.as_bytes()[0] {
                    break;
                }
                if wildcard_match(&s[i + 1..], &p[1..]) {
                    return true;
                }
            }
            false
        }
        c => {
            if s.is_empty() || s[0] != c {
                false
            } else {
                wildcard_match(&s[1..], &p[1..])
            }
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
