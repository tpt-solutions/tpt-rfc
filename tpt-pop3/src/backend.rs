// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable mailbox storage backend for the POP3 server.
//!
//! A POP3 server only ever serves *one* mailbox per authenticated user, so the
//! backend trait is intentionally minimal: it authenticates the user, hands the
//! session a snapshot of the user's messages, and commits deletions on `QUIT`.
//! The session layer owns the deletion flags and message numbering during a
//! transaction; the backend just stores durable state.

pub use crate::error::BackendError;

/// A single mailbox message as observed by a POP3 session.
///
/// `content` should be CRLF (`\r\n`) line-terminated; the session performs
/// POP3 "byte-stuffing" (a leading `.` is escaped to `..`) and appends the
/// terminating CRLF automatically when sending the message to a client.
#[derive(Debug, Clone)]
pub struct MailboxMessage {
    /// Stable unique identifier used by the `UIDL` command. Must be unique
    /// within a mailbox and remain constant for the life of the message.
    pub uid: String,
    /// Size of the message in octets (bytes). Defaults to `content.len()` when
    /// constructed via [`MailboxMessage::new`].
    pub octets: usize,
    /// Raw message bytes (headers, blank line, body).
    pub content: Vec<u8>,
}

impl MailboxMessage {
    /// Create a message, deriving `octets` from `content.len()`.
    pub fn new(uid: impl Into<String>, content: Vec<u8>) -> Self {
        let octets = content.len();
        Self {
            uid: uid.into(),
            octets,
            content,
        }
    }
}

/// Backend trait a POP3 server uses to authenticate users and load/store mail.
///
/// Implementors must be `Send + Sync` so a single backend instance can serve
/// many connections behind an `Arc`.
pub trait MailboxBackend: Send + Sync {
    /// Check `user`/`pass` (the `USER` + `PASS` sequence) and return `Ok(true)`
    /// if the credentials are accepted.
    fn authenticate(&self, user: &str, pass: &str) -> Result<bool, BackendError>;

    /// Check an `APOP` attempt. `timestamp` is the exact string that appeared
    /// inside `<...>` in the server greeting; `digest` is the client-supplied
    /// hex MD5 digest. A correct implementation computes
    /// `md5(timestamp + password)` and compares it case-insensitively to
    /// `digest`. Backends that do not support APOP may return `Ok(false)`.
    fn authenticate_apop(
        &self,
        user: &str,
        timestamp: &str,
        digest: &str,
    ) -> Result<bool, BackendError> {
        let _ = (user, timestamp, digest);
        Ok(false)
    }

    /// Return the current set of messages for `user`. Called once when a user
    /// enters the TRANSACTION state. Deletions made later in the session are
    /// *not* reflected here — they are reported via [`MailboxBackend::expunge`].
    fn messages(&self, user: &str) -> Result<Vec<MailboxMessage>, BackendError>;

    /// Permanently remove the messages identified by `uids` for `user`. Called
    /// once, during the UPDATE state (on `QUIT`), for messages marked deleted
    /// in the session. A backend that ignores deletions (e.g. read-only) can
    /// implement this as a no-op returning `Ok(())`.
    fn expunge(&self, user: &str, uids: &[String]) -> Result<(), BackendError>;
}
