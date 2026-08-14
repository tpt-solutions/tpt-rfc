// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pluggable mailbox storage trait.
//!
//! Implementors own the actual message data; the server owns protocol state
//! (selected mailbox, sequence-number↔UID mapping, per-session expunge view).
//! All methods take `&self` so a single backend can serve many connections
//! behind an `Arc`.

use std::collections::HashSet;

use crate::error::Result;
use crate::types::*;

/// A mailbox storage backend. Implement this trait to plug your own message
/// store (database, filesystem, object storage, ...) into the IMAP server.
///
/// The trait is object-safe and is used behind an `Arc<dyn MailboxStore>` by
/// the server, so a single instance can serve every connection.
pub trait MailboxStore: Send + Sync + 'static {
    /// Validate `username`/`password`. Returns `Ok(true)` if they are valid.
    fn authenticate(&self, username: &str, password: &str) -> Result<bool>;

    /// List mailboxes matching `reference` + `pattern` (RFC 9051 §6.3.8 LIST).
    fn list(&self, username: &str, reference: &str, pattern: &str) -> Result<Vec<ListEntry>>;

    /// List *subscribed* mailboxes matching `reference` + `pattern`
    /// (RFC 9051 §6.3.9 LSUB).
    fn lsub(&self, username: &str, reference: &str, pattern: &str) -> Result<Vec<ListEntry>>;

    /// Create a mailbox (RFC 9051 §6.3.3 CREATE).
    fn create(&self, username: &str, name: &str) -> Result<()>;

    /// Delete a mailbox (RFC 9051 §6.3.4 DELETE).
    fn delete(&self, username: &str, name: &str) -> Result<()>;

    /// Rename a mailbox (RFC 9051 §6.3.5 RENAME).
    fn rename(&self, username: &str, from: &str, to: &str) -> Result<()>;

    /// Mark a mailbox as subscribed (RFC 9051 §6.3.6 SUBSCRIBE).
    fn subscribe(&self, username: &str, name: &str) -> Result<()>;

    /// Remove a mailbox's subscription (RFC 9051 §6.3.7 UNSUBSCRIBE).
    fn unsubscribe(&self, username: &str, name: &str) -> Result<()>;

    /// Return status counters for a mailbox.
    fn mailbox_status(&self, username: &str, name: &str) -> Result<MailboxStatus>;

    /// Return a snapshot of every message in a mailbox, ordered by UID.
    fn messages(&self, username: &str, name: &str) -> Result<Vec<MessageSnapshot>>;

    /// Modify the flags of a single message (by UID) and return the resulting
    /// flag set.
    fn set_flags(
        &self,
        username: &str,
        name: &str,
        uid: u32,
        op: FlagOp,
        flags: &[Flag],
    ) -> Result<HashSet<Flag>>;

    /// Permanently remove the identified messages (which must carry
    /// `\Deleted`) and return the UIDs removed, in ascending order.
    fn expunge_uids(&self, username: &str, name: &str, uids: &[u32]) -> Result<Vec<u32>>;

    /// Expunge every `\Deleted` message. The default implementation derives
    /// the target UIDs from [`MailboxStore::messages`] and delegates to
    /// [`MailboxStore::expunge_uids`].
    fn expunge(&self, username: &str, name: &str) -> Result<Vec<u32>> {
        let deleted: Vec<u32> = self
            .messages(username, name)?
            .into_iter()
            .filter(|m| m.flags.contains(&Flag::System(SystemFlag::Deleted)))
            .map(|m| m.uid)
            .collect();
        self.expunge_uids(username, name, &deleted)
    }

    /// Append a message to a mailbox (RFC 9051 §6.3.11 APPEND).
    fn append(&self, username: &str, name: &str, msg: AppendMessage) -> Result<()>;

    /// Copy the identified messages from one mailbox to another, assigning
    /// fresh UIDs in the destination.
    fn copy_messages(&self, username: &str, from: &str, uids: &[u32], to: &str) -> Result<()>;
}

/// Convenience: does this store contain a mailbox for the user?
pub fn mailbox_exists<S: MailboxStore>(store: &S, user: &str, name: &str) -> bool {
    store.mailbox_status(user, name).is_ok()
}
