// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core data types shared between the server and pluggable mailbox backends.

use std::collections::HashSet;

/// System (server-defined) IMAP flags.
///
/// Per RFC 9051 (IMAP4rev2) the `\Recent` flag is obsolete and is not
/// represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemFlag {
    /// `\Seen` — the message has been read.
    Seen,
    /// `\Answered` — the message has been answered.
    Answered,
    /// `\Flagged` — the message is flagged for urgent/special attention.
    Flagged,
    /// `\Deleted` — the message is marked for removal by EXPUNGE.
    Deleted,
    /// `\Draft` — the message is a draft.
    Draft,
}

/// An IMAP message flag: either a [`SystemFlag`] or a user keyword.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Flag {
    /// A server-defined flag.
    System(SystemFlag),
    /// A user-defined keyword (any atom that does not begin with `\`).
    Keyword(String),
}

impl Flag {
    /// Render the flag in IMAP syntax (e.g. `\Seen`, `MyKeyword`).
    pub fn as_str(&self) -> String {
        match self {
            Flag::System(s) => match s {
                SystemFlag::Seen => "\\Seen".to_string(),
                SystemFlag::Answered => "\\Answered".to_string(),
                SystemFlag::Flagged => "\\Flagged".to_string(),
                SystemFlag::Deleted => "\\Deleted".to_string(),
                SystemFlag::Draft => "\\Draft".to_string(),
            },
            Flag::Keyword(k) => k.clone(),
        }
    }
}

impl std::str::FromStr for Flag {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "\\Seen" | "\\seen" => Ok(Flag::System(SystemFlag::Seen)),
            "\\Answered" | "\\answered" => Ok(Flag::System(SystemFlag::Answered)),
            "\\Flagged" | "\\flagged" => Ok(Flag::System(SystemFlag::Flagged)),
            "\\Deleted" | "\\deleted" => Ok(Flag::System(SystemFlag::Deleted)),
            "\\Draft" | "\\draft" => Ok(Flag::System(SystemFlag::Draft)),
            _ => {
                if s.starts_with('\\') {
                    Err(())
                } else {
                    Ok(Flag::Keyword(s.to_string()))
                }
            }
        }
    }
}

impl std::fmt::Display for Flag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// How a [`MailboxStore::set_flags`](crate::store::MailboxStore::set_flags)
/// operation combines the supplied flags with the existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagOp {
    /// Replace the flag set entirely.
    Replace,
    /// Add the supplied flags.
    Add,
    /// Remove the supplied flags.
    Remove,
}

/// One entry returned by `LIST` / `LSUB`.
#[derive(Debug, Clone)]
pub struct ListEntry {
    /// Canonical mailbox name.
    pub name: String,
    /// Mailbox attributes (e.g. `\Subscribed`, `\Unmarked`).
    pub attributes: Vec<String>,
    /// Hierarchy delimiter (typically `/`).
    pub delimiter: String,
}

/// Aggregate status counters for a mailbox (RFC 9051 §6.3.10 STATUS items).
#[derive(Debug, Clone)]
pub struct MailboxStatus {
    /// Number of messages.
    pub messages: u32,
    /// Next UID to be assigned.
    pub uidnext: u32,
    /// UIDVALIDITY of the mailbox.
    pub uidvalidity: u32,
    /// Number of messages without `\Seen`.
    pub unseen: u32,
    /// Number of messages with `\Deleted`.
    pub deleted: u32,
}

/// An immutable snapshot of a single message, as returned by the store.
#[derive(Debug, Clone)]
pub struct MessageSnapshot {
    /// Unique identifier within the mailbox.
    pub uid: u32,
    /// Current flags.
    pub flags: HashSet<Flag>,
    /// Internal (received/store) date, as Unix epoch seconds.
    pub internal_date: i64,
    /// Full RFC 822 message bytes.
    pub data: Vec<u8>,
}

/// A message to be appended to a mailbox (RFC 9051 §6.3.11 APPEND).
#[derive(Debug, Clone)]
pub struct AppendMessage {
    /// Full RFC 822 message bytes.
    pub data: Vec<u8>,
    /// Flags to assign on append.
    pub flags: HashSet<Flag>,
    /// Optional internal date; `None` means "now".
    pub internal_date: Option<i64>,
}
