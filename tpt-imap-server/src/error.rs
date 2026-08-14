// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for the IMAP server.

use thiserror::Error;

/// Errors surfaced while handling an IMAP session or querying the store.
#[derive(Debug, Error)]
pub enum ImapError {
    /// The requested mailbox does not exist.
    #[error("no such mailbox")]
    NoSuchMailbox,
    /// The mailbox already exists.
    #[error("mailbox already exists")]
    MailboxExists,
    /// Authentication failed (bad credentials).
    #[error("authentication failed")]
    AuthFailed,
    /// The session is not authenticated.
    #[error("not authenticated")]
    NotAuthenticated,
    /// No mailbox is currently selected.
    #[error("no mailbox selected")]
    NoMailboxSelected,
    /// A command argument could not be parsed.
    #[error("invalid arguments")]
    InvalidArguments,
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Base64 decoding failure (SASL payloads).
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Any other backend-specific failure.
    #[error("{0}")]
    Other(String),
}

/// Convenience result alias used across the crate.
pub type Result<T> = std::result::Result<T, ImapError>;
