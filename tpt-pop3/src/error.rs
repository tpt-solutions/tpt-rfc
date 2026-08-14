// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for the POP3 server.

use thiserror::Error;

/// Errors surfaced by a [`crate::backend::MailboxBackend`] implementation.
///
/// These are storage- and authentication-level failures. The session layer maps
/// them onto `-ERR` responses; they are not used for ordinary protocol-level
/// rejections (e.g. a malformed argument), which are handled inline.
#[derive(Debug, Error)]
pub enum BackendError {
    /// Credentials were rejected by the backend.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// A referenced message does not exist (or has already been deleted).
    #[error("message not found")]
    MessageNotFound,

    /// A backend-level I/O failure (e.g. disk error). The message text is
    /// intentionally opaque to clients; it is logged server-side only.
    #[error("backend I/O error")]
    Io,

    /// Any other backend-specific failure.
    #[error("{0}")]
    Other(String),
}
