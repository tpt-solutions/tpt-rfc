// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error types for `tpt-sip`.

use std::str::Utf8Error;

use thiserror::Error;

/// Errors produced while parsing or constructing SIP messages, URIs,
/// headers, or while driving a transaction state machine.
#[derive(Debug, Error)]
pub enum SipError {
    /// A SIP message could not be parsed.
    #[error("invalid SIP message: {0}")]
    InvalidMessage(String),

    /// A SIP URI could not be parsed.
    #[error("invalid SIP URI: {0}")]
    InvalidUri(String),

    /// A header value was malformed for the expected typed form.
    #[error("invalid header `{name}`: {reason}")]
    InvalidHeader {
        /// The offending header name.
        name: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// A method token was not recognised.
    #[error("unknown method: {0}")]
    UnknownMethod(String),

    /// An operation on a transaction failed or was applied in the wrong
    /// state.
    #[error("transaction error: {0}")]
    Transaction(String),

    /// A value could not be decoded as UTF-8.
    #[error("utf-8 error: {0}")]
    Utf8(#[from] Utf8Error),

    /// A wrapped I/O error (typically from the UDP transport).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, SipError>;
