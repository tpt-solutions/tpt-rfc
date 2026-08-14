// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for the SMTP client and codec.

use thiserror::Error;

use crate::reply::Reply;

/// Errors produced by the SMTP client and low-level codec.
///
/// Server-side protocol rejections are *not* represented here: they are
/// ordinary `-ERR`-style SMTP replies handled inline by the session state
/// machine. This type is for transport/IO failures, malformed protocol on the
/// wire, and server replies that reject a client command.
#[derive(Debug, Error)]
pub enum SmtpError {
    /// An underlying I/O error (socket read/write, connect, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The peer closed the connection before a complete reply was read.
    #[error("connection closed by peer")]
    ConnectionClosed,

    /// A reply from the server could not be parsed (not a 3-digit reply code).
    #[error("invalid reply from server: {0}")]
    InvalidReply(String),

    /// The server rejected a command with a negative completion reply.
    #[error("server rejected command: {0}")]
    Rejected(Reply),

    /// A line read from the server was not valid UTF-8.
    #[error("invalid UTF-8 in server reply")]
    InvalidUtf8,

    /// A supplied argument (e.g. an address) violated the SMTP grammar.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
