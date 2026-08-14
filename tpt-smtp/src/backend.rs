// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable message delivery backend for the SMTP server.
//!
//! The server's job ends at the `DATA` dot-terminator: it collects the message
//! and hands a fully-formed [`Envelope`] to the backend, which decides what to
//! do with it (store, relay, pipe to a command, etc.). This keeps the protocol
//! engine storage-agnostic and lets callers bring their own mail store.

/// A complete SMTP transaction handed to a [`MailDelivery`] backend after the
/// client sends a message body terminated by `<CRLF>.<CRLF>`.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The reverse-path (the `MAIL FROM:` argument). `None` for a null
    /// reverse-path (`MAIL FROM:<>`), used for bounces.
    pub from: Option<String>,
    /// The forward-paths (the `RCPT TO:` arguments), in order received.
    pub recipients: Vec<String>,
    /// The raw message bytes as received (headers + body, CRLF line endings).
    pub message: Vec<u8>,
}

impl Envelope {
    /// Construct a new, empty envelope.
    pub fn new(from: Option<String>, recipients: Vec<String>, message: Vec<u8>) -> Self {
        Self {
            from,
            recipients,
            message,
        }
    }
}

/// Errors a delivery backend may report. These map onto SMTP negative replies
/// (`4xy`/`5xy`) at the session layer.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// A recipient is unknown / not acceptable (`550`).
    #[error("no such recipient: {0}")]
    NoSuchRecipient(String),

    /// The message was rejected (e.g. policy, size) (`552`/`554`).
    #[error("message rejected: {0}")]
    Rejected(String),

    /// A transient backend failure (`451`).
    #[error("temporary delivery failure: {0}")]
    Temporary(String),

    /// Any other backend-specific error.
    #[error("{0}")]
    Other(String),
}

/// A mail delivery sink used by the SMTP server.
///
/// Implementors must be `Send + Sync` so a single backend instance can serve
/// many connections behind an `Arc`.
pub trait MailDelivery: Send + Sync {
    /// Deliver `envelope`. Return `Ok(())` on successful acceptance, or a
    /// [`DeliveryError`] to reject (the session translates it into the
    /// appropriate `4xy`/`5xy` reply).
    fn deliver(&self, envelope: &Envelope) -> Result<(), DeliveryError>;

    /// Optionally validate a recipient during the `RCPT TO:` phase. The default
    /// accepts everyone; override to implement local-part / domain checks.
    fn accept_recipient(&self, _recipient: &str) -> Result<(), DeliveryError> {
        Ok(())
    }

    /// Optionally validate the reverse-path during `MAIL FROM:`. The default
    /// accepts everything.
    fn accept_sender(&self, _from: Option<&str>) -> Result<(), DeliveryError> {
        Ok(())
    }
}
