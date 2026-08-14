// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for the NETCONF crate.

use thiserror::Error;

/// The result type used throughout this crate.
pub type Result<T> = std::result::Result<T, NetconfError>;

/// Errors produced while handling NETCONF sessions and messages.
#[derive(Debug, Error)]
pub enum NetconfError {
    /// The XML in a NETCONF message could not be parsed.
    #[error("xml parse error: {0}")]
    XmlParse(String),

    /// A message failed the NETCONF framing rules (RFC 6242).
    #[error("framing error: {0}")]
    Framing(String),

    /// The transport (SSH channel) reported a closed connection.
    #[error("transport closed")]
    TransportClosed,

    /// A NETCONF `<rpc>` was received without a `message-id` attribute.
    #[error("rpc is missing the required message-id attribute")]
    MissingMessageId,

    /// The `<hello>` capability exchange did not complete.
    #[error("capability exchange error: {0}")]
    CapabilityExchange(String),

    /// An operation was attempted against an unsupported datastore.
    #[error("unknown datastore: {0}")]
    UnknownDatastore(String),

    /// An RPC produced an error reply.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// A low-level I/O/transport failure.
    #[error("io error: {0}")]
    Io(String),

    /// An error propagated from the underlying SSH transport ([`tpt_ssh`]).
    #[error("ssh transport error: {0}")]
    Ssh(String),
}

impl From<tpt_ssh::Error> for NetconfError {
    fn from(e: tpt_ssh::Error) -> Self {
        NetconfError::Ssh(e.to_string())
    }
}

impl From<NetconfError> for String {
    fn from(e: NetconfError) -> String {
        e.to_string()
    }
}
