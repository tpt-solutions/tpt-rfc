// SPDX-License-Identifier: MIT OR Apache-2.0
//! SIP methods (RFC 3261 §7.1, §10).

use crate::error::{Result, SipError};

/// A SIP method token.
///
/// The six methods defined by the core SIP spec are first-class; any
/// other token is preserved verbatim in [`Method::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// `INVITE` — initiate a session.
    Invite,
    /// `ACK` — confirm a session establishment.
    Ack,
    /// `BYE` — terminate a session.
    Bye,
    /// `CANCEL` — cancel a pending request.
    Cancel,
    /// `REGISTER` — bind a contact to an address-of-record.
    Register,
    /// `OPTIONS` — query capabilities.
    Options,
    /// Any extension method, preserved as-is.
    Other(String),
}

impl Method {
    /// Parse a method token, case-insensitively for the known methods.
    pub fn parse(token: &str) -> Result<Method> {
        if token.is_empty() {
            return Err(SipError::UnknownMethod(token.to_string()));
        }
        Ok(match token.to_ascii_uppercase().as_str() {
            "INVITE" => Method::Invite,
            "ACK" => Method::Ack,
            "BYE" => Method::Bye,
            "CANCEL" => Method::Cancel,
            "REGISTER" => Method::Register,
            "OPTIONS" => Method::Options,
            _ => Method::Other(token.to_string()),
        })
    }

    /// `true` for `INVITE` (used by the transaction layer to select the
    /// INVITE-specific state machine).
    pub fn is_invite(&self) -> bool {
        matches!(self, Method::Invite)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Other(o) => o.as_str(),
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for Method {
    type Err = SipError;
    fn from_str(s: &str) -> Result<Self> {
        Method::parse(s)
    }
}
