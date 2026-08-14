// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for BGP encode/decode and protocol operations.

use thiserror::Error;

/// Errors that occur while decoding a BGP message or attribute from wire bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The byte buffer is shorter than the fixed 19-byte BGP header.
    #[error("message too short for BGP header: need at least 19 bytes, got {actual}")]
    TruncatedHeader {
        /// Bytes actually available.
        actual: usize,
    },

    /// The declared message length field is smaller than the 19-byte header, or
    /// larger than the bytes actually present.
    #[error("message length mismatch: header says {declared}, buffer has {actual}")]
    LengthMismatch {
        /// Length declared in the message header.
        declared: usize,
        /// Bytes actually available.
        actual: usize,
    },

    /// The BGP message type byte is not one of OPEN/UPDATE/NOTIFICATION/KEEPALIVE.
    #[error("unknown BGP message type: {0}")]
    UnknownMessageType(u8),

    /// A sub-field could not be read because the buffer ended prematurely.
    #[error("field truncated while decoding (needed {needed} bytes at offset {offset}, buffer len {len})")]
    TruncatedField {
        /// Number of bytes expected.
        needed: usize,
        /// Offset at which the read was attempted.
        offset: usize,
        /// Total buffer length.
        len: usize,
    },

    /// An OPEN message carries a BGP version this implementation does not
    /// support (only version 4 is implemented).
    #[error("unsupported BGP version: {0}")]
    UnsupportedVersion(u8),

    /// The optional-parameter length runs past the end of the OPEN message.
    #[error("OPEN optional parameters truncated")]
    OpenParamsTruncated,

    /// An optional-parameter capability is malformed (length too short).
    #[error("malformed BGP capability (code {code}, len {len})")]
    MalformedCapability {
        /// Capability code.
        code: u8,
        /// Declared capability length.
        len: u8,
    },

    /// A path attribute's flags are illegal (e.g. a well-known attribute marked
    /// Partial).
    #[error("illegal attribute flags for attribute type {type_code}")]
    IllegalAttributeFlags {
        /// The offending attribute type code.
        type_code: u8,
    },

    /// The total path-attribute length runs past the end of the UPDATE message.
    #[error("UPDATE path attributes truncated")]
    PathAttributesTruncated,

    /// An MP_REACH/MP_UNREACH_NLRI attribute carries an unknown AFI/SAFI pair.
    #[error("unsupported AFI {afi} / SAFI {safi}")]
    UnsupportedAfiSafi {
        /// Address Family Identifier.
        afi: u16,
        /// Subsequent Address Family Identifier.
        safi: u8,
    },

    /// A NOTIFICATION error code/subcode pair is not recognised.
    #[error("unknown NOTIFICATION code {code} / subcode {subcode}")]
    UnknownNotification {
        /// NOTIFICATION error code.
        code: u8,
        /// NOTIFICATION error subcode.
        subcode: u8,
    },
}

/// Errors raised by protocol-side operations (FSM, RIB, decision process).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BgpError {
    /// A NOTIFICATION was raised and the session must be torn down.
    #[error("BGP NOTIFICATION: code {code}, subcode {subcode}: {data:?}")]
    Notification {
        /// NOTIFICATION error code.
        code: u8,
        /// NOTIFICATION error subcode.
        subcode: u8,
        /// Trailing data carried by the NOTIFICATION.
        data: Vec<u8>,
    },

    /// The peer's OPEN message failed validation against the local
    /// configuration (e.g. AS mismatch, hold-time conflict, missing required
    /// capability).
    #[error("OPEN negotiation failed: {0}")]
    OpenNegotiationFailed(&'static str),

    /// The finite-state machine received an event that is not valid in its
    /// current state.
    #[error("invalid FSM event {event:?} in state {state:?}")]
    InvalidFsmEvent {
        /// The event that was attempted.
        event: &'static str,
        /// The state the FSM was in.
        state: &'static str,
    },

    /// An attempt to install a route failed because the prefix is malformed.
    #[error("malformed route prefix")]
    MalformedPrefix,
}

/// The crate-wide result type used by the codec (decoding can only fail with a
/// [`DecodeError`]).
pub type Result<T> = std::result::Result<T, DecodeError>;
