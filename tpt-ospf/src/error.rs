// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for OSPF encode/decode and protocol operations.

use thiserror::Error;

/// Errors that occur while decoding an OSPF packet or LSA from wire bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The byte buffer is shorter than the fixed OSPF packet header (24 bytes
    /// for OSPFv2, 16 bytes for OSPFv3).
    #[error("packet too short for OSPF header: need at least {needed} bytes, got {actual}")]
    TruncatedHeader {
        /// Minimum header length in bytes.
        needed: usize,
        /// Bytes actually available.
        actual: usize,
    },

    /// The OSPF version byte is neither 2 (OSPFv2) nor 3 (OSPFv3).
    #[error("unsupported OSPF version: {0}")]
    UnsupportedVersion(u8),

    /// The packet type byte is not one of Hello/DBD/LSR/LSU/LSAck.
    #[error("unknown OSPF packet type: {0}")]
    UnknownPacketType(u8),

    /// The declared packet length field exceeds the bytes actually present, or
    /// is smaller than the header.
    #[error("packet length mismatch: header says {declared}, buffer has {actual}")]
    LengthMismatch {
        /// Length declared in the packet header.
        declared: usize,
        /// Bytes actually available.
        actual: usize,
    },

    /// The trailing body of a packet (e.g. a list of LSA headers) runs past the
    /// end of the declared packet length.
    #[error("packet body truncated while decoding sub-records")]
    TruncatedBody,

    /// A 32-bit IP/router/area id field could not be read.
    #[error("could not read a {size}-byte field at offset {offset} (buffer len {len})")]
    FieldRead {
        /// Number of bytes expected.
        size: usize,
        /// Offset at which the read was attempted.
        offset: usize,
        /// Total buffer length.
        len: usize,
    },

    /// A Link State Id / advertising router / sequence-number triple did not
    /// parse into a recognised LSA type.
    #[error("unrecognised LSA type value: {0}")]
    UnknownLsaType(u8),

    /// A Router-LSA link record was shorter than the 12-byte minimum.
    #[error("router-LSA link record truncated")]
    TruncatedRouterLink,
}

/// Errors raised by protocol-side operations (LSDB, FSM, SPF).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OspfError {
    /// Attempted to install an LSA whose header is older than the one already in
    /// the database (not a hard error, but rejected by flooding checks).
    #[error("LSA is older than the current database copy (seq {current} > {incoming})")]
    LsaTooOld {
        /// Sequence number currently stored.
        current: u32,
        /// Sequence number of the incoming LSA.
        incoming: u32,
    },

    /// SPF was run from a root router that has no Router-LSA in the database.
    #[error("SPF root {0:?} has no Router-LSA in the database")]
    SpfRootMissing([u8; 4]),

    /// A neighbor FSM event is not valid in the current state (a no-op in the
    /// spec, surfaced here for callers that want strict checking).
    #[error("invalid neighbor event {event:?} in state {state:?}")]
    InvalidNeighborEvent {
        /// The event that was attempted.
        event: &'static str,
        /// The state the neighbor was in.
        state: &'static str,
    },
}

/// The crate-wide result type.
pub type Result<T> = std::result::Result<T, DecodeError>;
