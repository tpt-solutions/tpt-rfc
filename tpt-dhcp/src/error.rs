// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for `tpt-dhcp`.

use std::net::Ipv4Addr;

use thiserror::Error;

/// Failure decoding a DHCP message from wire bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The packet is shorter than the 236-byte BOOTP header.
    #[error("message too short for BOOTP header (need {expected} bytes, got {actual})")]
    TruncatedHeader {
        /// Number of bytes required for the header.
        expected: usize,
        /// Number of bytes actually present.
        actual: usize,
    },
    /// The 4-byte magic cookie (99.130.83.99) was missing or wrong.
    #[error("bad DHCP magic cookie")]
    BadMagicCookie,
    /// An option's length field ran past the end of the packet.
    #[error("option length {len} exceeds remaining buffer of {remaining} bytes")]
    TruncatedOption {
        /// Declared option length.
        len: usize,
        /// Bytes actually remaining.
        remaining: usize,
    },
    /// A BOOTP `op` field held an unrecognised value.
    #[error("unknown BOOTP op value {0}")]
    UnknownOp(u8),
}

/// Errors surfaced by a [`crate::lease::LeaseStore`] implementation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LeaseError {
    /// No free address could be found in the managed pool.
    #[error("no free address in the pool")]
    PoolExhausted,
    /// The requested address is outside the managed pool range.
    #[error("address {0} is not in the managed pool")]
    OutOfPool(Ipv4Addr),
    /// The address is currently in declined (probation) state.
    #[error("address {0} is currently declined")]
    Declined(Ipv4Addr),
    /// No active lease exists for the address.
    #[error("no active lease for {0}")]
    NoLease(Ipv4Addr),
    /// The lease for the address belongs to a different client.
    #[error("lease for {0} belongs to a different client")]
    ClientMismatch(Ipv4Addr),
    /// The address is already leased to another client.
    #[error("address {0} is already leased to another client")]
    AddressInUse(Ipv4Addr),
    /// Any other backend-specific failure.
    #[error("{0}")]
    Other(String),
}

/// Top-level DHCP error.
#[derive(Debug, Error)]
pub enum DhcpError {
    /// A message could not be decoded.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// The lease backend rejected an operation.
    #[error(transparent)]
    Lease(#[from] LeaseError),
    /// A message arrived that is not valid in the client's current state.
    #[error("message is not valid in the current client state")]
    UnexpectedMessage,
}
