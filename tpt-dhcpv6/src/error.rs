// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for `tpt-dhcpv6`.

use std::net::Ipv6Addr;

use thiserror::Error;

/// Failure decoding a DHCPv6 message or option from wire bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The packet is shorter than the 4-byte DHCPv6 message header
    /// (`msg-type` + 3-byte transaction id).
    #[error("message too short for DHCPv6 header (need {expected} bytes, got {actual})")]
    TruncatedHeader {
        /// Number of bytes required for the header.
        expected: usize,
        /// Number of bytes actually present.
        actual: usize,
    },
    /// The `msg-type` field held an unrecognised value.
    #[error("unknown DHCPv6 message type {0}")]
    BadMessageType(u8),
    /// An option's length field ran past the end of the message.
    #[error("option length {len} exceeds remaining buffer of {remaining} bytes")]
    TruncatedOption {
        /// Declared option length.
        len: usize,
        /// Bytes actually remaining.
        remaining: usize,
    },
    /// A DUID could not be parsed (too short for its declared type/length).
    #[error("malformed DUID in option data")]
    BadDuid,
}

/// Errors surfaced by a [`crate::lease::LeaseStore`] implementation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LeaseError {
    /// No free address/prefix could be found in the managed pool.
    #[error("no free address/prefix in the pool")]
    PoolExhausted,
    /// The requested address/prefix is outside the managed pool range.
    #[error("address/prefix {0} is not in the managed pool")]
    OutOfPool(Ipv6Addr),
    /// No active lease exists for the (client, IA).
    #[error("no active lease for IA")]
    NoLease,
    /// The lease for the IA belongs to a different client.
    #[error("lease belongs to a different client")]
    ClientMismatch,
    /// The address/prefix is already leased to another client.
    #[error("address/prefix {0} is already leased to another client")]
    AddressInUse(Ipv6Addr),
    /// Any other backend-specific failure.
    #[error("{0}")]
    Other(String),
}

/// Top-level DHCPv6 error.
#[derive(Debug, Error)]
pub enum Dhcpv6Error {
    /// A message or option could not be decoded.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// The lease backend rejected an operation.
    #[error(transparent)]
    Lease(#[from] LeaseError),
    /// A message arrived that is not valid in the client's current state.
    #[error("message is not valid in the current client state")]
    UnexpectedMessage,
}
