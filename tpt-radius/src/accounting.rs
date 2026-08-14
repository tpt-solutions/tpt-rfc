// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Accounting types (RFC 2866) used for real-world interop.
//!
//! The wire encoding/decoding of accounting packets is handled by [`Packet`];
//! this module documents the `Acct-Status-Type` (40) values a server is most
//! likely to emit or consume.

/// `Acct-Status-Type` (RFC 2866 §5.1) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcctStatusType {
    /// `Start` (1): a session has begun.
    Start,
    /// `Stop` (2): a session has ended.
    Stop,
    /// `Interim-Update` (3): interim accounting record.
    InterimUpdate,
    /// `Accounting-On` (7): accounting enabled on the NAS.
    AccountingOn,
    /// `Accounting-Off` (8): accounting disabled on the NAS.
    AccountingOff,
    /// Any other (reserved/experimental) status code.
    Other(u32),
}

impl AcctStatusType {
    /// Map a raw `u32` to an [`AcctStatusType`].
    pub fn from_u32(v: u32) -> AcctStatusType {
        match v {
            1 => AcctStatusType::Start,
            2 => AcctStatusType::Stop,
            3 => AcctStatusType::InterimUpdate,
            7 => AcctStatusType::AccountingOn,
            8 => AcctStatusType::AccountingOff,
            other => AcctStatusType::Other(other),
        }
    }

    /// Map an [`AcctStatusType`] to its raw `u32`.
    pub fn to_u32(self) -> u32 {
        match self {
            AcctStatusType::Start => 1,
            AcctStatusType::Stop => 2,
            AcctStatusType::InterimUpdate => 3,
            AcctStatusType::AccountingOn => 7,
            AcctStatusType::AccountingOff => 8,
            AcctStatusType::Other(v) => v,
        }
    }
}
