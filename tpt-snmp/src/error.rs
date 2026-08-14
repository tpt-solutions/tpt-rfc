// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for `tpt-snmp`.

use thiserror::Error;

/// Failure decoding a single BER TLV or an SNMP value.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BerError {
    /// The buffer ended before a complete TLV could be read.
    #[error("truncated BER data")]
    Truncated,
    /// An indefinite length form was encountered (SNMP always uses definite length).
    #[error("indefinite length BER form is not supported")]
    IndefiniteLength,
    /// A tag that this implementation does not recognise as a valid SNMP syntax was seen.
    #[error("unknown BER tag {0:#04x}")]
    UnknownTag(u8),
    /// An INTEGER/OID was encoded with an invalid length or sign representation.
    #[error("invalid integer encoding")]
    BadInteger,
    /// An OBJECT IDENTIFIER was encoded with an invalid sub-identifier.
    #[error("invalid object identifier encoding")]
    BadOid,
}

/// Top-level error for the SNMP crate.
#[derive(Debug, Error)]
pub enum SnmpError {
    /// A BER decode step failed.
    #[error(transparent)]
    Ber(#[from] BerError),
    /// The leading `version` INTEGER was not 0 (v1), 1 (v2c) or 3 (v3).
    #[error("unsupported SNMP version {0}")]
    UnknownVersion(i64),
    /// A CHOICE tag did not map to a known PDU type.
    #[error("unknown PDU type tag {0:#04x}")]
    UnknownPdu(u8),
    /// The nested structure of a message did not match expectations.
    #[error("malformed SNMP message structure")]
    Malformed,
    /// SNMPv3 USM authentication parameters did not verify.
    #[error("USM authentication failure")]
    AuthFailure,
    /// SNMPv3 USM ciphertext could not be decrypted.
    #[error("USM decryption error")]
    DecryptError,
    /// A security model other than USM (3) was signalled.
    #[error("unsupported security model {0}")]
    UnsupportedSecurityModel(i64),
    /// A MIB operation reported a problem.
    #[error("MIB error: {0}")]
    Mib(String),
}
