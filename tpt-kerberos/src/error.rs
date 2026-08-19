// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for `tpt-kerberos`.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can arise while encoding/decoding or processing Kerberos messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A DER/ASN.1 decode or encode step failed.
    Asn1(der::Error),
    /// A value was outside the range the spec permits (e.g. a KerberosTime that
    /// cannot be represented as a 32-bit microsecond offset).
    Range(&'static str),
    /// A required field was absent from a decoded structure.
    MissingField(&'static str),
    /// An unexpected/unsupported tag or field value was encountered.
    Unexpected(&'static str),
    /// The supplied encryption type is unknown or unsupported.
    UnsupportedEnctype(u32),
    /// A checksum/checksum verification failed.
    ChecksumMismatch,
    /// Decryption of an `EncryptedData` failed (wrong key, tampering, or CTS
    /// processing error).
    DecryptFailed,
    /// The key-derivation parameters did not match what was expected.
    KeyDerivation(String),
    /// The message integrity code (MIC) did not verify.
    MicMismatch,
    /// A KDC/AP exchange returned an error code.
    KrbError { code: i32, etext: Option<String> },
    /// The pre-authentication data was missing or unacceptable.
    PreauthRequired,
    /// A principal name / realm did not parse or normalise as expected.
    Principal(String),
    /// An I/O or length constraint was violated.
    Constraint(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(e) => write!(f, "ASN.1 error: {e}"),
            Error::Range(s) => write!(f, "value out of range: {s}"),
            Error::MissingField(s) => write!(f, "missing required field: {s}"),
            Error::Unexpected(s) => write!(f, "unexpected value: {s}"),
            Error::UnsupportedEnctype(n) => write!(f, "unsupported enctype {n}"),
            Error::ChecksumMismatch => write!(f, "checksum mismatch"),
            Error::DecryptFailed => write!(f, "decryption failed"),
            Error::KeyDerivation(s) => write!(f, "key derivation error: {s}"),
            Error::MicMismatch => write!(f, "SPNEGO MIC mismatch"),
            Error::KrbError { code, etext } => {
                write!(f, "Kerberos error {code}")?;
                if let Some(t) = etext {
                    write!(f, ": {t}")?;
                }
                Ok(())
            }
            Error::PreauthRequired => write!(f, "pre-authentication required"),
            Error::Principal(s) => write!(f, "principal error: {s}"),
            Error::Constraint(s) => write!(f, "constraint violated: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Asn1(e)
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Constraint(Box::leak(format!("getrandom: {e}").into_boxed_str()))
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Constraint(s)
    }
}
