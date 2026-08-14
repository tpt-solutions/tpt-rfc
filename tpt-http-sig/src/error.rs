// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for `tpt-http-sig`.

use std::fmt;

/// Errors produced while building, signing, or verifying an HTTP Message
/// Signature (RFC 9421).
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpSigError {
    /// A covered component could not be derived from the target message
    /// (e.g. an unknown derived component name, or a required header field
    /// is absent).
    ComponentNotFound(String),
    /// A component identifier was malformed or used an unsupported parameter.
    InvalidComponent(String),
    /// The `Signature-Input` or `Signature` header could not be parsed as a
    /// Structured Field.
    StructuredField(String),
    /// The signature base could not be constructed.
    SignatureBase(String),
    /// No signature matching the requested label was found in the message.
    SignatureNotFound(String),
    /// The algorithm named by the `alg` parameter (or supplied by the
    /// caller) is not supported or not allowed.
    UnsupportedAlgorithm(String),
    /// The key material could not be parsed or is the wrong type for the
    /// algorithm.
    Key(String),
    /// Cryptographic signing failed.
    Sign(String),
    /// Cryptographic verification failed (the signature is invalid for the
    /// given key and message).
    Verify(String),
    /// An application-level policy check failed (for example the signature
    /// has expired, or a required component was not covered).
    Policy(String),
}

impl std::error::Error for HttpSigError {}

impl fmt::Display for HttpSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpSigError::ComponentNotFound(s) => write!(f, "component not found: {s}"),
            HttpSigError::InvalidComponent(s) => write!(f, "invalid component: {s}"),
            HttpSigError::StructuredField(s) => write!(f, "structured field error: {s}"),
            HttpSigError::SignatureBase(s) => write!(f, "signature base error: {s}"),
            HttpSigError::SignatureNotFound(s) => write!(f, "signature not found: {s}"),
            HttpSigError::UnsupportedAlgorithm(s) => write!(f, "unsupported algorithm: {s}"),
            HttpSigError::Key(s) => write!(f, "key error: {s}"),
            HttpSigError::Sign(s) => write!(f, "signing error: {s}"),
            HttpSigError::Verify(s) => write!(f, "verification failed: {s}"),
            HttpSigError::Policy(s) => write!(f, "policy violation: {s}"),
        }
    }
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, HttpSigError>;
