//! Error types for `tpt-kerberos`.

use thiserror::Error;

/// Errors produced across the crate (crypto, ASN.1, protocol, transport).
#[derive(Debug, Error)]
pub enum Error {
    /// An encryption type is not implemented or is unsupported.
    #[error("unsupported enctype {0}")]
    UnsupportedEnctype(u32),

    /// A checksum type is not implemented or is unsupported.
    #[error("unsupported checksum type {0}")]
    UnsupportedChecksum(u32),

    /// The supplied key length does not match the enctype's required length.
    #[error("invalid key length {got} for enctype expecting {want}")]
    InvalidKeyLength { got: usize, want: usize },

    /// DER (ASN.1) decoding failed.
    #[error("ASN.1 decode error: {0}")]
    Asn1Decode(String),

    /// DER (ASN.1) encoding failed.
    #[error("ASN.1 encode error: {0}")]
    Asn1Encode(String),

    /// The ciphertext length is invalid for the cipher (too short / wrong size).
    #[error("invalid ciphertext length {0}")]
    InvalidCiphertextLength(usize),

    /// Integrity check (HMAC / checksum) failed.
    #[error("integrity check failed")]
    IntegrityCheck,

    /// A required protocol field/structure was missing or malformed.
    #[error("malformed message: {0}")]
    Malformed(String),

    /// No usable credential / key material was available for an operation.
    #[error("missing credential for {0}")]
    MissingCredential(String),

    /// ASN.1/SPNEGO mechanism negotiation produced no common mechanism.
    #[error("SPNEGO negotiation produced no common mechanism")]
    SpnegoNoMatch,

    /// A transport-level failure occurred during a client exchange.
    #[error("transport error: {0}")]
    Transport(String),
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
