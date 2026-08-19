//! Error types for RFC 3161 TSP handling.

use thiserror::Error;

/// Errors that can occur while building, parsing, or verifying RFC 3161
/// Time-Stamp Protocol messages.
#[derive(Debug, Error)]
pub enum TspError {
    /// A wrapped ASN.1/DER decoding error.
    #[error("ASN.1/DER error: {0}")]
    Asn1(#[from] der::Error),

    /// The top-level `ContentInfo` `contentType` was not the expected one.
    #[error("the top-level ContentInfo contentType is not {expected} (got {got})")]
    UnexpectedContentType {
        /// The expected `contentType` OID string.
        expected: String,
        /// The actual `contentType` OID string.
        got: String,
    },

    /// The `TimeStampToken` was not a CMS `SignedData`.
    #[error("the TimeStampToken is not a CMS SignedData (expected {expected}, got {got})")]
    NotSignedData {
        /// The expected `contentType` OID string.
        expected: String,
        /// The actual `contentType` OID string.
        got: String,
    },

    /// An unsupported or unknown hash-algorithm OID was encountered.
    #[error("unsupported or unknown hash algorithm OID: {0}")]
    UnsupportedHash(String),

    /// An unsupported or unknown signature-algorithm OID was encountered.
    #[error("unsupported or unknown signature algorithm OID: {0}")]
    UnsupportedSignature(String),

    /// An unsupported public-key algorithm OID was encountered.
    #[error("unsupported public key algorithm OID: {0}")]
    UnsupportedKey(String),

    /// An unsupported elliptic-curve OID was encountered.
    #[error("unsupported elliptic curve OID: {0}")]
    UnsupportedCurve(String),

    /// No signer certificate in the token matched the signer identifier.
    #[error("no signer certificate was found matching the signer identifier")]
    SignerCertNotFound,

    /// The CMS `content-type` signed attribute did not match the encapsulated type.
    #[error("the CMS content-type signed attribute does not match the TSTInfo content type")]
    ContentTypeMismatch,

    /// The CMS `message-digest` signed attribute did not match the content digest.
    #[error("the CMS message-digest signed attribute does not match the content digest")]
    MessageDigestMismatch,

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    Signature(String),

    /// A `TSTInfo` field did not match what was expected.
    #[error("TSTInfo field mismatch: {0}")]
    TstInfoMismatch(String),

    /// The nonce in the response did not match the request nonce.
    #[error("the nonce in the response does not match the request nonce")]
    NonceMismatch,

    /// The response had a non-zero `PKIStatus` (rejection/waiting/failure).
    #[error("the response has a non-zero PKIStatus (grantedWithMods/rejection/waiting/failure): {0}")]
    PkiStatus(u8),

    /// The request did not include a nonce but verification required one.
    #[error("the request did not include a nonce but the signer requires nonce checking")]
    MissingNonce,

    /// The request's `messageImprint` hash algorithm is unsupported.
    #[error("the TimeStampReq messageImprint hash algorithm is unsupported")]
    UnsupportedMessageImprint,

    /// The certificate chain could not be built or validated.
    #[error("certificate chain failed to build/validate: {0}")]
    CertChain(String),

    /// AES key unwrap failed (integrity check failed).
    #[error("AES key unwrap failed (integrity check failed)")]
    KeyUnwrap,

    /// A generic key/crypto primitive error.
    #[error("key/crypto primitive error: {0}")]
    Crypto(String),
}

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, TspError>;
