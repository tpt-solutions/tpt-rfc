//! Error types for RFC 3161 TSP handling.

use thiserror::Error;

/// Errors that can occur while building, parsing, or verifying RFC 3161
/// time-stamp messages.
#[derive(Debug, Error)]
pub enum TspError {
    #[error("ASN.1/DER encoding/decoding error: {0}")]
    Der(#[from] der::Error),

    #[error("unsupported or unknown hash algorithm OID: {0}")]
    UnsupportedHash(String),

    #[error("unsupported or unknown signature algorithm OID: {0}")]
    UnsupportedSignature(String),

    #[error("unsupported public key algorithm OID: {0}")]
    UnsupportedKey(String),

    #[error("the request is missing a message imprint")]
    MissingMessageImprint,

    #[error("the request asked for a certificate but the TSA did not return one")]
    CertRequestedButMissing,

    #[error("TSA rejected the request: status {status} ({reason})")]
    RequestRejected { status: u8, reason: String },

    #[error("TSTInfo message imprint does not match the requested data")]
    MessageImprintMismatch,

    #[error("TSTInfo policy {got} does not match the requested policy {want}")]
    PolicyMismatch { got: String, want: String },

    #[error("TSTInfo nonce does not match the requested nonce")]
    NonceMismatch,

    #[error("the CMS message-digest attribute does not match the token content")]
    MessageDigestMismatch,

    #[error("the CMS content-type attribute is not id-ct-TSTInfo")]
    ContentTypeMismatch,

    #[error("no signer certificate was found matching the signer identifier")]
    SignerCertNotFound,

    #[error("signature verification failed: {0}")]
    Signature(String),

    #[error("the TSA certificate is not trusted by any supplied trust anchor: {0}")]
    Untrusted(String),

    #[error("key/crypto primitive error: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(String),
}

pub(crate) type Result<T> = std::result::Result<T, TspError>;
