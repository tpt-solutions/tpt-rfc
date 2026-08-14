//! Error types for RFC 5652 CMS handling.

use thiserror::Error;

/// Errors that can occur while building, parsing, or verifying CMS messages.
#[derive(Debug, Error)]
pub enum CmsError {
    #[error("ASN.1/DER error: {0}")]
    Asn1(#[from] der::Error),

    #[error("the top-level ContentInfo contentType is not {expected} (got {got})")]
    UnexpectedContentType { expected: String, got: String },

    #[error("unsupported or unknown hash algorithm OID: {0}")]
    UnsupportedHash(String),

    #[error("unsupported or unknown content-encryption algorithm OID: {0}")]
    UnsupportedContentEncryption(String),

    #[error("unsupported or unknown key-wrap algorithm OID: {0}")]
    UnsupportedKeyWrap(String),

    #[error("unsupported or unknown key-transport algorithm OID: {0}")]
    UnsupportedKeyTransport(String),

    #[error("unsupported or unknown key-agreement algorithm OID: {0}")]
    UnsupportedKeyAgreement(String),

    #[error("unsupported or unknown signature algorithm OID: {0}")]
    UnsupportedSignature(String),

    #[error("unsupported public key algorithm OID: {0}")]
    UnsupportedKey(String),

    #[error("unsupported elliptic curve OID: {0}")]
    UnsupportedCurve(String),

    #[error("no signer certificate was found matching the signer identifier")]
    SignerCertNotFound,

    #[error("no recipient private key matched any RecipientInfo")]
    NoMatchingRecipient,

    #[error("the CMS content-type signed attribute does not match the encapsulated content type")]
    ContentTypeMismatch,

    #[error("the CMS message-digest signed attribute does not match the content digest")]
    MessageDigestMismatch,

    #[error("signature verification failed: {0}")]
    Signature(String),

    #[error("the signer certificate is not trusted by any supplied trust anchor: {0}")]
    Untrusted(String),

    #[error("certificate chain failed to build/validate: {0}")]
    CertChain(String),

    #[error("the encrypted content is missing (detached signature)")]
    MissingContent,

    #[error("AES key unwrap failed (integrity check failed)")]
    KeyUnwrap,

    #[error("key/crypto primitive error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, CmsError>;
