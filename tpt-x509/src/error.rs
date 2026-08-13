//! Error types returned by the validation engine.

use thiserror::Error;

/// Errors produced while validating an X.509 certification path.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// A certificate (or CRL) could not be decoded from DER.
    #[error("DER decoding failed: {0}")]
    Encoding(#[from] der::Error),

    /// A signature over a certificate (or CRL) did not verify.
    #[error("signature over a certificate issued by {issuer} failed: {reason}")]
    Signature { issuer: String, reason: String },

    /// The certificate's validity period does not cover the evaluation time.
    #[error("certificate validity period does not cover the evaluation time")]
    InvalidValidity,

    /// An issuer certificate is missing the CA basic constraint.
    #[error("issuer {0} is missing the CA basic constraint")]
    NotCa(String),

    /// A `pathLenConstraint` was violated.
    #[error("path length constraint violated at depth {depth} (limit {limit})")]
    PathLen { depth: usize, limit: u8 },

    /// An issuer is missing the `keyCertSign` key usage bit.
    #[error("issuer {0} is missing the keyCertSign key usage")]
    MissingKeyCertSign(String),

    /// A required key usage bit was absent.
    #[error("key usage violation: {0}")]
    KeyUsage(String),

    /// An extended key usage purpose was not permitted by the chain.
    #[error("extended key usage not permitted by the chain: {0}")]
    EkuViolation(String),

    /// A name constraint was violated.
    #[error("name constraint violated: {0}")]
    NameConstraint(String),

    /// The certificate was found on a CRL.
    #[error("certificate (serial {serial}) has been revoked")]
    Revoked { serial: String },

    /// No valid certification path could be constructed to any trust anchor.
    #[error("no valid certification path was found to any trust anchor")]
    NoPath,

    /// The public key or signature algorithm is unsupported by this engine.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The policy set could not be satisfied.
    #[error("policy validation failed: {0}")]
    Policy(String),

    /// A trust anchor could not be constructed.
    #[error("trust anchor error: {0}")]
    TrustAnchor(String),

    /// A configuration or internal error.
    #[error("invalid configuration: {0}")]
    Config(String),
}
