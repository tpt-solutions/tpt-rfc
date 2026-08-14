//! Error types for `tpt-privacy-pass`.

use thiserror::Error;

/// Errors produced by the OPRF/VOPRF/POPRF core (RFC 9497).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OprfError {
    /// A group element could not be deserialized (wrong length, invalid
    /// encoding, or the identity element, which is never a valid input).
    #[error("invalid group element encoding")]
    InvalidElement,

    /// A scalar could not be deserialized (wrong length or out of range).
    #[error("invalid scalar encoding")]
    InvalidScalar,

    /// `HashToGroup` mapped the input to the group identity element.
    #[error("input mapped to the group identity element")]
    IdentityElement,

    /// The DLEQ proof supplied during `Finalize` did not verify.
    #[error("DLEQ proof verification failed")]
    ProofVerification,

    /// `BlindEvaluate` was asked to invert the group order (private-key
    /// collision in the POPRF path). The issuer should rotate its key.
    #[error("POPRF inverse of zero encountered")]
    InverseError,
}

/// Errors produced by the Privacy Pass issuance / redemption protocol
/// (RFC 9578).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    /// A protocol message (request/response/token) had an unexpected
    /// length or structure.
    #[error("malformed protocol message")]
    Malformed,

    /// The token type in a message is not supported by this implementation.
    #[error("unsupported token type: {0:#06x}")]
    UnsupportedType(u16),

    /// The truncated key identifier did not match the issuer key.
    #[error("key identifier mismatch")]
    KeyIdMismatch,

    /// Token redemption failed: the authenticator did not verify.
    #[error("token verification failed")]
    Verification,

    /// Underlying OPRF primitive error.
    #[error(transparent)]
    Oprf(#[from] OprfError),
}
