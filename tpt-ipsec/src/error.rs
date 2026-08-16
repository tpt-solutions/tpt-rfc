//! Error types for the IKEv2 / IPsec implementation.

use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("truncated message: need {needed} bytes, have {have}")]
    Truncated { needed: usize, have: usize },

    #[error("invalid payload length {0} (must be >= 4 and a multiple of 4)")]
    BadPayloadLength(usize),

    #[error("unsupported payload type {0}")]
    UnsupportedPayload(u8),

    #[error("unsupported exchange type {0}")]
    UnsupportedExchange(u8),

    #[error("unsupported transform type {0}")]
    UnsupportedTransformType(u8),

    #[error("unsupported / unknown transform id (type {t}, id {id})")]
    UnsupportedTransformId { t: u8, id: u16 },

    #[error("unsupported DH group {0}")]
    UnsupportedDhGroup(u16),

    #[error("unsupported encryption algorithm id {0}")]
    UnsupportedEncr(u16),

    #[error("unsupported PRF id {0}")]
    UnsupportedPrf(u16),

    #[error("unsupported integrity algorithm id {0}")]
    UnsupportedInteg(u16),

    #[error("unsupported authentication method {0}")]
    UnsupportedAuthMethod(u8),

    #[error("unsupported ID type {0}")]
    UnsupportedIdType(u8),

    #[error("unsupported certificate encoding {0}")]
    UnsupportedCertEncoding(u8),

    #[error("integrity check failed (AUTH / ICV mismatch)")]
    IntegrityCheckFailed,

    #[error("decryption failed")]
    DecryptFailed,

    #[error("unexpected state for exchange {exchange:?}: {msg}")]
    UnexpectedState { exchange: &'static str, msg: &'static str },

    #[error("invalid SPI length {0} (expected 0 or 8 for IKE)")]
    BadSpiLength(usize),

    #[error("no proposal accepted by responder")]
    NoProposalChosen,

    #[error("diffie-hellman shared-secret computation failed")]
    DhFailed,

    #[error("ed25519 error: {0}")]
    Ed25519(String),

    #[error("crypto primitive error: {0}")]
    Crypto(String),

    #[error("{0}")]
    Other(String),
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
