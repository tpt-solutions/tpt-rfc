// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for RFC 6960 OCSP handling.

use thiserror::Error;

/// Errors that can occur while building, parsing, or verifying RFC 6960
/// OCSP messages.
#[derive(Debug, Error)]
pub enum OcspError {
    #[error("ASN.1/DER decoding error: {0}")]
    Decode(#[from] der::Error),

    #[error("unsupported or unknown hash algorithm OID: {0}")]
    UnsupportedHash(String),

    #[error("unsupported public key algorithm OID: {0}")]
    UnsupportedKey(String),

    #[error("the response status was not 'success' (code {0})")]
    ResponseStatus(u8),

    #[error("the response did not carry a responseBytes field")]
    MissingResponseBytes,

    #[error("the response type was not id-pkix-ocsp-basic")]
    WrongResponseType,

    #[error("the OCSP request contained no requests")]
    EmptyRequest,

    #[error("the request contained no nonce but one was required")]
    NonceRequired,

    #[error("the response nonce did not match the request nonce")]
    NonceMismatch,

    #[error("unsupported signature algorithm OID: {0}")]
    UnsupportedSignature(String),

    #[error("no responder certificate matched the trusted anchors")]
    ResponderUntrusted,

    #[error("the responder ID did not match the trusted responder certificate")]
    ResponderIdMismatch,

    #[error("the response did not contain a status for the requested certificate")]
    CertIdNotFound,

    #[error("signature verification failed: {0}")]
    Signature(String),

    #[error("key/crypto primitive error: {0}")]
    Crypto(String),
}

pub type OcspResult<T> = std::result::Result<T, OcspError>;
