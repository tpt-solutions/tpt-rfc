// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "serde")]
use std::fmt;

/// Errors produced while encoding or decoding CBOR.
#[derive(Debug, thiserror::Error)]
pub enum CborError {
    /// The input byte stream ended before a complete data item could be read.
    #[error("unexpected end of input while decoding")]
    UnexpectedEof,

    /// A byte was encountered that does not begin a valid CBOR data item
    /// (e.g. an additional-information value reserved by the spec).
    #[error("invalid initial byte: 0x{0:02x}")]
    InvalidInitialByte(u8),

    /// A reserved simple value (20–31) was used.
    #[error("reserved simple value: {0}")]
    ReservedSimpleValue(u8),

    /// A map contained duplicate keys while strict decoding was enabled.
    #[error("duplicate map key encountered in canonical/strict mode")]
    DuplicateKey,

    /// Indefinite-length encoding was used but the decoder was configured to
    /// reject it (strict mode).
    #[error("indefinite-length item not allowed in strict mode")]
    IndefiniteNotAllowed,

    /// An integer value was too large to represent in the chosen target type.
    #[error("integer out of range for target type")]
    IntegerOutOfRange,

    /// A UTF-8 string failed validation.
    #[error("invalid UTF-8 in text string")]
    InvalidUtf8,

    /// A `serde` data type was not representable / not supported by this
    /// implementation.
    #[error("unsupported serde data model: {0}")]
    #[cfg(feature = "serde")]
    Unsupported(&'static str),

    /// A `serde` deserialization error wrapper carrying the custom message.
    #[cfg(feature = "serde")]
    #[error("{0}")]
    Custom(String),

    /// Wraps an I/O error from the underlying writer/reader.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(feature = "serde")]
impl serde::de::Error for CborError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        CborError::Custom(msg.to_string())
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Error for CborError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        CborError::Custom(msg.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CborError>;
