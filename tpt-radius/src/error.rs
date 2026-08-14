// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for the `tpt-radius` crate.

use crate::attribute::AttributeType;
use thiserror::Error;

/// Errors that can occur while decoding a RADIUS packet from its wire bytes.
///
/// These are pure parsing failures and carry no secret material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The buffer is shorter than the 20-octet RADIUS header.
    #[error("packet is shorter than the 20-octet RADIUS header")]
    TooShort,
    /// The `Length` field declares more octets than the buffer contains.
    #[error("declared length {declared} exceeds the available {available} octets")]
    LengthMismatch {
        /// The value of the `Length` field.
        declared: usize,
        /// The number of octets actually present.
        available: usize,
    },
    /// An attribute's `Length` field is smaller than the 2-octet attribute header.
    #[error(
        "attribute at offset {offset} declares length {len}, which is below the 2-octet minimum"
    )]
    AttributeTooShort {
        /// Offset of the offending attribute in the packet.
        offset: usize,
        /// The declared attribute length.
        len: usize,
    },
    /// An attribute's `Length` field runs past the end of the packet.
    #[error("attribute at offset {offset} with length {len} runs past the packet end {end}")]
    AttributeTruncated {
        /// Offset of the offending attribute in the packet.
        offset: usize,
        /// The declared attribute length.
        len: usize,
        /// The end of the packet (its declared length).
        end: usize,
    },
}

/// Higher-level RADIUS errors: encoding, shared-secret cryptography, and
/// server-side processing.
#[derive(Debug, Error)]
pub enum RadiusError {
    /// A packet could not be decoded.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// The shared secret is empty, which would permit trivial forgery.
    #[error("shared secret must not be empty")]
    EmptySecret,
    /// A `User-Password` attribute was required but not present.
    #[error("the User-Password attribute is required but missing")]
    MissingPassword,
    /// A `User-Password` value was not a multiple of 16 octets.
    #[error("User-Password length {0} is not a multiple of 16 octets")]
    PasswordLength(usize),
    /// Password hiding/decryption was attempted on a non-Access-Request packet.
    #[error("password hiding/decryption requires an Access-Request packet")]
    NotAccessRequest,
    /// The response authenticator did not match the recomputed value.
    #[error("response authenticator mismatch: expected {expected:?}, computed {computed:?}")]
    AuthenticatorMismatch {
        /// The authenticator taken from the wire.
        expected: [u8; 16],
        /// The value recomputed from the packet and secret.
        computed: [u8; 16],
    },
    /// The accounting-request authenticator did not match the recomputed value.
    #[error(
        "accounting request authenticator mismatch: expected {expected:?}, computed {computed:?}"
    )]
    AcctAuthenticatorMismatch {
        /// The authenticator taken from the wire.
        expected: [u8; 16],
        /// The value recomputed from the packet and secret.
        computed: [u8; 16],
    },
    /// A `Message-Authenticator` (RFC 3579) value failed verification.
    #[error("Message-Authenticator verification failed")]
    MessageAuthenticatorMismatch,
    /// The operation does not apply to this packet code.
    #[error("unsupported packet code {0} for this operation")]
    UnsupportedCode(u8),
    /// An attribute's value was not valid UTF-8 text where text was expected.
    #[error("attribute {0:?} value is not valid UTF-8")]
    InvalidUtf8(AttributeType),
    /// An attribute's value had an unexpected length for its typed accessor.
    #[error("attribute {0:?} value has an unexpected length")]
    InvalidLength(AttributeType),
    /// The authentication backend reported an error.
    #[error("backend error: {0}")]
    Backend(String),
}
