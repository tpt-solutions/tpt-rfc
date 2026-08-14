// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for `tpt-dtls`.

use std::io;

/// Errors produced while building, parsing, protecting, or processing DTLS
/// records, handshake messages, or connections.
#[derive(Debug, thiserror::Error)]
pub enum DtlsError {
    /// The wire buffer ended before a complete value could be read.
    #[error("unexpected end of buffer")]
    UnexpectedEof,

    /// A length prefix declared more bytes than remain in the buffer.
    #[error("length prefix {declared} exceeds remaining {remaining}")]
    LengthExceedsBuffer {
        /// Bytes declared by the prefix.
        declared: usize,
        /// Bytes actually available.
        remaining: usize,
    },

    /// A record's declared length does not match the buffer it was read from.
    #[error("record length {0} does not match buffer {1}")]
    RecordLengthMismatch(usize, usize),

    /// The DTLS version field carried an unsupported value.
    #[error("unsupported DTLS version: {0:#06x}")]
    UnsupportedVersion(u16),

    /// The record layer carried an unknown or unsupported content type.
    #[error("unsupported content type: {0}")]
    UnsupportedContentType(u8),

    /// The cipher suite in a message is not supported by this implementation.
    #[error("unsupported cipher suite: {0:#06x}")]
    UnsupportedCipherSuite(u16),

    /// A handshake message type code was not recognised.
    #[error("unknown handshake message type: {0}")]
    UnknownHandshakeType(u8),

    /// A handshake message arrived out of the expected order/state.
    #[error("unexpected handshake message: {0:?}")]
    UnexpectedHandshake(crate::handshake::HandshakeType),

    /// A handshake fragment referenced bytes beyond the message's total length.
    #[error("handshake fragment out of range (offset {offset}, len {len}, total {total})")]
    FragmentOutOfRange {
        /// Declared fragment offset.
        offset: u32,
        /// Declared fragment length.
        len: u32,
        /// Total message length.
        total: u32,
    },

    /// Reassembly was attempted for an unknown message sequence number.
    #[error("no reassembly buffer for message_seq {0}")]
    NoReassemblyBuffer(u16),

    /// The AEAD decryption/authentication of a record failed.
    #[error("record decryption failed (bad tag or truncated)")]
    DecryptFailed,

    /// The anti-replay window rejected a record (replayed or too-old sequence).
    #[error("replay detected: sequence {0} outside the replay window")]
    Replay(u64),

    /// The 48-bit record sequence number overflowed its epoch.
    #[error("sequence number overflow for epoch {0}")]
    SequenceOverflow(u16),

    /// A cookie from the client did not match the server's expectation.
    #[error("cookie mismatch")]
    CookieMismatch,

    /// A CertificateVerify signature did not verify against the peer's key.
    #[error("certificate verify failed")]
    CertificateVerifyFailed,

    /// A Finished verify_data did not match the computed value.
    #[error("finished verification failed")]
    FinishedMismatch,

    /// The handshake completed without producing the expected traffic keys.
    #[error("handshake incomplete: {0}")]
    HandshakeIncomplete(&'static str),

    /// A message was processed by the wrong role (client vs server).
    #[error("operation not valid for role: {0}")]
    WrongRole(&'static str),

    /// A handshake step produced no output when some was required.
    #[error("no handshake output available")]
    NoOutput,

    /// A wrapped I/O error (typically from a transport driver).
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Convenience `Result` alias used throughout the crate.
pub type Result<T> = std::result::Result<T, DtlsError>;
