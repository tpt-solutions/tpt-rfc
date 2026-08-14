//! Error types for `tpt-bfd`.

use std::io;

/// Errors produced while parsing, validating, or authenticating BFD
/// control packets, or while driving a [`crate::session::Session`].
#[derive(Debug, thiserror::Error)]
pub enum BfdError {
    /// The received buffer was shorter than the BFD control header.
    #[error("packet too short: {0} bytes (need at least 24)")]
    PacketTooShort(usize),

    /// A reserved diagnostic code (9-31) was carried in the packet.
    #[error("reserved diagnostic code: {0}")]
    ReservedDiagnostic(u8),

    /// An invalid session-state code (4-255) was carried in the packet.
    #[error("invalid session state code: {0}")]
    InvalidState(u8),

    /// The `Length` field exceeded the actual buffer length.
    #[error("length field {0} exceeds available buffer {1}")]
    LengthMismatch(usize, usize),

    /// An authentication type that this implementation does not support
    /// (e.g. MD5-based) was encountered.
    #[error("unsupported authentication type: {0}")]
    UnsupportedAuth(u8),

    /// A received packet failed authentication.
    #[error("authentication failed")]
    AuthFailed,

    /// A meticulous-keyed sequence number regressed or repeated.
    #[error("meticulous sequence number replay/regression")]
    AuthSeqReplay,

    /// A wrapped I/O error (typically from the UDP transport).
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}
