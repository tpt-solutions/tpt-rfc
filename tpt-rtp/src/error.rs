//! Error types for `tpt-rtp`.

/// Errors produced while parsing, validating, or encoding RTP / RTCP packets,
/// or while updating receiver statistics.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RtpError {
    /// The buffer was too short to contain the mandatory RTP/RTCP header.
    #[error("packet too short: {0} bytes (need at least {1})")]
    PacketTooShort(usize, usize),

    /// The RTP/RTCP version field was not 2.
    #[error("unsupported RTP/RTCP version: {0} (expected 2)")]
    UnsupportedVersion(u8),

    /// The CSRC count implied a header larger than the available buffer.
    #[error("CSRC list of {0} entries needs {1} bytes, only {2} available")]
    CsrcOverflow(usize, usize, usize),

    /// The header-extension length field ran past the end of the buffer.
    #[error("header extension length {0} words exceeds available buffer")]
    ExtensionOverflow(usize),

    /// The padding flag was set but the final octet indicated more padding
    /// than the payload contains.
    #[error("padding length {0} exceeds packet payload size")]
    PaddingOverflow(usize),

    /// An RTCP packet type (PT) was encountered that this implementation does
    /// not recognize.
    #[error("unknown RTCP packet type: {0}")]
    UnknownRtcpType(u8),

    /// The RTCP packet `length` field (in 32-bit words minus one) implied a
    /// packet larger than the supplied buffer.
    #[error("RTCP length field {0} words exceeds available buffer")]
    RtcpLengthOverflow(usize),

    /// An SDES item length exceeded the remaining bytes in its chunk.
    #[error("SDES item length {0} exceeds remaining chunk bytes")]
    SdesItemOverflow(usize),

    /// An SDES chunk did not end on a 32-bit boundary (missing END item or
    /// insufficient padding).
    #[error("SDES chunk not 32-bit aligned")]
    SdesUnaligned,

    /// A supplied value was out of the range representable in the wire field
    /// (e.g. a CSRC count or payload type exceeding 15).
    #[error("field value out of range: {0}")]
    FieldOutOfRange(&'static str),

    /// A payload buffer supplied for encoding was larger than can be carried
    /// by the wire format (e.g. > 2^16 - 1 padding bytes).
    #[error("payload too large for format: {0} bytes")]
    PayloadTooLarge(usize),
}
