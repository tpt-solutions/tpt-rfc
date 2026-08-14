//! RFC 3551 audio/video profile static payload types.
//!
//! RFC 3551 §6 defines a fixed (static) mapping of payload type (PT) values
//! 0–34 to specific audio/video encodings, together with their default clock
//! rates and channel counts. This module exposes that table for
//! inspection/negotiation. Values 35–71 are unassigned/reserved and 72–76 are
//! reserved for RTCP conflict avoidance; 77–95 are dynamic and 96–127 are
//! dynamic payload types.

/// Static description of an RFC 3551 payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadTypeInfo {
    /// Payload type value (0–34 for the static table).
    pub payload_type: u8,
    /// Encoding name (e.g. `"PCMU"`, `"H263"`).
    pub encoding: &'static str,
    /// Default media clock rate in Hz.
    pub clock_rate: u32,
    /// Default number of channels (audio only; 0 for video/other).
    pub channels: u8,
}

/// A static payload-type entry in the RFC 3551 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticPayload {
    /// The PT value.
    pub payload_type: u8,
    /// Encoding name.
    pub encoding: &'static str,
    /// Media type: `"audio"` or `"video"`.
    pub media: &'static str,
    /// Default clock rate (Hz).
    pub clock_rate: u32,
    /// Default channels (audio), or 0 for video.
    pub channels: u8,
}

/// The full RFC 3551 static payload-type table (PT 0–34).
pub const PAYLOAD_TYPES: &[StaticPayload] = &[
    StaticPayload { payload_type: 0, encoding: "PCMU", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 1, encoding: "reserved (1016)", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 2, encoding: "G721", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 3, encoding: "GSM", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 4, encoding: "G723", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 5, encoding: "DVI4", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 6, encoding: "DVI4", media: "audio", clock_rate: 16000, channels: 1 },
    StaticPayload { payload_type: 7, encoding: "LPC", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 8, encoding: "PCMA", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 9, encoding: "G722", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 10, encoding: "L16", media: "audio", clock_rate: 44100, channels: 2 },
    StaticPayload { payload_type: 11, encoding: "L16", media: "audio", clock_rate: 44100, channels: 1 },
    StaticPayload { payload_type: 12, encoding: "QCELP", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 13, encoding: "CN", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 14, encoding: "MPA", media: "audio", clock_rate: 90000, channels: 0 },
    StaticPayload { payload_type: 15, encoding: "G728", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 16, encoding: "DVI4", media: "audio", clock_rate: 11025, channels: 1 },
    StaticPayload { payload_type: 17, encoding: "DVI4", media: "audio", clock_rate: 22050, channels: 1 },
    StaticPayload { payload_type: 18, encoding: "G729", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 19, encoding: "reserved (CN)", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 20, encoding: "unassigned", media: "audio", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 21, encoding: "unassigned", media: "audio", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 22, encoding: "unassigned", media: "audio", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 23, encoding: "unassigned", media: "audio", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 24, encoding: "unassigned", media: "video", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 25, encoding: "unassigned", media: "video", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 26, encoding: "unassigned", media: "video", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 27, encoding: "unassigned", media: "video", clock_rate: 0, channels: 0 },
    StaticPayload { payload_type: 28, encoding: "reserved (G729D)", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 29, encoding: "reserved (G729E)", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 30, encoding: "reserved (G723.1)", media: "audio", clock_rate: 8000, channels: 1 },
    StaticPayload { payload_type: 31, encoding: "H261", media: "video", clock_rate: 90000, channels: 0 },
    StaticPayload { payload_type: 32, encoding: "MPV", media: "video", clock_rate: 90000, channels: 0 },
    StaticPayload { payload_type: 33, encoding: "MP2T", media: "video", clock_rate: 90000, channels: 0 },
    StaticPayload { payload_type: 34, encoding: "H263", media: "video", clock_rate: 90000, channels: 0 },
];

/// Look up a static payload-type entry by PT value.
pub fn lookup(payload_type: u8) -> Option<&'static StaticPayload> {
    PAYLOAD_TYPES.iter().find(|p| p.payload_type == payload_type)
}

/// Returns `true` if the PT is in the static range (0–34) defined by RFC 3551.
pub fn is_static(payload_type: u8) -> bool {
    payload_type <= 34
}

/// Returns `true` if the PT is in the dynamic range (96–127).
pub fn is_dynamic(payload_type: u8) -> bool {
    payload_type >= 96
}

/// Convenience conversion from [`StaticPayload`] to [`PayloadTypeInfo`].
impl From<StaticPayload> for PayloadTypeInfo {
    fn from(p: StaticPayload) -> PayloadTypeInfo {
        PayloadTypeInfo {
            payload_type: p.payload_type,
            encoding: p.encoding,
            clock_rate: p.clock_rate,
            channels: p.channels,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_coverage() {
        // 35 entries: PT 0..=34
        assert_eq!(PAYLOAD_TYPES.len(), 35);
        for (i, p) in PAYLOAD_TYPES.iter().enumerate() {
            assert_eq!(p.payload_type, i as u8);
        }
    }

    #[test]
    fn known_entries() {
        let pcmu = lookup(0).unwrap();
        assert_eq!(pcmu.encoding, "PCMU");
        assert_eq!(pcmu.clock_rate, 8000);
        assert!(is_static(0));
        assert!(is_dynamic(96));
        assert!(!is_static(96));
        assert_eq!(lookup(34).unwrap().encoding, "H263");
        assert!(lookup(95).is_none());
    }
}
