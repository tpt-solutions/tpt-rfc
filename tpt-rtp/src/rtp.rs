//! RTP packet encode/decode (RFC 3550 §5).
//!
//! The wire format is owned-typed: [`RtpPacket`] carries a [`RtpHeader`] plus
//! the media payload and any trailing padding. Both allocating (`encode` /
//! `decode`) and borrow-into-slice (`encode_to_slice` / `decode_from_slice`)
//! APIs are provided so callers can avoid allocation on the hot path.

use crate::error::RtpError;

/// The RTP version this crate implements and expects on the wire.
pub const RTP_VERSION: u8 = 2;

/// Maximum CSRC count per RTP header (4-bit field).
pub const MAX_CSRC: usize = 15;

/// The fixed RTP header, excluding the CSRC list, extension, and payload.
///
/// The version is always 2 on both encode and decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    /// Padding bit (P). When set, the packet carries trailing padding octets
    /// (see [`RtpPacket::padding`]); the last octet of the padding holds the
    /// total padding count including itself.
    pub padding: bool,
    /// Extension bit (X). When set, the header is followed by a header
    /// extension (see [`RtpHeader::extension_profile`] / [`RtpHeader::extension_words`]).
    pub extension: bool,
    /// Contributing source (CSRC) identifiers. Length must be ≤ [`MAX_CSRC`].
    pub csrc: Vec<u32>,
    /// Marker bit (M).
    pub marker: bool,
    /// Payload type (PT), 7 bits.
    pub payload_type: u8,
    /// Sequence number, 16 bits.
    pub sequence_number: u16,
    /// Timestamp, 32 bits.
    pub timestamp: u32,
    /// Synchronization source (SSRC) identifier, 32 bits.
    pub ssrc: u32,
    /// Header-extension profile (16 bits), meaningful only when `extension`
    /// is set.
    pub extension_profile: u16,
    /// Header-extension words (each 32 bits), meaningful only when `extension`
    /// is set. The on-wire `length` field equals `extension_words.len()`.
    pub extension_words: Vec<u32>,
}

impl RtpHeader {
    /// Length in bytes of the fixed 12-byte header plus the CSRC list and
    /// (if present) the header extension.
    fn wire_len(&self) -> usize {
        let mut len = 12 + self.csrc.len() * 4;
        if self.extension {
            // profile (2) + length (2) + words
            len += 4 + self.extension_words.len() * 4;
        }
        len
    }
}

/// A complete RTP packet: fixed header, CSRC list, optional header extension,
/// media payload, and optional trailing padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    /// The RTP header.
    pub header: RtpHeader,
    /// The media payload, excluding any trailing padding.
    pub payload: Vec<u8>,
    /// Trailing padding octets. The last octet holds the total padding count
    /// (including itself). Empty when [`RtpHeader::padding`] is `false`.
    pub padding: Vec<u8>,
}

impl RtpPacket {
    /// Total on-wire length of this packet in bytes.
    pub fn encoded_len(&self) -> usize {
        self.header.wire_len() + self.payload.len() + self.padding.len()
    }

    /// Set the trailing padding to exactly `n` octets (the last octet carrying
    /// the count `n`), and set the header padding bit. `n` must be ≥ 1.
    pub fn set_padding(&mut self, n: u8) -> Result<(), RtpError> {
        if n == 0 {
            return Err(RtpError::FieldOutOfRange("padding must be >= 1"));
        }
        let mut pad = vec![0u8; n as usize];
        pad[n as usize - 1] = n;
        self.padding = pad;
        self.header.padding = true;
        Ok(())
    }

    /// Decode an RTP packet from `buf`, validating the header, CSRC list,
    /// header extension, and padding.
    pub fn decode(buf: &[u8]) -> Result<RtpPacket, RtpError> {
        Self::decode_from_slice(buf)
    }

    /// Decode from a byte slice (alias of [`RtpPacket::decode`]).
    pub fn decode_from_slice(buf: &[u8]) -> Result<RtpPacket, RtpError> {
        if buf.len() < 12 {
            return Err(RtpError::PacketTooShort(buf.len(), 12));
        }
        let b0 = buf[0];
        let version = b0 >> 6;
        if version != RTP_VERSION {
            return Err(RtpError::UnsupportedVersion(version));
        }
        let pad_bit = (b0 & 0x20) != 0;
        let extension = (b0 & 0x10) != 0;
        let cc = (b0 & 0x0f) as usize;

        let b1 = buf[1];
        let marker = (b1 & 0x80) != 0;
        let payload_type = b1 & 0x7f;

        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let mut pos = 12;
        if cc > MAX_CSRC {
            return Err(RtpError::FieldOutOfRange("csrc count"));
        }
        let needed = pos + cc * 4;
        if buf.len() < needed {
            return Err(RtpError::CsrcOverflow(cc, needed, buf.len()));
        }
        let mut csrc = Vec::with_capacity(cc);
        for _ in 0..cc {
            csrc.push(u32::from_be_bytes([
                buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3],
            ]));
            pos += 4;
        }

        let (extension_profile, extension_words) = if extension {
            if buf.len() < pos + 4 {
                return Err(RtpError::ExtensionOverflow(0));
            }
            let profile = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;
            let needed = pos + ext_len * 4;
            if buf.len() < needed {
                return Err(RtpError::ExtensionOverflow(ext_len));
            }
            let mut words = Vec::with_capacity(ext_len);
            for _ in 0..ext_len {
                words.push(u32::from_be_bytes([
                    buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3],
                ]));
                pos += 4;
            }
            (profile, words)
        } else {
            (0, Vec::new())
        };

        let mut tail = &buf[pos..];
        let (payload, padding_vec) = if pad_bit {
            if tail.is_empty() {
                return Err(RtpError::PaddingOverflow(0));
            }
            let p = tail[tail.len() - 1] as usize;
            if p == 0 || p > tail.len() {
                return Err(RtpError::PaddingOverflow(p));
            }
            let split = tail.len() - p;
            let pad = tail[split..].to_vec();
            let pl = tail[..split].to_vec();
            tail = &[];
            (pl, pad)
        } else {
            (tail.to_vec(), Vec::new())
        };
        let _ = tail;

        Ok(RtpPacket {
            header: RtpHeader {
                padding: pad_bit,
                extension,
                csrc,
                marker,
                payload_type,
                sequence_number: seq,
                timestamp,
                ssrc,
                extension_profile,
                extension_words,
            },
            payload,
            padding: padding_vec,
        })
    }

    /// Encode the packet, allocating a fresh `Vec<u8>`.
    pub fn encode(&self) -> Result<Vec<u8>, RtpError> {
        let len = self.encoded_len();
        let mut buf = vec![0u8; len];
        let n = self.encode_to_slice(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Encode the packet into `buf`, returning the number of bytes written.
    ///
    /// `buf` must be at least [`RtpPacket::encoded_len`] bytes long.
    pub fn encode_to_slice(&self, buf: &mut [u8]) -> Result<usize, RtpError> {
        let need = self.encoded_len();
        if buf.len() < need {
            return Err(RtpError::PacketTooShort(buf.len(), need));
        }
        if self.header.csrc.len() > MAX_CSRC {
            return Err(RtpError::FieldOutOfRange("csrc count"));
        }
        if self.header.payload_type > 0x7f {
            return Err(RtpError::FieldOutOfRange("payload_type"));
        }
        if self.header.padding && self.padding.is_empty() {
            return Err(RtpError::FieldOutOfRange("padding flag set but no padding"));
        }
        if self.header.padding {
            let n = self.padding.len();
            let last = self.padding[n - 1];
            if last as usize != n {
                return Err(RtpError::FieldOutOfRange("padding last octet != length"));
            }
        }

        let ext_present = self.header.extension && !self.header.extension_words.is_empty();
        let cc = self.header.csrc.len() as u8;

        buf[0] = (RTP_VERSION << 6)
            | if self.header.padding { 0x20 } else { 0 }
            | if ext_present { 0x10 } else { 0 }
            | cc;
        buf[1] = if self.header.marker { 0x80 } else { 0 } | (self.header.payload_type & 0x7f);
        buf[2..4].copy_from_slice(&self.header.sequence_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.header.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.header.ssrc.to_be_bytes());

        let mut pos = 12;
        for &c in &self.header.csrc {
            buf[pos..pos + 4].copy_from_slice(&c.to_be_bytes());
            pos += 4;
        }
        if ext_present {
            buf[pos..pos + 2].copy_from_slice(&self.header.extension_profile.to_be_bytes());
            buf[pos + 2..pos + 4]
                .copy_from_slice(&(self.header.extension_words.len() as u16).to_be_bytes());
            pos += 4;
            for &w in &self.header.extension_words {
                buf[pos..pos + 4].copy_from_slice(&w.to_be_bytes());
                pos += 4;
            }
        }
        buf[pos..pos + self.payload.len()].copy_from_slice(&self.payload);
        pos += self.payload.len();
        if self.header.padding {
            buf[pos..pos + self.padding.len()].copy_from_slice(&self.padding);
            pos += self.padding.len();
        }
        Ok(pos)
    }

    /// Borrowed view of the media payload (excluding padding).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Parse only the fixed header fields of an RTP packet from `buf` without
/// copying CSRC/extension/payload. Useful for fast dispatch on the receive
/// path. Returns a lightweight summary.
pub fn peek_header(buf: &[u8]) -> Result<RtpHeaderSummary, RtpError> {
    if buf.len() < 12 {
        return Err(RtpError::PacketTooShort(buf.len(), 12));
    }
    let b0 = buf[0];
    if b0 >> 6 != RTP_VERSION {
        return Err(RtpError::UnsupportedVersion(b0 >> 6));
    }
    Ok(RtpHeaderSummary {
        padding: (b0 & 0x20) != 0,
        extension: (b0 & 0x10) != 0,
        csrc_count: (b0 & 0x0f) as usize,
        marker: (buf[1] & 0x80) != 0,
        payload_type: buf[1] & 0x7f,
        sequence_number: u16::from_be_bytes([buf[2], buf[3]]),
        timestamp: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ssrc: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
    })
}

/// A minimal, zero-copy summary of the fixed RTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeaderSummary {
    /// Padding bit.
    pub padding: bool,
    /// Extension bit.
    pub extension: bool,
    /// Number of CSRC identifiers present.
    pub csrc_count: usize,
    /// Marker bit.
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Synchronization source.
    pub ssrc: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_round_trip() {
        let pkt = RtpPacket {
            header: RtpHeader {
                padding: false,
                extension: false,
                csrc: vec![],
                marker: false,
                payload_type: 0,
                sequence_number: 0x1234,
                timestamp: 0x0a0b0c0d,
                ssrc: 0xdeadbeef,
                extension_profile: 0,
                extension_words: vec![],
            },
            payload: vec![1, 2, 3, 4],
            padding: vec![],
        };
        let enc = pkt.encode().unwrap();
        let dec = RtpPacket::decode(&enc).unwrap();
        assert_eq!(pkt, dec);
    }

    #[test]
    fn padding_round_trip() {
        let mut pkt = RtpPacket {
            header: RtpHeader {
                padding: true,
                extension: false,
                csrc: vec![],
                marker: true,
                payload_type: 96,
                sequence_number: 7,
                timestamp: 100,
                ssrc: 1,
                extension_profile: 0,
                extension_words: vec![],
            },
            payload: vec![0xaa, 0xbb],
            padding: vec![],
        };
        pkt.set_padding(4).unwrap();
        let enc = pkt.encode().unwrap();
        assert_eq!(enc.len(), 12 + 2 + 4);
        assert_eq!(enc[enc.len() - 1], 4);
        let dec = RtpPacket::decode(&enc).unwrap();
        assert_eq!(dec, pkt);
        assert_eq!(dec.payload(), &[0xaa, 0xbb]);
    }

    #[test]
    fn csrc_and_extension() {
        let pkt = RtpPacket {
            header: RtpHeader {
                padding: false,
                extension: true,
                csrc: vec![0x11111111, 0x22222222],
                marker: false,
                payload_type: 10,
                sequence_number: 42,
                timestamp: 9999,
                ssrc: 0x55555555,
                extension_profile: 0xbede,
                extension_words: vec![0x12345678, 0x9abcdef0],
            },
            payload: vec![9, 8, 7],
            padding: vec![],
        };
        let enc = pkt.encode().unwrap();
        let mut dec = RtpPacket::decode(&enc).unwrap();
        assert_eq!(dec.header.csrc, pkt.header.csrc);
        assert_eq!(dec.header.extension_words, pkt.header.extension_words);
        assert_eq!(dec.payload(), &[9, 8, 7]);
        // toggle a field and re-encode
        dec.header.payload_type = 11;
        let enc2 = dec.encode().unwrap();
        let dec2 = RtpPacket::decode(&enc2).unwrap();
        assert_eq!(dec2.header.payload_type, 11);
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = [0u8; 12];
        buf[0] = 0x40; // version 1
        assert!(matches!(
            RtpPacket::decode(&buf),
            Err(RtpError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn peek_matches() {
        let pkt = RtpPacket {
            header: RtpHeader {
                padding: false,
                extension: false,
                csrc: vec![],
                marker: true,
                payload_type: 34,
                sequence_number: 0xffff,
                timestamp: 1,
                ssrc: 2,
                extension_profile: 0,
                extension_words: vec![],
            },
            payload: vec![],
            padding: vec![],
        };
        let enc = pkt.encode().unwrap();
        let s = peek_header(&enc).unwrap();
        assert_eq!(s.payload_type, 34);
        assert!(s.marker);
        assert_eq!(s.sequence_number, 0xffff);
    }
}
