// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal, clean-room BER (Basic Encoding Rules) codec used by SNMP.
//!
//! SNMP uses a small subset of BER: definite-length encoding, the universal
//! tags for `INTEGER`/`OCTET STRING`/`NULL`/`OBJECT IDENTIFIER`/`SEQUENCE`,
//! and application/context-specific tags for the SMI syntaxes and PDU CHOICEs.
//! Implementing exactly this subset keeps the wire format fully auditable and
//! avoids pulling in a general-purpose ASN.1 library.

use crate::error::BerError;

/// Universal tag for `INTEGER`.
pub const TAG_INTEGER: u8 = 0x02;
/// Universal tag for `OCTET STRING`.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// Universal tag for `OBJECT IDENTIFIER`.
pub const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
/// Universal tag/constructed bit for `SEQUENCE`/`SEQUENCE OF`.
pub const TAG_SEQUENCE: u8 = 0x30;

// Application-tagged SNMPv2 syntaxes (RFC 2578 §7.1, RFC 3416 §6).
/// Application tag 0 — `IpAddress`.
pub const TAG_IPADDRESS: u8 = 0x40;
/// Application tag 1 — `Counter32`.
pub const TAG_COUNTER32: u8 = 0x41;
/// Application tag 2 — `Gauge32`.
pub const TAG_GAUGE32: u8 = 0x42;
/// Application tag 3 — `TimeTicks`.
pub const TAG_TIMETICKS: u8 = 0x43;
/// Application tag 4 — `Opaque`.
pub const TAG_OPAQUE: u8 = 0x44;
/// Application tag 6 — `Counter64`.
pub const TAG_COUNTER64: u8 = 0x46;

// SNMPv2 exception values (context-specific IMPLICIT NULL).
/// `noSuchObject` — context tag 0.
pub const TAG_NO_SUCH_OBJECT: u8 = 0x80;
/// `noSuchInstance` — context tag 1.
pub const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
/// `endOfMibView` — context tag 2.
pub const TAG_END_OF_MIB_VIEW: u8 = 0x82;

/// Incremental BER writer.
pub struct BerWriter {
    out: Vec<u8>,
}

impl BerWriter {
    /// Create a new, empty writer.
    pub fn new() -> Self {
        BerWriter { out: Vec::new() }
    }

    /// Consume the writer, returning the accumulated bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// Append already-encoded BER bytes verbatim.
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// Write a complete TLV (`tag` byte, definite length, `content`).
    pub fn write_tlv(&mut self, tag: u8, content: &[u8]) {
        self.out.push(tag);
        let len = content.len();
        if len < 128 {
            self.out.push(len as u8);
        } else {
            let mut body = Vec::new();
            let mut l = len;
            while l > 0 {
                body.push((l & 0xff) as u8);
                l >>= 8;
            }
            body.reverse();
            self.out.push(0x80 | body.len() as u8);
            self.out.extend_from_slice(&body);
        }
        self.out.extend_from_slice(content);
    }

    /// Write an OCTET STRING (universal tag).
    pub fn write_octet_string(&mut self, s: &[u8]) {
        self.write_tlv(TAG_OCTET_STRING, s);
    }

    /// Write a SEQUENCE wrapping `content` (universal constructed tag).
    pub fn write_sequence(&mut self, content: &[u8]) {
        self.write_tlv(TAG_SEQUENCE, content);
    }

    /// Write a NULL of the given tag (e.g. an exception value).
    pub fn write_null(&mut self, tag: u8) {
        self.write_tlv(tag, &[]);
    }

    /// Write a signed INTEGER (two's complement, minimal encoding).
    pub fn write_integer(&mut self, v: i64) {
        self.write_tlv(TAG_INTEGER, &encode_signed(v));
    }

    /// Write a non-negative INTEGER value (used for Counters/Gauges/TimeTicks).
    pub fn write_unsigned(&mut self, tag: u8, v: u64) {
        self.write_tlv(tag, &encode_unsigned(v));
    }
}

/// Encode a signed integer as minimal big-endian two's complement.
pub(crate) fn encode_signed(v: i64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let negative = v < 0;
    // Work with the absolute byte representation of the two's complement.
    let mut bytes = (v as i128).to_be_bytes().to_vec();
    // Trim leading 0x00 (positive) or 0xff (negative) bytes, keeping sign bit clear.
    while bytes.len() > 1 {
        let first = bytes[0];
        let second = bytes[1];
        let redundant = if !negative {
            first == 0x00 && (second & 0x80) == 0
        } else {
            first == 0xff && (second & 0x80) != 0
        };
        if redundant {
            bytes.remove(0);
        } else {
            break;
        }
    }
    bytes
}

/// Encode a non-negative integer as minimal big-endian (no sign extension).
pub(crate) fn encode_unsigned(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0x00 {
        bytes.remove(0);
    }
    bytes
}

/// Decode a minimal big-endian two's complement INTEGER into `i64`.
pub(crate) fn decode_signed(content: &[u8]) -> Result<i64, BerError> {
    if content.is_empty() {
        return Err(BerError::BadInteger);
    }
    if content.len() > 8 {
        // Could still fit with sign, but guard against absurd lengths.
        if content.len() > 9 || (content.len() == 9 && content[0] != 0x00 && content[0] != 0xff) {
            return Err(BerError::BadInteger);
        }
    }
    let negative = (content[0] & 0x80) != 0;
    let mut acc: i128 = 0;
    for &b in content {
        acc = (acc << 8) | b as i128;
    }
    if negative {
        // account for the bits beyond the content width
        let bits = content.len() * 8;
        acc -= 1i128 << bits;
    }
    Ok(acc as i64)
}

/// Decode a minimal big-endian non-negative INTEGER into `u64`.
pub(crate) fn decode_unsigned(content: &[u8]) -> Result<u64, BerError> {
    let v = decode_signed(content)?;
    if v < 0 {
        return Err(BerError::BadInteger);
    }
    Ok(v as u64)
}

/// Incremental BER reader over a borrowed buffer.
pub struct BerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    /// Create a reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        BerReader { buf, pos: 0 }
    }

    /// Whether the entire buffer has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Read the next TLV, returning `(tag, content)` where `content` borrows the input.
    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), BerError> {
        if self.pos >= self.buf.len() {
            return Err(BerError::Truncated);
        }
        let tag = self.buf[self.pos];
        self.pos += 1;
        let len = self.read_length()?;
        if self.pos + len > self.buf.len() {
            return Err(BerError::Truncated);
        }
        let content = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, content))
    }

    fn read_length(&mut self) -> Result<usize, BerError> {
        if self.pos >= self.buf.len() {
            return Err(BerError::Truncated);
        }
        let first = self.buf[self.pos];
        self.pos += 1;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        if first == 0x80 {
            return Err(BerError::IndefiniteLength);
        }
        let n = (first & 0x7f) as usize;
        if self.pos + n > self.buf.len() {
            return Err(BerError::Truncated);
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | self.buf[self.pos] as usize;
            self.pos += 1;
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_roundtrip() {
        for v in [
            0i64,
            1,
            -1,
            127,
            128,
            -128,
            255,
            -256,
            65535,
            i64::MIN / 2,
            i64::MAX,
        ] {
            let mut w = BerWriter::new();
            w.write_integer(v);
            let bytes = w.into_bytes();
            let (tag, content) = BerReader::new(&bytes).read_tlv().unwrap();
            assert_eq!(tag, TAG_INTEGER);
            assert_eq!(decode_signed(content).unwrap(), v);
        }
    }

    #[test]
    fn length_forms() {
        let mut w = BerWriter::new();
        w.write_octet_string(&[0u8; 200]);
        let bytes = w.into_bytes();
        // 0x04 0x81 0xC8 (200)
        assert_eq!(bytes[0], 0x04);
        assert_eq!(bytes[1], 0x81);
        assert_eq!(bytes[2], 0xC8);
        let (_, content) = BerReader::new(&bytes).read_tlv().unwrap();
        assert_eq!(content.len(), 200);
    }
}
