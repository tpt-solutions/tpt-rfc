// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH on-the-wire data type encoding/decoding (RFC 4251 §5).
//!
//! The SSH binary protocol transmits a small fixed set of data types:
//! `boolean`, `byte`, `uint32`, `uint64`, `string`, `name-list`, and
//! `mpint`. The two entry points here are [`Writer`] (encode into a buffer)
//! and [`Reader`] (decode from a buffer with bounds checking).

use thiserror::Error;

/// Errors raised while encoding or decoding SSH wire types.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before a complete value could be read.
    #[error("unexpected end of buffer")]
    UnexpectedEof,
    /// A `boolean` was encoded with a value other than 0 or 1.
    #[error("invalid boolean byte: {0}")]
    InvalidBoolean(u8),
    /// Not all input was consumed by a decoder.
    #[error("trailing data after decoding")]
    TrailingData,
}

pub type Result<T> = std::result::Result<T, WireError>;

/// Accumulates SSH wire-encoded bytes.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume the writer, returning the encoded bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Number of encoded bytes so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Write a single `byte` (RFC 4251 §5, "byte").
    pub fn write_byte(&mut self, b: u8) -> &mut Self {
        self.buf.push(b);
        self
    }

    /// Write a `boolean` (1 byte: 1 = true, 0 = false).
    pub fn write_bool(&mut self, b: bool) -> &mut Self {
        self.buf.push(if b { 1 } else { 0 });
        self
    }

    /// Write a `uint32` (4 bytes, most-significant byte first).
    pub fn write_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Write a `uint64` (8 bytes, most-significant byte first).
    pub fn write_u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Write a `string` (4-byte length prefix + that many bytes).
    pub fn write_string(&mut self, s: &[u8]) -> &mut Self {
        self.write_u32(s.len() as u32);
        self.buf.extend_from_slice(s);
        self
    }

    /// Write a `name-list` from an iterator of name parts (comma-joined).
    pub fn write_name_list<'a, I>(&mut self, parts: I) -> &mut Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let joined: Vec<u8> = parts.into_iter().collect::<Vec<_>>().join(&b',');
        self.write_string(&joined)
    }

    /// Write an `mpint` (multiple precision integer, two's complement,
    /// big-endian, with a leading `0x00` added if the high bit would
    /// otherwise signal a negative number).
    pub fn write_mpint(&mut self, v: &[u8]) -> &mut Self {
        let start = v.iter().position(|&b| b != 0).unwrap_or(v.len());
        let mut body: Vec<u8> = v[start..].to_vec();
        if body.first().is_some_and(|&b| b & 0x80 != 0) {
            body.insert(0, 0);
        }
        if body.is_empty() {
            self.write_u32(0);
        } else {
            self.write_string(&body);
        }
        self
    }
}

/// Reads SSH wire-encoded bytes from a buffer with bounds checking.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(WireError::UnexpectedEof);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a `byte`.
    pub fn read_byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a `boolean`.
    pub fn read_bool(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(WireError::InvalidBoolean(b)),
        }
    }

    /// Read a `uint32`.
    pub fn read_u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a `uint64`.
    pub fn read_u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }

    /// Read a `string`.
    pub fn read_string(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }

    /// Read a `name-list`, returning the comma-separated parts.
    pub fn read_name_list(&mut self) -> Result<Vec<&'a [u8]>> {
        let s = self.read_string()?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        Ok(s.split(|&b| b == b',').collect())
    }

    /// Read an `mpint`, returning the minimal big-endian byte
    /// representation (no leading zeros; empty for zero). Only non-negative
    /// values are supported (the only kind produced by our DH/ECDH flows).
    pub fn read_mpint(&mut self) -> Result<Vec<u8>> {
        let raw = self.read_string()?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
        Ok(raw[start..].to_vec())
    }

    /// Ensure all input has been consumed.
    pub fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::TrailingData)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_primitives() {
        let mut w = Writer::new();
        w.write_byte(7)
            .write_bool(true)
            .write_u32(0x01020304)
            .write_u64(0x0102030405060708)
            .write_string(b"hello")
            .write_name_list([b"aes128-ctr".as_ref(), b"aes256-ctr".as_ref()]);
        let bytes = w.into_inner();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_byte().unwrap(), 7);
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_u32().unwrap(), 0x01020304);
        assert_eq!(r.read_u64().unwrap(), 0x0102030405060708);
        assert_eq!(r.read_string().unwrap(), b"hello");
        let names = r.read_name_list().unwrap();
        assert_eq!(names, vec![&b"aes128-ctr"[..], &b"aes256-ctr"[..]]);
        r.finish().unwrap();
    }

    #[test]
    fn mpint_sign_extension() {
        // 0x80 must be prefixed with 0x00 when encoded as mpint.
        let mut w = Writer::new();
        w.write_mpint(&[0x80, 0x00]);
        let out = w.into_inner();
        assert_eq!(out, vec![0, 0, 0, 3, 0x00, 0x80, 0x00]);

        // Zero encodes as a zero-length string.
        let mut w2 = Writer::new();
        w2.write_mpint(&[0x00, 0x00]);
        assert_eq!(w2.into_inner(), vec![0, 0, 0, 0]);

        // Small positive value: no leading zeros.
        let mut w3 = Writer::new();
        w3.write_mpint(&[0x00, 0x2a]);
        assert_eq!(w3.into_inner(), vec![0, 0, 0, 1, 0x2a]);
    }

    #[test]
    fn errors_on_short_buffer() {
        let mut r = Reader::new(&[0x00, 0x01]);
        assert_eq!(r.read_u32(), Err(WireError::UnexpectedEof));
        let mut r2 = Reader::new(&[0x02]);
        assert_eq!(r2.read_bool(), Err(WireError::InvalidBoolean(2)));
    }
}
