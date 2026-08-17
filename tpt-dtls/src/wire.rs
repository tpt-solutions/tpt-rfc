// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS-style on-the-wire encoding/decoding helpers.
//!
//! DTLS/TLS use big-endian integers, a 24-bit length type (`uint24`), and
//! length-prefixed vectors whose prefix width depends on the field. The two
//! entry points are [`Writer`] (accumulate bytes) and [`Reader`] (decode from
//! a buffer with bounds checking).

use crate::error::{DtlsError, Result};

/// Accumulates big-endian wire-encoded bytes.
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

    /// Append raw bytes.
    pub fn put_bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Append a single byte.
    pub fn put_u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a `uint16` (2 bytes, big-endian).
    pub fn put_u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a `uint24` (3 bytes, big-endian).
    pub fn put_u24(&mut self, v: u32) -> &mut Self {
        self.buf
            .extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
        self
    }

    /// Append a `uint48` (6 bytes, big-endian) — DTLS record sequence numbers.
    pub fn put_u48(&mut self, v: u64) -> &mut Self {
        let b = v.to_be_bytes();
        self.buf.extend_from_slice(&b[2..]);
        self
    }

    /// Append a vector prefixed by a `uint8` length.
    pub fn put_vec_u8(&mut self, v: &[u8]) -> &mut Self {
        debug_assert!(v.len() <= u8::MAX as usize);
        self.put_u8(v.len() as u8).put_bytes(v);
        self
    }

    /// Append a vector prefixed by a `uint16` length.
    pub fn put_vec_u16(&mut self, v: &[u8]) -> &mut Self {
        debug_assert!(v.len() <= u16::MAX as usize);
        self.put_u16(v.len() as u16).put_bytes(v);
        self
    }

    /// Append a vector prefixed by a `uint24` length.
    pub fn put_vec_u24(&mut self, v: &[u8]) -> &mut Self {
        debug_assert!(v.len() <= 0xFF_FFFF);
        self.put_u24(v.len() as u32).put_bytes(v);
        self
    }
}

/// Decodes big-endian values from a buffer with bounds checking.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Remaining unread bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether all input has been consumed.
    pub fn eof(&self) -> bool {
        self.remaining() == 0
    }

    /// Read exactly `n` bytes, advancing the cursor.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(DtlsError::UnexpectedEof);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Read a `uint16` (big-endian).
    pub fn read_u16(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a `uint24` (big-endian) into a `u32`.
    pub fn read_u24(&mut self) -> Result<u32> {
        let b = self.read_bytes(3)?;
        Ok(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }

    /// Read a `uint48` (big-endian) into a `u64`.
    pub fn read_u48(&mut self) -> Result<u64> {
        let b = self.read_bytes(6)?;
        let mut full = [0u8; 8];
        full[2..].copy_from_slice(b);
        Ok(u64::from_be_bytes(full))
    }

    /// Read a `uint8`-length-prefixed vector.
    pub fn read_vec_u8(&mut self) -> Result<&'a [u8]> {
        let n = self.read_u8()? as usize;
        self.read_bytes(n)
    }

    /// Read a `uint16`-length-prefixed vector.
    pub fn read_vec_u16(&mut self) -> Result<&'a [u8]> {
        let n = self.read_u16()? as usize;
        self.read_bytes(n)
    }

    /// Read a `uint24`-length-prefixed vector.
    pub fn read_vec_u24(&mut self) -> Result<&'a [u8]> {
        let n = self.read_u24()? as usize;
        self.read_bytes(n)
    }

    /// Assert that the reader has consumed all input.
    pub fn expect_eof(&self) -> Result<()> {
        if self.eof() {
            Ok(())
        } else {
            Err(DtlsError::UnexpectedEof)
        }
    }
}
