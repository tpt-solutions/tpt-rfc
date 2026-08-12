// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{CborError, Result};
use crate::value::{DecodeOptions, Value};

/// A streaming CBOR decoder over a byte slice with configurable strictness.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    opts: DecodeOptions,
}

impl<'a> Decoder<'a> {
    /// Create a decoder with the given options.
    pub fn new(data: &'a [u8], opts: DecodeOptions) -> Self {
        Decoder { data, pos: 0, opts }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(CborError::UnexpectedEof);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(CborError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read the additional-information length field. Returns `None` for the
    /// indefinite-length marker (additional info 31).
    fn read_len(&mut self, major: u8, ai: u8) -> Result<Option<(u64, u8)>> {
        match ai {
            0..=23 => Ok(Some((ai as u64, 0))),
            24 => {
                let v = self.read_u8()?;
                Ok(Some((v as u64, 1)))
            }
            25 => {
                let b = self.read_exact(2)?;
                Ok(Some(((b[0] as u64) << 8 | b[1] as u64, 2)))
            }
            26 => {
                let b = self.read_exact(4)?;
                let mut v: u64 = 0;
                for &x in b {
                    v = (v << 8) | x as u64;
                }
                Ok(Some((v, 4)))
            }
            27 => {
                let b = self.read_exact(8)?;
                let mut v: u64 = 0;
                for &x in b {
                    v = (v << 8) | x as u64;
                }
                Ok(Some((v, 8)))
            }
            28..=30 => Err(CborError::InvalidInitialByte((major << 5) | ai)),
            31 => Ok(None),
            _ => Err(CborError::InvalidInitialByte((major << 5) | ai)),
        }
    }

    /// Decode a single data item from the current position.
    pub fn decode_value(&mut self) -> Result<Value> {
        let b = self.read_u8()?;
        let major = b >> 5;
        let ai = b & 0x1f;

        match major {
            0 | 1 => {
                let (len, nbytes) = self
                    .read_len(major, ai)?
                    .ok_or(CborError::InvalidInitialByte(b))?;
                if self.opts.canonical {
                    Self::check_shortest_int(len, nbytes)?;
                }
                let value = if major == 0 {
                    len as i128
                } else {
                    -1i128 - (len as i128)
                };
                Ok(Value::Integer(value))
            }
            2 => self.decode_bytes(ai, false),
            3 => self.decode_bytes(ai, true),
            4 => self.decode_array(ai),
            5 => self.decode_map(ai),
            6 => self.decode_tag(ai),
            7 => self.decode_simple(ai),
            _ => Err(CborError::InvalidInitialByte(b)),
        }
    }

    fn decode_bytes(&mut self, ai: u8, is_text: bool) -> Result<Value> {
        let len = self.read_len(2, ai)?;
        match len {
            Some((n, _)) => {
                let bytes = self.read_exact(n as usize)?.to_vec();
                self.materialize_string(bytes, is_text)
            }
            None => {
                // Indefinite-length byte/text string: concatenate chunks.
                if self.opts.reject_indefinite {
                    return Err(CborError::IndefiniteNotAllowed);
                }
                let mut acc = Vec::new();
                loop {
                    let b = self.read_u8()?;
                    if b == 0xff {
                        break;
                    }
                    let chunk_major = b >> 5;
                    let chunk_ai = b & 0x1f;
                    if chunk_major != 2 + (is_text as u8) {
                        return Err(CborError::InvalidInitialByte(b));
                    }
                    let (n, _) = self
                        .read_len(chunk_major, chunk_ai)?
                        .ok_or(CborError::InvalidInitialByte(b))?;
                    let bytes = self.read_exact(n as usize)?;
                    acc.extend_from_slice(bytes);
                }
                self.materialize_string(acc, is_text)
            }
        }
    }

    fn materialize_string(&self, bytes: Vec<u8>, is_text: bool) -> Result<Value> {
        if is_text {
            let s = String::from_utf8(bytes).map_err(|_| CborError::InvalidUtf8)?;
            Ok(Value::Text(s))
        } else {
            Ok(Value::Bytes(bytes))
        }
    }

    fn decode_array(&mut self, ai: u8) -> Result<Value> {
        let len = self.read_len(4, ai)?;
        match len {
            Some((n, _)) => {
                let mut items = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    items.push(self.decode_value()?);
                }
                Ok(Value::Array(items))
            }
            None => {
                if self.opts.reject_indefinite {
                    return Err(CborError::IndefiniteNotAllowed);
                }
                let mut items = Vec::new();
                loop {
                    if self.remaining() == 0 {
                        return Err(CborError::UnexpectedEof);
                    }
                    if self.data[self.pos] == 0xff {
                        self.pos += 1;
                        break;
                    }
                    items.push(self.decode_value()?);
                }
                Ok(Value::Array(items))
            }
        }
    }

    fn decode_map(&mut self, ai: u8) -> Result<Value> {
        let len = self.read_len(5, ai)?;
        match len {
            Some((n, _)) => self.decode_map_body(n as usize, false),
            None => {
                if self.opts.reject_indefinite {
                    return Err(CborError::IndefiniteNotAllowed);
                }
                self.decode_map_body(usize::MAX, true)
            }
        }
    }

    fn decode_map_body(&mut self, n: usize, indefinite: bool) -> Result<Value> {
        let mut pairs: Vec<(Value, Value)> = Vec::new();
        let mut count = 0usize;
        loop {
            if indefinite {
                if self.remaining() == 0 {
                    return Err(CborError::UnexpectedEof);
                }
                if self.data[self.pos] == 0xff {
                    self.pos += 1;
                    break;
                }
            } else if count >= n {
                break;
            }
            let key = self.decode_value()?;
            let val = self.decode_value()?;
            if (self.opts.reject_duplicate_keys || self.opts.canonical)
                && pairs.iter().any(|(k, _)| *k == key)
            {
                return Err(CborError::DuplicateKey);
            }
            if self.opts.canonical {
                if let Some((last, _)) = pairs.last() {
                    if !Self::canonical_key_lt(last, &key) {
                        return Err(CborError::DuplicateKey);
                    }
                }
            }
            pairs.push((key, val));
            count += 1;
        }
        Ok(Value::Map(pairs))
    }

    fn decode_tag(&mut self, ai: u8) -> Result<Value> {
        let (tag, _) = self
            .read_len(6, ai)?
            .ok_or(CborError::InvalidInitialByte(6 << 5 | ai))?;
        let inner = self.decode_value()?;
        // Collapse bignum tags (2/3) into Integer when they fit i128.
        if tag == 2 || tag == 3 {
            if let Value::Bytes(bytes) = &inner {
                if let Some(v) = bignum_to_i128(tag, bytes) {
                    return Ok(Value::Integer(v));
                }
            }
        }
        Ok(Value::Tag(tag, Box::new(inner)))
    }

    fn decode_simple(&mut self, ai: u8) -> Result<Value> {
        match ai {
            0..=19 => Ok(Value::Simple(ai)),
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Ok(Value::Undefined),
            24 => {
                let v = self.read_u8()?;
                if v <= 31 {
                    return Err(CborError::ReservedSimpleValue(v));
                }
                Ok(Value::Simple(v))
            }
            25 => {
                let b = self.read_exact(2)?;
                Ok(Value::Float(f16_to_f64(u16::from_be_bytes([b[0], b[1]]))))
            }
            26 => {
                let b = self.read_exact(4)?;
                let mut v: u32 = 0;
                for &x in b {
                    v = (v << 8) | x as u32;
                }
                Ok(Value::Float(f32::from_bits(v) as f64))
            }
            27 => {
                let b = self.read_exact(8)?;
                let mut v: u64 = 0;
                for &x in b {
                    v = (v << 8) | x as u64;
                }
                Ok(Value::Float(f64::from_bits(v)))
            }
            31 => Err(CborError::InvalidInitialByte(0xff)),
            _ => Err(CborError::InvalidInitialByte(0xe0 | ai)),
        }
    }

    fn check_shortest_int(len: u64, nbytes: u8) -> Result<()> {
        let minimal = if len < 24 {
            0
        } else if len <= 0xff {
            1
        } else if len <= 0xffff {
            2
        } else if len <= 0xffff_ffff {
            4
        } else {
            8
        };
        if nbytes != minimal {
            return Err(CborError::InvalidInitialByte(0));
        }
        Ok(())
    }

    fn canonical_key_lt(a: &Value, b: &Value) -> bool {
        use std::cmp::Ordering;
        let ea = crate::value::encode_value_to_vec(a, &crate::value::EncodeOptions::default());
        let eb = crate::value::encode_value_to_vec(b, &crate::value::EncodeOptions::default());
        match ea.len().cmp(&eb.len()) {
            Ordering::Equal => ea < eb,
            other => other == Ordering::Less,
        }
    }
}

fn bignum_to_i128(tag: u64, bytes: &[u8]) -> Option<i128> {
    if bytes.len() > 16 {
        return None;
    }
    let mut shifted = [0u8; 16];
    shifted[16 - bytes.len()..].copy_from_slice(bytes);
    let magnitude = i128::from_be_bytes(shifted);
    if tag == 2 {
        Some(magnitude)
    } else {
        // tag 3: value = -1 - magnitude
        Some(-1i128 - magnitude)
    }
}

/// Decode the first (and, if `strict`, only) CBOR data item from `data`.
pub fn decode_value(data: &[u8], opts: DecodeOptions) -> Result<Value> {
    let mut d = Decoder::new(data, opts);
    let value = d.decode_value()?;
    if d.pos != data.len() && opts.canonical {
        return Err(CborError::InvalidInitialByte(0));
    }
    Ok(value)
}

// Re-import float helper so this module can use it.
use crate::value::f16_to_f64;
