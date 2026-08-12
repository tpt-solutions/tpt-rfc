// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

/// An in-memory representation of a CBOR data item (RFC 8949 §2).
///
/// Integers use `i128` to cover both the unsigned and negative major types as
/// well as the bignum tags (2 and 3) that fit within 128 bits. Values larger
/// than that are surfaced as [`Value::Tag`] so callers can inspect the raw
/// content.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Major type 0 and 1. Integers in `[-2^128 + 1, 2^128 - 1]`.
    Integer(i128),
    /// Major type 7, additional info 25/26/27 — IEEE-754 floating point.
    Float(f64),
    /// Major type 7, `false` (`0xf4`).
    Bool(bool),
    /// Major type 7, `null` (`0xf6`).
    Null,
    /// Major type 7, `undefined` (`0xf7`).
    Undefined,
    /// Major type 7, an unassigned simple value in `0..=19` or `32..=255`.
    Simple(u8),
    /// Major type 2 — byte string.
    Bytes(Vec<u8>),
    /// Major type 3 — text string (guaranteed valid UTF-8).
    Text(String),
    /// Major type 4 — array (definite or indefinite in the source bytes, but
    /// always materialized as a `Vec` here).
    Array(Vec<Value>),
    /// Major type 5 — map. Kept as a list of pairs; callers needing a `HashMap`
    /// can build one. Order is preserved as decoded unless canonical encoding
    /// sorts it.
    Map(Vec<(Value, Value)>),
    /// Major type 6 — tagged data item.
    Tag(u64, Box<Value>),
}

impl Value {
    /// Convenience constructor for a text string.
    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    /// Convenience constructor for a byte string.
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Value::Bytes(b.into())
    }

    /// Returns the integer value if this is an [`Value::Integer`].
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the inner string if this is a [`Value::Text`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the inner bytes if this is a [`Value::Bytes`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

/// Decoding options controlling strictness and determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DecodeOptions {
    /// Reject indefinite-length items (RFC 8949 §4.2.1).
    pub reject_indefinite: bool,
    /// Reject duplicate map keys (RFC 8949 §4.2.1).
    pub reject_duplicate_keys: bool,
    /// Reject non-canonical representations (e.g. non-shortest integer/float
    /// encodings, out-of-order map keys).
    pub canonical: bool,
}

impl DecodeOptions {
    /// Strict mode: reject indefinite-length items and duplicate map keys.
    pub fn strict() -> Self {
        DecodeOptions {
            reject_indefinite: true,
            reject_duplicate_keys: true,
            canonical: false,
        }
    }

    /// Canonical mode: like strict, plus require canonical (shortest, sorted)
    /// encodings.
    pub fn canonical() -> Self {
        DecodeOptions {
            reject_indefinite: true,
            reject_duplicate_keys: true,
            canonical: true,
        }
    }
}

/// Encoding options controlling determinism (RFC 8949 §4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EncodeOptions {
    /// Produce canonical output: shortest lengths, shortest float forms, and
    /// maps serialized with keys sorted by the canonical ordering defined in
    /// the spec.
    pub canonical: bool,
}

impl EncodeOptions {
    /// Canonical encoding mode.
    pub fn canonical() -> Self {
        EncodeOptions { canonical: true }
    }
}

/// Canonical ordering of map keys (RFC 8949 §4.2.2): shorter encoding first,
/// then bytewise lexicographic comparison of the encodings.
fn canonical_key_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    let ea = encode_value_to_vec(a, &EncodeOptions::default());
    let eb = encode_value_to_vec(b, &EncodeOptions::default());
    // If encoding fails (shouldn't for valid keys), fall back to length then raw.
    match ea.len().cmp(&eb.len()) {
        std::cmp::Ordering::Equal => ea.cmp(&eb),
        other => other,
    }
}

/// Encode a [`Value`] into a fresh `Vec<u8>`.
pub fn encode_value_to_vec(value: &Value, opts: &EncodeOptions) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, opts, &mut out);
    out
}

fn write_type_number(out: &mut Vec<u8>, major: u8, value: u64) {
    let major_bits = major << 5;
    if value < 24 {
        out.push(major_bits | (value as u8));
    } else if value < 0x100 {
        out.push(major_bits | 24);
        out.push(value as u8);
    } else if value < 0x10000 {
        out.push(major_bits | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 0x1_0000_0000 {
        out.push(major_bits | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major_bits | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_value(value: &Value, opts: &EncodeOptions, out: &mut Vec<u8>) {
    match value {
        Value::Integer(i) => encode_integer(*i, out),
        Value::Float(f) => encode_float(*f, out),
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Undefined => out.push(0xf7),
        Value::Simple(s) => encode_simple(*s, out),
        Value::Bytes(b) => {
            write_type_number(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            write_type_number(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            write_type_number(out, 4, items.len() as u64);
            for item in items {
                encode_value(item, opts, out);
            }
        }
        Value::Map(pairs) => {
            let mut pairs = pairs.clone();
            if opts.canonical {
                pairs.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
            }
            write_type_number(out, 5, pairs.len() as u64);
            for (k, v) in &pairs {
                encode_value(k, opts, out);
                encode_value(v, opts, out);
            }
        }
        Value::Tag(tag, inner) => {
            write_type_number(out, 6, *tag);
            encode_value(inner, opts, out);
        }
    }
}

fn encode_integer(i: i128, out: &mut Vec<u8>) {
    if i >= 0 {
        if let Ok(u) = u64::try_from(i) {
            write_type_number(out, 0, u);
            return;
        }
        // Positive bignum (tag 2): content is `i` as a minimal big-endian
        // unsigned byte string.
        let mut bytes = (i as u128).to_be_bytes().to_vec();
        trim_be(&mut bytes);
        write_type_number(out, 6, 2);
        write_type_number(out, 2, bytes.len() as u64);
        out.extend_from_slice(&bytes);
        return;
    }
    let magnitude = match u64::try_from(-i - 1) {
        Ok(n) => n,
        _ => {
            // Negative bignum (tag 3): content is `(-1 - i)` as minimal
            // big-endian unsigned bytes.
            let mut bytes = ((-i - 1) as u128).to_be_bytes().to_vec();
            trim_be(&mut bytes);
            write_type_number(out, 6, 3);
            write_type_number(out, 2, bytes.len() as u64);
            out.extend_from_slice(&bytes);
            return;
        }
    };
    // Major type 1 encodes `-1 - n`, so `n = -1 - i`.
    write_type_number(out, 1, magnitude);
}

fn trim_be(bytes: &mut Vec<u8>) {
    let first_nonzero = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let keep = bytes.len() - first_nonzero;
    let keep = keep.max(1);
    bytes.drain(..bytes.len() - keep);
}

fn encode_simple(s: u8, out: &mut Vec<u8>) {
    // Reserved range 20..=31 is never produced; constructor guards via caller.
    if s <= 23 {
        out.push(0xe0 | s);
    } else {
        out.push(0xf8);
        out.push(s);
    }
}

/// Encode an IEEE-754 `f64` using the shortest form that round-trips exactly
/// (RFC 8949 §3.8.2 preferred serialization).
fn encode_float(f: f64, out: &mut Vec<u8>) {
    if f.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
        return;
    }
    let half = f64_to_f16(f);
    if f16_to_f64(half) == f {
        out.push(0xf9);
        out.extend_from_slice(&half.to_be_bytes());
        return;
    }
    let single = f as f32;
    if single as f64 == f {
        out.push(0xfa);
        out.extend_from_slice(&single.to_be_bytes());
        return;
    }
    out.push(0xfb);
    out.extend_from_slice(&f.to_be_bytes());
}

// --- half-precision helpers ------------------------------------------------

fn f64_to_f16(f: f64) -> u16 {
    let bits = f.to_bits();
    let sign = (bits >> 48) & 0x8000; // top bit as u16
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let mant = bits & 0x000f_ffff_ffff_ffff;

    if exp == 0x7ff {
        // Inf or NaN -> half Inf.
        return sign as u16 | 0x7c00;
    }

    let m = (1u64 << 52) | mant; // 53-bit mantissa with implicit leading 1
    let e = exp - 1008; // f64 bias 1023 minus f16 bias 15

    if e >= 0x1f {
        // Overflow -> Inf.
        return sign as u16 | 0x7c00;
    }

    if e >= 1 {
        // Normal half-precision.
        let hmant = (m >> 42) & 0x3ff;
        let rem = m & ((1u64 << 42) - 1);
        let mut h = ((e as u16) << 10) | hmant as u16;
        if rem != 0 {
            // Round to nearest, ties to even.
            if rem > (1u64 << 41) || (rem == (1u64 << 41) && (h & 1) == 1) {
                h += 1;
            }
        }
        return sign as u16 | h;
    }

    // Subnormal or zero in half-precision.
    let shift = 1051 - exp; // number of bits to drop to reach 2^-24 scale
    if shift >= 64 {
        return sign as u16; // underflow to zero
    }
    let s = m >> shift;
    let rem = m & ((1u64 << shift) - 1);
    let mut sub = s as u16;
    if rem != 0 && (rem > (1u64 << (shift - 1)) || (rem == (1u64 << (shift - 1)) && (sub & 1) == 1))
    {
        sub += 1;
    }
    if sub > 0x3ff {
        // Rounded up into the smallest normal number.
        return sign as u16 | 0x0400;
    }
    sign as u16 | sub
}

pub(crate) fn f16_to_f64(h: u16) -> f64 {
    let sign = (h >> 15) & 0x1;
    let exp = (h >> 10) & 0x1f;
    let mant = h & 0x3ff;

    if exp == 0 {
        if mant == 0 {
            if sign == 1 {
                -0.0
            } else {
                0.0
            }
        } else {
            let m = mant as f64;
            let e = f64::powi(2.0, -14 - 10);
            if sign == 1 {
                -m * e
            } else {
                m * e
            }
        }
    } else if exp == 0x1f {
        if mant == 0 {
            if sign == 1 {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }
        } else {
            f64::NAN
        }
    } else {
        let m = 1.0 + (mant as f64) / 1024.0;
        let e = f64::powi(2.0, (exp as i32) - 15);
        let val = m * e;
        if sign == 1 {
            -val
        } else {
            val
        }
    }
}

/// Re-export of the encoder entrypoint used by `Value::encode`.
impl Value {
    /// Encode this value using the given options.
    pub fn encode(&self, opts: &EncodeOptions) -> Vec<u8> {
        encode_value_to_vec(self, opts)
    }
}
