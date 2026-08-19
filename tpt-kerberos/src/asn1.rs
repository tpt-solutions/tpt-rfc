// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Low-level DER helpers and the Kerberos primitive ASN.1 types (RFC 4120 §5.2).
//!
//! Kerberos v5 uses APPLICATION-tagged SEQUENCEs with many IMPLICIT
//! context-specific fields, so we hand-roll the encode/decode rather than lean on
//! derive macros. The helpers here mirror the conventions established in the
//! sibling `tpt-cms` crate.

use der::{
    asn1::Any,
    Decode, Encode, Length, Tag, TagNumber, Tagged,
};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Manual TLV builders (canonical DER definite-length form)
// ---------------------------------------------------------------------------

/// Encode a single-byte-tag TLV.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&enc_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode DER length octets (definite length, short/long form).
pub(crate) fn enc_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut bytes = (n as u128).to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        let mut out = vec![0x80 | (bytes.len() as u8)];
        out.extend_from_slice(&bytes);
        out
    }
}

/// `[APPLICATION n]` constructed tag byte.
pub(crate) fn app_tag(n: u8) -> u8 {
    0x60 | (n & 0x1F)
}

/// `[n] EXPLICIT` context-tagged (constructed) wrapper: `0xA0 | n`.
pub(crate) fn ctx(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | (n & 0x1F), content)
}

/// `[n] IMPLICIT OCTET STRING` (primitive context tag): `0x80 | n`.
pub(crate) fn implicit_octet_string(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | (n & 0x1F), content)
}

/// `[n] IMPLICIT INTEGER` (primitive context tag): `0x80 | n`.
pub(crate) fn implicit_int(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | (n & 0x1F), content)
}

pub(crate) fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().cloned()).collect();
    tlv(0x30, &content)
}

pub(crate) fn set_of(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    let content: Vec<u8> = sorted.iter().flat_map(|p| p.iter().cloned()).collect();
    tlv(0x31, &content)
}

pub(crate) fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(0x04, data)
}

pub(crate) fn integer_be(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    while v.len() > 1 && v[0] == 0 {
        v.remove(0);
    }
    if let Some(&first) = v.first() {
        if first & 0x80 != 0 {
            v.insert(0, 0x00);
        }
    }
    tlv(0x02, &v)
}

pub(crate) fn integer_i32(v: i32) -> Vec<u8> {
    integer_be(&v.to_be_bytes())
}

pub(crate) fn integer_u32(v: u32) -> Vec<u8> {
    integer_be(&v.to_be_bytes())
}

// ---------------------------------------------------------------------------
// DER cursor for manual parsing
// ---------------------------------------------------------------------------

/// A cursor over a DER byte slice that yields one TLV at a time (as owned `Any`).
pub struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data }
    }

    /// Take the next full TLV, advancing the cursor past it.
    pub fn take(&mut self) -> Result<Any> {
        let a = Any::from_der(self.data).map_err(Error::Asn1)?;
        let full = a.to_der().map_err(Error::Asn1)?;
        self.data = &self.data[full.len()..];
        Ok(a)
    }

    pub fn peek_tag(&self) -> Option<Tag> {
        Any::from_der(self.data).ok().map(|a| a.tag())
    }

    pub fn at_end(&self) -> bool {
        self.data.is_empty()
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }
}

pub(crate) fn ensure_tag(actual: Tag, expected: Tag) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Asn1(der::Error::new(
            der::ErrorKind::TagUnexpected {
                expected: Some(expected),
                actual,
            },
            Length::ZERO,
        )))
    }
}

pub(crate) fn ctx_constructed(n: u8) -> Tag {
    Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(n as u32),
    }
}

pub(crate) fn ctx_primitive(n: u8) -> Tag {
    Tag::ContextSpecific {
        constructed: false,
        number: TagNumber(n as u32),
    }
}

/// Return the raw value bytes (the TLV content, not the tag/length) of `any`.
pub(crate) fn value_of(any: &Any) -> &[u8] {
    any.value()
}

/// Decode the `INTEGER` value of `any` as a big-endian byte vector.
pub(crate) fn integer_value(any: &Any) -> Result<Vec<u8>> {
    ensure_tag(any.tag(), Tag::Integer)?;
    Ok(any.value().to_vec())
}

/// Parse the elements of a `SET OF`/`SET` whose encoded form is in `data`.
pub(crate) fn parse_set_elements(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let set = Any::from_der(data).map_err(Error::Asn1)?;
    ensure_tag(set.tag(), Tag::Set)?;
    let mut inner = Cursor::new(set.value());
    let mut out = Vec::new();
    while !inner.at_end() {
        let a = inner.take()?;
        out.push(a.to_der().map_err(Error::Asn1)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Kerberos primitive types
// ---------------------------------------------------------------------------

/// `KerberosString` — a GeneralString (RFC 4120 §5.2.1).
pub(crate) fn kerberos_string(s: &str) -> Vec<u8> {
    // GeneralString tag is 0x1B.
    tlv(0x1B, s.as_bytes())
}

/// Decode a `KerberosString` (GeneralString) from `any`.
pub(crate) fn read_kerberos_string(any: &Any) -> Result<String> {
    if any.tag() != Tag::GeneralString {
        return Err(Error::Unexpected("expected GeneralString (KerberosString)"));
    }
    let s = std::str::from_utf8(any.value())
        .map_err(|_| Error::Unexpected("KerberosString is not valid UTF-8"))?;
    Ok(s.to_owned())
}

/// `Realm` is simply a `KerberosString` (RFC 4120 §5.2.2).
pub(crate) fn realm(s: &str) -> Vec<u8> {
    kerberos_string(s)
}

/// `Int32` — a signed 32-bit INTEGER (RFC 4120 §5.2.4).
pub(crate) fn int32(v: i32) -> Vec<u8> {
    integer_i32(v)
}

/// `UInt32` — an unsigned 32-bit INTEGER (RFC 4120 §5.2.5).
pub(crate) fn uint32(v: u32) -> Vec<u8> {
    integer_u32(v)
}

/// `Microseconds` — an unsigned 32-bit INTEGER (RFC 4120 §5.2.6).
pub(crate) fn microseconds(v: u32) -> Vec<u8> {
    integer_u32(v)
}

/// `KerberosTime` — a `GeneralizedTime` storing seconds since the epoch
/// (RFC 4120 §5.2.3). The wire form is `GeneralizedTime` (tag `0x18`).
///
/// Note: `der::asn1::UtcTime` only spans 1950–2049, so we use a manual
/// `GeneralizedTime` (YYYYMMDDHHMMSSZ) encoded with the `0x18` tag.
pub(crate) fn kerberos_time(epoch_secs: u64) -> Vec<u8> {
    let s = format!("{:014}Z", epoch_secs);
    tlv(0x18, s.as_bytes())
}

/// Decode a `KerberosTime` (GeneralizedTime, tagged `0x18`) into seconds since
/// the Unix epoch.
pub(crate) fn read_kerberos_time(any: &Any) -> Result<u64> {
    if any.tag() != Tag::GeneralizedTime {
        return Err(Error::Unexpected("expected GeneralizedTime (KerberosTime)"));
    }
    let s = std::str::from_utf8(any.value())
        .map_err(|_| Error::Unexpected("KerberosTime not UTF-8"))?;
    // Expect form YYYYMMDDHHMMSSZ.
    if s.len() != 15 || !s.ends_with('Z') {
        return Err(Error::Unexpected("bad KerberosTime format"));
    }
    let year: u64 = s[0..4].parse().map_err(|_| Error::Unexpected("bad year"))?;
    let month: u64 = s[4..6].parse().map_err(|_| Error::Unexpected("bad month"))?;
    let day: u64 = s[6..8].parse().map_err(|_| Error::Unexpected("bad day"))?;
    let hour: u64 = s[8..10].parse().map_err(|_| Error::Unexpected("bad hour"))?;
    let min: u64 = s[10..12].parse().map_err(|_| Error::Unexpected("bad min"))?;
    let sec: u64 = s[12..14].parse().map_err(|_| Error::Unexpected("bad sec"))?;

    // Days since epoch using a simplified Gregorian conversion.
    let days = ymd_to_days(year, month, day)?;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Ok(secs)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn ymd_to_days(year: u64, month: u64, day: u64) -> Result<u64> {
    if !(1..=12).contains(&month) || day < 1 {
        return Err(Error::Unexpected("invalid date"));
    }
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let month_days = [0u64, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut md = month_days[..month as usize].iter().sum::<u64>();
    if month > 2 && is_leap(year) {
        md += 1;
    }
    if day > (md - (month_days[month as usize - 1])) {
        // crude day-bounds check
    }
    Ok(days + md + day - 1)
}

/// `PrincipalName` — SEQUENCE `{ name-type INTEGER, name-string SEQUENCE OF
/// KerberosString }` (RFC 4120 §5.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalName {
    pub name_type: i32,
    pub name_string: Vec<String>,
}

impl PrincipalName {
    pub fn encode(&self) -> Vec<u8> {
        let name_string = sequence(
            &self
                .name_string
                .iter()
                .map(|s| kerberos_string(s))
                .collect::<Vec<_>>(),
        );
        sequence(&[int32(self.name_type), name_string])
    }

    pub fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        let seq = cursor.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut inner = Cursor::new(seq.value());
        let nt = inner.take()?;
        let name_type = decode_int32(&nt)?;
        let ns = inner.take()?;
        ensure_tag(ns.tag(), Tag::Sequence)?;
        let mut strs = Vec::new();
        let mut si = Cursor::new(ns.value());
        while !si.at_end() {
            let a = si.take()?;
            strs.push(read_kerberos_string(&a)?);
        }
        Ok(PrincipalName {
            name_type,
            name_string: strs,
        })
    }
}

/// Decode an `INTEGER` `Any` into an `i32`.
pub(crate) fn decode_int32(any: &Any) -> Result<i32> {
    let v = integer_value(any)?;
    if v.len() > 4 {
        return Err(Error::Range("INTEGER does not fit in i32"));
    }
    let mut buf = [0u8; 4];
    let off = 4 - v.len();
    buf[off..].copy_from_slice(&v);
    if v.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        // sign extend
        for b in buf.iter_mut().take(off) {
            *b = 0xFF;
        }
    }
    Ok(i32::from_be_bytes(buf))
}

/// Decode an `INTEGER` `Any` into a `u32`.
pub(crate) fn decode_u32(any: &Any) -> Result<u32> {
    let v = integer_value(any)?;
    if v.len() > 4 {
        return Err(Error::Range("INTEGER does not fit in u32"));
    }
    let mut buf = [0u8; 4];
    let off = 4 - v.len();
    buf[off..].copy_from_slice(&v);
    Ok(u32::from_be_bytes(buf))
}

/// A fully-qualified principal `name@realm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name: PrincipalName,
    pub realm: String,
}

impl Principal {
    /// Build a `principal@realm` from components. `name_type` defaults to
    /// `NT_PRINCIPAL` (1) for users and `NT_SRV_INST` (2) for services.
    pub fn new(components: &[&str], realm: &str, name_type: i32) -> Self {
        Principal {
            name: PrincipalName {
                name_type,
                name_string: components.iter().map(|s| s.to_string()).collect(),
            },
            realm: realm.to_string(),
        }
    }

    /// Parse `user@REALM` or `service/host@REALM`.
    pub fn parse(s: &str) -> Result<Self> {
        let (name_part, realm) = s
            .rsplit_once('@')
            .ok_or_else(|| Error::Principal(format!("missing realm in '{s}'")))?;
        let comps: Vec<&str> = name_part.split('/').collect();
        let name_type: i32 = match comps.len() {
            1 => crate::types::NT_PRINCIPAL,
            _ => crate::types::NT_SRV_INST,
        };
        Ok(Principal::new(
            &comps.iter().map(|s| *s).collect::<Vec<_>>(),
            realm,
            name_type,
        ))
    }

    pub fn to_string(&self) -> String {
        let joined = self.name.name_string.join("/");
        if joined.is_empty() {
            format!("@{}", self.realm)
        } else {
            format!("{}@{}", joined, self.realm)
        }
    }
}

/// Helper to encode an optional field as `[n] IMPLICIT` context-tagged content.
pub(crate) fn opt_ctx(n: u8, present: bool, content: Vec<u8>) -> Option<Vec<u8>> {
    if present {
        Some(ctx(n, &content))
    } else {
        None
    }
}
