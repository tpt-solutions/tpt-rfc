//! Low-level ASN.1/DER helpers and wire types for RFC 5652 CMS.
//!
//! Encoding is performed with manual TLV helpers (so the crate stays in full
//! control of DER ordering, sorting of SET OF elements, and the exact
//! `IMPLICIT`/`EXPLICIT` tagging the spec mandates). Decoding reuses the `der`
//! primitives via a small [`Cursor`] abstraction and hand-written parsers for
//! the IMPLICIT-tagged CMS fields.

use const_oid::ObjectIdentifier;
use der::{
    asn1::{AnyRef, OctetStringRef, UintRef},
    Decode, Encode, Length, SliceReader, Tag, TagNumber, Tagged,
};
use spki::AlgorithmIdentifierRef;

use crate::error::{CmsError, Result};

// ---------------------------------------------------------------------------
// Manual TLV builders
// ---------------------------------------------------------------------------

/// Encode a definite-length TLV with a single-byte tag.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&enc_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode the DER length octets for `n` (definite length, short/long form).
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

/// `[n] EXPLICIT` (or IMPLICIT-constructed) context tag: `0xA0 | n`.
pub(crate) fn ctx(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | (n & 0x1F), content)
}

/// `[n] IMPLICIT OCTET STRING` (primitive context tag): `0x80 | n`.
pub(crate) fn implicit_octet_string(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | (n & 0x1F), content)
}

pub(crate) fn integer_be(bytes: &[u8]) -> Vec<u8> {
    // Minimal big-endian encoding with the DER integer sign rule.
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

pub(crate) fn integer_u64(v: u64) -> Vec<u8> {
    integer_be(&v.to_be_bytes())
}

pub(crate) fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(0x04, data)
}

pub(crate) fn bit_string(data: &[u8]) -> Vec<u8> {
    // Unused-bits count 0, then the raw bytes.
    let mut content = vec![0x00];
    content.extend_from_slice(data);
    tlv(0x03, &content)
}

pub(crate) fn oid_der(oid: &ObjectIdentifier) -> Vec<u8> {
    oid.to_der().expect("oid der")
}

/// Build an `AlgorithmIdentifier` SEQUENCE `{ OID, [params] }`.
pub(crate) fn algorithm_identifier(oid: &ObjectIdentifier, params: Option<&[u8]>) -> Vec<u8> {
    let mut parts = vec![oid_der(oid)];
    if let Some(p) = params {
        parts.push(p.to_vec());
    }
    sequence(&parts)
}

pub(crate) fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flatten().cloned().collect();
    tlv(0x30, &content)
}

/// Build a `SET OF` TLV, with elements DER-sorted (canonical order).
pub(crate) fn set_of(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    let content: Vec<u8> = sorted.iter().flatten().cloned().collect();
    tlv(0x31, &content)
}

/// Build a CMS `Attribute` SEQUENCE `{ attrType, attrValues SET OF value }`.
pub(crate) fn attribute(attr_oid: &ObjectIdentifier, value: &[u8]) -> Vec<u8> {
    sequence(&[oid_der(attr_oid), tlv(0x31, value)])
}

/// Re-wrap SET content with an explicit `SET` (0x31) tag + length.
pub(crate) fn signed_attrs_tlv(content: &[u8]) -> Vec<u8> {
    tlv(0x31, content)
}

// ---------------------------------------------------------------------------
// Tag helpers for manual decoding
// ---------------------------------------------------------------------------

/// Context-specific, constructed tag `[n]` (EXPLICIT wrapper / IMPLICIT SET).
pub(crate) fn ctx_tag(n: u8) -> Tag {
    Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(n as u32),
    }
}

/// Context-specific, primitive tag `[n]` (IMPLICIT OCTET STRING).
pub(crate) fn ctx_tag_prim(n: u8) -> Tag {
    Tag::ContextSpecific {
        constructed: false,
        number: TagNumber(n as u32),
    }
}

/// Construct a `CmsError::Asn1` for an unexpected tag.
pub(crate) fn unexpected_tag(actual: Tag, expected: Tag) -> CmsError {
    CmsError::Asn1(der::Error::new(der::ErrorKind::TagUnexpected {
        expected: Some(expected),
        actual,
    }))
}

// ---------------------------------------------------------------------------
// DER cursor for manual parsing
// ---------------------------------------------------------------------------

/// A cursor over a DER byte slice that yields one TLV at a time.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data }
    }

    /// Take the next TLV, advancing the cursor past it.
    pub fn take(&mut self) -> Result<AnyRef<'a>> {
        let a = AnyRef::from_der(self.data).map_err(CmsError::Asn1)?;
        let full = a.to_der().map_err(CmsError::Asn1)?;
        self.data = &self.data[full.len()..];
        Ok(a)
    }

    /// Peek at the next tag without consuming it.
    pub fn peek_tag(&self) -> Option<Tag> {
        AnyRef::from_der(self.data).ok().map(|a| a.tag())
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
        Err(unexpected_tag(actual, expected))
    }
}

pub(crate) fn ensure_ctx(actual: Tag, n: u8) -> Result<()> {
    ensure_tag(actual, ctx_tag(n))
}

/// Decode the OID carried by `any` (whose tag must be OBJECT IDENTIFIER).
pub(crate) fn oid_of(any: &AnyRef) -> Result<ObjectIdentifier> {
    ObjectIdentifier::from_der(any.value()).map_err(CmsError::Asn1)
}

/// Decode the `AlgorithmIdentifier` carried by `any`.
pub(crate) fn algid_of<'a>(any: &AnyRef<'a>) -> Result<AlgorithmIdentifierRef<'a>> {
    AlgorithmIdentifierRef::from_der(any.value()).map_err(CmsError::Asn1)
}

/// Decode the OCTET STRING carried by `any` and return its value bytes.
pub(crate) fn octet_value(any: &AnyRef) -> Result<Vec<u8>> {
    let os = OctetStringRef::from(any.value());
    Ok(os.as_bytes().to_vec())
}

/// Decode `any` as an INTEGER and return its (raw) value bytes.
pub(crate) fn integer_value(any: &AnyRef) -> Result<Vec<u8>> {
    Ok(any.value().to_vec())
}

/// Decode a `SET OF T` from a cursor, returning each element's full DER.
pub(crate) fn take_set_of_raw(c: &mut Cursor<'_>) -> Result<Vec<Vec<u8>>> {
    let set = c.take()?;
    ensure_tag(set.tag(), Tag::Set)?;
    let mut inner = Cursor::new(set.value());
    let mut out = Vec::new();
    while !inner.at_end() {
        let a = inner.take()?;
        out.push(a.as_bytes().to_vec());
    }
    Ok(out)
}

/// Extract the OCTET STRING content of an `AlgorithmIdentifier` parameter.
pub(crate) fn octet_value_param(param: Option<&der::asn1::AnyRef>, what: &str) -> Result<Vec<u8>> {
    let p = param.ok_or_else(|| CmsError::Crypto(format!("missing {what}")))?;
    let os: &OctetStringRef = OctetStringRef::try_from(p.value()).map_err(CmsError::Asn1)?;
    Ok(os.as_bytes().to_vec())
}

/// Decode a `SET OF T` (DER-sorted element list) into owned `T` values.
pub(crate) fn decode_set_elements<'a, T: Decode<'a>>(data: &'a [u8]) -> Result<Vec<T>> {
    let set = AnyRef::from_der(data).map_err(CmsError::Asn1)?;
    ensure_tag(set.tag(), Tag::Set)?;
    let mut inner = Cursor::new(set.value());
    let mut out = Vec::new();
    while !inner.at_end() {
        let a = inner.take()?;
        out.push(T::from_der(a.as_bytes()).map_err(CmsError::Asn1)?);
    }
    Ok(out)
}

/// Parse the elements of a `SET`/`SET OF` whose DER is in `data`.
pub(crate) fn parse_set_elements_raw<'a>(data: &'a [u8]) -> Result<Vec<&'a [u8]>> {
    let set = AnyRef::from_der(data).map_err(CmsError::Asn1)?;
    ensure_tag(set.tag(), Tag::Set)?;
    let mut inner = Cursor::new(set.value());
    let mut out = Vec::new();
    while !inner.at_end() {
        let a = inner.take()?;
        out.push(a.as_bytes());
    }
    Ok(out)
}

/// Parse an IMPLICIT `[n] EXPLICIT { SEQUENCE { ... } }` context tag and return
/// the inner SEQUENCE content cursor. `n` is the outer context tag number.
pub(crate) fn open_ctx_sequence<'a>(c: &mut Cursor<'a>, n: u8) -> Result<Cursor<'a>> {
    let any = c.take()?;
    ensure_tag(any.tag(), ctx_tag(n))?;
    let seq = AnyRef::from_der(any.value()).map_err(CmsError::Asn1)?;
    ensure_tag(seq.tag(), Tag::Sequence)?;
    Ok(Cursor::new(seq.value()))
}
