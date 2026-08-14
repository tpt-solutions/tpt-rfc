// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clean-room BER (Basic Encoding Rules, ITU-T X.690) codec used by LDAP
//! ([RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)). LDAP uses BER, which
//! permits both definite and indefinite lengths and both primitive and
//! constructed encodings. This is implemented from the X.690 specification
//! rather than depending on an external ASN.1 library, keeping the crate
//! self-contained and auditable.

use thiserror::Error;

/// Tag classes (high two bits of the identifier octet).
/// Universal (ASN.1 built-in) tags.
pub const CLASS_UNIVERSAL: u8 = 0;
/// Application-specific tags (protocol-defined).
pub const CLASS_APPLICATION: u8 = 1;
/// Context-specific tags (field discrimination within a sequence).
pub const CLASS_CONTEXT: u8 = 2;
/// Private tags.
pub const CLASS_PRIVATE: u8 = 3;

/// Universal tag numbers used by this crate.
pub mod universal {
    /// INTEGER / ENUMERATED
    pub const INTEGER: u32 = 2;
    /// BIT STRING
    pub const BIT_STRING: u32 = 3;
    /// OCTET STRING
    pub const OCTET_STRING: u32 = 4;
    /// ENUMERATED (encoded identically to INTEGER)
    pub const ENUMERATED: u32 = 10;
    /// NULL
    pub const NULL: u32 = 5;
    /// OBJECT IDENTIFIER
    pub const OBJECT_IDENTIFIER: u32 = 6;
    /// BOOLEAN
    pub const BOOLEAN: u32 = 1;
    /// SEQUENCE / SEQUENCE OF
    pub const SEQUENCE: u32 = 16;
    /// SET / SET OF
    pub const SET: u32 = 17;
}

/// A BER identifier (tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// 0 = universal, 1 = application, 2 = context-specific, 3 = private.
    pub class: u8,
    /// `true` for constructed (has nested elements), `false` for primitive.
    pub constructed: bool,
    /// The tag number (low 5 bits of the identifier octet, or the high-tag form).
    pub number: u32,
}

impl Tag {
    /// A primitive universal tag.
    pub const fn universal(number: u32) -> Self {
        Self {
            class: CLASS_UNIVERSAL,
            constructed: false,
            number,
        }
    }

    /// A primitive application tag.
    pub const fn application(number: u32) -> Self {
        Self {
            class: CLASS_APPLICATION,
            constructed: false,
            number,
        }
    }

    /// A primitive context-specific tag.
    pub const fn context(number: u32) -> Self {
        Self {
            class: CLASS_CONTEXT,
            constructed: false,
            number,
        }
    }

    /// A primitive private tag.
    pub const fn private(number: u32) -> Self {
        Self {
            class: CLASS_PRIVATE,
            constructed: false,
            number,
        }
    }

    /// Mark this tag as constructed (contains nested elements).
    pub const fn constructed(mut self) -> Self {
        self.constructed = true;
        self
    }

    fn first_byte(&self) -> u8 {
        let class_bits = self.class << 6;
        let pc_bit = if self.constructed { 0x20 } else { 0 };
        let mut b = class_bits | pc_bit;
        if self.number < 31 {
            b |= self.number as u8;
        } else {
            b |= 0x1F;
        }
        b
    }
}

/// Errors raised while decoding BER.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BerError {
    /// Not enough bytes to form a complete element.
    #[error("unexpected end of BER input")]
    Truncated,
    /// The identifier octet could not be parsed.
    #[error("invalid BER tag")]
    BadTag,
    /// The length octets could not be parsed.
    #[error("invalid BER length")]
    BadLength,
    /// Indefinite length used on a primitive element (forbidden by X.690).
    #[error("indefinite length on a primitive element")]
    IndefinitePrimitive,
    /// An integer did not fit in the expected range.
    #[error("integer out of range")]
    IntegerRange,
    /// A required field was missing or of the wrong type.
    #[error("unexpected BER element")]
    Unexpected,
}

/// The content of a decoded BER element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BerContent {
    /// Primitive content: the raw value bytes.
    Primitive(Vec<u8>),
    /// Constructed content: the nested elements.
    Constructed(Vec<BerElement>),
}

/// A single decoded BER element (tag + content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BerElement {
    /// The element's tag.
    pub tag: Tag,
    /// The element's content.
    pub content: BerContent,
}

impl BerElement {
    /// An INTEGER/ENUMERATED value (universal tag 2).
    pub fn integer(value: i64) -> Self {
        Self {
            tag: Tag::universal(universal::INTEGER),
            content: BerContent::Primitive(int_to_bytes(value)),
        }
    }

    /// An ENUMERATED value (universal tag 10). Encoded identically to INTEGER.
    pub fn enumerated(value: i64) -> Self {
        Self {
            tag: Tag::universal(universal::ENUMERATED),
            content: BerContent::Primitive(int_to_bytes(value)),
        }
    }

    /// A BOOLEAN value (universal tag 1).
    pub fn boolean(value: bool) -> Self {
        Self {
            tag: Tag::universal(universal::BOOLEAN),
            content: BerContent::Primitive(vec![if value { 0xFF } else { 0x00 }]),
        }
    }

    /// An OCTET STRING value (universal tag 4).
    pub fn octet_string(data: &[u8]) -> Self {
        Self {
            tag: Tag::universal(universal::OCTET_STRING),
            content: BerContent::Primitive(data.to_vec()),
        }
    }

    /// A NULL value (universal tag 5).
    pub fn null() -> Self {
        Self {
            tag: Tag::universal(universal::NULL),
            content: BerContent::Primitive(Vec::new()),
        }
    }

    /// A constructed SEQUENCE (universal tag 16).
    pub fn sequence(children: Vec<BerElement>) -> Self {
        Self {
            tag: Tag::universal(universal::SEQUENCE).constructed(),
            content: BerContent::Constructed(children),
        }
    }

    /// A constructed SET (universal tag 17).
    pub fn set(children: Vec<BerElement>) -> Self {
        Self {
            tag: Tag::universal(universal::SET).constructed(),
            content: BerContent::Constructed(children),
        }
    }

    /// A constructed application-tagged SEQUENCE.
    pub fn application_sequence(tag: u32, children: Vec<BerElement>) -> Self {
        Self {
            tag: Tag::application(tag).constructed(),
            content: BerContent::Constructed(children),
        }
    }

    /// A constructed context-tagged SEQUENCE.
    pub fn context_sequence(tag: u32, children: Vec<BerElement>) -> Self {
        Self {
            tag: Tag::context(tag).constructed(),
            content: BerContent::Constructed(children),
        }
    }

    /// A primitive context-tagged value.
    pub fn context_primitive(tag: u32, data: &[u8]) -> Self {
        Self {
            tag: Tag::context(tag),
            content: BerContent::Primitive(data.to_vec()),
        }
    }

    /// A primitive application-tagged value.
    pub fn application_primitive(tag: u32, data: &[u8]) -> Self {
        Self {
            tag: Tag::application(tag),
            content: BerContent::Primitive(data.to_vec()),
        }
    }

    /// `true` if this is the end-of-contents marker (universal tag 0, empty).
    pub fn is_eoc(&self) -> bool {
        self.tag == Tag::universal(0)
            && !self.tag.constructed
            && matches!(&self.content, BerContent::Primitive(p) if p.is_empty())
    }

    /// Borrow the primitive value bytes, if this element is primitive.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            BerContent::Primitive(p) => Some(p),
            BerContent::Constructed(_) => None,
        }
    }

    /// Borrow the nested elements, if this element is constructed.
    pub fn as_children(&self) -> Option<&[BerElement]> {
        match &self.content {
            BerContent::Constructed(c) => Some(c),
            BerContent::Primitive(_) => None,
        }
    }

    /// Decode an INTEGER/ENUMERATED value into `i64`.
    pub fn as_int(&self) -> Result<i64, BerError> {
        let bytes = self.as_bytes().ok_or(BerError::Unexpected)?;
        bytes_to_int(bytes)
    }

    /// Decode a BOOLEAN value.
    pub fn as_bool(&self) -> Result<bool, BerError> {
        let bytes = self.as_bytes().ok_or(BerError::Unexpected)?;
        if bytes.len() != 1 {
            return Err(BerError::BadLength);
        }
        Ok(bytes[0] != 0x00)
    }

    /// Decode an OCTET STRING as a UTF-8 string (used for LDAPDN, LDAPString).
    pub fn as_str(&self) -> Result<&str, BerError> {
        let bytes = self.as_bytes().ok_or(BerError::Unexpected)?;
        std::str::from_utf8(bytes).map_err(|_| BerError::Unexpected)
    }

    /// Serialize this element back to BER (definite length form).
    pub fn encode(&self) -> Vec<u8> {
        match &self.content {
            BerContent::Primitive(bytes) => encode_tlv(self.tag, bytes),
            BerContent::Constructed(children) => {
                let mut inner = Vec::new();
                for c in children {
                    inner.extend_from_slice(&c.encode());
                }
                encode_tlv(self.tag, &inner)
            }
        }
    }

    /// Decode a single complete top-level element from `buf`, returning the
    /// element and the number of bytes it consumed.
    pub fn decode_partial(buf: &[u8]) -> Result<(BerElement, usize), BerError> {
        let mut pos = 0usize;
        let el = read_element(buf, &mut pos)?;
        Ok((el, pos))
    }
}

fn int_to_bytes(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut val = value;
    while val != 0 && val != -1 {
        buf.push((val & 0xff) as u8);
        val >>= 8;
    }
    if buf.is_empty() {
        return vec![0xff];
    }
    let last = *buf.last().unwrap();
    if value >= 0 && (last & 0x80) != 0 {
        buf.push(0x00);
    } else if value < 0 && (last & 0x80) == 0 {
        buf.push(0xff);
    }
    buf.reverse();
    buf
}

fn bytes_to_int(bytes: &[u8]) -> Result<i64, BerError> {
    if bytes.is_empty() {
        return Err(BerError::BadLength);
    }
    if bytes.len() > 8 {
        return Err(BerError::IntegerRange);
    }
    let mut val: i64 = 0;
    for &b in bytes {
        val = (val << 8) | (b as i64);
    }
    if bytes[0] & 0x80 != 0 {
        let bits = bytes.len() * 8;
        val -= 1i64 << bits;
    }
    Ok(val)
}

fn encode_tlv(tag: Tag, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag.first_byte());
    if tag.number >= 31 {
        let mut n = tag.number;
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push((n & 0x7f) as u8);
        n >>= 7;
        while n > 0 {
            bytes.push((n & 0x7f) as u8 | 0x80);
            n >>= 7;
        }
        bytes.reverse();
        out.extend_from_slice(&bytes);
    }
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut bytes: Vec<u8> = Vec::new();
        let mut l = len;
        while l > 0 {
            bytes.push((l & 0xff) as u8);
            l >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

fn read_element(buf: &[u8], pos: &mut usize) -> Result<BerElement, BerError> {
    let tag = read_tag(buf, pos)?;
    let (len, indefinite) = read_length(buf, pos)?;
    if indefinite {
        if !tag.constructed {
            return Err(BerError::IndefinitePrimitive);
        }
        let mut children: Vec<BerElement> = Vec::new();
        loop {
            let child = read_element(buf, pos)?;
            if child.is_eoc() {
                break;
            }
            children.push(child);
        }
        Ok(BerElement {
            tag,
            content: BerContent::Constructed(children),
        })
    } else {
        let content_start = *pos;
        let content_end = content_start.checked_add(len).ok_or(BerError::BadLength)?;
        if content_end > buf.len() {
            return Err(BerError::Truncated);
        }
        let content = &buf[content_start..content_end];
        *pos = content_end;
        if tag.constructed {
            let mut children: Vec<BerElement> = Vec::new();
            let mut cpos = content_start;
            while cpos < content_end {
                let child = read_element(buf, &mut cpos)?;
                children.push(child);
            }
            Ok(BerElement {
                tag,
                content: BerContent::Constructed(children),
            })
        } else {
            Ok(BerElement {
                tag,
                content: BerContent::Primitive(content.to_vec()),
            })
        }
    }
}

fn read_tag(buf: &[u8], pos: &mut usize) -> Result<Tag, BerError> {
    let b = *buf.get(*pos).ok_or(BerError::Truncated)?;
    *pos += 1;
    let class = b >> 6;
    let constructed = (b & 0x20) != 0;
    let mut number = (b & 0x1f) as u32;
    if number == 0x1f {
        number = 0;
        let mut shift: u32 = 0;
        loop {
            let n = *buf.get(*pos).ok_or(BerError::Truncated)?;
            *pos += 1;
            number = (number << 7) | (n & 0x7f) as u32;
            if n & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return Err(BerError::BadTag);
            }
        }
    }
    Ok(Tag {
        class,
        constructed,
        number,
    })
}

fn read_length(buf: &[u8], pos: &mut usize) -> Result<(usize, bool), BerError> {
    let b = *buf.get(*pos).ok_or(BerError::Truncated)?;
    *pos += 1;
    if b == 0x80 {
        return Ok((0, true));
    }
    if b & 0x80 == 0 {
        return Ok((b as usize, false));
    }
    let num_bytes = (b & 0x7f) as usize;
    if num_bytes > 8 {
        return Err(BerError::BadLength);
    }
    let mut len = 0usize;
    for _ in 0..num_bytes {
        let n = *buf.get(*pos).ok_or(BerError::Truncated)?;
        *pos += 1;
        len = (len << 8) | n as usize;
    }
    Ok((len, false))
}
