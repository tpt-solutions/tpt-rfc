// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SNMP [`ObjectIdentifier`] type (clean-room BER encoding).

use crate::ber::{BerReader, BerWriter, TAG_OBJECT_IDENTIFIER};
use crate::error::BerError;

/// An SNMP `OBJECT IDENTIFIER` (e.g. `1.3.6.1.2.1.1.1.0`).
///
/// Stored as the ordered list of sub-identifiers. Encoding follows the
/// standard OID base-128 BER rules (RFC 2578 §7.1 / X.690): the first two
/// sub-identifiers are packed as `40*a + b`, then each sub-identifier is
/// encoded as a series of 7-bit groups with the high bit set on all but the
/// last group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectIdentifier(pub Vec<u32>);

impl ObjectIdentifier {
    /// Create an OID from sub-identifiers.
    pub fn new(subidents: Vec<u32>) -> Self {
        ObjectIdentifier(subidents)
    }

    /// Encode as the content octets of an `OBJECT IDENTIFIER` TLV.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let sub = &self.0;
        if sub.len() >= 2 {
            // Per spec the first two sub-identifiers are combined as 40*X + Y
            // with X <= 2. We encode the raw combination; the decoder splits it.
            let combined = sub[0] * 40 + sub[1];
            out.extend_from_slice(&base128(combined as u64));
        }
        for &s in &sub[2..] {
            out.extend_from_slice(&base128(s as u64));
        }
        out
    }

    /// Decode `OBJECT IDENTIFIER` content octets.
    pub fn decode(content: &[u8]) -> Result<ObjectIdentifier, BerError> {
        let mut sub = Vec::new();
        let mut i = 0;
        let mut value: u64 = 0;
        let mut first = true;
        while i < content.len() {
            let byte = content[i] as u64;
            i += 1;
            value = (value << 7) | (byte & 0x7f);
            if byte & 0x80 == 0 {
                if first {
                    // split combined first value
                    let a = (value / 40).min(2);
                    let b = value - a * 40;
                    sub.push(a as u32);
                    sub.push(b as u32);
                    first = false;
                } else {
                    sub.push(value as u32);
                }
                value = 0;
            }
        }
        if first {
            return Err(BerError::BadOid);
        }
        Ok(ObjectIdentifier(sub))
    }
}

fn base128(mut v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let mut groups: Vec<u8> = Vec::new();
    while v > 0 {
        groups.push((v & 0x7f) as u8);
        v >>= 7;
    }
    groups.reverse();
    for i in 0..groups.len() - 1 {
        groups[i] |= 0x80;
    }
    groups
}

/// Encode a full `OBJECT IDENTIFIER` TLV.
pub(crate) fn write_oid(w: &mut BerWriter, oid: &ObjectIdentifier) {
    w.write_tlv(TAG_OBJECT_IDENTIFIER, &oid.encode());
}

/// Read an `OBJECT IDENTIFIER` TLV, returning the decoded OID.
pub(crate) fn read_oid(r: &mut BerReader) -> Result<ObjectIdentifier, BerError> {
    let (tag, content) = r.read_tlv()?;
    if tag != TAG_OBJECT_IDENTIFIER {
        return Err(BerError::UnknownTag(tag));
    }
    ObjectIdentifier::decode(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        let cases = [
            vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
            vec![1, 3, 6, 1, 4, 1, 2680, 1, 2, 1],
            vec![0, 0],
            vec![2, 25, 1, 0],
        ];
        for c in cases {
            let oid = ObjectIdentifier::new(c);
            let mut w = BerWriter::new();
            write_oid(&mut w, &oid);
            let bytes = w.into_bytes();
            let (tag, content) = BerReader::new(&bytes).read_tlv().unwrap();
            assert_eq!(tag, TAG_OBJECT_IDENTIFIER);
            let decoded = ObjectIdentifier::decode(content).unwrap();
            assert_eq!(decoded, oid);
        }
    }
}
