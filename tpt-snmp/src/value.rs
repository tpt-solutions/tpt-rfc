// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SNMP syntax values and variable bindings (`VarBind`).

use crate::ber::{
    BerReader, BerWriter, TAG_COUNTER32, TAG_COUNTER64, TAG_END_OF_MIB_VIEW, TAG_GAUGE32,
    TAG_INTEGER, TAG_IPADDRESS, TAG_NO_SUCH_INSTANCE, TAG_NO_SUCH_OBJECT, TAG_OBJECT_IDENTIFIER,
    TAG_OPAQUE, TAG_OCTET_STRING, TAG_TIMETICKS,
};
use crate::error::BerError;
use crate::oid::{write_oid, ObjectIdentifier, read_oid};

/// A single SNMP value, one of the SMI application syntaxes (RFC 2578 §7.1,
/// RFC 3416 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpValue {
    /// `INTEGER` / `Integer32` (universal tag).
    Integer(i32),
    /// `OCTET STRING` (universal tag).
    OctetString(Vec<u8>),
    /// `OBJECT IDENTIFIER` (universal tag).
    ObjectId(ObjectIdentifier),
    /// `IpAddress` (application tag 0).
    IpAddress([u8; 4]),
    /// `Counter32` (application tag 1).
    Counter32(u32),
    /// `Gauge32` (application tag 2).
    Gauge32(u32),
    /// `TimeTicks` (application tag 3).
    TimeTicks(u32),
    /// `Opaque` (application tag 4).
    Opaque(Vec<u8>),
    /// `Counter64` (application tag 6).
    Counter64(u64),
    /// `noSuchObject` exception (context tag 0).
    NoSuchObject,
    /// `noSuchInstance` exception (context tag 1).
    NoSuchInstance,
    /// `endOfMibView` exception (context tag 2).
    EndOfMibView,
}

impl SnmpValue {
    /// Encode this value as a complete BER TLV.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        match self {
            SnmpValue::Integer(v) => w.write_integer(*v as i64),
            SnmpValue::OctetString(s) => w.write_octet_string(s),
            SnmpValue::ObjectId(oid) => write_oid(&mut w, oid),
            SnmpValue::IpAddress(a) => w.write_tlv(TAG_IPADDRESS, a),
            SnmpValue::Counter32(v) => w.write_unsigned(TAG_COUNTER32, *v as u64),
            SnmpValue::Gauge32(v) => w.write_unsigned(TAG_GAUGE32, *v as u64),
            SnmpValue::TimeTicks(v) => w.write_unsigned(TAG_TIMETICKS, *v as u64),
            SnmpValue::Opaque(s) => w.write_tlv(TAG_OPAQUE, s),
            SnmpValue::Counter64(v) => w.write_unsigned(TAG_COUNTER64, *v),
            SnmpValue::NoSuchObject => w.write_null(TAG_NO_SUCH_OBJECT),
            SnmpValue::NoSuchInstance => w.write_null(TAG_NO_SUCH_INSTANCE),
            SnmpValue::EndOfMibView => w.write_null(TAG_END_OF_MIB_VIEW),
        }
        w.into_bytes()
    }

    /// Decode a value from its `(tag, content)` pair.
    pub fn decode(tag: u8, content: &[u8]) -> Result<SnmpValue, BerError> {
        match tag {
            TAG_INTEGER => Ok(SnmpValue::Integer(decode_int(content)? as i32)),
            TAG_OCTET_STRING => Ok(SnmpValue::OctetString(content.to_vec())),
            TAG_OBJECT_IDENTIFIER => Ok(SnmpValue::ObjectId(ObjectIdentifier::decode(content)?)),
            TAG_IPADDRESS => {
                if content.len() != 4 {
                    return Err(BerError::BadInteger);
                }
                let mut a = [0u8; 4];
                a.copy_from_slice(content);
                Ok(SnmpValue::IpAddress(a))
            }
            TAG_COUNTER32 => Ok(SnmpValue::Counter32(decode_int(content)? as u32)),
            TAG_GAUGE32 => Ok(SnmpValue::Gauge32(decode_int(content)? as u32)),
            TAG_TIMETICKS => Ok(SnmpValue::TimeTicks(decode_int(content)? as u32)),
            TAG_OPAQUE => Ok(SnmpValue::Opaque(content.to_vec())),
            TAG_COUNTER64 => Ok(SnmpValue::Counter64(decode_int(content)?)),
            TAG_NO_SUCH_OBJECT => Ok(SnmpValue::NoSuchObject),
            TAG_NO_SUCH_INSTANCE => Ok(SnmpValue::NoSuchInstance),
            TAG_END_OF_MIB_VIEW => Ok(SnmpValue::EndOfMibView),
            other => Err(BerError::UnknownTag(other)),
        }
    }

    /// Convenience: build an `OctetString` value.
    pub fn from_str(s: &str) -> SnmpValue {
        SnmpValue::OctetString(s.as_bytes().to_vec())
    }
}

fn decode_int(content: &[u8]) -> Result<u64, BerError> {
    crate::ber::decode_signed(content)
        .map(|v| v as u64)
        .or_else(|_| crate::ber::decode_unsigned(content))
}

/// A variable binding: an `OBJECT IDENTIFIER` paired with its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    /// The object name (OID).
    pub oid: ObjectIdentifier,
    /// The bound value.
    pub value: SnmpValue,
}

impl VarBind {
    /// Create a binding from an OID and a value.
    pub fn new(oid: ObjectIdentifier, value: SnmpValue) -> Self {
        VarBind { oid, value }
    }

    /// Encode as a `SEQUENCE { name, value }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        let mut inner = BerWriter::new();
        write_oid(&mut inner, &self.oid);
        inner.write_raw(&self.value.encode());
        w.write_sequence(&inner.into_bytes());
        w.into_bytes()
    }

    /// Decode a single `VarBind` from its `(tag, content)` (tag must be
    /// `SEQUENCE`).
    pub fn decode(tag: u8, content: &[u8]) -> Result<VarBind, BerError> {
        if tag != crate::ber::TAG_SEQUENCE {
            return Err(BerError::UnknownTag(tag));
        }
        let mut r = BerReader::new(content);
        let oid = read_oid(&mut r)?;
        let (vtag, vcontent) = r.read_tlv()?;
        let value = SnmpValue::decode(vtag, vcontent)?;
        Ok(VarBind { oid, value })
    }
}

/// A `VarBindList` (`SEQUENCE OF VarBind`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VarBindList(pub Vec<VarBind>);

impl VarBindList {
    /// Encode as `SEQUENCE OF VarBind`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        let mut inner = BerWriter::new();
        for vb in &self.0 {
            inner.write_raw(&vb.encode());
        }
        w.write_sequence(&inner.into_bytes());
        w.into_bytes()
    }

    /// Decode a `VarBindList` (tag must be `SEQUENCE`).
    pub fn decode(tag: u8, content: &[u8]) -> Result<VarBindList, BerError> {
        if tag != crate::ber::TAG_SEQUENCE {
            return Err(BerError::UnknownTag(tag));
        }
        let mut r = BerReader::new(content);
        let mut list = Vec::new();
        while !r.is_empty() {
            let (vtag, vcontent) = r.read_tlv()?;
            list.push(VarBind::decode(vtag, vcontent)?);
        }
        Ok(VarBindList(list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_roundtrip() {
        let vals = [
            SnmpValue::Integer(-123456),
            SnmpValue::OctetString(b"hello".to_vec()),
            SnmpValue::ObjectId(ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])),
            SnmpValue::IpAddress([192, 168, 0, 1]),
            SnmpValue::Counter32(4294967295),
            SnmpValue::Gauge32(1234),
            SnmpValue::TimeTicks(99999),
            SnmpValue::Opaque(vec![1, 2, 3]),
            SnmpValue::Counter64(18446744073709551615),
            SnmpValue::NoSuchObject,
            SnmpValue::NoSuchInstance,
            SnmpValue::EndOfMibView,
        ];
        for v in vals {
            let bytes = v.encode();
            let (tag, content) = BerReader::new(&bytes).read_tlv().unwrap();
            assert_eq!(SnmpValue::decode(tag, content).unwrap(), v);
        }
    }

    #[test]
    fn varbind_list_roundtrip() {
        let list = VarBindList(vec![
            VarBind::new(
                ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
                SnmpValue::from_str("test"),
            ),
            VarBind::new(
                ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 3, 0]),
                SnmpValue::Integer(42),
            ),
        ]);
        let bytes = list.encode();
        let (tag, content) = BerReader::new(&bytes).read_tlv().unwrap();
        assert_eq!(VarBindList::decode(tag, content).unwrap(), list);
    }
}
