// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SNMP PDUs and the community-string (v1/v2c) message wrapper.

use crate::ber::{BerReader, BerWriter, TAG_IPADDRESS, TAG_SEQUENCE, TAG_TIMETICKS};
use crate::error::SnmpError;
use crate::oid::{read_oid, write_oid, ObjectIdentifier};
use crate::value::{SnmpValue, VarBind, VarBindList};

/// SNMP protocol version. `V3` is carried by [`crate::v3::V3Message`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    /// SNMPv1 (message `version` INTEGER = 0).
    V1,
    /// SNMPv2c (message `version` INTEGER = 1).
    V2c,
    /// SNMPv3 (message `version` INTEGER = 3; see [`crate::v3`]).
    V3,
}

impl SnmpVersion {
    /// The on-the-wire INTEGER value.
    pub fn to_int(self) -> i64 {
        match self {
            SnmpVersion::V1 => 0,
            SnmpVersion::V2c => 1,
            SnmpVersion::V3 => 3,
        }
    }

    /// Parse a `version` INTEGER into a [`SnmpVersion`].
    pub fn from_int(v: i64) -> Result<SnmpVersion, SnmpError> {
        match v {
            0 => Ok(SnmpVersion::V1),
            1 => Ok(SnmpVersion::V2c),
            3 => Ok(SnmpVersion::V3),
            other => Err(SnmpError::UnknownVersion(other)),
        }
    }
}

/// The SNMP PDU CHOICE type. The BER tag value doubles as the CHOICE tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    /// `GetRequest-PDU` (tag `0xA0`).
    GetRequest,
    /// `GetNextRequest-PDU` (tag `0xA1`).
    GetNextRequest,
    /// `GetResponse-PDU` / `Response-PDU` (tag `0xA2`).
    GetResponse,
    /// `SetRequest-PDU` (tag `0xA3`).
    SetRequest,
    /// `GetBulkRequest-PDU` (tag `0xA5`).
    GetBulkRequest,
    /// `InformRequest-PDU` (tag `0xA6`).
    InformRequest,
    /// `SNMPv2-Trap-PDU` (tag `0xA7`).
    SnmpV2Trap,
    /// `Report-PDU` (tag `0xA8`).
    Report,
}

impl PduType {
    /// The context-specific constructed tag for this PDU type.
    pub fn tag(self) -> u8 {
        match self {
            PduType::GetRequest => 0xA0,
            PduType::GetNextRequest => 0xA1,
            PduType::GetResponse => 0xA2,
            PduType::SetRequest => 0xA3,
            PduType::GetBulkRequest => 0xA5,
            PduType::InformRequest => 0xA6,
            PduType::SnmpV2Trap => 0xA7,
            PduType::Report => 0xA8,
        }
    }

    /// Map a CHOICE tag to a [`PduType`].
    pub fn from_tag(tag: u8) -> Result<PduType, SnmpError> {
        match tag {
            0xA0 => Ok(PduType::GetRequest),
            0xA1 => Ok(PduType::GetNextRequest),
            0xA2 => Ok(PduType::GetResponse),
            0xA3 => Ok(PduType::SetRequest),
            0xA5 => Ok(PduType::GetBulkRequest),
            0xA6 => Ok(PduType::InformRequest),
            0xA7 => Ok(PduType::SnmpV2Trap),
            0xA8 => Ok(PduType::Report),
            other => Err(SnmpError::UnknownPdu(other)),
        }
    }
}

/// A standard SNMP PDU (`GetRequest`, `GetNextRequest`, `SetRequest`,
/// `GetResponse`, `GetBulkRequest`, `InformRequest`, `SNMPv2-Trap`,
/// `Report`). `GetBulkRequest` reuses `error_status` as *non-repeaters* and
/// `error_index` as *max-repetitions* (RFC 3416 §4.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// PDU CHOICE type (also the BER tag).
    pub pdu_type: PduType,
    /// `request-id` — echoed back in the response.
    pub request_id: i32,
    /// `error-status` (or `non-repeaters` for `GetBulkRequest`).
    pub error_status: i32,
    /// `error-index` (or `max-repetitions` for `GetBulkRequest`).
    pub error_index: i32,
    /// Variable bindings.
    pub varbinds: VarBindList,
}

impl Pdu {
    /// Create a request/response PDU.
    pub fn new(
        pdu_type: PduType,
        request_id: i32,
        error_status: i32,
        error_index: i32,
        varbinds: VarBindList,
    ) -> Self {
        Pdu {
            pdu_type,
            request_id,
            error_status,
            error_index,
            varbinds,
        }
    }

    /// Encode the PDU (with its CHOICE tag) as a single BER TLV.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        let mut inner = BerWriter::new();
        inner.write_integer(self.request_id as i64);
        inner.write_integer(self.error_status as i64);
        inner.write_integer(self.error_index as i64);
        inner.write_raw(&self.varbinds.encode());
        w.write_tlv(self.pdu_type.tag(), &inner.into_bytes());
        w.into_bytes()
    }

    /// Decode a PDU from its `(tag, content)`.
    pub fn decode(tag: u8, content: &[u8]) -> Result<Pdu, SnmpError> {
        let pdu_type = PduType::from_tag(tag)?;
        let mut r = BerReader::new(content);
        let (_, rid) = r.read_tlv()?;
        let request_id = crate::ber::decode_signed(rid)? as i32;
        let (_, es) = r.read_tlv()?;
        let error_status = crate::ber::decode_signed(es)? as i32;
        let (_, ei) = r.read_tlv()?;
        let error_index = crate::ber::decode_signed(ei)? as i32;
        let (vl_tag, vl_content) = r.read_tlv()?;
        let varbinds = VarBindList::decode(vl_tag, vl_content)?;
        Ok(Pdu {
            pdu_type,
            request_id,
            error_status,
            error_index,
            varbinds,
        })
    }
}

/// An SNMPv1 `Trap-PDU` (tag `0xA4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapV1 {
    /// `enterprise` OBJECT IDENTIFIER.
    pub enterprise: ObjectIdentifier,
    /// `agent-addr` (`IpAddress`).
    pub agent_address: [u8; 4],
    /// `generic-trap` INTEGER.
    pub generic_trap: i32,
    /// `specific-trap` INTEGER.
    pub specific_trap: i32,
    /// `time-stamp` `TimeTicks`.
    pub time_stamp: u32,
    /// Variable bindings.
    pub varbinds: VarBindList,
}

impl TrapV1 {
    /// Encode the `Trap-PDU` (tag `0xA4`) as a single BER TLV.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        let mut inner = BerWriter::new();
        write_oid(&mut inner, &self.enterprise);
        inner.write_tlv(TAG_IPADDRESS, &self.agent_address);
        inner.write_integer(self.generic_trap as i64);
        inner.write_integer(self.specific_trap as i64);
        inner.write_unsigned(TAG_TIMETICKS, self.time_stamp as u64);
        inner.write_raw(&self.varbinds.encode());
        w.write_tlv(0xA4, &inner.into_bytes());
        w.into_bytes()
    }

    /// Decode a `Trap-PDU` from its `(tag, content)`.
    pub fn decode(tag: u8, content: &[u8]) -> Result<TrapV1, SnmpError> {
        if tag != 0xA4 {
            return Err(SnmpError::UnknownPdu(tag));
        }
        let mut r = BerReader::new(content);
        let enterprise = read_oid(&mut r)?;
        let (at, ac) = r.read_tlv()?;
        if at != TAG_IPADDRESS || ac.len() != 4 {
            return Err(SnmpError::Malformed);
        }
        let mut agent_address = [0u8; 4];
        agent_address.copy_from_slice(ac);
        let (_, gt) = r.read_tlv()?;
        let generic_trap = crate::ber::decode_signed(gt)? as i32;
        let (_, st) = r.read_tlv()?;
        let specific_trap = crate::ber::decode_signed(st)? as i32;
        let (_, ts) = r.read_tlv()?;
        let time_stamp = crate::ber::decode_unsigned(ts)? as u32;
        let (vl_tag, vl_content) = r.read_tlv()?;
        let varbinds = VarBindList::decode(vl_tag, vl_content)?;
        Ok(TrapV1 {
            enterprise,
            agent_address,
            generic_trap,
            specific_trap,
            time_stamp,
            varbinds,
        })
    }
}

/// The `data` CHOICE of a community-string message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageData {
    /// Any standard PDU.
    Pdu(Pdu),
    /// An SNMPv1 trap.
    TrapV1(TrapV1),
}

/// An SNMPv1/v2c message: `SEQUENCE { version, community, data }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Protocol version (must be `V1` or `V2c` for this wrapper).
    pub version: SnmpVersion,
    /// Community string.
    pub community: Vec<u8>,
    /// Message body.
    pub data: MessageData,
}

impl Message {
    /// Encode the full message.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        let mut inner = BerWriter::new();
        inner.write_integer(self.version.to_int());
        inner.write_octet_string(&self.community);
        match &self.data {
            MessageData::Pdu(p) => inner.write_raw(&p.encode()),
            MessageData::TrapV1(t) => inner.write_raw(&t.encode()),
        }
        w.write_sequence(&inner.into_bytes());
        w.into_bytes()
    }

    /// Decode a full community-string message.
    pub fn decode(bytes: &[u8]) -> Result<Message, SnmpError> {
        let mut r = BerReader::new(bytes);
        let (tag, content) = r.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(SnmpError::Malformed);
        }
        let mut inner = BerReader::new(content);
        let (_, vc) = inner.read_tlv()?;
        let version = SnmpVersion::from_int(crate::ber::decode_signed(vc)?)?;
        if version == SnmpVersion::V3 {
            return Err(SnmpError::Malformed);
        }
        let (_, cc) = inner.read_tlv()?;
        let community = cc.to_vec();
        let (dtag, dcontent) = inner.read_tlv()?;
        let data = if dtag == 0xA4 {
            MessageData::TrapV1(TrapV1::decode(dtag, dcontent)?)
        } else {
            MessageData::Pdu(Pdu::decode(dtag, dcontent)?)
        };
        Ok(Message {
            version,
            community,
            data,
        })
    }
}

/// Helper used by the agent to produce a response PDU for a request.
pub(crate) fn response_for(request: &Pdu, varbinds: VarBindList) -> Pdu {
    Pdu::new(PduType::GetResponse, request.request_id, 0, 0, varbinds)
}

/// Build a `noSuchObject`-valued varbind for a missing OID (SNMPv2 semantics).
pub(crate) fn missing_binding(oid: &ObjectIdentifier) -> VarBind {
    VarBind::new(oid.clone(), SnmpValue::NoSuchObject)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::ObjectIdentifier;

    #[test]
    fn message_v2c_roundtrip() {
        let req = Pdu::new(
            PduType::GetRequest,
            123,
            0,
            0,
            VarBindList(vec![VarBind::new(
                ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
                SnmpValue::Integer(0),
            )]),
        );
        let msg = Message {
            version: SnmpVersion::V2c,
            community: b"public".to_vec(),
            data: MessageData::Pdu(req),
        };
        let bytes = msg.encode();
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn getbulk_fields() {
        let bulk = Pdu::new(
            PduType::GetBulkRequest,
            7,
            0,  // non-repeaters
            10, // max-repetitions
            VarBindList(vec![]),
        );
        let bytes = bulk.encode();
        let (tag, content) = BerReader::new(&bytes).read_tlv().unwrap();
        let decoded = Pdu::decode(tag, content).unwrap();
        assert_eq!(decoded.pdu_type, PduType::GetBulkRequest);
        assert_eq!(decoded.error_status, 0);
        assert_eq!(decoded.error_index, 10);
    }
}
