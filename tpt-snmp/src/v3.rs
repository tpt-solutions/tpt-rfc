// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SNMPv3 message processing and the User-based Security Model (USM) envelope
//! (RFC 3412 §6, RFC 3414).
//!
//! The v3 message is `SEQUENCE { msgVersion, msgGlobalData, msgSecurityParameters
//! (OCTET STRING wrapping the BER-encoded UsmSecurityParameters), msgData }`
//! where `msgData` is either a plaintext `ScopedPdu` (`SEQUENCE`) or an
//! encrypted PDU (`OCTET STRING`).

use crate::ber::{BerReader, BerWriter, TAG_SEQUENCE};
use crate::error::SnmpError;
use crate::pdu::Pdu;
use crate::usm::{auth_mac, AuthProtocol};

/// SNMPv3 message header data (`msgGlobalData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderData {
    /// `msgID` (used to match requests/responses).
    pub msg_id: i64,
    /// `msgMaxSize` — maximum message size the sender can accept.
    pub msg_max_size: i64,
    /// `msgFlags` — bit 0 auth, bit 1 priv, bit 2 reportable.
    pub msg_flags: u8,
    /// `msgSecurityModel` — 3 for USM.
    pub msg_security_model: i64,
}

impl HeaderData {
    /// Whether the auth flag (bit 0) is set.
    pub fn auth(&self) -> bool {
        self.msg_flags & 0x01 != 0
    }
    /// Whether the priv flag (bit 1) is set.
    pub fn is_priv(&self) -> bool {
        self.msg_flags & 0x02 != 0
    }
    /// Whether the reportable flag (bit 2) is set.
    pub fn reportable(&self) -> bool {
        self.msg_flags & 0x04 != 0
    }
}

/// USM security parameters (`UsmSecurityParameters`; RFC 3414 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsmSecurityParameters {
    /// `msgAuthoritativeEngineID`.
    pub authoritative_engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots`.
    pub authoritative_engine_boots: u32,
    /// `msgAuthoritativeEngineTime`.
    pub authoritative_engine_time: u32,
    /// `msgUserName`.
    pub user_name: Vec<u8>,
    /// `msgAuthenticationParameters` (12 bytes once filled in).
    pub auth_parameters: [u8; 12],
    /// `msgPrivacyParameters` (8-byte salt).
    pub priv_parameters: [u8; 8],
}

/// A `ScopedPdu`: `SEQUENCE { contextEngineID, contextName, data }` where
/// `data` is a standard PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPdu {
    /// `contextEngineID`.
    pub context_engine_id: Vec<u8>,
    /// `contextName`.
    pub context_name: Vec<u8>,
    /// The wrapped PDU.
    pub pdu: Pdu,
}

/// The `msgData` CHOICE of a v3 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V3Data {
    /// Plaintext `ScopedPdu`.
    Plain(ScopedPdu),
    /// Encrypted PDU (ciphertext of a `ScopedPdu`).
    Encrypted(Vec<u8>),
}

/// An SNMPv3 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Message {
    /// Message header (`msgGlobalData`).
    pub header: HeaderData,
    /// USM security parameters.
    pub security_parameters: UsmSecurityParameters,
    /// Message body (plaintext or encrypted `ScopedPdu`).
    pub data: V3Data,
}

fn encode_usm(usm: &UsmSecurityParameters) -> Vec<u8> {
    let mut w = BerWriter::new();
    let mut inner = BerWriter::new();
    inner.write_octet_string(&usm.authoritative_engine_id);
    inner.write_integer(usm.authoritative_engine_boots as i64);
    inner.write_integer(usm.authoritative_engine_time as i64);
    inner.write_octet_string(&usm.user_name);
    inner.write_octet_string(&usm.auth_parameters);
    inner.write_octet_string(&usm.priv_parameters);
    w.write_sequence(&inner.into_bytes());
    w.into_bytes()
}

fn decode_usm(content: &[u8]) -> Result<UsmSecurityParameters, SnmpError> {
    let mut r = BerReader::new(content);
    // The encoded USM is a SEQUENCE; unwrap it to read its fields.
    let (tag, inner) = r.read_tlv()?;
    if tag != crate::ber::TAG_SEQUENCE {
        return Err(SnmpError::Malformed);
    }
    let mut r = BerReader::new(inner);
    let (_, eid) = r.read_tlv()?;
    let (_, b) = r.read_tlv()?;
    let boots = crate::ber::decode_unsigned(b)? as u32;
    let (_, t) = r.read_tlv()?;
    let time = crate::ber::decode_unsigned(t)? as u32;
    let (_, u) = r.read_tlv()?;
    let (_, a) = r.read_tlv()?;
    if a.len() != 12 {
        return Err(SnmpError::Malformed);
    }
    let mut auth_parameters = [0u8; 12];
    auth_parameters.copy_from_slice(a);
    let (_, p) = r.read_tlv()?;
    if p.len() != 8 {
        return Err(SnmpError::Malformed);
    }
    let mut priv_parameters = [0u8; 8];
    priv_parameters.copy_from_slice(p);
    Ok(UsmSecurityParameters {
        authoritative_engine_id: eid.to_vec(),
        authoritative_engine_boots: boots,
        authoritative_engine_time: time,
        user_name: u.to_vec(),
        auth_parameters,
        priv_parameters,
    })
}

pub(crate) fn encode_scoped(scoped: &ScopedPdu) -> Vec<u8> {
    let mut w = BerWriter::new();
    let mut inner = BerWriter::new();
    inner.write_octet_string(&scoped.context_engine_id);
    inner.write_octet_string(&scoped.context_name);
    inner.write_raw(&scoped.pdu.encode());
    w.write_sequence(&inner.into_bytes());
    w.into_bytes()
}

pub(crate) fn decode_scoped(content: &[u8]) -> Result<ScopedPdu, SnmpError> {
    let mut r = BerReader::new(content);
    let (tag, inner) = r.read_tlv()?;
    if tag != crate::ber::TAG_SEQUENCE {
        return Err(SnmpError::Malformed);
    }
    let mut r = BerReader::new(inner);
    let (_, ceid) = r.read_tlv()?;
    let (_, cn) = r.read_tlv()?;
    let (ptag, pcontent) = r.read_tlv()?;
    let pdu = Pdu::decode(ptag, pcontent)?;
    Ok(ScopedPdu {
        context_engine_id: ceid.to_vec(),
        context_name: cn.to_vec(),
        pdu,
    })
}

impl V3Message {
    /// Encode the message. Authentication parameters are written as carried;
    /// use [`V3Message::encode_signed`] to compute and embed the HMAC.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        let mut body = BerWriter::new();
        body.write_integer(3);
        let mut g = BerWriter::new();
        g.write_integer(self.header.msg_id);
        g.write_integer(self.header.msg_max_size);
        g.write_octet_string(&[self.header.msg_flags]);
        g.write_integer(self.header.msg_security_model);
        body.write_sequence(&g.into_bytes());
        let usm = encode_usm(&self.security_parameters);
        body.write_octet_string(&usm);
        match &self.data {
            V3Data::Plain(scoped) => {
                let s = encode_scoped(scoped);
                // `encode_scoped` already emits the scopedPDU SEQUENCE.
                body.write_raw(&s);
            }
            V3Data::Encrypted(ct) => {
                body.write_octet_string(ct);
            }
        }
        w.write_sequence(&body.into_bytes());
        w.into_bytes()
    }

    /// Encode the message and, if `auth_key`/`auth_proto` are provided,
    /// compute the HMAC-MD5/SHA-96 over the whole message (with the auth
    /// parameters zeroed) and embed the 12-byte result.
    pub fn encode_signed(&self, auth_key: Option<&[u8]>, auth_proto: AuthProtocol) -> Vec<u8> {
        let mut msg = self.clone();
        if auth_key.is_some() {
            msg.security_parameters.auth_parameters = [0u8; 12];
        }
        let bytes = msg.encode();
        if let Some(key) = auth_key {
            if let Some(off) = find_auth_offset(&bytes) {
                let mac = auth_mac(auth_proto, key, &bytes);
                let mut b = bytes;
                b[off..off + 12].copy_from_slice(&mac);
                return b;
            }
        }
        bytes
    }

    /// Decode a v3 message (authentication is *not* verified here — see
    /// [`V3Message::verify_auth`]).
    pub fn decode(bytes: &[u8]) -> Result<V3Message, SnmpError> {
        let mut r = BerReader::new(bytes);
        let (tag, content) = r.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(SnmpError::Malformed);
        }
        let mut inner = BerReader::new(content);
        let (_, vc) = inner.read_tlv()?;
        let version = crate::ber::decode_signed(vc)?;
        if version != 3 {
            return Err(SnmpError::UnknownVersion(version));
        }
        let (_, gc) = inner.read_tlv()?;
        let mut gr = BerReader::new(gc);
        let (_, idc) = gr.read_tlv()?;
        let msg_id = crate::ber::decode_signed(idc)?;
        let (_, ms) = gr.read_tlv()?;
        let msg_max_size = crate::ber::decode_signed(ms)?;
        let (_, ff) = gr.read_tlv()?;
        if ff.len() != 1 {
            return Err(SnmpError::Malformed);
        }
        let msg_flags = ff[0];
        let (_, sm) = gr.read_tlv()?;
        let msg_security_model = crate::ber::decode_signed(sm)?;
        if msg_security_model != 3 {
            return Err(SnmpError::UnsupportedSecurityModel(msg_security_model));
        }
        let (_, sc) = inner.read_tlv()?;
        let usm = decode_usm(sc)?;
        let (dtag, dcontent) = inner.read_tlv()?;
        let data = if dtag == TAG_SEQUENCE {
            // `read_tlv` returned the *content* of the ScopedPdu SEQUENCE;
            // re-wrap it so `decode_scoped` receives the full ScopedPdu TLV
            // (the same representation produced by ciphertext decryption).
            let mut w = BerWriter::new();
            w.write_tlv(dtag, dcontent);
            V3Data::Plain(decode_scoped(&w.into_bytes())?)
        } else {
            V3Data::Encrypted(dcontent.to_vec())
        };
        Ok(V3Message {
            header: HeaderData {
                msg_id,
                msg_max_size,
                msg_flags,
                msg_security_model,
            },
            security_parameters: usm,
            data,
        })
    }

    /// Verify the HMAC over this message using `auth_key`/`auth_proto`.
    pub fn verify_auth(&self, bytes: &[u8], auth_key: &[u8], auth_proto: AuthProtocol) -> bool {
        match find_auth_offset(bytes) {
            None => false,
            Some(off) => {
                let mut zeroed = bytes.to_vec();
                zeroed[off..off + 12].copy_from_slice(&[0u8; 12]);
                let mac = auth_mac(auth_proto, auth_key, &zeroed);
                bytes[off..off + 12] == mac
            }
        }
    }
}

/// Locate the 12-byte authentication-parameter content within an encoded USM
/// message by scanning for the `04 0c <12> 04 08` structure.
fn find_auth_offset(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 16 <= bytes.len() {
        if bytes[i] == 0x04
            && bytes[i + 1] == 0x0c
            && bytes[i + 14] == 0x04
            && bytes[i + 15] == 0x08
        {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_plain_roundtrip() {
        let scoped = ScopedPdu {
            context_engine_id: b"engine".to_vec(),
            context_name: Vec::new(),
            pdu: Pdu::new(
                crate::pdu::PduType::GetRequest,
                5,
                0,
                0,
                crate::value::VarBindList(vec![]),
            ),
        };
        let msg = V3Message {
            header: HeaderData {
                msg_id: 1,
                msg_max_size: 65507,
                msg_flags: 0x04,
                msg_security_model: 3,
            },
            security_parameters: UsmSecurityParameters {
                authoritative_engine_id: b"engine".to_vec(),
                authoritative_engine_boots: 1,
                authoritative_engine_time: 100,
                user_name: b"user".to_vec(),
                auth_parameters: [0; 12],
                priv_parameters: [0; 8],
            },
            data: V3Data::Plain(scoped),
        };
        let bytes = msg.encode();
        let decoded = V3Message::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }
}
