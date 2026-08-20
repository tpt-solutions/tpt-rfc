// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kerberos v5 protocol data units (RFC 4120 §5.3–5.10).
//!
//! Each type provides `encode()` (producing its own DER value) and a
//! corresponding `decode()` driven by [`crate::asn1::Cursor`]. APPLICATION-tagged
//! outer messages (`AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, `AP-REQ`, `AP-REP`)
//! are tagged in the dedicated constructor/decoder functions.

use crate::asn1::*;
use crate::error::{Error, Result};
use der::asn1::Any;
use der::{Decode, Encode, Tag, TagNumber, Tagged};

// Well-known NameTypes (RFC 4120 §6.2 / krb5.h).
pub const NT_UNKNOWN: i32 = 0;
pub const NT_PRINCIPAL: i32 = 1;
pub const NT_SRV_INST: i32 = 2;
pub const NT_SRV_HST: i32 = 3;
pub const NT_SRV_XHST: i32 = 4;
pub const NT_UID: i32 = 5;
pub const NT_X500_PRINCIPAL: i32 = 6;
pub const NT_SMTP_NAME: i32 = 7;
pub const NT_ENTERPRISE_PRINCIPAL: i32 = 10;

// PA-DATA types (RFC 4120 §5.2.7.1).
pub const PA_TGS_REQ: i32 = 1;
pub const PA_ENC_TIMESTAMP: i32 = 2;
pub const PA_PK_AS_REQ: i32 = 14;
pub const PA_PK_AS_REP: i32 = 15;
pub const PA_ETYPE_INFO2: i32 = 19;
pub const PA_PAC_REQUEST: i32 = 128;

// Authorisation-data AD types.
pub const AD_IF_RELEVANT: i32 = 1;
pub const AD_KDCISSUED: i32 = 4;
pub const AD_AND_OR: i32 = 5;
pub const AD_MANDATORY_TICKET_EXTENSIONS: i32 = 2;
pub const AD_MANDATORY_TGS_EXTENSIONS: i32 = 7;

// ---------------------------------------------------------------------------
// EncryptedData (RFC 4120 §5.2.9)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    pub etype: i32,        // EncryptionType
    pub kvno: Option<u32>, // version number (optional)
    pub cipher: Vec<u8>,   // encrypted data (OCTET STRING)
}

impl EncryptedData {
    /// Encode as `[n] IMPLICIT SEQUENCE { etype, kvno?, cipher }`.
    pub fn encode_implicit(&self, n: u8) -> Vec<u8> {
        let mut parts = vec![int32(self.etype)];
        if let Some(kvno) = self.kvno {
            parts.push(int32(kvno as i32));
        }
        parts.push(octet_string(&self.cipher));
        implicit_octet_string(n, &sequence(&parts))
    }

    pub fn decode_implicit(n: u8, any: &Any) -> Result<Self> {
        ensure_tag(any.tag(), ctx_primitive(n))?;
        let seq = Any::from_der(any.value()).map_err(Error::Asn1)?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut cur = Cursor::new(seq.value());
        let etype = decode_int32(&cur.take()?)?;
        let mut kvno = None;
        let mut cipher = Vec::new();
        while !cur.at_end() {
            let a = cur.take()?;
            match a.tag() {
                Tag::Integer => kvno = Some(decode_u32(&a)?),
                Tag::OctetString => cipher = a.value().to_vec(),
                _ => return Err(Error::Unexpected("EncryptedData field")),
            }
        }
        if cipher.is_empty() {
            return Err(Error::MissingField("EncryptedData.cipher"));
        }
        Ok(EncryptedData {
            etype,
            kvno,
            cipher,
        })
    }
}

// ---------------------------------------------------------------------------
// Checksum (RFC 4120 §5.2.10)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    pub cksumtype: i32,
    pub checksum: Vec<u8>,
}

impl Checksum {
    pub fn encode_implicit(&self, n: u8) -> Vec<u8> {
        implicit_octet_string(
            n,
            &sequence(&[int32(self.cksumtype), octet_string(&self.checksum)]),
        )
    }

    pub fn decode_implicit(n: u8, any: &Any) -> Result<Self> {
        ensure_tag(any.tag(), ctx_primitive(n))?;
        let seq = Any::from_der(any.value()).map_err(Error::Asn1)?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut cur = Cursor::new(seq.value());
        let cksumtype = decode_int32(&cur.take()?)?;
        let cs = cur.take()?;
        ensure_tag(cs.tag(), Tag::OctetString)?;
        Ok(Checksum {
            cksumtype,
            checksum: cs.value().to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// PA-DATA (RFC 4120 §5.2.7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaData {
    pub padata_type: i32,
    pub padata_value: Vec<u8>,
}

impl PaData {
    pub fn encode(&self) -> Vec<u8> {
        sequence(&[int32(self.padata_type), octet_string(&self.padata_value)])
    }

    pub fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut inner = Cursor::new(seq.value());
        let ptype = decode_int32(&inner.take()?)?;
        let val = inner.take()?;
        ensure_tag(val.tag(), Tag::OctetString)?;
        Ok(PaData {
            padata_type: ptype,
            padata_value: val.value().to_vec(),
        })
    }
}

/// A SET OF PA-DATA.
pub(crate) fn encode_pa_data(list: &[PaData]) -> Vec<u8> {
    set_of(&list.iter().map(|p| p.encode()).collect::<Vec<_>>())
}

pub(crate) fn decode_pa_data(any: &Any) -> Result<Vec<PaData>> {
    ensure_tag(any.tag(), Tag::Set)?;
    let mut cur = Cursor::new(any.value());
    let mut out = Vec::new();
    while !cur.at_end() {
        out.push(PaData::decode(&mut cur)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// HostAddress + HostAddresses (RFC 4120 §5.2.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    pub addr_type: i32,
    pub address: Vec<u8>,
}

impl HostAddress {
    fn encode(&self) -> Vec<u8> {
        sequence(&[int32(self.addr_type), octet_string(&self.address)])
    }
    fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut inner = Cursor::new(seq.value());
        let addr_type = decode_int32(&inner.take()?)?;
        let a = inner.take()?;
        ensure_tag(a.tag(), Tag::OctetString)?;
        Ok(HostAddress {
            addr_type,
            address: a.value().to_vec(),
        })
    }
}

/// `HostAddresses` — `SEQUENCE OF HostAddress`.
pub(crate) fn encode_host_addresses(list: &[HostAddress]) -> Vec<u8> {
    sequence(&list.iter().map(|h| h.encode()).collect::<Vec<_>>())
}

pub(crate) fn decode_host_addresses(any: &Any) -> Result<Vec<HostAddress>> {
    let seq = unwrap_sequence(any.value())?;
    let mut cur = Cursor::new(seq.value());
    let mut out = Vec::new();
    while !cur.at_end() {
        out.push(HostAddress::decode(&mut cur)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// AuthorizationData (RFC 4120 §5.2.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDataElement {
    pub ad_type: i32,
    pub ad_data: Vec<u8>,
}

pub type AuthorizationData = Vec<AuthorizationDataElement>;

pub(crate) fn encode_authorization_data(ad: &AuthorizationData) -> Vec<u8> {
    let elems = ad
        .iter()
        .map(|e| sequence(&[int32(e.ad_type), octet_string(&e.ad_data)]))
        .collect::<Vec<_>>();
    sequence(&elems)
}

pub(crate) fn decode_authorization_data(any: &Any) -> Result<AuthorizationData> {
    let seq = unwrap_sequence(any.value())?;
    let mut cur = Cursor::new(seq.value());
    let mut out = Vec::new();
    while !cur.at_end() {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut inner = Cursor::new(seq.value());
        let ad_type = decode_int32(&inner.take()?)?;
        let d = inner.take()?;
        ensure_tag(d.tag(), Tag::OctetString)?;
        out.push(AuthorizationDataElement {
            ad_type,
            ad_data: d.value().to_vec(),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// KDC-REQ-BODY (RFC 4120 §5.4.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcReqBody {
    pub kdc_options: u32, // KDCOptions (BIT STRING)
    pub cname: Option<PrincipalName>,
    pub realm: String,
    pub sname: Option<PrincipalName>,
    pub from: Option<u64>,
    pub till: u64,
    pub rtime: Option<u64>,
    pub nonce: u32,
    pub etype: Vec<i32>, // SEQUENCE OF INTEGER (EncryptionType)
    pub addresses: Option<Vec<HostAddress>>,
    pub enc_authorization_data: Option<EncryptedData>,
    pub additional_tickets: Option<Vec<Ticket>>,
}

impl KdcReqBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        // [0] kdc-options (BIT STRING, IMPLICIT)
        parts.push(ctx(0, &bit_string_u32(self.kdc_options)));
        // [1] cname
        if let Some(c) = &self.cname {
            parts.push(ctx(1, &c.encode()));
        }
        // [2] realm (KerberosString, IMPLICIT)
        parts.push(ctx(2, &realm(&self.realm)));
        // [3] sname
        if let Some(s) = &self.sname {
            parts.push(ctx(3, &s.encode()));
        }
        // [4] from (KerberosTime, IMPLICIT)
        if let Some(f) = self.from {
            parts.push(ctx(4, &kerberos_time(f)));
        }
        // [5] till
        parts.push(ctx(5, &kerberos_time(self.till)));
        // [6] rtime
        if let Some(r) = self.rtime {
            parts.push(ctx(6, &kerberos_time(r)));
        }
        // [7] nonce (INTEGER, IMPLICIT)
        parts.push(ctx(7, &integer_u32(self.nonce)));
        // [8] etype (SEQUENCE OF INTEGER)
        parts.push(ctx(
            8,
            &sequence(
                &self
                    .etype
                    .iter()
                    .map(|e| integer_i32(*e))
                    .collect::<Vec<_>>(),
            ),
        ));
        // [9] addresses
        if let Some(addrs) = &self.addresses {
            parts.push(ctx(9, &encode_host_addresses(addrs)));
        }
        // [10] enc-authorization-data (IMPLICIT EncryptedData)
        if let Some(ea) = &self.enc_authorization_data {
            parts.push(ea.encode_implicit(10));
        }
        // [11] additional-tickets (SEQUENCE OF Ticket)
        if let Some(tkts) = &self.additional_tickets {
            let t = sequence(
                &tkts
                    .iter()
                    .map(|t| t.encode_application(1))
                    .collect::<Vec<_>>(),
            );
            parts.push(ctx(11, &t));
        }
        sequence(&parts)
    }

    pub fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = Cursor::new(seq.value());
        let mut body = KdcReqBody {
            kdc_options: 0,
            cname: None,
            realm: String::new(),
            sname: None,
            from: None,
            till: 0,
            rtime: None,
            nonce: 0,
            etype: Vec::new(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
        while !c.at_end() {
            let a = c.take()?;
            let tag = a.tag();
            match tag {
                t if t == ctx_constructed(0) => {
                    body.kdc_options = read_bit_string_u32(&a)?;
                }
                t if t == ctx_constructed(1) => {
                    let mut ic = Cursor::new(a.value());
                    body.cname = Some(PrincipalName::decode(&mut ic)?);
                }
                t if t == ctx_constructed(2) => {
                    let r = Any::from_der(&a.to_der()?)?;
                    body.realm = read_kerberos_string(&r)?;
                }
                t if t == ctx_constructed(3) => {
                    let mut ic = Cursor::new(a.value());
                    body.sname = Some(PrincipalName::decode(&mut ic)?);
                }
                t if t == ctx_constructed(4) => {
                    body.from = Some(read_kerberos_time(&a)?);
                }
                t if t == ctx_constructed(5) => {
                    body.till = read_kerberos_time(&a)?;
                }
                t if t == ctx_constructed(6) => {
                    body.rtime = Some(read_kerberos_time(&a)?);
                }
                t if t == ctx_constructed(7) => {
                    body.nonce = decode_u32(&a)?;
                }
                t if t == ctx_constructed(8) => {
                    let mut ic = Cursor::new(a.value());
                    while !ic.at_end() {
                        body.etype.push(decode_int32(&ic.take()?)?);
                    }
                }
                t if t == ctx_constructed(9) => {
                    body.addresses = Some(decode_host_addresses(&a)?);
                }
                t if t == ctx_primitive(10) => {
                    body.enc_authorization_data = Some(EncryptedData::decode_implicit(10, &a)?);
                }
                t if t == ctx_constructed(11) => {
                    body.additional_tickets = Some(decode_tickets(&a)?);
                }
                _ => return Err(Error::Unexpected("KDC-REQ-BODY field")),
            }
        }
        Ok(body)
    }
}

/// `BIT STRING` of a `u32` (unused-bits byte `0` then 4 bytes BE).
pub(crate) fn bit_string_u32(v: u32) -> Vec<u8> {
    let mut content = vec![0x00u8];
    content.extend_from_slice(&v.to_be_bytes());
    tlv(0x03, &content)
}

pub(crate) fn read_bit_string_u32(any: &Any) -> Result<u32> {
    let any = peel_explicit(any)?;
    ensure_tag(any.tag(), Tag::BitString)?;
    let v = any.value();
    if v.len() != 5 || v[0] != 0 {
        return Err(Error::Unexpected("BIT STRING length/used-bits"));
    }
    Ok(u32::from_be_bytes([v[1], v[2], v[3], v[4]]))
}

// ---------------------------------------------------------------------------
// KDC-REQ / AS-REQ / TGS-REQ (RFC 4120 §5.4.1 / §5.4.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcReq {
    pub pvno: i32,
    pub msg_type: i32,
    pub padata: Option<Vec<PaData>>,
    pub req_body: KdcReqBody,
}

impl KdcReq {
    /// Encode as APPLICATION 10 (AS-REQ) or 12 (TGS-REQ).
    pub fn encode_application(&self, app: u8) -> Vec<u8> {
        let mut parts = vec![int32(self.pvno), int32(self.msg_type)];
        if let Some(pa) = &self.padata {
            parts.push(encode_pa_data(pa));
        }
        parts.push(self.req_body.encode());
        tlv(app_tag(app), &sequence(&parts))
    }

    pub fn decode_application(app: u8, data: &[u8]) -> Result<Self> {
        let outer = Any::from_der(data)?;
        ensure_tag(
            outer.tag(),
            Tag::Application {
                constructed: true,
                number: TagNumber(app as u32),
            },
        )?;
        let seq = unwrap_sequence(outer.value())?;
        let mut c = Cursor::new(seq.value());
        let pvno = decode_int32(&c.take()?)?;
        let msg_type = decode_int32(&c.take()?)?;
        let mut padata = None;
        let mut req_body = None;
        while !c.at_end() {
            let a = c.take()?;
            if a.tag() == Tag::Set {
                padata = Some(decode_pa_data(&a)?);
            } else if a.tag() == Tag::Sequence {
                // req-body is a SEQUENCE [APPLICATION-inner] -> decode via fresh cursor
                let mut bc = Cursor::new(a.value());
                req_body = Some(KdcReqBody::decode(&mut bc)?);
            } else {
                return Err(Error::Unexpected("KDC-REQ element"));
            }
        }
        let req_body = req_body.ok_or(Error::MissingField("KDC-REQ.req-body"))?;
        Ok(KdcReq {
            pvno,
            msg_type,
            padata,
            req_body,
        })
    }
}

// ---------------------------------------------------------------------------
// Ticket (RFC 4120 §5.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub tkt_vno: i32,
    pub realm: String,
    pub sname: PrincipalName,
    pub enc_part: EncryptedData,
}

impl Ticket {
    /// Encode as APPLICATION 1 (Ticket).
    pub fn encode_application(&self, app: u8) -> Vec<u8> {
        let parts = vec![
            int32(self.tkt_vno),
            realm(&self.realm),
            self.sname.encode(),
            self.enc_part.encode_implicit(3),
        ];
        tlv(app_tag(app), &sequence(&parts))
    }
}

/// Decode a `SEQUENCE OF Ticket` carried in a `[n] IMPLICIT` context field.
/// Each element is an APPLICATION 1 Ticket.
pub(crate) fn decode_tickets(any: &Any) -> Result<Vec<Ticket>> {
    ensure_tag(any.tag(), ctx_constructed(0))?;
    // The content is a SEQUENCE whose elements are APPLICATION 1 tickets.
    let mut cur = Cursor::new(any.value());
    let seq = cur.take()?;
    ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut inner = Cursor::new(seq.value());
    let mut out = Vec::new();
    while !inner.at_end() {
        let a = inner.take()?;
        out.push(decode_ticket(&a.to_der()?)?);
    }
    Ok(out)
}

/// Decode a single APPLICATION 1 Ticket from a full DER byte slice.
pub fn decode_ticket(data: &[u8]) -> Result<Ticket> {
    let outer = Any::from_der(data)?;
    ensure_tag(
        outer.tag(),
        Tag::Application {
            constructed: true,
            number: TagNumber(1),
        },
    )?;
    decode_ticket_value(outer.value())
}

pub(crate) fn decode_ticket_value(value: &[u8]) -> Result<Ticket> {
    let seq = unwrap_sequence(value)?;
    let mut c = Cursor::new(seq.value());
    let tkt_vno = decode_int32(&c.take()?)?;
    let r = c.take()?;
    let realm = read_kerberos_string(&r)?;
    // sname is the next element (a plain, untagged SEQUENCE); PrincipalName::decode
    // consumes its own Sequence TLV directly from the cursor.
    let sname = PrincipalName::decode(&mut c)?;
    let enc = c.take()?;
    let enc_part = EncryptedData::decode_implicit(3, &enc)?;
    Ok(Ticket {
        tkt_vno,
        realm,
        sname,
        enc_part,
    })
}

// ---------------------------------------------------------------------------
// EncTicketPart (RFC 4120 §5.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncTicketPart {
    pub flags: u32, // TicketFlags BIT STRING
    pub key: EncryptionKey,
    pub crealm: String,
    pub cname: PrincipalName,
    pub transited: TransitedEncoding,
    pub authtime: u64,
    pub starttime: Option<u64>,
    pub endtime: u64,
    pub renew_till: Option<u64>,
    pub caddr: Option<Vec<HostAddress>>,
    pub authorization_data: Option<AuthorizationData>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitedEncoding {
    pub tr_type: i32,
    pub contents: Vec<u8>,
}

impl EncTicketPart {
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![bit_string_u32(self.flags), self.key.encode_key_implicit(0)];
        parts.push(ctx(1, &realm(&self.crealm)));
        parts.push(ctx(2, &self.cname.encode()));
        // [3] transited
        parts.push(ctx(
            3,
            &sequence(&[
                int32(self.transited.tr_type),
                octet_string(&self.transited.contents),
            ]),
        ));
        // [4] authtime
        parts.push(ctx(4, &kerberos_time(self.authtime)));
        if let Some(s) = self.starttime {
            parts.push(ctx(5, &kerberos_time(s)));
        }
        // [6] endtime
        parts.push(ctx(6, &kerberos_time(self.endtime)));
        if let Some(r) = self.renew_till {
            parts.push(ctx(7, &kerberos_time(r)));
        }
        if let Some(addr) = &self.caddr {
            parts.push(ctx(8, &encode_host_addresses(addr)));
        }
        if let Some(ad) = &self.authorization_data {
            parts.push(ctx(9, &encode_authorization_data(ad)));
        }
        sequence(&parts)
    }

    pub fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = Cursor::new(seq.value());
        let mut etp = EncTicketPart {
            flags: 0,
            key: EncryptionKey::default(),
            crealm: String::new(),
            cname: PrincipalName {
                name_type: 0,
                name_string: Vec::new(),
            },
            transited: TransitedEncoding {
                tr_type: 0,
                contents: Vec::new(),
            },
            authtime: 0,
            starttime: None,
            endtime: 0,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        while !c.at_end() {
            let a = c.take()?;
            match a.tag() {
                t if t == Tag::BitString => etp.flags = read_bit_string_u32(&a)?,
                // [0] key
                t if t == ctx_primitive(0) => {
                    etp.key = EncryptionKey::decode_implicit(0, &a)?;
                }
                t if t == ctx_constructed(1) => {
                    etp.crealm = read_kerberos_string(&a)?;
                }
                t if t == ctx_constructed(2) => {
                    let mut nc = Cursor::new(a.value());
                    etp.cname = PrincipalName::decode(&mut nc)?;
                }
                t if t == ctx_constructed(3) => {
                    let seq = unwrap_sequence(a.value())?;
                    let mut tc = Cursor::new(seq.value());
                    etp.transited.tr_type = decode_int32(&tc.take()?)?;
                    let c = tc.take()?;
                    ensure_tag(c.tag(), Tag::OctetString)?;
                    etp.transited.contents = c.value().to_vec();
                }
                t if t == ctx_constructed(4) => etp.authtime = read_kerberos_time(&a)?,
                t if t == ctx_constructed(5) => etp.starttime = Some(read_kerberos_time(&a)?),
                t if t == ctx_constructed(6) => etp.endtime = read_kerberos_time(&a)?,
                t if t == ctx_constructed(7) => etp.renew_till = Some(read_kerbos_time(&a)?),
                t if t == ctx_constructed(8) => etp.caddr = Some(decode_host_addresses(&a)?),
                t if t == ctx_constructed(9) => {
                    etp.authorization_data = Some(decode_authorization_data(&a)?)
                }
                _ => return Err(Error::Unexpected("EncTicketPart field")),
            }
        }
        Ok(etp)
    }
}

fn read_kerbos_time(any: &Any) -> Result<u64> {
    read_kerberos_time(any)
}

// ---------------------------------------------------------------------------
// EncryptionKey (RFC 4120 §5.2.9 — also used in EncKDCRepPart/Authenticator)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncryptionKey {
    pub keytype: i32,
    pub keyvalue: Vec<u8>,
}

impl EncryptionKey {
    pub fn encode(&self) -> Vec<u8> {
        sequence(&[int32(self.keytype), octet_string(&self.keyvalue)])
    }

    pub fn decode_implicit(n: u8, any: &Any) -> Result<Self> {
        ensure_tag(any.tag(), ctx_primitive(n))?;
        let seq = Any::from_der(any.value()).map_err(Error::Asn1)?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut cur = Cursor::new(seq.value());
        let keytype = decode_int32(&cur.take()?)?;
        let v = cur.take()?;
        ensure_tag(v.tag(), Tag::OctetString)?;
        Ok(EncryptionKey {
            keytype,
            keyvalue: v.value().to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// KDC-REP / AS-REP / TGS-REP (RFC 4120 §5.4.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcRep {
    pub pvno: i32,
    pub msg_type: i32,
    pub padata: Option<Vec<PaData>>,
    pub crealm: String,
    pub cname: PrincipalName,
    pub ticket: Ticket,
    pub enc_part: EncryptedData, // EncKDCRepPart (IMPLICIT [6])
}

impl KdcRep {
    pub fn encode_application(&self, app: u8) -> Vec<u8> {
        let mut parts = vec![int32(self.pvno), int32(self.msg_type)];
        if let Some(pa) = &self.padata {
            parts.push(encode_pa_data(pa));
        }
        parts.push(ctx(1, &realm(&self.crealm)));
        parts.push(ctx(2, &self.cname.encode()));
        parts.push(self.ticket.encode_application(1));
        parts.push(self.enc_part.encode_implicit(6));
        tlv(app_tag(app), &sequence(&parts))
    }

    pub fn decode_application(app: u8, data: &[u8]) -> Result<Self> {
        let outer = Any::from_der(data)?;
        ensure_tag(
            outer.tag(),
            Tag::Application {
                constructed: true,
                number: TagNumber(app as u32),
            },
        )?;
        let seq = unwrap_sequence(outer.value())?;
        let mut c = Cursor::new(seq.value());
        let pvno = decode_int32(&c.take()?)?;
        let msg_type = decode_int32(&c.take()?)?;
        let mut padata = None;
        let mut crealm = String::new();
        let mut cname = None;
        let mut ticket = None;
        let mut enc_part = None;
        while !c.at_end() {
            let a = c.take()?;
            match a.tag() {
                Tag::Set => padata = Some(decode_pa_data(&a)?),
                t if t == ctx_constructed(1) => crealm = read_kerberos_string(&a)?,
                t if t == ctx_constructed(2) => {
                    let mut nc = Cursor::new(a.value());
                    cname = Some(PrincipalName::decode(&mut nc)?);
                }
                t if t
                    == Tag::Application {
                        constructed: true,
                        number: TagNumber(1),
                    } =>
                {
                    ticket = Some(decode_ticket_value(a.value())?);
                }
                t if t == ctx_primitive(6) => {
                    enc_part = Some(EncryptedData::decode_implicit(6, &a)?);
                }
                _ => return Err(Error::Unexpected("KDC-REP field")),
            }
        }
        Ok(KdcRep {
            pvno,
            msg_type,
            padata,
            crealm: crealm,
            cname: cname.ok_or(Error::MissingField("KDC-REP.cname"))?,
            ticket: ticket.ok_or(Error::MissingField("KDC-REP.ticket"))?,
            enc_part: enc_part.ok_or(Error::MissingField("KDC-REP.enc-part"))?,
        })
    }
}

// ---------------------------------------------------------------------------
// EncKDCRepPart (RFC 4120 §5.4.2 — AS-REP / TGS-REP share the body)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKdcRepPart {
    pub key: EncryptionKey,
    pub last_req: Vec<LastReq>,
    pub nonce: u32,
    pub key_expiration: Option<u64>,
    pub flags: u32, // TicketFlags
    pub authtime: u64,
    pub starttime: Option<u64>,
    pub endtime: u64,
    pub renew_till: Option<u64>,
    pub srealm: String,
    pub sname: PrincipalName,
    pub caddr: Option<Vec<HostAddress>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastReq {
    pub lr_type: i32,
    pub lr_value: u64,
}

impl EncKdcRepPart {
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![self.key.encode()];
        // [0] last-req (SEQUENCE OF LastReq)
        let lr = sequence(
            &self
                .last_req
                .iter()
                .map(|l| sequence(&[int32(l.lr_type), kerberos_time(l.lr_value)]))
                .collect::<Vec<_>>(),
        );
        parts.push(ctx(0, &lr));
        // [1] nonce
        parts.push(ctx(1, &integer_u32(self.nonce)));
        // [2] key-expiration
        if let Some(k) = self.key_expiration {
            parts.push(ctx(2, &kerberos_time(k)));
        }
        // [3] flags
        parts.push(ctx(3, &bit_string_u32(self.flags)));
        // [4] authtime
        parts.push(ctx(4, &kerberos_time(self.authtime)));
        if let Some(s) = self.starttime {
            parts.push(ctx(5, &kerberos_time(s)));
        }
        // [6] endtime
        parts.push(ctx(6, &kerberos_time(self.endtime)));
        if let Some(r) = self.renew_till {
            parts.push(ctx(7, &kerberos_time(r)));
        }
        // [8] srealm
        parts.push(ctx(8, &realm(&self.srealm)));
        // [9] sname
        parts.push(ctx(9, &self.sname.encode()));
        if let Some(addr) = &self.caddr {
            parts.push(ctx(10, &encode_host_addresses(addr)));
        }
        sequence(&parts)
    }

    pub fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = Cursor::new(seq.value());
        let mut ek = EncKdcRepPart {
            key: EncryptionKey::default(),
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: 0,
            authtime: 0,
            starttime: None,
            endtime: 0,
            renew_till: None,
            srealm: String::new(),
            sname: PrincipalName {
                name_type: 0,
                name_string: Vec::new(),
            },
            caddr: None,
        };
        while !c.at_end() {
            let a = c.take()?;
            match a.tag() {
                Tag::Sequence => {
                    ek.key = {
                        let mut kc = Cursor::new(a.value());
                        let keytype = decode_int32(&kc.take()?)?;
                        let v = kc.take()?;
                        EncryptionKey {
                            keytype,
                            keyvalue: v.value().to_vec(),
                        }
                    }
                }
                t if t == ctx_constructed(0) => {
                    let outer_seq = unwrap_sequence(a.value())?;
                    let mut lc = Cursor::new(outer_seq.value());
                    while !lc.at_end() {
                        let seq = lc.take()?;
                        ensure_tag(seq.tag(), Tag::Sequence)?;
                        let mut ic = Cursor::new(seq.value());
                        let lr_type = decode_int32(&ic.take()?)?;
                        let lr_value = read_kerberos_time(&ic.take()?)?;
                        ek.last_req.push(LastReq { lr_type, lr_value });
                    }
                }
                t if t == ctx_constructed(1) => ek.nonce = decode_u32(&a)?,
                t if t == ctx_constructed(2) => ek.key_expiration = Some(read_kerberos_time(&a)?),
                t if t == ctx_constructed(3) => ek.flags = read_bit_string_u32(&a)?,
                t if t == ctx_constructed(4) => ek.authtime = read_kerberos_time(&a)?,
                t if t == ctx_constructed(5) => ek.starttime = Some(read_kerberos_time(&a)?),
                t if t == ctx_constructed(6) => ek.endtime = read_kerberos_time(&a)?,
                t if t == ctx_constructed(7) => ek.renew_till = Some(read_kerberos_time(&a)?),
                t if t == ctx_constructed(8) => ek.srealm = read_kerberos_string(&a)?,
                t if t == ctx_constructed(9) => {
                    let mut nc = Cursor::new(a.value());
                    ek.sname = PrincipalName::decode(&mut nc)?;
                }
                t if t == ctx_constructed(10) => ek.caddr = Some(decode_host_addresses(&a)?),
                _ => return Err(Error::Unexpected("EncKDCRepPart field")),
            }
        }
        Ok(ek)
    }
}

// ---------------------------------------------------------------------------
// Authenticator (RFC 4120 §5.5.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticator {
    pub authenticator_vno: i32,
    pub crealm: String,
    pub cname: PrincipalName,
    pub checksum: Option<Checksum>,
    pub cusec: u32,
    pub ctime: u64,
    pub subkey: Option<EncryptionKey>,
    pub seq_number: Option<u32>,
    pub authorization_data: Option<AuthorizationData>,
}

impl Authenticator {
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![
            int32(self.authenticator_vno),
            realm(&self.crealm),
            self.cname.encode(),
        ];
        if let Some(cs) = &self.checksum {
            parts.push(cs.encode_implicit(3));
        }
        // [4] cusec
        parts.push(ctx(4, &integer_u32(self.cusec)));
        // [5] ctime
        parts.push(ctx(5, &kerberos_time(self.ctime)));
        if let Some(sk) = &self.subkey {
            parts.push(sk.encode_key_implicit(6));
        }
        if let Some(seq) = self.seq_number {
            parts.push(ctx(7, &integer_u32(seq)));
        }
        if let Some(ad) = &self.authorization_data {
            parts.push(ctx(8, &encode_authorization_data(ad)));
        }
        sequence(&parts)
    }

    pub fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = Cursor::new(seq.value());
        let authenticator_vno = decode_int32(&c.take()?)?;
        let crealm = read_kerberos_string(&c.take()?)?;
        // cname is a plain, untagged SEQUENCE; PrincipalName::decode consumes
        // its own Sequence TLV directly from the cursor.
        let cname = PrincipalName::decode(&mut c)?;
        let mut au = Authenticator {
            authenticator_vno,
            crealm,
            cname,
            checksum: None,
            cusec: 0,
            ctime: 0,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        while !c.at_end() {
            let a = c.take()?;
            match a.tag() {
                t if t == ctx_primitive(3) => au.checksum = Some(Checksum::decode_implicit(3, &a)?),
                t if t == ctx_constructed(4) => au.cusec = decode_u32(&a)?,
                t if t == ctx_constructed(5) => au.ctime = read_kerberos_time(&a)?,
                t if t == ctx_primitive(6) => {
                    au.subkey = Some(EncryptionKey::decode_implicit(6, &a)?)
                }
                t if t == ctx_constructed(7) => au.seq_number = Some(decode_u32(&a)?),
                t if t == ctx_constructed(8) => {
                    au.authorization_data = Some(decode_authorization_data(&a)?)
                }
                _ => return Err(Error::Unexpected("Authenticator field")),
            }
        }
        Ok(au)
    }
}

impl EncryptionKey {
    /// Encode as `[n] IMPLICIT SEQUENCE { keytype, keyvalue }`.
    pub fn encode_key_implicit(&self, n: u8) -> Vec<u8> {
        implicit_octet_string(n, &self.encode())
    }
}

// ---------------------------------------------------------------------------
// AP-REQ / AP-REP (RFC 4120 §5.5.1 / §5.5.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApReq {
    pub pvno: i32,
    pub msg_type: i32, // 14
    pub ap_options: u32,
    pub ticket: Ticket,
    pub authenticator: EncryptedData, // Encrypted Authenticator
}

impl ApReq {
    pub fn encode_application(&self) -> Vec<u8> {
        let parts = vec![
            int32(self.pvno),
            int32(self.msg_type),
            ctx(0, &bit_string_u32(self.ap_options)),
            self.ticket.encode_application(1),
            self.authenticator.encode_implicit(2),
        ];
        tlv(app_tag(14), &sequence(&parts))
    }

    pub fn decode_application(data: &[u8]) -> Result<Self> {
        let outer = Any::from_der(data)?;
        ensure_tag(
            outer.tag(),
            Tag::Application {
                constructed: true,
                number: TagNumber(14),
            },
        )?;
        let seq = unwrap_sequence(outer.value())?;
        let mut c = Cursor::new(seq.value());
        let pvno = decode_int32(&c.take()?)?;
        let msg_type = decode_int32(&c.take()?)?;
        let mut ap_options = 0u32;
        let mut ticket = None;
        let mut authenticator = None;
        while !c.at_end() {
            let a = c.take()?;
            match a.tag() {
                t if t == ctx_constructed(0) => ap_options = read_bit_string_u32(&a)?,
                t if t
                    == Tag::Application {
                        constructed: true,
                        number: TagNumber(1),
                    } =>
                {
                    ticket = Some(decode_ticket_value(a.value())?);
                }
                t if t == ctx_primitive(2) => {
                    authenticator = Some(EncryptedData::decode_implicit(2, &a)?);
                }
                _ => return Err(Error::Unexpected("AP-REQ field")),
            }
        }
        Ok(ApReq {
            pvno,
            msg_type,
            ap_options,
            ticket: ticket.ok_or(Error::MissingField("AP-REQ.ticket"))?,
            authenticator: authenticator.ok_or(Error::MissingField("AP-REQ.authenticator"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApRep {
    pub pvno: i32,
    pub msg_type: i32,           // 15
    pub enc_part: EncryptedData, // EncAPRepPart (IMPLICIT [0])
}

impl ApRep {
    pub fn encode_application(&self) -> Vec<u8> {
        let parts = vec![
            int32(self.pvno),
            int32(self.msg_type),
            self.enc_part.encode_implicit(0),
        ];
        tlv(app_tag(15), &sequence(&parts))
    }

    pub fn decode_application(data: &[u8]) -> Result<Self> {
        let outer = Any::from_der(data)?;
        ensure_tag(
            outer.tag(),
            Tag::Application {
                constructed: true,
                number: TagNumber(15),
            },
        )?;
        let seq = unwrap_sequence(outer.value())?;
        let mut c = Cursor::new(seq.value());
        let pvno = decode_int32(&c.take()?)?;
        let msg_type = decode_int32(&c.take()?)?;
        let enc_part = {
            let a = c.take()?;
            EncryptedData::decode_implicit(0, &a)?
        };
        Ok(ApRep {
            pvno,
            msg_type,
            enc_part,
        })
    }
}

/// EncAPRepPart (RFC 4120 §5.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncApRepPart {
    pub ctime: u64,
    pub cusec: u32,
    pub subkey: Option<EncryptionKey>,
    pub seq_number: Option<u32>,
}

impl EncApRepPart {
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![
            ctx(0, &kerberos_time(self.ctime)),
            ctx(1, &integer_u32(self.cusec)),
        ];
        if let Some(sk) = &self.subkey {
            parts.push(sk.encode_key_implicit(2));
        }
        if let Some(seq) = self.seq_number {
            parts.push(ctx(3, &integer_u32(seq)));
        }
        sequence(&parts)
    }

    pub fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let seq = cur.take()?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = Cursor::new(seq.value());
        let mut e = EncApRepPart {
            ctime: 0,
            cusec: 0,
            subkey: None,
            seq_number: None,
        };
        while !c.at_end() {
            let a = c.take()?;
            match a.tag() {
                t if t == ctx_constructed(0) => e.ctime = read_kerberos_time(&a)?,
                t if t == ctx_constructed(1) => e.cusec = decode_u32(&a)?,
                t if t == ctx_primitive(2) => {
                    e.subkey = Some(EncryptionKey::decode_implicit(2, &a)?)
                }
                t if t == ctx_constructed(3) => e.seq_number = Some(decode_u32(&a)?),
                _ => return Err(Error::Unexpected("EncAPRepPart field")),
            }
        }
        Ok(e)
    }
}

// ---------------------------------------------------------------------------
// PA-ENC-TIMESTAMP / PA-ETYPE-INFO2 helpers
// ---------------------------------------------------------------------------

/// `PA-ENC-TIMESTAMP` padata value: `EncryptedData` of a `PA-ENC-TS-ENC`
/// `{ patimestamp, pausec? }`.
pub mod pa_enc_ts {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PaEncTsEnc {
        pub patimestamp: u64,
        pub pausec: Option<u32>,
    }

    impl PaEncTsEnc {
        pub fn encode(&self) -> Vec<u8> {
            let mut parts = vec![kerberos_time(self.patimestamp)];
            if let Some(us) = self.pausec {
                parts.push(microseconds(us));
            }
            sequence(&parts)
        }

        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut c = Cursor::new(data);
            let seq = c.take()?;
            ensure_tag(seq.tag(), Tag::Sequence)?;
            let mut ic = Cursor::new(seq.value());
            let patimestamp = read_kerberos_time(&ic.take()?)?;
            let mut pausec = None;
            if !ic.at_end() {
                pausec = Some(decode_u32(&ic.take()?)?);
            }
            Ok(PaEncTsEnc {
                patimestamp,
                pausec,
            })
        }
    }
}

/// `PA-ETYPE-INFO2` padata value: `SEQUENCE OF ETYPE-INFO2-ENTRY { etype,
/// salt?, s2kparams? }`.
pub mod pa_etype_info2 {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EtypeInfo2Entry {
        pub etype: i32,
        pub salt: Option<Vec<u8>>,
        pub s2kparams: Option<Vec<u8>>,
    }

    pub fn encode(list: &[EtypeInfo2Entry]) -> Vec<u8> {
        let elems = list
            .iter()
            .map(|e| {
                let mut parts = vec![int32(e.etype)];
                if let Some(s) = &e.salt {
                    parts.push(octet_string(s));
                }
                if let Some(p) = &e.s2kparams {
                    parts.push(octet_string(p));
                }
                sequence(&parts)
            })
            .collect::<Vec<_>>();
        sequence(&elems)
    }

    pub fn decode(data: &[u8]) -> Result<Vec<EtypeInfo2Entry>> {
        let seq = Any::from_der(data)?;
        ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = Cursor::new(seq.value());
        let mut out = Vec::new();
        while !c.at_end() {
            let e = c.take()?;
            ensure_tag(e.tag(), Tag::Sequence)?;
            let mut ec = Cursor::new(e.value());
            let etype = decode_int32(&ec.take()?)?;
            let mut salt = None;
            let mut s2kparams = None;
            while !ec.at_end() {
                let a = ec.take()?;
                ensure_tag(a.tag(), Tag::OctetString)?;
                if salt.is_none() {
                    salt = Some(a.value().to_vec());
                } else {
                    s2kparams = Some(a.value().to_vec());
                }
            }
            out.push(EtypeInfo2Entry {
                etype,
                salt,
                s2kparams,
            });
        }
        Ok(out)
    }
}
