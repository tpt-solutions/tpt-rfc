//! IKEv2 message and payload codec (RFC 7296 §3).

use crate::crypto::{Encr, Integ};
use crate::error::{Error, Result};
use crate::transforms::{Proposal, SaPayload, Transform};
use crate::types::{
    AuthMethod, CertEncoding, DhGroup, ExchangeType, IdType, PayloadType, ProtocolId,
    TransformType,
};
use subtle::ConstantTimeEq;

const IKE_HEADER_LEN: usize = 28;
const PAYLOAD_HEADER_LEN: usize = 4;
const BLOCK: usize = 16;

// ===========================================================================
// IKE header
// ===========================================================================

/// The fixed 28-byte IKE header (RFC 7296 §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    pub next_payload: PayloadType,
    pub version: u8,
    pub exchange: ExchangeType,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(IKE_HEADER_LEN);
        b.extend_from_slice(&self.spi_i);
        b.extend_from_slice(&self.spi_r);
        b.push(self.next_payload.to_u8());
        b.push(self.version);
        b.push(self.exchange.to_u8());
        b.push(self.flags);
        b.extend_from_slice(&self.message_id.to_be_bytes());
        b.extend_from_slice(&self.length.to_be_bytes());
        b
    }

    pub fn decode(buf: &[u8]) -> Result<Header> {
        if buf.len() < IKE_HEADER_LEN {
            return Err(Error::Truncated {
                needed: IKE_HEADER_LEN,
                have: buf.len(),
            });
        }
        let mut spi_i = [0u8; 8];
        let mut spi_r = [0u8; 8];
        spi_i.copy_from_slice(&buf[0..8]);
        spi_r.copy_from_slice(&buf[8..16]);
        let next = PayloadType::from_u8(buf[16]).ok_or(Error::UnsupportedPayload(buf[16]))?;
        let version = buf[17];
        let exchange =
            ExchangeType::from_u8(buf[18]).ok_or(Error::UnsupportedExchange(buf[18]))?;
        let flags = buf[19];
        let message_id = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let length = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        Ok(Header {
            spi_i,
            spi_r,
            next_payload: next,
            version,
            exchange,
            flags,
            message_id,
            length: length as u32,
        })
    }

    pub fn is_initiator(&self) -> bool {
        self.flags & crate::types::flags::INITIATOR != 0
    }
    pub fn is_response(&self) -> bool {
        self.flags & crate::types::flags::RESPONSE != 0
    }
}

// ===========================================================================
// Payload model
// ===========================================================================

/// A decoded IKEv2 payload.
#[derive(Debug, Clone)]
pub enum Payload {
    Sa(SaPayload),
    Ke(KePayload),
    Nonce(NoncePayload),
    Idi(IdPayload),
    Idr(IdPayload),
    Auth(AuthPayload),
    Cert(CertPayload),
    CertReq(CertPayload),
    TSi(TsPayload),
    TSr(TsPayload),
    Notify(NotifyPayload),
    Sk(EncryptedPayload),
    Raw(RawPayload),
}

impl Payload {
    pub fn ptype(&self) -> PayloadType {
        match self {
            Payload::Sa(_) => PayloadType::Sa,
            Payload::Ke(_) => PayloadType::Ke,
            Payload::Nonce(_) => PayloadType::Nonce,
            Payload::Idi(_) => PayloadType::Idi,
            Payload::Idr(_) => PayloadType::Idr,
            Payload::Auth(_) => PayloadType::Auth,
            Payload::Cert(_) => PayloadType::Cert,
            Payload::CertReq(_) => PayloadType::CertReq,
            Payload::TSi(_) => PayloadType::TSi,
            Payload::TSr(_) => PayloadType::TSr,
            Payload::Notify(_) => PayloadType::Notify,
            Payload::Sk(_) => PayloadType::Sk,
            Payload::Raw(r) => r.ptype,
        }
    }
}

/// A generic, undecoded payload (V, D, CP, EAP, ...).
#[derive(Debug, Clone)]
pub struct RawPayload {
    pub ptype: PayloadType,
    pub critical: bool,
    pub data: Vec<u8>,
}

// --- SA -------------------------------------------------------------------

/// Diffie-Hellman key exchange payload (RFC 7296 §3.4).
#[derive(Debug, Clone)]
pub struct KePayload {
    pub group: DhGroup,
    pub public_key: Vec<u8>,
}

/// Nonce payload (RFC 7296 §3.9).
#[derive(Debug, Clone)]
pub struct NoncePayload {
    pub nonce: Vec<u8>,
}

/// Identification payload (RFC 7296 §3.5).
#[derive(Debug, Clone)]
pub struct IdPayload {
    pub id_type: IdType,
    pub data: Vec<u8>,
}

/// Authentication payload (RFC 7296 §3.8).
#[derive(Debug, Clone)]
pub struct AuthPayload {
    pub method: AuthMethod,
    pub data: Vec<u8>,
}

/// Certificate / Certificate Request payload (RFC 7296 §3.6).
#[derive(Debug, Clone)]
pub struct CertPayload {
    pub encoding: CertEncoding,
    pub data: Vec<u8>,
}

/// Traffic selector payload (RFC 7296 §3.13).
#[derive(Debug, Clone)]
pub struct TsPayload {
    pub selectors: Vec<TrafficSelector>,
}

#[derive(Debug, Clone)]
pub struct TrafficSelector {
    pub ts_type: u8,
    pub iproto: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: Vec<u8>,
    pub end_addr: Vec<u8>,
}

/// Notify payload (RFC 7296 §3.10).
#[derive(Debug, Clone)]
pub struct NotifyPayload {
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub notify_type: u16,
    pub data: Vec<u8>,
}

/// Encrypted (SK) payload envelope (RFC 7296 §3.14).
#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub next_payload: PayloadType,
    pub critical: bool,
    pub iv: Vec<u8>,
    /// Encrypted inner payloads (CBC: ciphertext; AEAD: ciphertext only).
    pub ciphertext: Vec<u8>,
    /// Integrity checksum (CBC) or AEAD tag.
    pub icv: Vec<u8>,
}

// ===========================================================================
// Encoding helpers
// ===========================================================================

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Build the 4-byte generic payload header for `body` of given `next`.
fn payload_header(next: PayloadType, critical: bool, body_len: usize) -> [u8; 4] {
    let mut h = [0u8; 4];
    h[0] = next.to_u8();
    h[1] = if critical { 0x80 } else { 0 };
    h[2..4].copy_from_slice(&(body_len as u16).to_be_bytes());
    h
}

// --- SA body (no generic header) -------------------------------------------

pub fn encode_sa_body(sa: &SaPayload) -> Vec<u8> {
    let mut out = Vec::new();
    for prop in &sa.proposals {
        let spi = &prop.spi;
        let n_trans = prop.transforms.len();
        // Proposal substructure header (8 bytes) + spi
        let prop_len = 8 + spi.len() + prop.transforms.iter().map(|t| transform_len(t)).sum::<usize>();
        out.push(prop.proposal_num);
        out.push(prop.protocol.to_u8());
        out.push(spi.len() as u8);
        out.push(n_trans as u8);
        out.extend_from_slice(spi);
        for (i, t) in prop.transforms.iter().enumerate() {
            let last = i + 1 == n_trans;
            encode_transform(&mut out, t, last);
        }
    }
    out
}

fn transform_len(t: &Transform) -> usize {
    // 8 (header + type/id) + attributes
    let mut attrs = 0;
    if t.transform_type == TransformType::Encr && t.key_len.is_some() {
        attrs += 4; // KEY_LENGTH basic attribute
    }
    attrs + 8
}

fn encode_transform(out: &mut Vec<u8>, t: &Transform, last: bool) {
    let next = if last { 0u8 } else { 3u8 };
    out.push(next);
    out.push(0); // reserved
    put_u16(out, transform_len(t) as u16);
    out.push(t.transform_type.to_u8());
    out.push(0); // reserved
    put_u16(out, t.transform_id);
    if t.transform_type == TransformType::Encr {
        if let Some(kl) = t.key_len {
            // KEY_LENGTH attribute (type 14, basic format, value = bits)
            put_u16(out, 0x000E);
            put_u16(out, kl as u16 * 8); // bits
        }
    }
}

pub fn decode_sa_body(body: &[u8]) -> Result<SaPayload> {
    let mut proposals = Vec::new();
    let mut off = 0;
    while off < body.len() {
        if body.len() - off < 8 {
            return Err(Error::Truncated {
                needed: 8,
                have: body.len() - off,
            });
        }
        let proposal_num = body[off];
        let protocol = ProtocolId::from_u8(body[off + 1]).ok_or(Error::UnsupportedPayload(body[off + 1]))?;
        let spi_size = body[off + 2] as usize;
        let n_trans = body[off + 3] as usize;
        let spi = body[off + 4..off + 4 + spi_size].to_vec();
        let mut p = off + 4 + spi_size;
        let mut transforms = Vec::with_capacity(n_trans);
        for _ in 0..n_trans {
            let (t, nxt) = decode_transform(&body[p..])?;
            transforms.push(t);
            // advance by transform length stored in the transform header
            let tlen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
            p += tlen;
            if nxt == 0 {
                break;
            }
        }
        proposals.push(Proposal {
            proposal_num,
            protocol,
            spi,
            transforms,
        });
        // advance to next proposal: we already consumed transforms; the proposal
        // length isn't carried, so we stop when transforms are consumed.
        off = p;
    }
    Ok(SaPayload { proposals })
}

fn decode_transform(buf: &[u8]) -> Result<(Transform, u8)> {
    if buf.len() < 8 {
        return Err(Error::Truncated {
            needed: 8,
            have: buf.len(),
        });
    }
    let next = buf[0];
    let ttype = TransformType::from_u8(buf[4]).ok_or(Error::UnsupportedTransformType(buf[4]))?;
    let tid = u16::from_be_bytes([buf[6], buf[7]]);
    let mut key_len = None;
    let mut a = 8;
    while a + 4 <= buf.len() {
        let atype = u16::from_be_bytes([buf[a], buf[a + 1]]);
        if atype & 0x8000 != 0 {
            // variable length
            let alen = u16::from_be_bytes([buf[a + 2], buf[a + 3]]) as usize;
            a += 4 + alen;
        } else {
            let val = u16::from_be_bytes([buf[a + 2], buf[a + 3]]);
            if atype == 0x000E {
                key_len = Some(val as usize / 8); // bits -> bytes
            }
            a += 4;
        }
    }
    Ok((
        Transform {
            transform_type: ttype,
            transform_id: tid,
            key_len,
        },
        next,
    ))
}

// --- simple payload bodies --------------------------------------------------

pub fn encode_ke_body(ke: &KePayload) -> Vec<u8> {
    let mut b = Vec::new();
    lput_u16(&mut b, ke.group.to_u16());
    lput_u16(&mut b, 0); // reserved
    b.extend_from_slice(&ke.public_key);
    b
}
fn lput_u16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_be_bytes());
}

pub fn decode_ke_body(body: &[u8]) -> Result<KePayload> {
    if body.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            have: body.len(),
        });
    }
    let group = DhGroup::from_u16(u16::from_be_bytes([body[0], body[1]]))
        .ok_or(Error::UnsupportedDhGroup(u16::from_be_bytes([body[0], body[1]])))?;
    let public_key = body[4..].to_vec();
    Ok(KePayload { group, public_key })
}

pub fn encode_nonce_body(n: &NoncePayload) -> Vec<u8> {
    n.nonce.clone()
}
pub fn decode_nonce_body(body: &[u8]) -> NoncePayload {
    NoncePayload {
        nonce: body.to_vec(),
    }
}

pub fn encode_id_body(id: &IdPayload) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(id.id_type.to_u8());
    b.extend_from_slice(&[0, 0, 0]);
    b.extend_from_slice(&id.data);
    b
}
pub fn decode_id_body(body: &[u8]) -> Result<IdPayload> {
    if body.is_empty() {
        return Err(Error::Truncated {
            needed: 1,
            have: 0,
        });
    }
    let id_type = IdType::from_u8(body[0]).ok_or(Error::UnsupportedIdType(body[0]))?;
    Ok(IdPayload {
        id_type,
        data: body[4..].to_vec(),
    })
}

pub fn encode_auth_body(a: &AuthPayload) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(a.method.to_u8());
    b.extend_from_slice(&[0, 0, 0]);
    b.extend_from_slice(&a.data);
    b
}
pub fn decode_auth_body(body: &[u8]) -> Result<AuthPayload> {
    if body.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            have: body.len(),
        });
    }
    let method = AuthMethod::from_u8(body[0]).ok_or(Error::UnsupportedAuthMethod(body[0]))?;
    Ok(AuthPayload {
        method,
        data: body[4..].to_vec(),
    })
}

pub fn encode_cert_body(c: &CertPayload) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(c.encoding.to_u8());
    b.extend_from_slice(&[0, 0, 0]);
    b.extend_from_slice(&c.data);
    b
}
pub fn decode_cert_body(body: &[u8]) -> Result<CertPayload> {
    if body.is_empty() {
        return Err(Error::Truncated {
            needed: 1,
            have: 0,
        });
    }
    let encoding =
        CertEncoding::from_u8(body[0]).ok_or(Error::UnsupportedCertEncoding(body[0]))?;
    Ok(CertPayload {
        encoding,
        data: body[4..].to_vec(),
    })
}

pub fn encode_ts_body(ts: &TsPayload) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(ts.selectors.len() as u8);
    b.extend_from_slice(&[0, 0, 0]);
    for s in &ts.selectors {
        b.push(s.ts_type);
        b.push(s.iproto);
        put_u16(&mut b, (8 + s.start_addr.len() + s.end_addr.len()) as u16);
        put_u16(&mut b, s.start_port);
        put_u16(&mut b, s.end_port);
        b.extend_from_slice(&s.start_addr);
        b.extend_from_slice(&s.end_addr);
    }
    b
}
pub fn decode_ts_body(body: &[u8]) -> Result<TsPayload> {
    if body.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            have: body.len(),
        });
    }
    let n = body[0] as usize;
    let mut selectors = Vec::with_capacity(n);
    let mut p = 4;
    for _ in 0..n {
        if p + 4 > body.len() {
            return Err(Error::Truncated {
                needed: 4,
                have: body.len() - p,
            });
        }
        let ts_type = body[p];
        let iproto = body[p + 1];
        let sel_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let start_port = u16::from_be_bytes([body[p + 4], body[p + 5]]);
        let end_port = u16::from_be_bytes([body[p + 6], body[p + 7]]);
        let addr_len = (sel_len - 8) / 2;
        let start_addr = body[p + 8..p + 8 + addr_len].to_vec();
        let end_addr = body[p + 8 + addr_len..p + 8 + 2 * addr_len].to_vec();
        selectors.push(TrafficSelector {
            ts_type,
            iproto,
            start_port,
            end_port,
            start_addr,
            end_addr,
        });
        p += sel_len;
    }
    Ok(TsPayload { selectors })
}

pub fn encode_notify_body(n: &NotifyPayload) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(n.protocol);
    b.push(n.spi.len() as u8);
    put_u16(&mut b, n.notify_type);
    b.extend_from_slice(&n.spi);
    b.extend_from_slice(&n.data);
    b
}
pub fn decode_notify_body(body: &[u8]) -> Result<NotifyPayload> {
    if body.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            have: body.len(),
        });
    }
    let protocol = body[0];
    let spi_size = body[1] as usize;
    let notify_type = u16::from_be_bytes([body[2], body[3]]);
    let spi = body[4..4 + spi_size].to_vec();
    Ok(NotifyPayload {
        protocol,
        spi,
        notify_type,
        data: body[4 + spi_size..].to_vec(),
    })
}

// ===========================================================================
// Message
// ===========================================================================

/// A full IKEv2 message: header + payloads.
#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub payloads: Vec<Payload>,
}

impl Message {
    /// Encode the message to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let n = self.payloads.len();
        for (i, p) in self.payloads.iter().enumerate() {
            let next = if i + 1 < n {
                self.payloads[i + 1].ptype()
            } else {
                PayloadType::None
            };
            encode_payload(&mut body, p, next);
        }
        let mut header = self.header.clone();
        header.next_payload = if n > 0 {
            self.payloads[0].ptype()
        } else {
            PayloadType::None
        };
        header.length = (IKE_HEADER_LEN + body.len()) as u32;
        let mut out = header.encode();
        out.extend_from_slice(&body);
        out
    }

    /// Decode a message (SK payloads are left encrypted).
    pub fn decode(buf: &[u8]) -> Result<Message> {
        let header = Header::decode(buf)?;
        let total = header.length as usize;
        if buf.len() < total {
            return Err(Error::Truncated {
                needed: total,
                have: buf.len(),
            });
        }
        let mut payloads = Vec::new();
        let mut off = IKE_HEADER_LEN;
        let mut cur = header.next_payload;
        while cur != PayloadType::None && off < total {
            let (p, next) = decode_one(&buf[off..total], cur)?;
            off += payload_len(&buf[off..total]);
            payloads.push(p);
            cur = next;
        }
        Ok(Message { header, payloads })
    }
}

fn payload_len(slice: &[u8]) -> usize {
    if slice.len() < PAYLOAD_HEADER_LEN {
        return slice.len();
    }
    u16::from_be_bytes([slice[2], slice[3]]) as usize
}

/// Encode a single payload (with its 4-byte generic header) into `out`.
pub fn encode_payload(out: &mut Vec<u8>, p: &Payload, next: PayloadType) {
    let body = payload_body(p);
    let ph = payload_header(next, is_critical(p), body.len());
    out.extend_from_slice(&ph);
    out.extend_from_slice(&body);
}

fn is_critical(_p: &Payload) -> bool {
    false
}

fn payload_body(p: &Payload) -> Vec<u8> {
    match p {
        Payload::Sa(s) => encode_sa_body(s),
        Payload::Ke(k) => encode_ke_body(k),
        Payload::Nonce(n) => encode_nonce_body(n),
        Payload::Idi(i) | Payload::Idr(i) => encode_id_body(i),
        Payload::Auth(a) => encode_auth_body(a),
        Payload::Cert(c) | Payload::CertReq(c) => encode_cert_body(c),
        Payload::TSi(t) | Payload::TSr(t) => encode_ts_body(t),
        Payload::Notify(n) => encode_notify_body(n),
        Payload::Sk(_) => Vec::new(), // SK encoded separately
        Payload::Raw(r) => r.data.clone(),
    }
}

/// Decode the payload at the start of `slice`, returning it and its `next`.
fn decode_one(slice: &[u8], ptype: PayloadType) -> Result<(Payload, PayloadType)> {
    if slice.len() < PAYLOAD_HEADER_LEN {
        return Err(Error::Truncated {
            needed: PAYLOAD_HEADER_LEN,
            have: slice.len(),
        });
    }
    let next = PayloadType::from_u8(slice[0]).ok_or(Error::UnsupportedPayload(slice[0]))?;
    let critical = slice[1] & 0x80 != 0;
    let len = u16::from_be_bytes([slice[2], slice[3]]) as usize;
    if len < PAYLOAD_HEADER_LEN || len % 4 != 0 {
        return Err(Error::BadPayloadLength(len));
    }
    if slice.len() < len {
        return Err(Error::Truncated {
            needed: len,
            have: slice.len(),
        });
    }
    let body = &slice[PAYLOAD_HEADER_LEN..len];
    let payload = match ptype {
        PayloadType::Sa => Payload::Sa(decode_sa_body(body)?),
        PayloadType::Ke => Payload::Ke(decode_ke_body(body)?),
        PayloadType::Nonce => Payload::Nonce(decode_nonce_body(body)),
        PayloadType::Idi => Payload::Idi(decode_id_body(body)?),
        PayloadType::Idr => Payload::Idr(decode_id_body(body)?),
        PayloadType::Auth => Payload::Auth(decode_auth_body(body)?),
        PayloadType::Cert => Payload::Cert(decode_cert_body(body)?),
        PayloadType::CertReq => Payload::CertReq(decode_cert_body(body)?),
        PayloadType::TSi => Payload::TSi(decode_ts_body(body)?),
        PayloadType::TSr => Payload::TSr(decode_ts_body(body)?),
        PayloadType::Notify => Payload::Notify(decode_notify_body(body)?),
        PayloadType::Sk => Payload::Sk(EncryptedPayload {
            next_payload: next,
            critical,
            iv: Vec::new(),
            ciphertext: Vec::new(),
            icv: Vec::new(),
        }),
        other => Payload::Raw(RawPayload {
            ptype: other,
            critical,
            data: body.to_vec(),
        }),
    };
    Ok((payload, next))
}

/// Decode a chain of payloads starting at `start` type from `buf`.
pub fn decode_payloads_chain(buf: &[u8], start: PayloadType) -> Result<Vec<Payload>> {
    let mut out = Vec::new();
    let mut off = 0;
    let mut cur = start;
    while cur != PayloadType::None && off < buf.len() {
        let (p, next) = decode_one(&buf[off..], cur)?;
        off += payload_len(&buf[off..]);
        out.push(p);
        cur = next;
    }
    Ok(out)
}

// ===========================================================================
// SK (Encrypted) payload envelope
// ===========================================================================

impl EncryptedPayload {
    /// Encrypt `inner` payloads into an SK payload.
    ///
    /// `header` is the (already length-correct) IKE header that will precede
    /// this SK payload, used for the CBC integrity checksum. `sk_e`/`sk_a`
    /// are the IKE SA encryption/integrity keys. `iv`/`salt` allow
    /// deterministic tests; if `None` they are generated randomly.
    pub fn encrypt(
        encr: Encr,
        integ: Option<Integ>,
        header: &Header,
        next: PayloadType,
        inner: &[Payload],
        sk_e: &[u8],
        sk_a: &[u8],
        iv: Option<&[u8]>,
        salt: Option<&[u8]>,
    ) -> Result<EncryptedPayload> {
        // Encode inner payloads into a chain.
        let mut inner_bytes = Vec::new();
        let n = inner.len();
        for (i, p) in inner.iter().enumerate() {
            let nxt = if i + 1 < n {
                inner[i + 1].ptype()
            } else {
                PayloadType::None
            };
            encode_payload(&mut inner_bytes, p, nxt);
        }
        // IKE padding: make (inner + pad + padlen) a multiple of BLOCK.
        let pad_len = (BLOCK - ((inner_bytes.len() + 1) % BLOCK)) % BLOCK;
        let mut plaintext = inner_bytes;
        plaintext.extend(std::iter::repeat(0u8).take(pad_len));
        plaintext.push(pad_len as u8);

        if encr.is_aead() {
            let salt = match salt {
                Some(s) => s.to_vec(),
                None => crypto_rand(4),
            };
            let iv8 = match iv {
                Some(i) if i.len() == 8 => i.to_vec(),
                _ => crypto_rand(8),
            };
            let nonce = {
                let mut n = salt.clone();
                n.extend_from_slice(&iv8);
                n
            };
            let (ct, tag) = encr.aead_encrypt(sk_e, &nonce, &plaintext, &[])?;
            Ok(EncryptedPayload {
                next_payload: next,
                critical: false,
                iv: iv8,
                ciphertext: ct,
                icv: tag,
            })
        } else {
            let integ = integ.ok_or_else(|| Error::Crypto("CBC needs integrity".into()))?;
            let iv = match iv {
                Some(i) => i.to_vec(),
                None => crypto_rand(encr.cbc_iv_len()),
            };
            let ct = encr.cbc_encrypt(sk_e, &iv, &plaintext)?;
            let icv_len = integ.icv_len();
            // SK header for ICV computation.
            let sk_len = PAYLOAD_HEADER_LEN + iv.len() + ct.len() + icv_len;
            let mut sk_hdr = payload_header(next, false, 0);
            sk_hdr[2..4].copy_from_slice(&(sk_len as u16).to_be_bytes());
            let icv = integ.icv(sk_a, &{
                let mut v = header.encode();
                v.extend_from_slice(&sk_hdr);
                v.extend_from_slice(&iv);
                v.extend_from_slice(&ct);
                v
            });
            Ok(EncryptedPayload {
                next_payload: next,
                critical: false,
                iv,
                ciphertext: ct,
                icv,
            })
        }
    }

    /// Decrypt and decode the inner payloads. `header` is the full IKE header
    /// (as received) used for the CBC integrity checksum.
    pub fn decrypt(
        &self,
        encr: Encr,
        integ: Option<Integ>,
        header: &Header,
        sk_e: &[u8],
        sk_a: &[u8],
        salt: &[u8],
    ) -> Result<Vec<Payload>> {
        let plaintext = if encr.is_aead() {
            let mut nonce = salt.to_vec();
            nonce.extend_from_slice(&self.iv);
            if self.iv.len() != 8 {
                // For the deterministic tests the IV length may differ; allow
                // the caller-supplied salt to define the full 12-byte nonce.
                let _ = &self.iv;
            }
            encr.aead_decrypt(sk_e, &nonce, &self.ciphertext, &self.icv, &[])?
        } else {
            let integ = integ.ok_or_else(|| Error::Crypto("CBC needs integrity".into()))?;
            let sk_len = PAYLOAD_HEADER_LEN + self.iv.len() + self.ciphertext.len() + integ.icv_len();
            let mut sk_hdr = payload_header(self.next_payload, false, 0);
            sk_hdr[2..4].copy_from_slice(&(sk_len as u16).to_be_bytes());
            let mut v = header.encode();
            v.extend_from_slice(&sk_hdr);
            v.extend_from_slice(&self.iv);
            v.extend_from_slice(&self.ciphertext);
            let expected = integ.icv(sk_a, &v);
            if expected.len() != self.icv.len()
                || bool::from(expected.as_slice().ct_eq(self.icv.as_slice())) == false
            {
                return Err(Error::IntegrityCheckFailed);
            }
            encr.cbc_decrypt(sk_e, &self.iv, &self.ciphertext)?
        };
        // Strip IKE padding: last byte is pad length.
        if plaintext.is_empty() {
            return Err(Error::DecryptFailed);
        }
        let pad_len = plaintext[plaintext.len() - 1] as usize;
        if pad_len + 1 > plaintext.len() {
            return Err(Error::DecryptFailed);
        }
        let inner = &plaintext[..plaintext.len() - 1 - pad_len];
        decode_payloads_chain(inner, self.next_payload)
    }

    /// Re-assemble the full SK payload wire bytes (header + iv + ct + icv/tag).
    pub fn to_wire(&self) -> Vec<u8> {
        let icv_len = self.icv.len();
        let sk_len = PAYLOAD_HEADER_LEN + self.iv.len() + self.ciphertext.len() + icv_len;
        let mut out = Vec::with_capacity(sk_len);
        out.extend_from_slice(&payload_header(self.next_payload, self.critical, sk_len));
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.icv);
        out
    }
}

fn crypto_rand(n: usize) -> Vec<u8> {
    crate::crypto::random_bytes(n)
}
