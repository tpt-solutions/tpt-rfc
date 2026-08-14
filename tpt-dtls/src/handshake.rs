// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DTLS 1.3 handshake message types, encoding/decoding, and the DTLS-specific
//! fragmentation/reassembly header (RFC 9147 §5.4 / RFC 8446 §4).
//!
//! Every handshake message is wrapped in a header carrying the total message
//! length, a `message_seq`, and a fragment offset/length so that large
//! messages can be split across multiple datagrams and reassembled by the
//! peer — a feature TLS (over TCP) does not need but DTLS (over UDP) requires.

use crate::error::{DtlsError, Result};
use crate::record::ConnectionId;
use crate::wire::{Reader, Writer};

/// Handshake message types used by this crate (RFC 8446 §4 / RFC 9147).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    /// `client_hello` (1).
    ClientHello,
    /// `server_hello` (2); also used (with a magic `random`) for
    /// HelloRetryRequest.
    ServerHello,
    /// `encrypted_extensions` (8).
    EncryptedExtensions,
    /// `certificate` (11).
    Certificate,
    /// `certificate_verify` (15).
    CertificateVerify,
    /// `finished` (20).
    Finished,
}

impl HandshakeType {
    /// The wire message-type code.
    pub fn code(&self) -> u8 {
        match self {
            HandshakeType::ClientHello => 1,
            HandshakeType::ServerHello => 2,
            HandshakeType::EncryptedExtensions => 8,
            HandshakeType::Certificate => 11,
            HandshakeType::CertificateVerify => 15,
            HandshakeType::Finished => 20,
        }
    }

    /// Parse a message-type code.
    pub fn from_code(c: u8) -> Result<HandshakeType> {
        Ok(match c {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            _ => return Err(DtlsError::UnknownHandshakeType(c)),
        })
    }
}

/// TLS/DTLS extension types referenced by this crate.
pub mod ext {
    /// `supported_versions` (RFC 8446 §4.2.1).
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// `supported_groups` (RFC 8446 §4.2.7).
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    /// `signature_algorithms` (RFC 8446 §4.2.3).
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// `key_share` (RFC 8446 §4.2.8).
    pub const KEY_SHARE: u16 = 0x0033;
    /// `cookie` (RFC 8446 §4.2.2, used by DTLS HRR).
    pub const COOKIE: u16 = 0x002c;
    /// `connection_id` (RFC 9146 §2).
    pub const CONNECTION_ID: u16 = 0x0039;
}

/// Named groups (RFC 8446 §4.2.7).
pub mod group {
    /// `x25519` (29).
    pub const X25519: u16 = 29;
}

/// Signature schemes (RFC 8446 §4.2.3).
pub mod sigscheme {
    /// `ed25519` (0x0807).
    pub const ED25519: u16 = 0x0807;
}

/// The DTLS 1.3 version code carried in `supported_versions` (0xfefc).
pub const DTLS_1_3_VERSION: u16 = 0xfefc;

/// The magic `random` value that distinguishes a HelloRetryRequest
/// ServerHello (RFC 8446 §4.1.3).
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Legacy client/server version field (0xfefd, same as DTLS 1.2).
pub const LEGACY_VERSION: u16 = 0xfefd;

/// A `(group, key_exchange)` entry in a `key_share` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// The named group (e.g. `group::X25519`).
    pub group: u16,
    /// The raw key-exchange bytes (the ephemeral public key).
    pub key_exchange: Vec<u8>,
}

/// `ClientHello` (RFC 8446 §4.1.2).
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Client random (32 bytes).
    pub random: [u8; 32],
    /// Legacy session id (echoed back by the server).
    pub session_id: Vec<u8>,
    /// Offered cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Offered named groups.
    pub groups: Vec<u16>,
    /// Offered signature schemes.
    pub sig_algs: Vec<u16>,
    /// Offered key-share entries.
    pub key_share: Vec<KeyShareEntry>,
    /// Stateless cookie (present only on the second ClientHello).
    pub cookie: Option<Vec<u8>>,
    /// Client's Connection ID offer (RFC 9146).
    pub connection_id: Option<ConnectionId>,
}

/// `ServerHello` (RFC 8446 §4.1.3). A `HelloRetryRequest` is a ServerHello
/// whose `random` equals [`HRR_RANDOM`].
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Server random (or the HRR magic).
    pub random: [u8; 32],
    /// Echo of the client's session id.
    pub session_id_echo: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected key-share entry (server's ephemeral key).
    pub key_share: Option<KeyShareEntry>,
    /// Server's Connection ID for the client to use (RFC 9146).
    pub connection_id: Option<ConnectionId>,
    /// Stateless cookie (present only in a HelloRetryRequest).
    pub cookie: Option<Vec<u8>>,
}

impl ServerHello {
    /// Whether this ServerHello is actually a HelloRetryRequest.
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HRR_RANDOM
    }
}

/// `EncryptedExtensions` (RFC 8446 §4.3.1).
#[derive(Debug, Clone, Default)]
pub struct EncryptedExtensions {
    /// Extension list (left empty by the reference handshake).
    pub extensions: Vec<(u16, Vec<u8>)>,
}

/// `Certificate` (RFC 8446 §4.4.2), using the raw-public-key form
/// (RFC 7250): `cert_data` carries the peer's raw public key directly.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Certificate request context (empty from the server).
    pub request_context: Vec<u8>,
    /// The raw public key bytes.
    pub cert_data: Vec<u8>,
}

/// `CertificateVerify` (RFC 8446 §4.4.3).
#[derive(Debug, Clone)]
pub struct CertificateVerify {
    /// Signature scheme (e.g. `sigscheme::ED25519`).
    pub algorithm: u16,
    /// The signature over the transcript hash.
    pub signature: Vec<u8>,
}

/// `Finished` (RFC 8446 §4.4.4).
#[derive(Debug, Clone)]
pub struct Finished {
    /// The HMAC verify_data (Hash.length bytes).
    pub verify_data: Vec<u8>,
}

/// A complete handshake message with its DTLS framing metadata.
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    /// The message type.
    pub msg_type: HandshakeType,
    /// The DTLS `message_seq` (monotonically assigned per direction).
    pub message_seq: u16,
    /// The typed body.
    pub body: HandshakeBody,
}

/// The typed body of a handshake message.
#[derive(Debug, Clone)]
pub enum HandshakeBody {
    /// A ClientHello.
    ClientHello(ClientHello),
    /// A ServerHello (or HelloRetryRequest).
    ServerHello(ServerHello),
    /// EncryptedExtensions.
    EncryptedExtensions(EncryptedExtensions),
    /// A Certificate (raw-public-key form).
    Certificate(Certificate),
    /// A CertificateVerify.
    CertificateVerify(CertificateVerify),
    /// A Finished.
    Finished(Finished),
}

impl HandshakeBody {
    /// The message type of this body.
    pub fn msg_type(&self) -> HandshakeType {
        match self {
            HandshakeBody::ClientHello(_) => HandshakeType::ClientHello,
            HandshakeBody::ServerHello(_) => HandshakeType::ServerHello,
            HandshakeBody::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            HandshakeBody::Certificate(_) => HandshakeType::Certificate,
            HandshakeBody::CertificateVerify(_) => HandshakeType::CertificateVerify,
            HandshakeBody::Finished(_) => HandshakeType::Finished,
        }
    }

    /// Serialize the body (without the handshake header).
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            HandshakeBody::ClientHello(c) => c.encode(&mut w),
            HandshakeBody::ServerHello(s) => s.encode(&mut w),
            HandshakeBody::EncryptedExtensions(e) => e.encode(&mut w),
            HandshakeBody::Certificate(c) => c.encode(&mut w),
            HandshakeBody::CertificateVerify(c) => c.encode(&mut w),
            HandshakeBody::Finished(f) => {
                w.put_bytes(&f.verify_data);
            }
        };
        w.into_inner()
    }
}

impl HandshakeMessage {
    /// Build a message from a body and an assigned `message_seq`.
    pub fn new(body: HandshakeBody, message_seq: u16) -> Self {
        let msg_type = body.msg_type();
        Self {
            msg_type,
            message_seq,
            body,
        }
    }

    /// Serialize the full handshake message (header + body), unfragmented.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body.body_bytes();
        let total = body.len() as u32;
        let mut w = Writer::new();
        w.put_u8(self.msg_type.code())
            .put_u24(total)
            .put_u16(self.message_seq)
            .put_u24(0) // fragment_offset
            .put_u24(total) // fragment_length
            .put_bytes(&body);
        w.into_inner()
    }

    /// Parse a full (single-fragment) handshake message.
    pub fn decode(buf: &[u8]) -> Result<HandshakeMessage> {
        let mut r = Reader::new(buf);
        let msg_type = HandshakeType::from_code(r.read_u8()?)?;
        let _length = r.read_u24()?;
        let message_seq = r.read_u16()?;
        let frag_offset = r.read_u24()?;
        let frag_length = r.read_u24()?;
        let body = r.read_bytes(frag_length as usize)?;
        if frag_offset != 0 || frag_length as usize != body.len() {
            return Err(DtlsError::FragmentOutOfRange {
                offset: frag_offset,
                len: frag_length,
                total: body.len() as u32,
            });
        }
        let body = HandshakeBody::parse(msg_type, body)?;
        Ok(HandshakeMessage {
            msg_type,
            message_seq,
            body,
        })
    }
}

impl HandshakeBody {
    /// Parse a body of `msg_type` from `bytes` (the fragment payload).
    pub fn parse(msg_type: HandshakeType, bytes: &[u8]) -> Result<HandshakeBody> {
        let mut r = Reader::new(bytes);
        Ok(match msg_type {
            HandshakeType::ClientHello => {
                HandshakeBody::ClientHello(ClientHello::parse(&mut r)?)
            }
            HandshakeType::ServerHello => {
                HandshakeBody::ServerHello(ServerHello::parse(&mut r)?)
            }
            HandshakeType::EncryptedExtensions => {
                HandshakeBody::EncryptedExtensions(EncryptedExtensions::parse(&mut r)?)
            }
            HandshakeType::Certificate => HandshakeBody::Certificate(Certificate::parse(&mut r)?),
            HandshakeType::CertificateVerify => {
                HandshakeBody::CertificateVerify(CertificateVerify::parse(&mut r)?)
            }
            HandshakeType::Finished => {
                HandshakeBody::Finished(Finished {
                    verify_data: bytes.to_vec(),
                })
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Body encoders/decoders
// ---------------------------------------------------------------------------

fn put_extensions(w: &mut Writer, exts: &[(u16, Vec<u8>)]) {
    let mut ew = Writer::new();
    for (ty, data) in exts {
        ew.put_u16(*ty).put_vec_u16(data);
    }
    w.put_vec_u16(&ew.into_inner());
}

fn read_extensions(r: &mut Reader) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut out = Vec::new();
    let list = r.read_vec_u16()?;
    let mut er = Reader::new(list);
    while !er.eof() {
        let ty = er.read_u16()?;
        let data = er.read_vec_u16()?;
        out.push((ty, data.to_vec()));
    }
    Ok(out)
}

fn find_ext<'a>(exts: &'a [(u16, Vec<u8>)], ty: u16) -> Option<&'a [u8]> {
    exts.iter().find(|(t, _)| *t == ty).map(|(_, d)| d.as_slice())
}

impl ClientHello {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(LEGACY_VERSION)
            .put_bytes(&self.random)
            .put_vec_u8(&self.session_id);
        let mut cs = Writer::new();
        for c in &self.cipher_suites {
            cs.put_u16(*c);
        }
        w.put_vec_u16(&cs.into_inner());
        w.put_vec_u8(&[0x00]); // legacy_compression_methods = { null }

        let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();

        // supported_versions: u16-length list of u16 versions.
        let mut sv = Writer::new();
        sv.put_vec_u16(&DTLS_1_3_VERSION.to_be_bytes());
        exts.push((ext::SUPPORTED_VERSIONS, sv.into_inner()));

        // supported_groups: u16-length list.
        let mut sg = Writer::new();
        for g in &self.groups {
            sg.put_u16(*g);
        }
        exts.push((ext::SUPPORTED_GROUPS, sg.into_inner()));

        // signature_algorithms: u16-length list.
        let mut sa = Writer::new();
        for s in &self.sig_algs {
            sa.put_u16(*s);
        }
        exts.push((ext::SIGNATURE_ALGORITHMS, sa.into_inner()));

        // key_share: u16-length list of entries.
        let mut ks = Writer::new();
        for e in &self.key_share {
            ks.put_u16(e.group).put_vec_u16(&e.key_exchange);
        }
        exts.push((ext::KEY_SHARE, ks.into_inner()));

        if let Some(cookie) = &self.cookie {
            exts.push((ext::COOKIE, cookie.clone()));
        }
        if let Some(cid) = &self.connection_id {
            exts.push((ext::CONNECTION_ID, cid.0.clone()));
        }

        put_extensions(w, &exts);
    }

    fn parse(r: &mut Reader) -> Result<ClientHello> {
        let _version = r.read_u16()?;
        let mut random = [0u8; 32];
        random.copy_from_slice(r.read_bytes(32)?);
        let session_id = r.read_vec_u8()?.to_vec();
        let _cs = r.read_vec_u16()?;
        let _comp = r.read_vec_u8()?;
        let exts = read_extensions(r)?;

        let groups = find_ext(&exts, ext::SUPPORTED_GROUPS)
            .map(parse_u16_list)
            .transpose()?
            .unwrap_or_default();
        let sig_algs = find_ext(&exts, ext::SIGNATURE_ALGORITHMS)
            .map(parse_u16_list)
            .transpose()?
            .unwrap_or_default();
        let key_share = match find_ext(&exts, ext::KEY_SHARE) {
            Some(ks) => {
                let mut kr = Reader::new(ks);
                let mut out = Vec::new();
                let list = kr.read_vec_u16()?;
                let mut lr = Reader::new(list);
                while !lr.eof() {
                    let group = lr.read_u16()?;
                    let key_exchange = lr.read_vec_u16()?.to_vec();
                    out.push(KeyShareEntry { group, key_exchange });
                }
                out
            }
            None => Vec::new(),
        };
        let cookie = find_ext(&exts, ext::COOKIE).map(|c| c.to_vec());
        let connection_id = find_ext(&exts, ext::CONNECTION_ID)
            .map(|c| ConnectionId::new(c.to_vec()))
            .transpose()?;

        Ok(ClientHello {
            random,
            session_id,
            cipher_suites: vec![crate::crypto::CipherSuite::TlsAes128GcmSha256.code()],
            groups,
            sig_algs,
            key_share,
            cookie,
            connection_id,
        })
    }
}

impl ServerHello {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(LEGACY_VERSION)
            .put_bytes(&self.random)
            .put_vec_u8(&self.session_id_echo);
        w.put_u16(self.cipher_suite).put_u8(0x00); // compression = null

        let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
        // supported_versions: single u16.
        exts.push((ext::SUPPORTED_VERSIONS, DTLS_1_3_VERSION.to_be_bytes().to_vec()));
        if let Some(ks) = &self.key_share {
            let mut e = Writer::new();
            e.put_u16(ks.group).put_vec_u16(&ks.key_exchange);
            // ServerHello key_share has NO outer length prefix.
            exts.push((ext::KEY_SHARE, e.into_inner()));
        }
        if let Some(cid) = &self.connection_id {
            exts.push((ext::CONNECTION_ID, cid.0.clone()));
        }
        if let Some(cookie) = &self.cookie {
            exts.push((ext::COOKIE, cookie.clone()));
        }
        put_extensions(w, &exts);
    }

    fn parse(r: &mut Reader) -> Result<ServerHello> {
        let _version = r.read_u16()?;
        let mut random = [0u8; 32];
        random.copy_from_slice(r.read_bytes(32)?);
        let session_id_echo = r.read_vec_u8()?.to_vec();
        let cipher_suite = r.read_u16()?;
        let _comp = r.read_u8()?;
        let exts = read_extensions(r)?;

        let key_share = match find_ext(&exts, ext::KEY_SHARE) {
            Some(ks) => {
                let mut kr = Reader::new(ks);
                let group = kr.read_u16()?;
                let key_exchange = kr.read_vec_u16()?.to_vec();
                Some(KeyShareEntry { group, key_exchange })
            }
            None => None,
        };
        let connection_id = find_ext(&exts, ext::CONNECTION_ID)
            .map(|c| ConnectionId::new(c.to_vec()))
            .transpose()?;
        let cookie = find_ext(&exts, ext::COOKIE).map(|c| c.to_vec());

        Ok(ServerHello {
            random,
            session_id_echo,
            cipher_suite,
            key_share,
            connection_id,
            cookie,
        })
    }
}

impl EncryptedExtensions {
    fn encode(&self, w: &mut Writer) {
        put_extensions(w, &self.extensions);
    }
    fn parse(r: &mut Reader) -> Result<EncryptedExtensions> {
        let extensions = read_extensions(r)?;
        Ok(EncryptedExtensions { extensions })
    }
}

impl Certificate {
    fn encode(&self, w: &mut Writer) {
        w.put_vec_u8(&self.request_context);
        let mut entry = Writer::new();
        entry.put_vec_u24(&self.cert_data);
        entry.put_vec_u16(&[]); // entry extensions (none)
        w.put_vec_u24(&entry.into_inner());
    }
    fn parse(r: &mut Reader) -> Result<Certificate> {
        let request_context = r.read_vec_u8()?.to_vec();
        let list = r.read_vec_u24()?;
        let mut lr = Reader::new(list);
        let cert_data = lr.read_vec_u24()?.to_vec();
        Ok(Certificate {
            request_context,
            cert_data,
        })
    }
}

impl CertificateVerify {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(self.algorithm).put_vec_u16(&self.signature);
    }
    fn parse(r: &mut Reader) -> Result<CertificateVerify> {
        let algorithm = r.read_u16()?;
        let signature = r.read_vec_u16()?.to_vec();
        Ok(CertificateVerify { algorithm, signature })
    }
}

fn parse_u16_list(r: &[u8]) -> Result<Vec<u16>> {
    let mut rr = Reader::new(r);
    let list = rr.read_vec_u16()?;
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while !lr.eof() {
        out.push(lr.read_u16()?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// DTLS fragmentation / reassembly
// ---------------------------------------------------------------------------

/// Split a full handshake message into DTLS fragments no larger than
/// `max_fragment` bytes (RFC 9147 §5.4). Each returned buffer is a complete
/// handshake record (header + one fragment) ready to be placed in a record.
pub fn fragment_message(full: &[u8], seq: u16, max_fragment: usize) -> Vec<Vec<u8>> {
    let total = full.len() as u32;
    let mut out = Vec::new();
    if total == 0 {
        let mut w = Writer::new();
        w.put_u8(HandshakeType::ClientHello.code())
            .put_u24(0)
            .put_u16(seq)
            .put_u24(0)
            .put_u24(0);
        out.push(w.into_inner());
        return out;
    }
    let mut offset = 0u32;
    while offset < total {
        let take = (total - offset).min(max_fragment as u32);
        let msg_type = full[0]; // first byte is the message type
        let mut w = Writer::new();
        w.put_u8(msg_type)
            .put_u24(total)
            .put_u16(seq)
            .put_u24(offset)
            .put_u24(take);
        w.put_bytes(&full[offset as usize..(offset + take) as usize]);
        out.push(w.into_inner());
        offset += take;
    }
    out
}

/// Reassembles DTLS handshake message fragments keyed by `message_seq`.
#[derive(Debug)]
pub struct Reassembler {
    seq: u16,
    total: u32,
    buffer: Vec<u8>,
    filled: Vec<bool>,
}

impl Reassembler {
    /// Begin reassembling the message identified by `seq` with total length
    /// `total`.
    pub fn new(seq: u16, total: u32) -> Self {
        Self {
            seq,
            total,
            buffer: vec![0u8; total as usize],
            filled: vec![false; total as usize],
        }
    }

    /// True once the message is fully reassembled.
    pub fn complete(&self) -> bool {
        self.filled.iter().all(|b| *b)
    }

    /// Add one fragment (header fields already parsed). Returns `Some(full)`
    /// when reassembly completes.
    pub fn add(&mut self, offset: u32, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let end = offset as usize + data.len();
        if end > self.buffer.len()
            || data.len() as u32 > self.total.saturating_sub(offset)
        {
            return Err(DtlsError::FragmentOutOfRange {
                offset,
                len: data.len() as u32,
                total: self.total,
            });
        }
        self.buffer[offset as usize..end].copy_from_slice(data);
        for b in &mut self.filled[offset as usize..end] {
            *b = true;
        }
        if self.complete() {
            Ok(Some(self.buffer.clone()))
        } else {
            Ok(None)
        }
    }
}
