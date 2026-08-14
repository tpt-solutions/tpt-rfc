// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The BGP-4 message codec: the 19-byte common header, the four message types
//! (OPEN, UPDATE, NOTIFICATION, KEEPALIVE), optional capabilities (RFC 5492),
//! the four-octet ASN capability (RFC 6793), and multiprotocol NLRI (RFC 4760).

use crate::attributes::{
    decode_prefix, encode_prefix_bits, Asn, Ipv4Prefix, PathAttribute, AS_TRANS,
};
use crate::error::{DecodeError, Result};

/// The BGP marker: 16 octets of `0xFF`. Used in the message header when no
/// authentication is in effect (OPEN, KEEPALIVE, and unauthenticated
/// UPDATE/NOTIFICATION).
pub const BGP_MARKER: [u8; 16] = [0xFF; 16];

/// The fixed BGP header length (marker + length + type).
pub const BGP_HEADER_LEN: usize = 19;

/// BGP message type codes.
pub mod msg_type {
    /// OPEN message.
    pub const OPEN: u8 = 1;
    /// UPDATE message.
    pub const UPDATE: u8 = 2;
    /// NOTIFICATION message.
    pub const NOTIFICATION: u8 = 3;
    /// KEEPALIVE message.
    pub const KEEPALIVE: u8 = 4;
}

/// BGP NOTIFICATION error codes (RFC 4271 §4.5).
pub mod err_code {
    /// Message header error.
    pub const HEADER: u8 = 1;
    /// OPEN message error.
    pub const OPEN: u8 = 2;
    /// UPDATE message error.
    pub const UPDATE: u8 = 3;
    /// Hold timer expired.
    pub const HOLD_TIMER_EXPIRED: u8 = 4;
    /// Finite state machine error.
    pub const FSM_ERROR: u8 = 5;
    /// Cease.
    pub const CEASE: u8 = 6;
}

/// OPEN message error subcodes (RFC 4271 §4.5).
pub mod open_subcode {
    /// Unsupported version number.
    pub const UNSUPPORTED_VERSION: u8 = 1;
    /// Bad peer AS.
    pub const BAD_PEER_AS: u8 = 2;
    /// Bad BGP identifier.
    pub const BAD_BGP_IDENTIFIER: u8 = 3;
    /// Unsupported optional parameter.
    pub const UNSUPPORTED_PARAMETER: u8 = 4;
    /// Deprecated (5).
    /// Unacceptable hold time.
    pub const UNACCEPTABLE_HOLD_TIME: u8 = 6;
    /// Unsupported capability (RFC 5492).
    pub const UNSUPPORTED_CAPABILITY: u8 = 7;
}

/// UPDATE message error subcodes (RFC 4271 §4.5).
pub mod update_subcode {
    /// Malformed attribute list.
    pub const MALFORMED_ATTR_LIST: u8 = 1;
    /// Unrecognized well-known attribute.
    pub const UNRECOGNIZED_WELL_KNOWN_ATTR: u8 = 2;
    /// Missing well-known attribute.
    pub const MISSING_WELL_KNOWN_ATTR: u8 = 3;
    /// Attribute flags error.
    pub const ATTR_FLAGS_ERROR: u8 = 4;
    /// Attribute length error.
    pub const ATTR_LENGTH_ERROR: u8 = 5;
    /// Invalid ORIGIN attribute.
    pub const INVALID_ORIGIN: u8 = 6;
    /// Deprecated (7).
    /// Invalid NEXT_HOP attribute.
    pub const INVALID_NEXT_HOP: u8 = 8;
    /// Optional attribute error.
    pub const OPTIONAL_ATTR_ERROR: u8 = 9;
    /// Invalid network field.
    pub const INVALID_NETWORK: u8 = 10;
    /// Malformed AS_PATH.
    pub const MALFORMED_AS_PATH: u8 = 11;
}

/// A BGP optional capability (RFC 5492), carried in the OPEN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Multiprotocol extension (RFC 4760), capability code 1.
    MultiProtocol {
        /// Address Family Identifier (e.g. 1 = IPv4, 2 = IPv6).
        afi: u16,
        /// Subsequent Address Family Identifier (e.g. 1 = unicast).
        safi: u8,
    },
    /// Four-octet ASN (RFC 6793), capability code 65.
    As4(Asn),
    /// An unrecognised capability, preserved verbatim.
    Unknown {
        /// Capability code.
        code: u8,
        /// Capability value bytes.
        value: Vec<u8>,
    },
}

impl Capability {
    /// The capability code byte.
    pub fn code(&self) -> u8 {
        match self {
            Capability::MultiProtocol { .. } => 1,
            Capability::As4(_) => 65,
            Capability::Unknown { code, .. } => *code,
        }
    }
}

/// An OPEN message (RFC 4271 §4.2). `my_asn` is the real (four-octet capable)
/// local ASN; the codec maps it to the two-octet OPEN field (using `AS_TRANS`
/// when needed) transparently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    /// BGP protocol version (always 4 in this implementation).
    pub version: u8,
    /// The real local Autonomous System Number.
    pub my_asn: Asn,
    /// Proposed hold time, in seconds.
    pub hold_time: u16,
    /// The local BGP identifier (typically an IPv4 address).
    pub bgp_id: [u8; 4],
    /// Optional capabilities advertised by the sender.
    pub capabilities: Vec<Capability>,
}

impl OpenMessage {
    /// Encode the OPEN message to its on-the-wire byte form (four-octet ASNs
    /// enabled by default).
    pub fn to_bytes(&self) -> Vec<u8> {
        Message::Open(self.clone()).to_bytes()
    }
}

/// An UPDATE message (RFC 4271 §4.3). The top-level `withdrawn_routes` and
/// `nlri` fields carry the legacy IPv4 unicast reachability; multiprotocol
/// routes are carried inside the path attributes
/// ([`PathAttribute::MpReachNlri`] / [`PathAttribute::MpUnreachNlri`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Update {
    /// Withdrawn IPv4 unicast routes (top-level).
    pub withdrawn_routes: Vec<Ipv4Prefix>,
    /// Path attributes.
    pub path_attributes: Vec<PathAttribute>,
    /// Advertised IPv4 unicast routes (top-level).
    pub nlri: Vec<Ipv4Prefix>,
}

impl Update {
    /// Encode the UPDATE message to its on-the-wire byte form (four-octet ASNs
    /// enabled by default).
    pub fn to_bytes(&self) -> Vec<u8> {
        Message::Update(self.clone()).to_bytes()
    }

    /// Encode the UPDATE message with explicit codec options.
    pub fn encode(&self, opts: CodecOptions) -> Vec<u8> {
        Message::Update(self.clone()).encode(opts)
    }
}

/// A NOTIFICATION message (RFC 4271 §4.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Notification {
    /// Major error code (see [`err_code`]).
    pub code: u8,
    /// Minor error subcode.
    pub subcode: u8,
    /// Trailing diagnostic data.
    pub data: Vec<u8>,
}

impl Notification {
    /// Build a NOTIFICATION from its code/subcode/data.
    pub fn new(code: u8, subcode: u8, data: Vec<u8>) -> Notification {
        Notification {
            code,
            subcode,
            data,
        }
    }

    /// A "Cease" notification with no data.
    pub fn cease() -> Notification {
        Notification::new(err_code::CEASE, 0, Vec::new())
    }

    /// A header-error notification.
    pub fn header_error(subcode: u8, data: Vec<u8>) -> Notification {
        Notification::new(err_code::HEADER, subcode, data)
    }

    /// An OPEN-error notification.
    pub fn open_error(subcode: u8, data: Vec<u8>) -> Notification {
        Notification::new(err_code::OPEN, subcode, data)
    }

    /// An UPDATE-error notification.
    pub fn update_error(subcode: u8, data: Vec<u8>) -> Notification {
        Notification::new(err_code::UPDATE, subcode, data)
    }
}

/// A complete BGP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// An OPEN message.
    Open(OpenMessage),
    /// An UPDATE message.
    Update(Update),
    /// A NOTIFICATION message.
    Notification(Notification),
    /// A KEEPALIVE message.
    Keepalive,
}

/// Options controlling message encode/decode.
#[derive(Debug, Clone, Copy)]
pub struct CodecOptions {
    /// Whether four-octet ASNs (RFC 6793) are in use for this session. Drives
    /// AS_PATH / AGGREGATOR width and OPEN capability handling.
    pub as4: bool,
}

impl Default for CodecOptions {
    fn default() -> Self {
        CodecOptions { as4: true }
    }
}

impl Message {
    /// Encode the message to its on-the-wire byte form, with four-octet ASNs
    /// enabled by default.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode(CodecOptions::default())
    }

    /// Encode the message with explicit codec options.
    pub fn encode(&self, opts: CodecOptions) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Message::Open(o) => encode_open(o, &mut body, opts.as4),
            Message::Update(u) => encode_update(u, &mut body, opts.as4),
            Message::Notification(n) => {
                body.push(n.code);
                body.push(n.subcode);
                body.extend_from_slice(&n.data);
            }
            Message::Keepalive => {}
        }
        let total = (BGP_HEADER_LEN + body.len()) as u16;
        let mut buf = Vec::with_capacity(BGP_HEADER_LEN + body.len());
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(match self {
            Message::Open(_) => msg_type::OPEN,
            Message::Update(_) => msg_type::UPDATE,
            Message::Notification(_) => msg_type::NOTIFICATION,
            Message::Keepalive => msg_type::KEEPALIVE,
        });
        buf.extend_from_slice(&body);
        buf
    }

    /// Decode a message from wire bytes, with four-octet ASNs enabled by
    /// default.
    pub fn from_bytes(bytes: &[u8]) -> Result<Message> {
        Message::decode(bytes, CodecOptions::default())
    }

    /// Decode a message with explicit codec options.
    pub fn decode(bytes: &[u8], opts: CodecOptions) -> Result<Message> {
        if bytes.len() < BGP_HEADER_LEN {
            return Err(DecodeError::TruncatedHeader {
                actual: bytes.len(),
            });
        }
        let declared = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        if declared < BGP_HEADER_LEN || declared != bytes.len() {
            return Err(DecodeError::LengthMismatch {
                declared,
                actual: bytes.len(),
            });
        }
        let type_byte = bytes[18];
        let body = &bytes[BGP_HEADER_LEN..];
        let msg = match type_byte {
            msg_type::OPEN => Message::Open(decode_open(body, opts.as4)?),
            msg_type::UPDATE => Message::Update(decode_update(body, opts.as4)?),
            msg_type::NOTIFICATION => {
                let mut r = Reader::new(body);
                let code = r.u8()?;
                let subcode = r.u8()?;
                let data = r.take(r.remaining())?;
                Message::Notification(Notification {
                    code,
                    subcode,
                    data,
                })
            }
            msg_type::KEEPALIVE => Message::Keepalive,
            other => return Err(DecodeError::UnknownMessageType(other)),
        };
        Ok(msg)
    }
}

// --- OPEN ---------------------------------------------------------------

fn encode_open(o: &OpenMessage, buf: &mut Vec<u8>, as4: bool) {
    buf.push(o.version);
    let wants_as4 = as4
        || o.capabilities
            .iter()
            .any(|c| matches!(c, Capability::As4(_)));
    let two_byte_as = if o.my_asn.fits_16bit() && !wants_as4 {
        o.my_asn.to_16bit()
    } else {
        AS_TRANS as u16
    };
    buf.extend_from_slice(&two_byte_as.to_be_bytes());
    buf.extend_from_slice(&o.hold_time.to_be_bytes());
    buf.extend_from_slice(&o.bgp_id);

    let mut caps = Vec::new();
    // Ensure the ASN4 capability reflects the real ASN when four-octet ASNs are
    // in use.
    if wants_as4 {
        let mut found = false;
        for c in &o.capabilities {
            if let Capability::As4(a) = c {
                found = true;
                encode_capability(&Capability::As4(*a), &mut caps);
            } else {
                encode_capability(c, &mut caps);
            }
        }
        if !found {
            encode_capability(&Capability::As4(o.my_asn), &mut caps);
        }
    } else {
        for c in &o.capabilities {
            encode_capability(c, &mut caps);
        }
    }
    buf.push(caps.len() as u8);
    buf.extend_from_slice(&caps);
}

fn encode_capability(c: &Capability, buf: &mut Vec<u8>) {
    match c {
        Capability::MultiProtocol { afi, safi } => {
            buf.push(1);
            buf.push(4);
            buf.extend_from_slice(&afi.to_be_bytes());
            buf.push(0); // reserved
            buf.push(*safi);
        }
        Capability::As4(a) => {
            buf.push(65);
            buf.push(4);
            buf.extend_from_slice(&a.0.to_be_bytes());
        }
        Capability::Unknown { code, value } => {
            buf.push(*code);
            buf.push(value.len() as u8);
            buf.extend_from_slice(value);
        }
    }
}

fn decode_open(body: &[u8], as4: bool) -> Result<OpenMessage> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    if version != 4 {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let two_byte_as = r.u16()?;
    let hold_time = r.u16()?;
    let mut bgp_id = [0u8; 4];
    bgp_id.copy_from_slice(&r.take(4)?);
    let param_len = r.u8()? as usize;
    let params = r.take(param_len)?;

    let mut capabilities = Vec::new();
    let mut rp = Reader::new(&params);
    while rp.remaining() > 0 {
        let code = rp.u8()?;
        let len = rp.u8()? as usize;
        let value = rp.take(len)?;
        match code {
            1 => {
                if value.len() < 4 {
                    return Err(DecodeError::MalformedCapability {
                        code,
                        len: len as u8,
                    });
                }
                let afi = u16::from_be_bytes([value[0], value[1]]);
                let safi = value[3];
                capabilities.push(Capability::MultiProtocol { afi, safi });
            }
            65 => {
                if value.len() < 4 {
                    return Err(DecodeError::MalformedCapability {
                        code,
                        len: len as u8,
                    });
                }
                let asn = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                capabilities.push(Capability::As4(Asn(asn)));
            }
            _ => capabilities.push(Capability::Unknown { code, value }),
        }
    }

    let (my_asn, as4_present) = {
        let as4_cap = capabilities.iter().find_map(|c| match c {
            Capability::As4(a) => Some(*a),
            _ => None,
        });
        match as4_cap {
            Some(a) => (a, true),
            None => (Asn(u32::from(two_byte_as)), false),
        }
    };
    // When `as4` is false (legacy session) but the peer sent AS_TRANS, we can
    // only recover the low 16 bits; surface that by keeping the two-byte field.
    let _ = (as4, as4_present);
    Ok(OpenMessage {
        version,
        my_asn,
        hold_time,
        bgp_id,
        capabilities,
    })
}

// --- UPDATE -------------------------------------------------------------

fn encode_update(u: &Update, buf: &mut Vec<u8>, as4: bool) {
    let mut withdrawn = Vec::new();
    for p in &u.withdrawn_routes {
        encode_prefix_bits(&mut withdrawn, p.addr.to_vec(), p.len);
    }
    buf.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    buf.extend_from_slice(&withdrawn);

    let mut attrs = Vec::new();
    for a in &u.path_attributes {
        a.encode(&mut attrs, as4);
    }
    buf.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    buf.extend_from_slice(&attrs);

    let mut nlri = Vec::new();
    for p in &u.nlri {
        encode_prefix_bits(&mut nlri, p.addr.to_vec(), p.len);
    }
    buf.extend_from_slice(&nlri);
}

fn decode_update(body: &[u8], as4: bool) -> Result<Update> {
    let mut r = Reader::new(body);

    let wlen = r.u16()? as usize;
    let withdrawn_bytes = r.take(wlen)?;
    let mut wr = Reader::new(&withdrawn_bytes);
    let mut withdrawn_routes = Vec::new();
    while wr.remaining() > 0 {
        withdrawn_routes.push(match decode_prefix(&mut wr, 4)? {
            crate::attributes::Prefix::V4(p) => p,
            crate::attributes::Prefix::V6(_) => unreachable!(),
        });
    }

    let alen = r.u16()? as usize;
    let attr_bytes = r.take(alen)?;
    let mut ar = Reader::new(&attr_bytes);
    let mut path_attributes = Vec::new();
    while ar.remaining() > 0 {
        path_attributes.push(PathAttribute::decode(&mut ar, as4)?);
    }

    let mut nlri_routes = Vec::new();
    while r.remaining() > 0 {
        nlri_routes.push(match decode_prefix(&mut r, 4)? {
            crate::attributes::Prefix::V4(p) => p,
            crate::attributes::Prefix::V6(_) => unreachable!(),
        });
    }

    Ok(Update {
        withdrawn_routes,
        path_attributes,
        nlri: nlri_routes,
    })
}

// --- Reader -------------------------------------------------------------

/// A bounds-checked big-endian reader over a byte slice.
pub struct Reader<'a> {
    d: &'a [u8],
    /// Current read offset.
    pub off: usize,
    /// Total buffer length (for diagnostics).
    pub len: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader over `d`.
    pub fn new(d: &'a [u8]) -> Self {
        Self {
            d,
            off: 0,
            len: d.len(),
        }
    }

    /// Bytes remaining to be read.
    pub fn remaining(&self) -> usize {
        self.d.len().saturating_sub(self.off)
    }

    /// Read a single byte.
    pub fn u8(&mut self) -> Result<u8> {
        let v = *self.d.get(self.off).ok_or(DecodeError::TruncatedField {
            needed: 1,
            offset: self.off,
            len: self.len,
        })?;
        self.off += 1;
        Ok(v)
    }

    /// Read a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(DecodeError::TruncatedField {
                needed: 2,
                offset: self.off,
                len: self.len,
            });
        }
        let v = u16::from_be_bytes([self.d[self.off], self.d[self.off + 1]]);
        self.off += 2;
        Ok(v)
    }

    /// Read a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(DecodeError::TruncatedField {
                needed: 4,
                offset: self.off,
                len: self.len,
            });
        }
        let v = u32::from_be_bytes([
            self.d[self.off],
            self.d[self.off + 1],
            self.d[self.off + 2],
            self.d[self.off + 3],
        ]);
        self.off += 4;
        Ok(v)
    }

    /// Take (and consume) the next `n` bytes as a fresh `Vec<u8>`.
    pub fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.remaining() < n {
            return Err(DecodeError::TruncatedField {
                needed: n,
                offset: self.off,
                len: self.len,
            });
        }
        let out = self.d[self.off..self.off + n].to_vec();
        self.off += n;
        Ok(out)
    }
}
