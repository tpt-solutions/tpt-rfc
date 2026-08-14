// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OSPF packet codec: the common packet header plus all five packet types
//! — Hello, Database Description, Link State Request, Link State Update, and
//! Link State Acknowledgement — for both OSPFv2 (RFC 2328 §A.3) and OSPFv3
//! (RFC 5340 §A.3), including the standard 16-bit Internet checksum.

use crate::error::{DecodeError, Result};
use crate::lsa::{Ip4, Lsa, LsaHeader};

/// OSPF version identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfVersion {
    /// OSPFv2 (RFC 2328).
    V2,
    /// OSPFv3 (RFC 5340).
    V3,
}

impl OspfVersion {
    /// Map a wire version byte to an [`OspfVersion`].
    pub fn from_u8(v: u8) -> Option<OspfVersion> {
        match v {
            2 => Some(OspfVersion::V2),
            3 => Some(OspfVersion::V3),
            _ => None,
        }
    }

    /// The wire version byte.
    pub fn to_u8(self) -> u8 {
        match self {
            OspfVersion::V2 => 2,
            OspfVersion::V3 => 3,
        }
    }

    /// The fixed OSPF header length for this version (24 bytes for v2 with the
    /// authentication field, 16 bytes for v3).
    pub fn header_len(self) -> usize {
        match self {
            OspfVersion::V2 => 24,
            OspfVersion::V3 => 16,
        }
    }
}

/// OSPF packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Hello (type 1).
    Hello,
    /// Database Description (type 2).
    Dbd,
    /// Link State Request (type 3).
    Lsr,
    /// Link State Update (type 4).
    Lsu,
    /// Link State Acknowledgement (type 5).
    LsAck,
}

impl PacketType {
    /// Map a wire type byte to a [`PacketType`].
    pub fn from_u8(v: u8) -> Option<PacketType> {
        match v {
            1 => Some(PacketType::Hello),
            2 => Some(PacketType::Dbd),
            3 => Some(PacketType::Lsr),
            4 => Some(PacketType::Lsu),
            5 => Some(PacketType::LsAck),
            _ => None,
        }
    }

    /// The wire type byte.
    pub fn to_u8(self) -> u8 {
        match self {
            PacketType::Hello => 1,
            PacketType::Dbd => 2,
            PacketType::Lsr => 3,
            PacketType::Lsu => 4,
            PacketType::LsAck => 5,
        }
    }
}

/// Authentication type for OSPFv2 packets (the `AuType` field).
pub const AUTH_NULL: u16 = 0;
/// Simple-password (cleartext) authentication.
pub const AUTH_SIMPLE: u16 = 1;
/// Cryptographic authentication.
pub const AUTH_CRYPTO: u16 = 2;

/// A Hello packet body (§A.3.2 / §A.3.2 for v3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPacket {
    /// Network mask (OSPFv2 only; OSPFv3 derives prefixes from the interface).
    pub network_mask: Ip4,
    /// Interface Id (OSPFv3 only).
    pub interface_id: u32,
    /// Hello interval, in seconds.
    pub hello_interval: u16,
    /// Options byte (v3 uses the low byte of its 24-bit options field).
    pub options: u8,
    /// Router priority (used in DR/BDR election).
    pub router_priority: u8,
    /// Router Dead interval, in seconds.
    pub router_dead_interval: u32,
    /// Designated Router.
    pub designated_router: Ip4,
    /// Backup Designated Router.
    pub backup_designated_router: Ip4,
    /// Router Ids of neighbors seen on the link.
    pub neighbors: Vec<Ip4>,
}

/// A single Link State Request (§A.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStateRequest {
    /// The LSA type requested.
    pub lsa_type: u16,
    /// The Link State Id of the LSA requested.
    pub link_state_id: Ip4,
    /// The Advertising Router of the LSA requested.
    pub advertising_router: Ip4,
}

/// A Database Description packet (§A.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbdPacket {
    /// Interface MTU.
    pub interface_mtu: u16,
    /// Options byte (low byte of the v3 24-bit options field).
    pub options: u8,
    /// Init bit — first DBD in the exchange.
    pub init: bool,
    /// More bit — more DBD packets follow.
    pub more: bool,
    /// Master/Slave bit — set if the sender is the master.
    pub master: bool,
    /// DD sequence number.
    pub dd_sequence: u32,
    /// The LSA headers summarised in this DBD.
    pub lsas: Vec<LsaHeader>,
}

/// A Link State Update packet (§A.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsuPacket {
    /// The full LSAs carried in this update.
    pub lsas: Vec<Lsa>,
}

/// A Link State Acknowledgement packet (§A.3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsAckPacket {
    /// The LSA headers being acknowledged.
    pub lsas: Vec<LsaHeader>,
}

/// The decoded body of an OSPF packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBody {
    /// A Hello packet.
    Hello(HelloPacket),
    /// A Database Description packet.
    Dbd(DbdPacket),
    /// A Link State Request packet.
    Lsr(Vec<LinkStateRequest>),
    /// A Link State Update packet.
    Lsu(LsuPacket),
    /// A Link State Acknowledgement packet.
    LsAck(LsAckPacket),
}

/// A complete OSPF packet (header + body) for either version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfPacket {
    /// OSPF version.
    pub version: OspfVersion,
    /// Packet type.
    pub packet_type: PacketType,
    /// Originating Router Id.
    pub router_id: Ip4,
    /// OSPF Area Id.
    pub area_id: Ip4,
    /// Authentication type (OSPFv2 only; 0 for v3).
    pub auth_type: u16,
    /// Authentication data (OSPFv2 only; zero for v3).
    pub auth: [u8; 8],
    /// OSPFv3 Instance Id (0 for v2).
    pub instance_id: u8,
    /// The packet body.
    pub body: PacketBody,
}

impl OspfPacket {
    /// Encode the packet to its on-the-wire byte form, computing and embedding
    /// the correct Internet checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        encode_body(self.version, &self.body, &mut body);

        let hdr_len = self.version.header_len();
        let total = (hdr_len + body.len()) as u16;

        let mut buf = Vec::with_capacity(hdr_len + body.len());
        buf.push(self.version.to_u8());
        buf.push(self.packet_type.to_u8());
        buf.extend_from_slice(&total.to_be_bytes());
        buf.extend_from_slice(&self.router_id);
        buf.extend_from_slice(&self.area_id);

        match self.version {
            OspfVersion::V2 => {
                buf.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
                buf.extend_from_slice(&self.auth_type.to_be_bytes());
                buf.extend_from_slice(&self.auth);
            }
            OspfVersion::V3 => {
                buf.push(self.instance_id);
                buf.push(0); // reserved
                buf.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
            }
        }
        buf.extend_from_slice(&body);

        // Compute and write the checksum.
        let checksum = match self.version {
            OspfVersion::V2 => internet_checksum_skip(&buf, 16..24),
            OspfVersion::V3 => internet_checksum(&buf),
        };
        let off = match self.version {
            OspfVersion::V2 => 12,
            OspfVersion::V3 => 14,
        };
        buf[off..off + 2].copy_from_slice(&checksum.to_be_bytes());
        buf
    }

    /// Decode a packet from wire bytes, verifying the declared packet length.
    pub fn from_bytes(bytes: &[u8]) -> Result<OspfPacket> {
        let version = OspfVersion::from_u8(*bytes.first().ok_or(DecodeError::TruncatedHeader {
            needed: 1,
            actual: 0,
        })?)
        .ok_or(DecodeError::UnsupportedVersion(bytes[0]))?;
        let hdr_len = version.header_len();
        if bytes.len() < hdr_len {
            return Err(DecodeError::TruncatedHeader {
                needed: hdr_len,
                actual: bytes.len(),
            });
        }
        let packet_type = PacketType::from_u8(bytes[1]).ok_or(DecodeError::UnknownPacketType(bytes[1]))?;
        let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if declared != bytes.len() {
            return Err(DecodeError::LengthMismatch {
                declared,
                actual: bytes.len(),
            });
        }

        let router_id = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let area_id = [bytes[8], bytes[9], bytes[10], bytes[11]];

        let (auth_type, auth, instance_id) = match version {
            OspfVersion::V2 => {
                let auth_type = u16::from_be_bytes([bytes[14], bytes[15]]);
                let mut auth = [0u8; 8];
                auth.copy_from_slice(&bytes[16..24]);
                (auth_type, auth, 0)
            }
            OspfVersion::V3 => (0, [0u8; 8], bytes[12]),
        };

        let body_bytes = &bytes[hdr_len..];
        let body = decode_body(version, packet_type, body_bytes)?;

        Ok(OspfPacket {
            version,
            packet_type,
            router_id,
            area_id,
            auth_type,
            auth,
            instance_id,
            body,
        })
    }
}

fn encode_body(version: OspfVersion, body: &PacketBody, buf: &mut Vec<u8>) {
    match body {
        PacketBody::Hello(h) => encode_hello(version, h, buf),
        PacketBody::Dbd(d) => encode_dbd(version, d, buf),
        PacketBody::Lsr(reqs) => encode_lsr(version, reqs, buf),
        PacketBody::Lsu(l) => encode_lsu(version, l, buf),
        PacketBody::LsAck(a) => encode_lsack(version, a, buf),
    }
}

fn decode_body(version: OspfVersion, pt: PacketType, b: &[u8]) -> Result<PacketBody> {
    Ok(match pt {
        PacketType::Hello => PacketBody::Hello(decode_hello(version, b)?),
        PacketType::Dbd => PacketBody::Dbd(decode_dbd(version, b)?),
        PacketType::Lsr => PacketBody::Lsr(decode_lsr(version, b)?),
        PacketType::Lsu => PacketBody::Lsu(decode_lsu(version, b)?),
        PacketType::LsAck => PacketBody::LsAck(decode_lsack(version, b)?),
    })
}

fn encode_hello(version: OspfVersion, h: &HelloPacket, buf: &mut Vec<u8>) {
    match version {
        OspfVersion::V2 => {
            buf.extend_from_slice(&h.network_mask);
            buf.extend_from_slice(&h.hello_interval.to_be_bytes());
            buf.push(h.options);
            buf.push(h.router_priority);
            buf.extend_from_slice(&h.router_dead_interval.to_be_bytes());
            buf.extend_from_slice(&h.designated_router);
            buf.extend_from_slice(&h.backup_designated_router);
            for n in &h.neighbors {
                buf.extend_from_slice(n);
            }
        }
        OspfVersion::V3 => {
            buf.extend_from_slice(&h.interface_id.to_be_bytes());
            buf.push(h.router_priority);
            buf.extend_from_slice(&[h.options, 0, 0]); // 24-bit options, low byte stored
            buf.extend_from_slice(&h.hello_interval.to_be_bytes());
            buf.extend_from_slice(&h.router_dead_interval.to_be_bytes());
            buf.extend_from_slice(&h.designated_router);
            buf.extend_from_slice(&h.backup_designated_router);
            buf.extend_from_slice(&(h.neighbors.len() as u32).to_be_bytes());
            for n in &h.neighbors {
                buf.extend_from_slice(n);
            }
        }
    }
}

fn decode_hello(version: OspfVersion, b: &[u8]) -> Result<HelloPacket> {
    let mut r = Reader::new(b);
    let (network_mask, interface_id, hello_interval, options, router_priority, dead, dr, bdr);
    let mut neighbors = Vec::new();
    match version {
        OspfVersion::V2 => {
            network_mask = r.ip()?;
            hello_interval = r.u16()?;
            options = r.u8()?;
            router_priority = r.u8()?;
            dead = r.u32()?;
            dr = r.ip()?;
            bdr = r.ip()?;
            while r.remaining() >= 4 {
                neighbors.push(r.ip()?);
            }
            interface_id = 0;
        }
        OspfVersion::V3 => {
            interface_id = r.u32()?;
            router_priority = r.u8()?;
            options = r.u8()?; // low byte of the 24-bit options field
            r.u8()?; // discard the remaining 2 bytes of options
            hello_interval = r.u16()?;
            dead = r.u32()?;
            dr = r.ip()?;
            bdr = r.ip()?;
            let n = r.u32()? as usize;
            for _ in 0..n {
                neighbors.push(r.ip()?);
            }
            network_mask = [0; 4];
        }
    }
    Ok(HelloPacket {
        network_mask,
        interface_id,
        hello_interval,
        options,
        router_priority,
        router_dead_interval: dead,
        designated_router: dr,
        backup_designated_router: bdr,
        neighbors,
    })
}

fn encode_dbd(version: OspfVersion, d: &DbdPacket, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&d.interface_mtu.to_be_bytes());
    match version {
        OspfVersion::V2 => buf.push(d.options),
        OspfVersion::V3 => buf.extend_from_slice(&[d.options, 0, 0]),
    }
    let mut flags = 0u8;
    if d.init {
        flags |= 1 << 2; // I
    }
    if d.more {
        flags |= 1 << 1; // M
    }
    if d.master {
        flags |= 1; // MS
    }
    buf.push(flags);
    buf.extend_from_slice(&d.dd_sequence.to_be_bytes());
    for h in &d.lsas {
        h.encode(buf);
    }
}

fn decode_dbd(version: OspfVersion, b: &[u8]) -> Result<DbdPacket> {
    let mut r = Reader::new(b);
    let mtu = r.u16()?;
    let options = match version {
        OspfVersion::V2 => r.u8()?,
        OspfVersion::V3 => {
            let o = r.u8()?;
            r.u8()?;
            r.u8()?;
            o
        }
    };
    let flags = r.u8()?;
    let dd_sequence = r.u32()?;
    let mut lsas = Vec::new();
    while r.remaining() >= crate::lsa::LSA_HEADER_LEN {
        let hdr_bytes = &b[r.off..r.off + crate::lsa::LSA_HEADER_LEN];
        lsas.push(LsaHeader::decode(version, hdr_bytes)?);
        r.off += crate::lsa::LSA_HEADER_LEN;
    }
    Ok(DbdPacket {
        interface_mtu: mtu,
        options,
        init: flags & (1 << 2) != 0,
        more: flags & (1 << 1) != 0,
        master: flags & 1 != 0,
        dd_sequence,
        lsas,
    })
}

fn encode_lsr(version: OspfVersion, reqs: &[LinkStateRequest], buf: &mut Vec<u8>) {
    for req in reqs {
        match version {
            OspfVersion::V2 => buf.extend_from_slice(&req.lsa_type.to_be_bytes()),
            OspfVersion::V3 => {
                buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
                buf.extend_from_slice(&req.lsa_type.to_be_bytes());
            }
        }
        buf.extend_from_slice(&req.link_state_id);
        buf.extend_from_slice(&req.advertising_router);
    }
}

fn decode_lsr(version: OspfVersion, b: &[u8]) -> Result<Vec<LinkStateRequest>> {
    let mut r = Reader::new(b);
    let entry = match version {
        OspfVersion::V2 => 12,
        OspfVersion::V3 => 16,
    };
    let mut out = Vec::new();
    while r.remaining() >= entry {
        let lsa_type = match version {
            OspfVersion::V2 => r.u32()? as u16,
            OspfVersion::V3 => {
                r.u16()?; // reserved
                r.u16()?
            }
        };
        let link_state_id = r.ip()?;
        let advertising_router = r.ip()?;
        out.push(LinkStateRequest {
            lsa_type,
            link_state_id,
            advertising_router,
        });
    }
    Ok(out)
}

fn encode_lsu(_version: OspfVersion, l: &LsuPacket, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(l.lsas.len() as u32).to_be_bytes());
    for lsa in &l.lsas {
        let mut lsa_bytes = Vec::new();
        lsa.encode(&mut lsa_bytes);
        buf.extend_from_slice(&lsa_bytes);
    }
}

fn decode_lsu(version: OspfVersion, b: &[u8]) -> Result<LsuPacket> {
    let mut r = Reader::new(b);
    let n = r.u32()? as usize;
    let mut lsas = Vec::with_capacity(n);
    for _ in 0..n {
        if r.remaining() < crate::lsa::LSA_HEADER_LEN {
            return Err(DecodeError::TruncatedBody);
        }
        let hdr = LsaHeader::decode(version, &b[r.off..])?;
        let len = hdr.length as usize;
        if len < crate::lsa::LSA_HEADER_LEN || r.off + len > b.len() {
            return Err(DecodeError::TruncatedBody);
        }
        let lsa = Lsa::decode(version, &b[r.off..r.off + len])?;
        lsas.push(lsa);
        r.off += len;
    }
    Ok(LsuPacket { lsas })
}

fn encode_lsack(_version: OspfVersion, a: &LsAckPacket, buf: &mut Vec<u8>) {
    for h in &a.lsas {
        h.encode(buf);
    }
}

fn decode_lsack(version: OspfVersion, b: &[u8]) -> Result<LsAckPacket> {
    let mut r = Reader::new(b);
    let mut lsas = Vec::new();
    while r.remaining() >= crate::lsa::LSA_HEADER_LEN {
        let hdr_bytes = &b[r.off..r.off + crate::lsa::LSA_HEADER_LEN];
        lsas.push(LsaHeader::decode(version, hdr_bytes)?);
        r.off += crate::lsa::LSA_HEADER_LEN;
    }
    Ok(LsAckPacket { lsas })
}

/// A bounds-checked big-endian reader over a byte slice.
struct Reader<'a> {
    d: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, off: 0 }
    }
    fn remaining(&self) -> usize {
        self.d.len().saturating_sub(self.off)
    }
    fn u8(&mut self) -> Result<u8> {
        let v = *self.d.get(self.off).ok_or(DecodeError::TruncatedBody)?;
        self.off += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(DecodeError::TruncatedBody);
        }
        let v = u16::from_be_bytes([self.d[self.off], self.d[self.off + 1]]);
        self.off += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(DecodeError::TruncatedBody);
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
    fn ip(&mut self) -> Result<Ip4> {
        if self.remaining() < 4 {
            return Err(DecodeError::TruncatedBody);
        }
        let v = [self.d[self.off], self.d[self.off + 1], self.d[self.off + 2], self.d[self.off + 3]];
        self.off += 4;
        Ok(v)
    }
}

/// The standard 16-bit one's-complement Internet checksum (RFC 1071) over
/// `data`.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The Internet checksum over `data`, excluding the byte range `skip` (used by
/// OSPFv2, which zeroes the authentication field while checksumming).
pub fn internet_checksum_skip(data: &[u8], skip: std::ops::Range<usize>) -> u16 {
    let mut v = Vec::with_capacity(data.len() - skip.len());
    v.extend_from_slice(&data[..skip.start]);
    v.extend_from_slice(&data[skip.end..]);
    internet_checksum(&v)
}
