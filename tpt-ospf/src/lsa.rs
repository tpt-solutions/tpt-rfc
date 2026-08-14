// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OSPF Link-State Advertisements (LSAs): the 20-byte LSA header (with
//! version-specific framing for OSPFv2 §A.3.1 and OSPFv3 §A.4.2) and the body
//! encode/decode for Router and Network LSAs (the LSAs that drive intra-area
//! SPF), plus an opaque fallback for the remaining LSA types.

use crate::error::{DecodeError, Result};
use crate::wire::OspfVersion;

/// The OSPFv2 LSA header is 20 bytes (§A.3.1).
pub const LSA_HEADER_LEN: usize = 20;

/// The maximum LSA sequence number (§12.1.6).
pub const MAX_SEQUENCE: u32 = 0x7FFF_FFFF;
/// The initial (first) LSA sequence number flooded by an originator.
pub const INITIAL_SEQUENCE: u32 = 0x8000_0001;
/// The MaxAge value: an LSA with this age must be flushed (§14.1).
pub const MAX_AGE: u16 = 0xFFFF;
/// The DoNotAge bit in the LS age field (OSPFv2 only).
pub const DO_NOT_AGE: u16 = 0x8000;

/// A 4-byte IPv4/id field.
pub type Ip4 = [u8; 4];

fn ip_from(b: &[u8]) -> Ip4 {
    [b[0], b[1], b[2], b[3]]
}

/// The identifying triple of an LSA: its type, Link State Id, and Advertising
/// Router. Two LSAs with the same key are instances of the same LSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsaKey {
    /// Raw LSA type (v2 8-bit value, v3 16-bit value).
    pub lsa_type: u16,
    /// Link State Id.
    pub link_state_id: Ip4,
    /// Advertising Router.
    pub advertising_router: Ip4,
}

/// The header shared by every LSA (§A.3.1 / §A.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaHeader {
    /// The OSPF version this LSA belongs to (controls header framing).
    pub version: OspfVersion,
    /// LS age, in seconds.
    pub age: u16,
    /// The options byte (v2: full byte; v3: the Options byte; scope bits live
    /// in the LS type for v3).
    pub options: u8,
    /// Raw LSA type. OSPFv2 stores the 8-bit function code in the low byte;
    /// OSPFv3 stores the full 16-bit type (S2/S1 scope bits + function code).
    pub lsa_type: u16,
    /// Link State Id.
    pub link_state_id: Ip4,
    /// Advertising Router.
    pub advertising_router: Ip4,
    /// LSA sequence number.
    pub sequence_number: u32,
    /// LSA checksum (Fletcher-style LS checksum over the LSA, excluding the age
    /// field).
    pub checksum: u16,
    /// Total LSA length in bytes, including the 20-byte header.
    pub length: u16,
}

impl LsaHeader {
    /// Build a minimal Router-LSA header (type 1 / 0x2001) for `advertising`
    /// with the given options. Sequence is set to the initial value; age,
    /// checksum, and length are left to be filled on origin/encode.
    pub fn router(advertising: Ip4, options: u8) -> Self {
        Self::new(OspfVersion::V2, advertising, options, 1)
    }

    /// Build a minimal Network-LSA header (type 2 / 0x2002).
    pub fn network(advertising: Ip4, options: u8) -> Self {
        Self::new(OspfVersion::V2, advertising, options, 2)
    }

    /// Build an LSA header for an arbitrary `lsa_type` (used for the LSA types
    /// this crate preserves opaquely, e.g. Summary/AS-external). For Router and
    /// Network LSAs prefer [`LsaHeader::router`] / [`LsaHeader::network`].
    pub fn new(version: OspfVersion, advertising: Ip4, options: u8, lsa_type: u16) -> Self {
        Self {
            version,
            age: 0,
            options,
            lsa_type,
            link_state_id: [0; 4],
            advertising_router: advertising,
            sequence_number: INITIAL_SEQUENCE,
            checksum: 0,
            length: 0,
        }
    }

    /// The key identifying this LSA instance within the link-state database.
    pub fn key(&self) -> LsaKey {
        LsaKey {
            lsa_type: self.lsa_type,
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }

    /// True if this is a Router-LSA (v2 type 1 / v3 type 0x2001).
    pub fn is_router(&self) -> bool {
        match self.version {
            OspfVersion::V2 => self.lsa_type == 1,
            OspfVersion::V3 => self.lsa_type == 0x2001,
        }
    }

    /// True if this is a Network-LSA (v2 type 2 / v3 type 0x2002).
    pub fn is_network(&self) -> bool {
        match self.version {
            OspfVersion::V2 => self.lsa_type == 2,
            OspfVersion::V3 => self.lsa_type == 0x2002,
        }
    }

    /// Encode the 20-byte header (without the body) into `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.age.to_be_bytes());
        match self.version {
            OspfVersion::V2 => {
                buf.push(self.options);
                buf.push(self.lsa_type as u8);
            }
            OspfVersion::V3 => {
                buf.extend_from_slice(&self.lsa_type.to_be_bytes());
                buf.push(self.options);
            }
        }
        buf.extend_from_slice(&self.link_state_id);
        buf.extend_from_slice(&self.advertising_router);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
    }

    /// Decode a 20-byte header (caller must ensure at least 20 bytes remain).
    pub fn decode(version: OspfVersion, data: &[u8]) -> Result<LsaHeader> {
        if data.len() < LSA_HEADER_LEN {
            return Err(DecodeError::FieldRead {
                size: LSA_HEADER_LEN,
                offset: 0,
                len: data.len(),
            });
        }
        let age = u16::from_be_bytes([data[0], data[1]]);
        let (options, lsa_type) = match version {
            OspfVersion::V2 => (data[2], data[3] as u16),
            OspfVersion::V3 => {
                let t = u16::from_be_bytes([data[2], data[3]]);
                (data[4], t)
            }
        };
        let link_state_id = ip_from(&data[4..8]);
        let advertising_router = ip_from(&data[8..12]);
        let sequence_number = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let length = u16::from_be_bytes([data[18], data[19]]);
        Ok(LsaHeader {
            version,
            age,
            options,
            lsa_type,
            link_state_id,
            advertising_router,
            sequence_number,
            checksum,
            length,
        })
    }
}

/// A single link record inside a Router-LSA (§A.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLink {
    /// Link type: 1 = point-to-point, 2 = transit (to a broadcast network),
    /// 3 = stub, 4 = virtual link.
    pub link_type: u8,
    /// Link Id: for p2p/virtual the neighbor Router Id; for transit the DR's
    /// interface address; for stub the subnet/network address.
    pub link_id: Ip4,
    /// Link Data: for p2p the local interface IP; for transit the local
    /// interface IP; for stub the address mask.
    pub link_data: Ip4,
    /// Output cost/metric of this link.
    pub metric: u16,
}

impl RouterLink {
    /// A point-to-point link to `neighbor` (Router Id) over local interface
    /// `local_ip` with `metric`.
    pub fn point_to_point(neighbor: Ip4, local_ip: Ip4, metric: u16) -> Self {
        Self {
            link_type: 1,
            link_id: neighbor,
            link_data: local_ip,
            metric,
        }
    }

    /// A stub (leaf) link advertising subnet `network`/`mask` with `metric`.
    pub fn stub(network: Ip4, mask: Ip4, metric: u16) -> Self {
        Self {
            link_type: 3,
            link_id: network,
            link_data: mask,
            metric,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.link_id);
        buf.extend_from_slice(&self.link_data);
        buf.push(self.link_type);
        buf.push(0); // # TOS — only the TOS 0 metric is supported
        buf.extend_from_slice(&self.metric.to_be_bytes());
    }

    fn decode(data: &[u8]) -> Result<RouterLink> {
        if data.len() < 12 {
            return Err(DecodeError::TruncatedRouterLink);
        }
        let link_id = ip_from(&data[0..4]);
        let link_data = ip_from(&data[4..8]);
        let link_type = data[8];
        let _tos = data[9];
        let metric = u16::from_be_bytes([data[10], data[11]]);
        Ok(RouterLink {
            link_type,
            link_id,
            link_data,
            metric,
        })
    }
}

/// A Router-LSA (type 1 / 0x2001) — the router's links within an area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsa {
    /// The LSA header. `lsa_type` must be a Router-LSA type for the version.
    pub header: LsaHeader,
    /// This router is a virtual-link endpoint (V bit).
    pub v: bool,
    /// This router is an AS boundary router (E bit).
    pub e: bool,
    /// This router is an area border router (B bit).
    pub b: bool,
    /// The link records.
    pub links: Vec<RouterLink>,
}

impl RouterLsa {
    /// Encode this Router-LSA (header + body) into `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut body = Vec::new();
        let mut flags = 0u8;
        if self.v {
            flags |= 1;
        }
        if self.e {
            flags |= 1 << 1;
        }
        if self.b {
            flags |= 1 << 2;
        }
        body.push(flags);
        body.push(self.links.len() as u8);
        for l in &self.links {
            l.encode(&mut body);
        }
        self.header.encode_with_body(buf, &body);
    }

    /// Decode a Router-LSA from `data` (a full LSA starting at the header).
    pub fn decode(version: OspfVersion, data: &[u8]) -> Result<RouterLsa> {
        let header = LsaHeader::decode(version, data)?;
        let body = &data[LSA_HEADER_LEN..];
        if body.len() < 2 {
            return Err(DecodeError::TruncatedBody);
        }
        let flags = body[0];
        let n = body[1] as usize;
        let mut links = Vec::with_capacity(n);
        let mut off = 2;
        for _ in 0..n {
            if off + 12 > body.len() {
                return Err(DecodeError::TruncatedRouterLink);
            }
            links.push(RouterLink::decode(&body[off..off + 12])?);
            off += 12;
        }
        Ok(RouterLsa {
            header,
            v: flags & 1 != 0,
            e: flags & (1 << 1) != 0,
            b: flags & (1 << 2) != 0,
            links,
        })
    }
}

/// A Network-LSA (type 2 / 0x2002) — the set of routers attached to a
/// broadcast/nbma network segment, originated by the DR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsa {
    /// The LSA header. `link_state_id` is the DR's interface address.
    pub header: LsaHeader,
    /// The network mask shared by all attached routers.
    pub network_mask: Ip4,
    /// The Router Ids of every attached router (including the DR).
    pub attached_routers: Vec<Ip4>,
}

impl NetworkLsa {
    /// Encode this Network-LSA (header + body) into `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&self.network_mask);
        for r in &self.attached_routers {
            body.extend_from_slice(r);
        }
        self.header.encode_with_body(buf, &body);
    }

    /// Decode a Network-LSA from `data`.
    pub fn decode(version: OspfVersion, data: &[u8]) -> Result<NetworkLsa> {
        let header = LsaHeader::decode(version, data)?;
        let body = &data[LSA_HEADER_LEN..];
        if body.len() < 4 {
            return Err(DecodeError::TruncatedBody);
        }
        let network_mask = ip_from(&body[0..4]);
        let mut attached = Vec::new();
        let mut off = 4;
        while off + 4 <= body.len() {
            attached.push(ip_from(&body[off..off + 4]));
            off += 4;
        }
        Ok(NetworkLsa {
            header,
            network_mask,
            attached_routers: attached,
        })
    }
}

/// An LSA whose body this crate does not decode (Summary, AS-external, and all
/// OSPFv3 LSA bodies in this baseline). It is preserved opaquely so that the
/// database and flooding logic can still treat it as a first-class LSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLsa {
    /// The LSA header.
    pub header: LsaHeader,
    /// The bytes following the 20-byte header (the LSA body).
    pub body: Vec<u8>,
}

impl RawLsa {
    /// Encode this opaque LSA (header + body) into `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode_with_body(buf, &self.body);
    }

    /// Decode an opaque LSA from `data`.
    pub fn decode(version: OspfVersion, data: &[u8]) -> Result<RawLsa> {
        let header = LsaHeader::decode(version, data)?;
        let body = data.get(LSA_HEADER_LEN..).unwrap_or(&[]).to_vec();
        Ok(RawLsa { header, body })
    }
}

/// A decoded LSA, discriminated by type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lsa {
    /// A Router-LSA.
    Router(RouterLsa),
    /// A Network-LSA.
    Network(NetworkLsa),
    /// Any other LSA, kept opaque.
    Raw(RawLsa),
}

impl Lsa {
    /// The LSA header (shared by all variants).
    pub fn header(&self) -> &LsaHeader {
        match self {
            Lsa::Router(r) => &r.header,
            Lsa::Network(n) => &n.header,
            Lsa::Raw(r) => &r.header,
        }
    }

    /// The OSPF version this LSA belongs to.
    pub fn version(&self) -> OspfVersion {
        self.header().version
    }

    /// The LSA key (type, link state id, advertising router).
    pub fn key(&self) -> LsaKey {
        self.header().key()
    }

    /// Encode the full LSA (header + body) into `buf`, computing the `length`
    /// field from the actual encoded size.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Lsa::Router(r) => r.encode(buf),
            Lsa::Network(n) => n.encode(buf),
            Lsa::Raw(r) => r.encode(buf),
        }
    }

    /// Decode a full LSA of `version` from `data`. Router and Network LSAs are
    /// decoded structurally; every other type is preserved opaquely as
    /// [`Lsa::Raw`].
    pub fn decode(version: OspfVersion, data: &[u8]) -> Result<Lsa> {
        let hdr = LsaHeader::decode(version, data)?;
        match version {
            OspfVersion::V2 => match hdr.lsa_type {
                1 => Ok(Lsa::Router(RouterLsa::decode(version, data)?)),
                2 => Ok(Lsa::Network(NetworkLsa::decode(version, data)?)),
                _ => Ok(Lsa::Raw(RawLsa::decode(version, data)?)),
            },
            OspfVersion::V3 => match hdr.lsa_type {
                0x2001 => Ok(Lsa::Router(RouterLsa::decode(version, data)?)),
                0x2002 => Ok(Lsa::Network(NetworkLsa::decode(version, data)?)),
                _ => Ok(Lsa::Raw(RawLsa::decode(version, data)?)),
            },
        }
    }
}

/// Helper on the header to encode header + body with the `length` field set.
trait EncodeWithBody {
    fn encode_with_body(&self, buf: &mut Vec<u8>, body: &[u8]);
}

impl EncodeWithBody for LsaHeader {
    fn encode_with_body(&self, buf: &mut Vec<u8>, body: &[u8]) {
        let mut header = self.clone();
        header.length = (LSA_HEADER_LEN + body.len()) as u16;
        header.encode(buf);
        buf.extend_from_slice(body);
    }
}
