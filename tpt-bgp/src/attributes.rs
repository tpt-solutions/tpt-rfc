// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! BGP path attributes, AS-path representation, and NLRI encoding
//! (RFC 4271 §4.3, RFC 6793 four-octet ASNs, RFC 4760 multiprotocol
//! reachability).

use crate::error::{DecodeError, Result};
use crate::wire::Reader;

/// The reserved "AS_TRANS" value (23456) used in the two-octet AS field of the
/// OPEN message when a four-octet AS number is in use (RFC 6793 §4).
pub const AS_TRANS: u32 = 23456;

/// A BGP Autonomous System Number. Capable of holding four-octet values
/// (RFC 6793); values ≤ 65535 are also representable in the legacy two-octet
/// form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn(pub u32);

impl Asn {
    /// The well-known reserved ASN for documentation/testing (RFC 5398).
    pub const RESERVED: Asn = Asn(0);
    /// The `AS_TRANS` sentinel value.
    pub const TRANS: Asn = Asn(AS_TRANS);

    /// Whether this ASN fits in the legacy two-octet form.
    pub fn fits_16bit(self) -> bool {
        self.0 <= 0xFFFF
    }

    /// Whether this is the `AS_TRANS` sentinel.
    pub fn is_trans(self) -> bool {
        self.0 == AS_TRANS
    }

    /// Encode the ASN as two octets (truncating the high half — callers must
    /// ensure [`Asn::fits_16bit`] or use `AS_TRANS` before calling this for a
    /// legacy peer).
    pub fn to_16bit(self) -> u16 {
        self.0 as u16
    }
}

impl From<u32> for Asn {
    fn from(v: u32) -> Self {
        Asn(v)
    }
}

/// An IPv4 route prefix (address + prefix length in bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Prefix {
    /// The (masked) IPv4 address.
    pub addr: [u8; 4],
    /// Prefix length in bits (0..=32).
    pub len: u8,
}

impl Ipv4Prefix {
    /// Construct a prefix, masking off any host bits beyond `len`.
    pub fn new(addr: [u8; 4], len: u8) -> Ipv4Prefix {
        let mut masked = addr;
        mask_in_place(&mut masked, len);
        Ipv4Prefix { addr: masked, len }
    }

    /// The AFI value for IPv4 (1).
    pub fn afi() -> u16 {
        1
    }
}

/// An IPv6 route prefix (address + prefix length in bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Prefix {
    /// The (masked) IPv6 address.
    pub addr: [u8; 16],
    /// Prefix length in bits (0..=128).
    pub len: u8,
}

impl Ipv6Prefix {
    /// Construct a prefix, masking off any host bits beyond `len`.
    pub fn new(addr: [u8; 16], len: u8) -> Ipv6Prefix {
        let mut masked = addr;
        mask_in_place(&mut masked, len);
        Ipv6Prefix { addr: masked, len }
    }

    /// The AFI value for IPv6 (2).
    pub fn afi() -> u16 {
        2
    }
}

/// A route prefix belonging to either address family, used for multiprotocol
/// NLRI (RFC 4760).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prefix {
    /// An IPv4 prefix.
    V4(Ipv4Prefix),
    /// An IPv6 prefix.
    V6(Ipv6Prefix),
}

impl Prefix {
    /// The AFI of this prefix.
    pub fn afi(&self) -> u16 {
        match self {
            Prefix::V4(_) => Ipv4Prefix::afi(),
            Prefix::V6(_) => Ipv6Prefix::afi(),
        }
    }

    /// The prefix length in bits.
    pub fn len(&self) -> u8 {
        match self {
            Prefix::V4(p) => p.len,
            Prefix::V6(p) => p.len,
        }
    }

    /// Whether this prefix is the default route (prefix length zero).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The (masked) address bytes.
    pub fn octets(&self) -> Vec<u8> {
        match self {
            Prefix::V4(p) => p.addr.to_vec(),
            Prefix::V6(p) => p.addr.to_vec(),
        }
    }

    /// The address length in bytes (4 for IPv4, 16 for IPv6).
    pub fn addr_len(&self) -> usize {
        match self {
            Prefix::V4(_) => 4,
            Prefix::V6(_) => 16,
        }
    }
}

fn mask_in_place(addr: &mut [u8], len: u8) {
    let bits = len as usize;
    for (i, byte) in addr.iter_mut().enumerate() {
        let byte_start = i * 8;
        if byte_start >= bits {
            *byte = 0;
        } else if byte_start + 8 > bits {
            let keep = 8 - (bits - byte_start);
            *byte &= 0xFF << (8 - keep);
        }
    }
}

/// ORIGIN path attribute (RFC 4271 §4.3, type code 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Route learned via the IGP (e.g. by redistribution).
    Igp,
    /// Route learned via the EGP.
    Egp,
    /// Route learned by some other means (incomplete).
    Incomplete,
}

impl Origin {
    /// Map a wire value to an [`Origin`].
    pub fn from_u8(v: u8) -> Option<Origin> {
        match v {
            0 => Some(Origin::Igp),
            1 => Some(Origin::Egp),
            2 => Some(Origin::Incomplete),
            _ => None,
        }
    }
    /// The wire value for this origin.
    pub fn to_u8(self) -> u8 {
        match self {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }
}

/// An AS_PATH segment type (RFC 4271 §4.3, type codes 1 and 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsPathSegmentType {
    /// An unordered set of ASNs (AS_SET).
    Set,
    /// An ordered set of ASNs (AS_SEQUENCE).
    Sequence,
}

impl AsPathSegmentType {
    /// Map a wire value to a segment type.
    pub fn from_u8(v: u8) -> Option<AsPathSegmentType> {
        match v {
            1 => Some(AsPathSegmentType::Set),
            2 => Some(AsPathSegmentType::Sequence),
            _ => None,
        }
    }
    /// The wire value for this segment type.
    pub fn to_u8(self) -> u8 {
        match self {
            AsPathSegmentType::Set => 1,
            AsPathSegmentType::Sequence => 2,
        }
    }
}

/// One AS_PATH segment: a sequence or set of ASNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathSegment {
    /// Whether this segment is an AS_SET or AS_SEQUENCE.
    pub segment_type: AsPathSegmentType,
    /// The ASNs in the segment, in path order for a sequence.
    pub asns: Vec<Asn>,
}

/// The AS_PATH path attribute (RFC 4271 §4.3, type code 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsPath {
    /// The segments composing the path, in order.
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// The flattened, in-order list of ASNs across all AS_SEQUENCE segments
    /// (AS_SET members are also included, in segment order). This is the list
    /// used by the decision process to compute path length.
    pub fn asns(&self) -> Vec<Asn> {
        let mut out = Vec::new();
        for seg in &self.segments {
            out.extend(seg.asns.iter().copied());
        }
        out
    }

    /// The AS-path length as defined by RFC 4271 §9.1.2.1(g): the number of
    /// AS_SET and AS_SEQUENCE segments in the path.
    pub fn path_length(&self) -> usize {
        self.segments.len()
    }

    /// The originating (leftmost / most recent) ASN, if any.
    pub fn first_asn(&self) -> Option<Asn> {
        self.segments.first().and_then(|s| s.asns.first().copied())
    }

    /// Encode the AS_PATH value (without the attribute header).
    pub fn encode_value(&self, buf: &mut Vec<u8>, as4: bool) {
        for seg in &self.segments {
            buf.push(seg.segment_type.to_u8());
            buf.push(seg.asns.len() as u8);
            for a in &seg.asns {
                if as4 {
                    buf.extend_from_slice(&a.0.to_be_bytes());
                } else {
                    buf.extend_from_slice(&a.to_16bit().to_be_bytes());
                }
            }
        }
    }

    /// Decode the AS_PATH value (without the attribute header).
    pub fn decode_value(r: &mut Reader, as4: bool) -> Result<AsPath> {
        let mut segments = Vec::new();
        while r.remaining() > 0 {
            let seg_type =
                AsPathSegmentType::from_u8(r.u8()?).ok_or(DecodeError::TruncatedField {
                    needed: 1,
                    offset: r.off,
                    len: r.len,
                })?;
            let count = r.u8()? as usize;
            let mut asns = Vec::with_capacity(count);
            for _ in 0..count {
                let v = if as4 { r.u32()? } else { u32::from(r.u16()?) };
                asns.push(Asn(v));
            }
            segments.push(AsPathSegment {
                segment_type: seg_type,
                asns,
            });
        }
        Ok(AsPath { segments })
    }
}

/// The AGGREGATOR path attribute (RFC 4271 §4.3, type code 7) or its four-octet
/// companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aggregator {
    /// The AS that formed the aggregate.
    pub asn: Asn,
    /// The BGP identifier of the aggregating speaker.
    pub addr: [u8; 4],
}

/// The NEXT_HOP for a multiprotocol NLRI (RFC 4760 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextHop {
    /// An IPv4 next hop.
    Ipv4([u8; 4]),
    /// An IPv6 next hop.
    Ipv6([u8; 16]),
    /// An IPv6 global + link-local next hop (RFC 2545 §2).
    Ipv6LinkLocal([u8; 16], [u8; 16]),
    /// A raw next-hop value whose form this implementation does not interpret.
    Other(Vec<u8>),
}

impl NextHop {
    /// The encoded next-hop bytes (without a length prefix).
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            NextHop::Ipv4(a) => buf.extend_from_slice(a),
            NextHop::Ipv6(a) => buf.extend_from_slice(a),
            NextHop::Ipv6LinkLocal(g, l) => {
                buf.extend_from_slice(g);
                buf.extend_from_slice(l);
            }
            NextHop::Other(v) => buf.extend_from_slice(v),
        }
    }

    /// The encoded next-hop length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            NextHop::Ipv4(_) => 4,
            NextHop::Ipv6(_) => 16,
            NextHop::Ipv6LinkLocal(_, _) => 32,
            NextHop::Other(v) => v.len(),
        }
    }

    fn decode(bytes: &[u8]) -> NextHop {
        match bytes.len() {
            4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(bytes);
                NextHop::Ipv4(a)
            }
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(bytes);
                NextHop::Ipv6(a)
            }
            32 => {
                let mut g = [0u8; 16];
                let mut l = [0u8; 16];
                g.copy_from_slice(&bytes[..16]);
                l.copy_from_slice(&bytes[16..]);
                NextHop::Ipv6LinkLocal(g, l)
            }
            _ => NextHop::Other(bytes.to_vec()),
        }
    }
}

/// The MP_REACH_NLRI path attribute (RFC 4760 §3, type code 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    /// Address Family Identifier.
    pub afi: u16,
    /// Subsequent Address Family Identifier.
    pub safi: u8,
    /// The next hop associated with the announced routes.
    pub next_hop: NextHop,
    /// The announced prefixes.
    pub nlri: Vec<Prefix>,
}

/// The MP_UNREACH_NLRI path attribute (RFC 4760 §4, type code 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreachNlri {
    /// Address Family Identifier.
    pub afi: u16,
    /// Subsequent Address Family Identifier.
    pub safi: u8,
    /// The withdrawn prefixes.
    pub withdrawn: Vec<Prefix>,
}

/// A full BGP path attribute, as carried in an UPDATE message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAttribute {
    /// ORIGIN (type 1).
    Origin(Origin),
    /// AS_PATH (type 2).
    AsPath(AsPath),
    /// NEXT_HOP (type 3), IPv4.
    NextHop([u8; 4]),
    /// MULTI_EXIT_DISC (type 4).
    MultiExitDisc(u32),
    /// LOCAL_PREF (type 5).
    LocalPref(u32),
    /// ATOMIC_AGGREGATE (type 6).
    AtomicAggregate,
    /// AGGREGATOR (type 7).
    Aggregator(Aggregator),
    /// COMMUNITY (type 8).
    Community(u32),
    /// ORIGINATOR_ID (type 9, route reflection).
    OriginatorId([u8; 4]),
    /// CLUSTER_LIST (type 10, route reflection).
    ClusterList(Vec<[u8; 4]>),
    /// MP_REACH_NLRI (type 14).
    MpReachNlri(MpReachNlri),
    /// MP_UNREACH_NLRI (type 15).
    MpUnreachNlri(MpUnreachNlri),
    /// An attribute this implementation does not interpret, preserved verbatim.
    Unknown {
        /// The attribute type code.
        type_code: u8,
        /// Whether the attribute is transitive (preserved when re-advertised).
        transitive: bool,
        /// The raw attribute value.
        value: Vec<u8>,
    },
}

impl PathAttribute {
    /// The attribute type code.
    pub fn type_code(&self) -> u8 {
        match self {
            PathAttribute::Origin(_) => 1,
            PathAttribute::AsPath(_) => 2,
            PathAttribute::NextHop(_) => 3,
            PathAttribute::MultiExitDisc(_) => 4,
            PathAttribute::LocalPref(_) => 5,
            PathAttribute::AtomicAggregate => 6,
            PathAttribute::Aggregator(_) => 7,
            PathAttribute::Community(_) => 8,
            PathAttribute::OriginatorId(_) => 9,
            PathAttribute::ClusterList(_) => 10,
            PathAttribute::MpReachNlri(_) => 14,
            PathAttribute::MpUnreachNlri(_) => 15,
            PathAttribute::Unknown { type_code, .. } => *type_code,
        }
    }

    /// The default attribute flags for this attribute type (RFC 4271 §4.3 /
    /// RFC 4760 §3–4).
    fn default_flags(&self) -> u8 {
        const OPTIONAL: u8 = 0x80;
        const TRANSITIVE: u8 = 0x40;
        match self {
            PathAttribute::Origin(_)
            | PathAttribute::AsPath(_)
            | PathAttribute::NextHop(_)
            | PathAttribute::LocalPref(_)
            | PathAttribute::AtomicAggregate => TRANSITIVE,
            PathAttribute::Aggregator(_) | PathAttribute::Community(_) => OPTIONAL | TRANSITIVE,
            PathAttribute::MultiExitDisc(_)
            | PathAttribute::OriginatorId(_)
            | PathAttribute::ClusterList(_)
            | PathAttribute::MpReachNlri(_)
            | PathAttribute::MpUnreachNlri(_) => OPTIONAL,
            PathAttribute::Unknown { transitive, .. } => {
                if *transitive {
                    OPTIONAL | TRANSITIVE
                } else {
                    OPTIONAL
                }
            }
        }
    }

    /// Encode the attribute (including its header) into `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>, as4: bool) {
        let mut value = Vec::new();
        match self {
            PathAttribute::Origin(o) => value.push(o.to_u8()),
            PathAttribute::AsPath(p) => p.encode_value(&mut value, as4),
            PathAttribute::NextHop(a) => value.extend_from_slice(a),
            PathAttribute::MultiExitDisc(v) => value.extend_from_slice(&v.to_be_bytes()),
            PathAttribute::LocalPref(v) => value.extend_from_slice(&v.to_be_bytes()),
            PathAttribute::AtomicAggregate => {}
            PathAttribute::Aggregator(agg) => {
                if as4 {
                    value.extend_from_slice(&agg.asn.0.to_be_bytes());
                } else {
                    value.extend_from_slice(&agg.asn.to_16bit().to_be_bytes());
                }
                value.extend_from_slice(&agg.addr);
            }
            PathAttribute::Community(v) => value.extend_from_slice(&v.to_be_bytes()),
            PathAttribute::OriginatorId(a) => value.extend_from_slice(a),
            PathAttribute::ClusterList(list) => {
                for a in list {
                    value.extend_from_slice(a);
                }
            }
            PathAttribute::MpReachNlri(m) => encode_mp_reach(m, &mut value),
            PathAttribute::MpUnreachNlri(m) => encode_mp_unreach(m, &mut value),
            PathAttribute::Unknown { value: v, .. } => value.extend_from_slice(v),
        }

        let mut flags = self.default_flags();
        if value.len() > 255 {
            flags |= 0x10; // extended length
        }
        buf.push(flags);
        buf.push(self.type_code());
        if flags & 0x10 != 0 {
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            buf.push(value.len() as u8);
        }
        buf.extend_from_slice(&value);
    }

    /// Decode a single attribute (header + value) from `r`.
    pub fn decode(r: &mut Reader, as4: bool) -> Result<PathAttribute> {
        let flags = r.u8()?;
        let type_code = r.u8()?;
        let extended = flags & 0x10 != 0;
        let len = if extended {
            r.u16()? as usize
        } else {
            r.u8()? as usize
        };
        let value = r.take(len)?;
        let mut vr = Reader::new(&value);

        let attr = match type_code {
            1 => PathAttribute::Origin(Origin::from_u8(vr.u8()?).ok_or(
                DecodeError::TruncatedField {
                    needed: 1,
                    offset: vr.off,
                    len: vr.len,
                },
            )?),
            2 => PathAttribute::AsPath(AsPath::decode_value(&mut vr, as4)?),
            3 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&vr.take(4)?);
                PathAttribute::NextHop(a)
            }
            4 => PathAttribute::MultiExitDisc(vr.u32()?),
            5 => PathAttribute::LocalPref(vr.u32()?),
            6 => PathAttribute::AtomicAggregate,
            7 => {
                let asn = if as4 { vr.u32()? } else { u32::from(vr.u16()?) };
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&vr.take(4)?);
                PathAttribute::Aggregator(Aggregator {
                    asn: Asn(asn),
                    addr,
                })
            }
            8 => PathAttribute::Community(vr.u32()?),
            9 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&vr.take(4)?);
                PathAttribute::OriginatorId(a)
            }
            10 => {
                let mut list = Vec::new();
                while vr.remaining() >= 4 {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&vr.take(4)?);
                    list.push(a);
                }
                PathAttribute::ClusterList(list)
            }
            14 => PathAttribute::MpReachNlri(decode_mp_reach(&mut vr)?),
            15 => PathAttribute::MpUnreachNlri(decode_mp_unreach(&mut vr)?),
            other => PathAttribute::Unknown {
                type_code: other,
                transitive: flags & 0x40 != 0,
                value,
            },
        };
        Ok(attr)
    }
}

fn encode_mp_reach(m: &MpReachNlri, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&m.afi.to_be_bytes());
    buf.push(m.safi);
    buf.push(m.next_hop.encoded_len() as u8);
    m.next_hop.encode(buf);
    buf.push(0); // reserved SNPA count
    for p in &m.nlri {
        encode_prefix_bits(buf, p.octets(), p.len());
    }
}

fn decode_mp_reach(r: &mut Reader) -> Result<MpReachNlri> {
    let afi = r.u16()?;
    let safi = r.u8()?;
    let nh_len = r.u8()? as usize;
    let nh = NextHop::decode(&r.take(nh_len)?);
    r.u8()?; // reserved SNPA count
    let addr_len = if afi == Ipv6Prefix::afi() { 16 } else { 4 };
    let mut nlri = Vec::new();
    while r.remaining() > 0 {
        nlri.push(decode_prefix(r, addr_len)?);
    }
    Ok(MpReachNlri {
        afi,
        safi,
        next_hop: nh,
        nlri,
    })
}

fn encode_mp_unreach(m: &MpUnreachNlri, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&m.afi.to_be_bytes());
    buf.push(m.safi);
    for p in &m.withdrawn {
        encode_prefix_bits(buf, p.octets(), p.len());
    }
}

fn decode_mp_unreach(r: &mut Reader) -> Result<MpUnreachNlri> {
    let afi = r.u16()?;
    let safi = r.u8()?;
    let addr_len = if afi == Ipv6Prefix::afi() { 16 } else { 4 };
    let mut withdrawn = Vec::new();
    while r.remaining() > 0 {
        withdrawn.push(decode_prefix(r, addr_len)?);
    }
    Ok(MpUnreachNlri {
        afi,
        safi,
        withdrawn,
    })
}

/// Encode a prefix given its full address bytes and prefix length in bits.
pub fn encode_prefix_bits(buf: &mut Vec<u8>, addr: Vec<u8>, len: u8) {
    buf.push(len);
    let nbytes = (len as usize).div_ceil(8);
    buf.extend_from_slice(&addr[..nbytes]);
}

/// Decode a prefix of `addr_len` bytes.
pub fn decode_prefix(r: &mut Reader, addr_len: usize) -> Result<Prefix> {
    let len = r.u8()?;
    if len as usize > addr_len * 8 {
        return Err(DecodeError::TruncatedField {
            needed: 1,
            offset: r.off,
            len: r.len,
        });
    }
    let nbytes = (len as usize).div_ceil(8);
    let mut addr = vec![0u8; addr_len];
    for b in addr.iter_mut().take(nbytes) {
        *b = r.u8()?;
    }
    if addr_len == 4 {
        let mut a = [0u8; 4];
        a.copy_from_slice(&addr);
        Ok(Prefix::V4(Ipv4Prefix { addr: a, len }))
    } else {
        let mut a = [0u8; 16];
        a.copy_from_slice(&addr);
        Ok(Prefix::V6(Ipv6Prefix { addr: a, len }))
    }
}
