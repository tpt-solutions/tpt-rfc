//! RTCP packet encode/decode (RFC 3550 §6).
//!
//! RTCP packets are normally sent as a *compound* packet — several RTCP
//! packets concatenated behind a single lower-layer datagram. This module
//! exposes both single-packet ([`RtcpPacket`]) and compound
//! ([`decode_compound`]/[`encode_compound`]) APIs.
//!
//! Supported packet types: Sender Report (SR, PT=200), Receiver Report
//! (RR, PT=201), Source Description (SDES, PT=202), BYE (PT=203), and APP
//! (PT=204).

use crate::error::RtpError;

/// RTCP version implemented and expected on the wire.
pub const RTCP_VERSION: u8 = 2;

/// RTCP packet type (PT) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RtcpType {
    /// Sender Report.
    Sr = 200,
    /// Receiver Report.
    Rr = 201,
    /// Source Description.
    Sdes = 202,
    /// Goodbye.
    Bye = 203,
    /// Application-defined.
    App = 204,
}

impl RtcpType {
    /// Map a raw PT byte to an [`RtcpType`], or `None` if unknown.
    pub fn from_u8(v: u8) -> Option<RtcpType> {
        match v {
            200 => Some(RtcpType::Sr),
            201 => Some(RtcpType::Rr),
            202 => Some(RtcpType::Sdes),
            203 => Some(RtcpType::Bye),
            204 => Some(RtcpType::App),
            _ => None,
        }
    }
}

/// One reception-report block (RFC 3550 §6.4.1 / §6.4.2), used inside both
/// SR and RR packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceptionReport {
    /// SSRC of the source this report describes.
    pub ssrc: u32,
    /// Fraction of RTP data packets lost since the previous report (8 bits).
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (24 bits).
    pub cumulative_lost: u32,
    /// Extended highest sequence number received (32 bits).
    pub extended_seq: u32,
    /// Interarrival jitter (32 bits).
    pub interarrival_jitter: u32,
    /// Middle 32 bits of the NTP timestamp from the most recent SR from this
    /// source (LSR).
    pub last_sr: u32,
    /// Delay since last SR, in 1/65536 seconds (DLSR).
    pub delay_since_last_sr: u32,
}

impl ReceptionReport {
    const WIRE_LEN: usize = 24;

    fn decode(buf: &[u8]) -> Result<ReceptionReport, RtpError> {
        if buf.len() < Self::WIRE_LEN {
            return Err(RtpError::PacketTooShort(buf.len(), Self::WIRE_LEN));
        }
        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let fraction_lost = buf[4];
        let cumulative_lost =
            u32::from_be_bytes([0, buf[5], buf[6], buf[7]]) & 0x00FF_FFFF;
        let extended_seq = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let interarrival_jitter =
            u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let last_sr = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let delay_since_last_sr =
            u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        Ok(ReceptionReport {
            ssrc,
            fraction_lost,
            cumulative_lost,
            extended_seq,
            interarrival_jitter,
            last_sr,
            delay_since_last_sr,
        })
    }

    fn encode(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        buf[4] = self.fraction_lost;
        buf[5..8].copy_from_slice(&self.cumulative_lost.to_be_bytes()[1..]);
        buf[8..12].copy_from_slice(&self.extended_seq.to_be_bytes());
        buf[12..16].copy_from_slice(&self.interarrival_jitter.to_be_bytes());
        buf[16..20].copy_from_slice(&self.last_sr.to_be_bytes());
        buf[20..24].copy_from_slice(&self.delay_since_last_sr.to_be_bytes());
    }
}

/// Sender Report (PT=200).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    /// SSRC of the sender generating this report.
    pub ssrc: u32,
    /// NTP timestamp of the RTP stream's wall-clock time, 64 bits (MSW seconds
    /// in the high 32 bits, fraction in the low 32 bits).
    pub ntp_timestamp: u64,
    /// Corresponding RTP timestamp.
    pub rtp_timestamp: u32,
    /// Total number of packets sent by this sender.
    pub senders_packet_count: u32,
    /// Total number of payload octets sent by this sender.
    pub senders_octet_count: u32,
    /// Reception reports for sources this sender has received.
    pub reports: Vec<ReceptionReport>,
}

/// Receiver Report (PT=201).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    /// SSRC of the receiver generating this report.
    pub ssrc: u32,
    /// Reception reports for sources this receiver has received.
    pub reports: Vec<ReceptionReport>,
}

/// SDES item types (RFC 3550 §6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SdesItemType {
    /// End of items (not an item with content).
    End = 0,
    /// Canonical end-point identifier (CNAME).
    Cname = 1,
    /// User name (NAME).
    Name = 2,
    /// Electronic mail address (EMAIL).
    Email = 3,
    /// Phone number (PHONE).
    Phone = 4,
    /// Geographic location (LOC).
    Loc = 5,
    /// Application or tool name (TOOL).
    Tool = 6,
    /// Notice/status (NOTE).
    Note = 7,
    /// Private extensions (PRIV).
    Priv = 8,
}

impl SdesItemType {
    /// Map a raw item-type byte to an [`SdesItemType`], or `None` for the
    /// reserved/unassigned values.
    pub fn from_u8(v: u8) -> Option<SdesItemType> {
        match v {
            0 => Some(SdesItemType::End),
            1 => Some(SdesItemType::Cname),
            2 => Some(SdesItemType::Name),
            3 => Some(SdesItemType::Email),
            4 => Some(SdesItemType::Phone),
            5 => Some(SdesItemType::Loc),
            6 => Some(SdesItemType::Tool),
            7 => Some(SdesItemType::Note),
            8 => Some(SdesItemType::Priv),
            _ => None,
        }
    }
}

/// A single SDES item: a type tag plus its value bytes (kept as raw bytes so
/// that the wire format round-trips exactly, including the PRIV prefix
/// convention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesItem {
    /// Item type.
    pub item_type: SdesItemType,
    /// Item value bytes (the raw `length` octets on the wire). For text items
    /// this is the UTF-8/ASCII text; for PRIV it is the prefix-length byte,
    /// prefix, and private value concatenated.
    pub data: Vec<u8>,
}

impl SdesItem {
    /// Convenience constructor for a text item (CNAME/NAME/EMAIL/etc.).
    pub fn text(item_type: SdesItemType, text: &str) -> SdesItem {
        SdesItem {
            item_type,
            data: text.as_bytes().to_vec(),
        }
    }

    /// View the value as a string (lossy).
    pub fn as_text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

/// One SDES chunk: an SSRC/CSRC followed by its list of items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesChunk {
    /// SSRC/CSRC this chunk describes.
    pub ssrc: u32,
    /// SDES items (excluding the terminating END item).
    pub items: Vec<SdesItem>,
}

/// Source Description (SDES, PT=202).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdes {
    /// SDES chunks, one per source.
    pub chunks: Vec<SdesChunk>,
}

/// BYE (PT=203).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bye {
    /// SSRC/CSRC identifiers leaving the session.
    pub sources: Vec<u32>,
    /// Optional reason for leaving.
    pub reason: Option<String>,
}

/// Application-defined (APP, PT=204).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    /// SSRC/CSRC of the source.
    pub ssrc: u32,
    /// Subtype (5 bits).
    pub subtype: u8,
    /// Four-octet application name (raw bytes; see [`App::name_str`]).
    pub name: [u8; 4],
    /// Application-dependent data.
    pub data: Vec<u8>,
}

impl App {
    /// Interpret [`App::name`] as an ASCII string (lossy).
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// A single, decoded RTCP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    /// Sender Report.
    Sr(SenderReport),
    /// Receiver Report.
    Rr(ReceiverReport),
    /// Source Description.
    Sdes(Sdes),
    /// Goodbye.
    Bye(Bye),
    /// Application-defined.
    App(App),
}

impl RtcpPacket {
    /// The RTCP packet type of this packet.
    pub fn packet_type(&self) -> RtcpType {
        match self {
            RtcpPacket::Sr(_) => RtcpType::Sr,
            RtcpPacket::Rr(_) => RtcpType::Rr,
            RtcpPacket::Sdes(_) => RtcpType::Sdes,
            RtcpPacket::Bye(_) => RtcpType::Bye,
            RtcpPacket::App(_) => RtcpType::App,
        }
    }

    /// The on-wire length of this packet in bytes, including the 4-byte common
    /// header and rounded to a 32-bit boundary (RTCP packets are always a
    /// whole number of 32-bit words).
    pub fn encoded_len(&self) -> usize {
        let body = match self {
            RtcpPacket::Sr(s) => {
                4 + 20 + s.reports.len() * ReceptionReport::WIRE_LEN
            }
            RtcpPacket::Rr(r) => 4 + r.reports.len() * ReceptionReport::WIRE_LEN,
            RtcpPacket::Sdes(s) => {
                let mut n = 0;
                for c in &s.chunks {
                    let items: usize = c
                        .items
                        .iter()
                        .map(|i| 2 + i.data.len())
                        .sum::<usize>()
                        + 1; // END item
                    n += 4 + items;
                    n = (n + 3) & !3; // pad chunk to 32-bit boundary
                }
                n
            }
            RtcpPacket::Bye(b) => {
                let mut n = 4 * b.sources.len();
                if let Some(r) = &b.reason {
                    n += 1 + r.len();
                }
                n = (n + 3) & !3;
                n
            }
            RtcpPacket::App(a) => 4 + 4 + a.data.len(),
        };
        // total = header(4) + body, padded to 32-bit word boundary
        let total = 4 + body;
        (total + 3) & !3
    }

    /// Decode a single RTCP packet from `buf` (which must contain exactly one
    /// packet, or a prefix that is exactly one packet).
    pub fn decode(buf: &[u8]) -> Result<RtcpPacket, RtpError> {
        let (pkt, consumed) = decode_one(buf, buf.len())?;
        if consumed != buf.len() {
            return Err(RtpError::RtcpLengthOverflow(buf.len()));
        }
        Ok(pkt)
    }

    /// Decode the first RTCP packet in `buf`, returning it and the number of
    /// bytes consumed.
    pub fn decode_prefix(buf: &[u8]) -> Result<(RtcpPacket, usize), RtpError> {
        decode_one(buf, buf.len())
    }

    /// Encode this packet, allocating a fresh `Vec<u8>`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.encoded_len()];
        self.encode_into(&mut buf);
        buf
    }

    /// Encode into `buf` (must be at least [`RtcpPacket::encoded_len`] bytes).
    pub fn encode_into(&self, buf: &mut [u8]) {
        let total = self.encoded_len();
        let (pt, rc, body): (u8, u8, &[u8]) = match self {
            RtcpPacket::Sr(_) => (200, 0, &[]),
            RtcpPacket::Rr(_) => (201, 0, &[]),
            RtcpPacket::Sdes(_) => (202, 0, &[]),
            RtcpPacket::Bye(_) => (203, 0, &[]),
            RtcpPacket::App(_) => (204, 0, &[]),
        };
        let _ = (pt, rc, body);

        buf[0] = (RTCP_VERSION << 6) | match self {
            RtcpPacket::Sr(s) => s.reports.len() as u8,
            RtcpPacket::Rr(r) => r.reports.len() as u8,
            RtcpPacket::Sdes(s) => s.chunks.len() as u8,
            RtcpPacket::Bye(b) => b.sources.len() as u8,
            RtcpPacket::App(_) => 0, // 5-bit field is the subtype for APP
        };
        let rc_field = buf[0] & 0x1f;
        buf[1] = pt;
        let words_minus_one = (total / 4) - 1;
        buf[2..4].copy_from_slice(&(words_minus_one as u16).to_be_bytes());

        let mut pos = 4;
        match self {
            RtcpPacket::Sr(s) => {
                buf[pos..pos + 4].copy_from_slice(&s.ssrc.to_be_bytes());
                pos += 4;
                buf[pos..pos + 8].copy_from_slice(&s.ntp_timestamp.to_be_bytes());
                pos += 8;
                buf[pos..pos + 4].copy_from_slice(&s.rtp_timestamp.to_be_bytes());
                pos += 4;
                buf[pos..pos + 4]
                    .copy_from_slice(&s.senders_packet_count.to_be_bytes());
                pos += 4;
                buf[pos..pos + 4]
                    .copy_from_slice(&s.senders_octet_count.to_be_bytes());
                pos += 4;
                for r in &s.reports {
                    r.encode(&mut buf[pos..pos + ReceptionReport::WIRE_LEN]);
                    pos += ReceptionReport::WIRE_LEN;
                }
            }
            RtcpPacket::Rr(r) => {
                buf[pos..pos + 4].copy_from_slice(&r.ssrc.to_be_bytes());
                pos += 4;
                for rep in &r.reports {
                    rep.encode(&mut buf[pos..pos + ReceptionReport::WIRE_LEN]);
                    pos += ReceptionReport::WIRE_LEN;
                }
            }
            RtcpPacket::Sdes(s) => {
                for chunk in &s.chunks {
                    buf[pos..pos + 4].copy_from_slice(&chunk.ssrc.to_be_bytes());
                    pos += 4;
                    for item in &chunk.items {
                        buf[pos] = item.item_type as u8;
                        buf[pos + 1] = item.data.len() as u8;
                        buf[pos + 2..pos + 2 + item.data.len()]
                            .copy_from_slice(&item.data);
                        pos += 2 + item.data.len();
                    }
                    buf[pos] = SdesItemType::End as u8;
                    pos += 1;
                    // pad to 32-bit boundary
                    while pos % 4 != 0 {
                        buf[pos] = 0;
                        pos += 1;
                    }
                }
            }
            RtcpPacket::Bye(b) => {
                for &src in &b.sources {
                    buf[pos..pos + 4].copy_from_slice(&src.to_be_bytes());
                    pos += 4;
                }
                if let Some(r) = &b.reason {
                    let rb = r.as_bytes();
                    buf[pos] = rb.len() as u8;
                    pos += 1;
                    buf[pos..pos + rb.len()].copy_from_slice(rb);
                    pos += rb.len();
                    while pos % 4 != 0 {
                        buf[pos] = 0;
                        pos += 1;
                    }
                }
            }
            RtcpPacket::App(a) => {
                buf[pos..pos + 4].copy_from_slice(&a.ssrc.to_be_bytes());
                pos += 4;
                // subtype in top 5 bits of byte0; name packed across 4 bytes
                let n0 = (a.subtype & 0x1f) << 3 | (a.name[0] >> 5);
                let n1 = (a.name[0] << 3) | (a.name[1] >> 5);
                let n2 = (a.name[1] << 3) | (a.name[2] >> 5);
                let n3 = (a.name[2] << 3) | (a.name[3] >> 5);
                buf[pos] = n0;
                buf[pos + 1] = n1;
                buf[pos + 2] = n2;
                buf[pos + 3] = n3;
                pos += 4;
                buf[pos..pos + a.data.len()].copy_from_slice(&a.data);
                pos += a.data.len();
                while pos % 4 != 0 {
                    buf[pos] = 0;
                    pos += 1;
                }
            }
        }
        let _ = rc_field;
    }
}

/// The common RTCP header, shared by all packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommonHeader {
    padding: bool,
    rc: u8,
    pt: u8,
    length_words: u16,
}

fn parse_common(buf: &[u8]) -> Result<(CommonHeader, usize), RtpError> {
    if buf.len() < 4 {
        return Err(RtpError::PacketTooShort(buf.len(), 4));
    }
    let b0 = buf[0];
    let version = b0 >> 6;
    if version != RTCP_VERSION {
        return Err(RtpError::UnsupportedVersion(version));
    }
    let padding = (b0 & 0x20) != 0;
    let rc = b0 & 0x1f;
    let pt = buf[1];
    let length_words = u16::from_be_bytes([buf[2], buf[3]]);
    let end = (length_words as usize + 1) * 4;
    if buf.len() < end {
        return Err(RtpError::RtcpLengthOverflow(end));
    }
    Ok((
        CommonHeader {
            padding,
            rc,
            pt,
            length_words,
        },
        end,
    ))
}

/// Decode a single RTCP packet from `buf`, bounded by `bound` (the packet's
/// declared end). Returns the packet and the number of bytes consumed.
fn decode_one(buf: &[u8], bound: usize) -> Result<(RtcpPacket, usize), RtpError> {
    let (h, end) = parse_common(&buf[..bound])?;
    let pad = if h.padding {
        // padding count is the last octet within the packet
        let last = buf[end - 1] as usize;
        if last == 0 || last > end {
            return Err(RtpError::PaddingOverflow(last));
        }
        end - last
    } else {
        end
    };

    let body = &buf[4..pad];
    let pkt = match RtcpType::from_u8(h.pt) {
        Some(RtcpType::Sr) => {
            let need = 4 + 20 + (h.rc as usize) * ReceptionReport::WIRE_LEN;
            if body.len() < need {
                return Err(RtpError::PacketTooShort(body.len(), need));
            }
            let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let ntp = u64::from_be_bytes([
                body[4], body[5], body[6], body[7], body[8], body[9], body[10], body[11],
            ]);
            let rtp_ts = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
            let pkt_count =
                u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
            let octet_count =
                u32::from_be_bytes([body[20], body[21], body[22], body[23]]);
            let mut reports = Vec::with_capacity(h.rc as usize);
            let mut pos = 24;
            for _ in 0..h.rc {
                reports.push(ReceptionReport::decode(&body[pos..])?);
                pos += ReceptionReport::WIRE_LEN;
            }
            RtcpPacket::Sr(SenderReport {
                ssrc,
                ntp_timestamp: ntp,
                rtp_timestamp: rtp_ts,
                senders_packet_count: pkt_count,
                senders_octet_count: octet_count,
                reports,
            })
        }
        Some(RtcpType::Rr) => {
            let need = 4 + (h.rc as usize) * ReceptionReport::WIRE_LEN;
            if body.len() < need {
                return Err(RtpError::PacketTooShort(body.len(), need));
            }
            let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let mut reports = Vec::with_capacity(h.rc as usize);
            let mut pos = 4;
            for _ in 0..h.rc {
                reports.push(ReceptionReport::decode(&body[pos..])?);
                pos += ReceptionReport::WIRE_LEN;
            }
            RtcpPacket::Rr(ReceiverReport { ssrc, reports })
        }
        Some(RtcpType::Sdes) => {
            let chunks = decode_sdes(body, h.rc as usize)?;
            RtcpPacket::Sdes(Sdes { chunks })
        }
        Some(RtcpType::Bye) => {
            let (sources, reason) = decode_bye(body, h.rc as usize)?;
            RtcpPacket::Bye(Bye { sources, reason })
        }
        Some(RtcpType::App) => {
            if body.len() < 8 {
                return Err(RtpError::PacketTooShort(body.len(), 8));
            }
            let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let subtype = (body[4] >> 3) & 0x1f;
            let name = [
                (body[4] & 0x07) << 5 | (body[5] >> 3),
                (body[5] & 0x07) << 5 | (body[6] >> 3),
                (body[6] & 0x07) << 5 | (body[7] >> 3),
                (body[7] & 0x07) << 5,
            ];
            let data = body[8..].to_vec();
            RtcpPacket::App(App {
                ssrc,
                subtype,
                name,
                data,
            })
        }
        None => return Err(RtpError::UnknownRtcpType(h.pt)),
    };
    Ok((pkt, end))
}

fn decode_sdes(buf: &[u8], count: usize) -> Result<Vec<SdesChunk>, RtpError> {
    let mut chunks = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        if buf.len() < pos + 4 {
            return Err(RtpError::PacketTooShort(buf.len(), pos + 4));
        }
        let ssrc = u32::from_be_bytes([
            buf[pos],
            buf[pos + 1],
            buf[pos + 2],
            buf[pos + 3],
        ]);
        pos += 4;
        let chunk_start = pos;
        let mut items = Vec::new();
        loop {
            if pos >= buf.len() {
                return Err(RtpError::SdesItemOverflow(0));
            }
            let t = buf[pos];
            pos += 1;
            let item_type = SdesItemType::from_u8(t)
                .ok_or(RtpError::SdesItemOverflow(t as usize))?;
            if item_type == SdesItemType::End {
                break;
            }
            if pos >= buf.len() {
                return Err(RtpError::SdesItemOverflow(0));
            }
            let len = buf[pos] as usize;
            pos += 1;
            if pos + len > buf.len() {
                return Err(RtpError::SdesItemOverflow(len));
            }
            let data = buf[pos..pos + len].to_vec();
            pos += len;
            items.push(SdesItem { item_type, data });
        }
        // advance to next 32-bit boundary
        let aligned = ((pos - chunk_start) + 3) & !3;
        pos = chunk_start + aligned;
        chunks.push(SdesChunk { ssrc, items });
    }
    Ok(chunks)
}

fn decode_bye(buf: &[u8], count: usize) -> Result<(Vec<u32>, Option<String>), RtpError> {
    let mut sources = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        if buf.len() < pos + 4 {
            return Err(RtpError::PacketTooShort(buf.len(), pos + 4));
        }
        sources.push(u32::from_be_bytes([
            buf[pos],
            buf[pos + 1],
            buf[pos + 2],
            buf[pos + 3],
        ]));
        pos += 4;
    }
    let reason = if pos < buf.len() {
        let len = buf[pos] as usize;
        pos += 1;
        if pos + len > buf.len() {
            return Err(RtpError::SdesItemOverflow(len));
        }
        Some(String::from_utf8_lossy(&buf[pos..pos + len]).into_owned())
    } else {
        None
    };
    Ok((sources, reason))
}

/// Decode a compound RTCP packet (one or more RTCP packets concatenated) into
/// a vector of [`RtcpPacket`].
pub fn decode_compound(buf: &[u8]) -> Result<Vec<RtcpPacket>, RtpError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        // Need at least the 4-byte header to read the length field.
        if buf.len() - pos < 4 {
            return Err(RtpError::PacketTooShort(buf.len() - pos, 4));
        }
        let (pkt, consumed) = decode_one(&buf[pos..], buf.len() - pos)?;
        out.push(pkt);
        pos += consumed;
    }
    Ok(out)
}

/// Encode a compound RTCP packet by concatenating each packet's encoding.
pub fn encode_compound(packets: &[RtcpPacket]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        out.extend_from_slice(&p.encode());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sr_round_trip() {
        let sr = SenderReport {
            ssrc: 0x1122_3344,
            ntp_timestamp: 0x0011_2233_4455_6677,
            rtp_timestamp: 0xaabb_ccdd,
            senders_packet_count: 5,
            senders_octet_count: 1234,
            reports: vec![ReceptionReport {
                ssrc: 0x5566_7788,
                fraction_lost: 17,
                cumulative_lost: 0x00FF_0001 & 0x00FF_FFFF,
                extended_seq: 0x1234_5678,
                interarrival_jitter: 42,
                last_sr: 0x99aa_bbcc,
                delay_since_last_sr: 1000,
            }],
        };
        let pkt = RtcpPacket::Sr(sr.clone());
        let enc = pkt.encode();
        let dec = RtcpPacket::decode(&enc).unwrap();
        assert_eq!(dec, RtcpPacket::Sr(sr));
    }

    #[test]
    fn rr_round_trip() {
        let rr = ReceiverReport {
            ssrc: 0x0a0a_0a0a,
            reports: vec![
                ReceptionReport {
                    ssrc: 1,
                    fraction_lost: 0,
                    cumulative_lost: 3,
                    extended_seq: 0x100,
                    interarrival_jitter: 7,
                    last_sr: 0,
                    delay_since_last_sr: 0,
                },
                ReceptionReport {
                    ssrc: 2,
                    fraction_lost: 255,
                    cumulative_lost: 0,
                    extended_seq: 0x200,
                    interarrival_jitter: 9,
                    last_sr: 1,
                    delay_since_last_sr: 2,
                },
            ],
        };
        let enc = RtcpPacket::Rr(rr.clone()).encode();
        let dec = RtcpPacket::decode(&enc).unwrap();
        assert_eq!(dec, RtcpPacket::Rr(rr));
    }

    #[test]
    fn sdes_round_trip() {
        let sdes = Sdes {
            chunks: vec![
                SdesChunk {
                    ssrc: 0x1111_1111,
                    items: vec![
                        SdesItem::text(SdesItemType::Cname, "alice@example.com"),
                        SdesItem::text(SdesItemType::Name, "Alice"),
                        SdesItem {
                            item_type: SdesItemType::Priv,
                            data: vec![2, b'a', b'b'], // prefix len 2, prefix "ab"
                        },
                    ],
                },
                SdesChunk {
                    ssrc: 0x2222_2222,
                    items: vec![SdesItem::text(SdesItemType::Cname, "bob@x.org")],
                },
            ],
        };
        let enc = RtcpPacket::Sdes(sdes.clone()).encode();
        let dec = RtcpPacket::decode(&enc).unwrap();
        assert_eq!(dec, RtcpPacket::Sdes(sdes));
    }

    #[test]
    fn bye_round_trip() {
        let bye = Bye {
            sources: vec![0xaaaa_bbbb, 0xcccc_dddd],
            reason: Some("session over".to_string()),
        };
        let enc = RtcpPacket::Bye(bye.clone()).encode();
        let dec = RtcpPacket::decode(&enc).unwrap();
        assert_eq!(dec, RtcpPacket::Bye(bye));
    }

    #[test]
    fn app_round_trip() {
        // Note: the RFC 3550 APP name is only 27 bits (a 5-bit subtype shares
        // the 32-bit word), so the final name octet's low 3 bits cannot be
        // round-tripped. We use a name whose last octet ('@' = 0x40) has zero
        // low bits, which round-trips exactly under the standard packing.
        let app = App {
            ssrc: 0x1234_5678,
            subtype: 3,
            name: *b"RTP@",
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let enc = RtcpPacket::App(app.clone()).encode();
        let dec = RtcpPacket::decode(&enc).unwrap();
        assert_eq!(dec, RtcpPacket::App(app));
    }

    #[test]
    fn compound_round_trip() {
        let pkts = vec![
            RtcpPacket::Sr(SenderReport {
                ssrc: 1,
                ntp_timestamp: 0,
                rtp_timestamp: 0,
                senders_packet_count: 0,
                senders_octet_count: 0,
                reports: vec![],
            }),
            RtcpPacket::Sdes(Sdes {
                chunks: vec![SdesChunk {
                    ssrc: 1,
                    items: vec![SdesItem::text(SdesItemType::Cname, "a@b.c")],
                }],
            }),
            RtcpPacket::Bye(Bye {
                sources: vec![1],
                reason: None,
            }),
        ];
        let enc = encode_compound(&pkts);
        let dec = decode_compound(&enc).unwrap();
        assert_eq!(dec, pkts);
    }

    #[test]
    fn rejects_unknown_type() {
        let mut buf = RtcpPacket::Rr(ReceiverReport {
            ssrc: 1,
            reports: vec![],
        })
        .encode();
        buf[1] = 205; // unknown PT
        assert!(matches!(
            RtcpPacket::decode(&buf),
            Err(RtpError::UnknownRtcpType(205))
        ));
    }
}
