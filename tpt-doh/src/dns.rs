// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal, clean-room DNS wire codec sufficient for a DoH client.
//!
//! This is intentionally small: it can *build* query messages and *parse*
//! responses (including name-compression pointers), which is all a DoH client
//! needs. It is not a general-purpose resolver library — bring a full crate
//! (e.g. `hickory-proto`) if you need zone transfers, UPDATE, or TSIG.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{DnsError, Result};

/// DNS record class: Internet.
pub const CLASS_IN: u16 = 1;

/// Common `QTYPE`/`TYPE` values.
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const OPT: u16 = 41; // EDNS
}

/// Header flags, decoded from the 16-bit `FLAGS` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub qr: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated: bool,
    pub checking_disabled: bool,
    pub rcode: u8,
}

impl Flags {
    fn from_u16(v: u16) -> Self {
        Flags {
            qr: (v & 0x8000) != 0,
            opcode: ((v >> 11) & 0x0f) as u8,
            authoritative: (v & 0x0400) != 0,
            truncated: (v & 0x0200) != 0,
            recursion_desired: (v & 0x0100) != 0,
            recursion_available: (v & 0x0080) != 0,
            authenticated: (v & 0x0020) != 0,
            checking_disabled: (v & 0x0010) != 0,
            rcode: (v & 0x000f) as u8,
        }
    }

    fn to_u16(self) -> u16 {
        let mut v = 0u16;
        if self.qr {
            v |= 0x8000;
        }
        v |= ((self.opcode & 0x0f) as u16) << 11;
        if self.authoritative {
            v |= 0x0400;
        }
        if self.truncated {
            v |= 0x0200;
        }
        if self.recursion_desired {
            v |= 0x0100;
        }
        if self.recursion_available {
            v |= 0x0080;
        }
        if self.authenticated {
            v |= 0x0020;
        }
        if self.checking_disabled {
            v |= 0x0010;
        }
        v |= (self.rcode & 0x0f) as u16;
        v
    }
}

/// A single question entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A decoded resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

/// Decoded record data. Unknown types are retained verbatim in [`RData::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx { preference: u16, exchange: String },
    Txt(Vec<String>),
    Opt(Opt),
    Other { data: Vec<u8> },
}

/// EDNS (OPT) record payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub requestor_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub options: Vec<u8>,
}

/// A DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: Flags,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    /// Build a single-question query message.
    ///
    /// `id` is left at `0` by default; set [`Message::id`] if you need to match
    /// the echoed identifier on the response. Recursion desired is enabled.
    pub fn query(name: &str, qtype: u16) -> Self {
        Message {
            id: 0,
            flags: Flags {
                qr: false,
                opcode: 0,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                authenticated: false,
                checking_disabled: false,
                rcode: 0,
            },
            questions: vec![Question {
                name: name.trim_end_matches('.').to_ascii_lowercase(),
                qtype,
                qclass: CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Helper for an `A` (IPv4) query.
    pub fn a_query(name: &str) -> Self {
        Message::query(name, rtype::A)
    }

    /// Helper for an `AAAA` (IPv6) query.
    pub fn aaaa_query(name: &str) -> Self {
        Message::query(name, rtype::AAAA)
    }

    /// Serialize this message to the DNS wire format.
    ///
    /// Only the header and question section are encoded; extra answer/authority/
    /// additional records are ignored. This is sufficient for the queries a DoH
    /// client sends.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for q in &self.questions {
            write_name(&q.name, &mut out);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        out
    }

    /// Parse a DNS message from its wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Message> {
        if data.len() < 12 {
            return Err(DnsError::Truncated.into());
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = Flags::from_u16(u16::from_be_bytes([data[2], data[3]]));
        let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
        let an = u16::from_be_bytes([data[6], data[7]]) as usize;
        let ns = u16::from_be_bytes([data[8], data[9]]) as usize;
        let ar = u16::from_be_bytes([data[10], data[11]]) as usize;

        let mut pos = 12usize;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            let (name, consumed) = read_name(data, pos)?;
            pos += consumed;
            if pos + 4 > data.len() {
                return Err(DnsError::Truncated.into());
            }
            let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            pos += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }

        let answers = read_records(data, &mut pos, an)?;
        let authorities = read_records(data, &mut pos, ns)?;
        let additionals = read_records(data, &mut pos, ar)?;

        Ok(Message {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

fn write_name(name: &str, out: &mut Vec<u8>) {
    if name.is_empty() {
        out.push(0);
        return;
    }
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

/// Read a (possibly compressed) domain name starting at `pos`.
///
/// Returns the name in presentation (dotted) form and the number of bytes
/// consumed at the *top level* (i.e. how far the caller should advance `pos`,
/// which stops just after the first compression pointer if one is followed).
fn read_name(data: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let start = pos;
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut iterations = 0;

    loop {
        if iterations > 255 {
            return Err(DnsError::NameTooLong.into());
        }
        iterations += 1;
        if pos >= data.len() {
            return Err(DnsError::Truncated.into());
        }
        let len = data[pos];
        if len & 0xc0 == 0xc0 {
            // Compression pointer (RFC 1035 §4.1.4). At the top level this
            // name field occupies exactly the 2 pointer bytes.
            if pos + 1 >= data.len() {
                return Err(DnsError::Truncated.into());
            }
            let ptr = (((len & 0x3f) as usize) << 8) | data[pos + 1] as usize;
            if !jumped {
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            pos += 1; // consume the root terminator
            break;
        }
        // Ordinary label.
        let l = len as usize;
        if pos + 1 + l > data.len() {
            return Err(DnsError::Truncated.into());
        }
        let label = &data[pos + 1..pos + 1 + l];
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + l;
    }

    // `consumed` is the number of bytes the name field occupies at the top
    // level: 2 for a (pure) compression pointer, otherwise `pos - start`.
    let consumed = if jumped { 2 } else { pos - start };
    Ok((labels.join("."), consumed))
}

fn read_records(data: &[u8], pos: &mut usize, count: usize) -> Result<Vec<Record>> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, consumed) = read_name(data, *pos)?;
        *pos += consumed;
        if *pos + 10 > data.len() {
            return Err(DnsError::Truncated.into());
        }
        let rtype = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        let rclass = u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]);
        let ttl = u32::from_be_bytes([
            data[*pos + 4],
            data[*pos + 5],
            data[*pos + 6],
            data[*pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([data[*pos + 8], data[*pos + 9]]) as usize;
        *pos += 10;
        if *pos + rdlen > data.len() {
            return Err(DnsError::Truncated.into());
        }
        let rdata_bytes = &data[*pos..*pos + rdlen];
        let rdata = parse_rdata(rtype, rdata_bytes)?;
        *pos += rdlen;
        records.push(Record {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        });
    }
    Ok(records)
}

fn parse_rdata(rtype: u16, data: &[u8]) -> Result<RData> {
    match rtype {
        rtype::A => {
            if data.len() < 4 {
                return Err(DnsError::Truncated.into());
            }
            Ok(RData::A(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
        }
        rtype::AAAA => {
            if data.len() < 16 {
                return Err(DnsError::Truncated.into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[..16]);
            Ok(RData::Aaaa(Ipv6Addr::from(octets)))
        }
        rtype::CNAME | rtype::NS | rtype::PTR => {
            let (name, _) = read_name(data, 0)?;
            Ok(match rtype {
                rtype::CNAME => RData::Cname(name),
                rtype::NS => RData::Ns(name),
                _ => RData::Ptr(name),
            })
        }
        rtype::MX => {
            if data.len() < 3 {
                return Err(DnsError::Truncated.into());
            }
            let preference = u16::from_be_bytes([data[0], data[1]]);
            let (exchange, _) = read_name(data, 2)?;
            Ok(RData::Mx {
                preference,
                exchange,
            })
        }
        rtype::TXT => {
            let mut txt = Vec::new();
            let mut i = 0;
            while i < data.len() {
                let l = data[i] as usize;
                i += 1;
                if i + l > data.len() {
                    return Err(DnsError::Truncated.into());
                }
                txt.push(String::from_utf8_lossy(&data[i..i + l]).into_owned());
                i += l;
            }
            Ok(RData::Txt(txt))
        }
        rtype::OPT => {
            let mut options = Vec::new();
            let mut i = 0;
            while i + 4 <= data.len() {
                let _opt_code = u16::from_be_bytes([data[i], data[i + 1]]);
                let opt_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                i += 4;
                if i + opt_len > data.len() {
                    return Err(DnsError::Truncated.into());
                }
                options.extend_from_slice(&data[i..i + opt_len]);
                i += opt_len;
            }
            // OPT is special: the TTL field carries extended rcode/version/DO.
            // We surface raw options; header-derived fields are read by the
            // caller if needed. Here we store a best-effort Opt via the
            // record's TTL — but TTL isn't available here, so stash what we can.
            Ok(RData::Opt(Opt {
                requestor_payload_size: 0,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: false,
                options,
            }))
        }
        _ => Ok(RData::Other {
            data: data.to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_a_query() {
        let msg = Message::a_query("example.com");
        let bytes = msg.to_bytes();
        // 12-byte header + len(1)+"example"(7) + len(1)+"com"(3) + root(1)
        //   + qtype(2) + qclass(2)
        assert_eq!(bytes.len(), 12 + 8 + 4 + 1 + 2 + 2);
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].qtype, rtype::A);
        assert!(parsed.flags.recursion_desired);
    }

    #[test]
    fn decode_response_with_compression() {
        // Hand-built response: header, one question (example.com),
        // one A answer pointing back to the question name via a compression
        // pointer (0xC00C = offset 12, where the question name starts).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        bytes.extend_from_slice(&0x8180u16.to_be_bytes()); // flags (QR=1, RD/RA)
        bytes.extend_from_slice(&1u16.to_be_bytes()); // qd
        bytes.extend_from_slice(&1u16.to_be_bytes()); // an
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        // question name: example.com
        for (label, _) in [("example", 0), ("com", 0)] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&rtype::A.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        // answer: name = pointer to offset 12 (0xC00C)
        bytes.extend_from_slice(&0xC00Cu16.to_be_bytes());
        bytes.extend_from_slice(&rtype::A.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&60u32.to_be_bytes()); // ttl
        bytes.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        bytes.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34

        let msg = Message::from_bytes(&bytes).unwrap();
        assert!(msg.flags.qr);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "example.com");
        assert_eq!(
            msg.answers[0].rdata,
            RData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn truncated_input_errors() {
        assert!(Message::from_bytes(&[0, 1, 2]).is_err());
    }
}
