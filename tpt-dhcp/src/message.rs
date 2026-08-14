// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DHCP/BOOTP message: the fixed BOOTP header (RFC 2131 §2) plus the
//! variable options field, with clean-room encode/decode and typed option
//! accessors.

use std::net::Ipv4Addr;

use crate::error::DecodeError;
use crate::options::{DhcpOption, MessageType, DHCP_MAGIC, OPTION_END, OPTION_PAD};

/// BOOTP operation: client → server vs server → client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageOp {
    /// BOOTREQUEST — sent by a client.
    BootRequest,
    /// BOOTREPLY — sent by a server.
    BootReply,
}

impl MessageOp {
    /// Map a wire value to a [`MessageOp`].
    pub fn from_u8(v: u8) -> Option<MessageOp> {
        match v {
            1 => Some(MessageOp::BootRequest),
            2 => Some(MessageOp::BootReply),
            _ => None,
        }
    }

    /// Map a [`MessageOp`] to its wire value.
    pub fn to_u8(self) -> u8 {
        match self {
            MessageOp::BootRequest => 1,
            MessageOp::BootReply => 2,
        }
    }
}

/// Hardware address type: 1 = Ethernet (RFC 2131 §2, RFC 1700).
pub const HARDWARE_ETHERNET: u8 = 1;

/// A DHCP/BOOTP message.
///
/// The fixed header fields follow RFC 2131 §2; `options` holds the trailing
/// TLV option list (RFC 2132). `sname` and `file` are kept as raw bytes in the
/// rare case they carry BOOTP data; DHCP itself routes almost everything
/// through `options`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    /// BOOTP op: request or reply.
    pub op: MessageOp,
    /// Hardware address type (e.g. `HARDWARE_ETHERNET`).
    pub htype: u8,
    /// Hardware address length in bytes (e.g. 6 for a MAC).
    pub hlen: u8,
    /// Relay-agent hop count (0 for direct client/server).
    pub hops: u8,
    /// Transaction id, echoed by the server to correlate replies.
    pub xid: u32,
    /// Seconds elapsed since client began address acquisition.
    pub secs: u16,
    /// Flags; bit 15 is the broadcast flag (RFC 2131 §2).
    pub flags: u16,
    /// Client's current IP (used in RENEWING/REBINDING/RELEASE).
    pub ciaddr: Ipv4Addr,
    /// "Your" IP — the address offered/assigned by the server.
    pub yiaddr: Ipv4Addr,
    /// Server's IP (next-server, used for boot file download).
    pub siaddr: Ipv4Addr,
    /// Relay agent IP (0 for direct exchanges).
    pub giaddr: Ipv4Addr,
    /// Client hardware address, padded to 16 bytes.
    pub chaddr: [u8; 16],
    /// Optional server host name (raw bytes).
    pub sname: Vec<u8>,
    /// Optional boot file name (raw bytes).
    pub file: Vec<u8>,
    /// DHCP options (TLV list).
    pub options: Vec<DhcpOption>,
}

impl Default for DhcpMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpMessage {
    /// Construct a minimal client request template: a `BootRequest` with
    /// Ethernet hardware type and zeroed addresses.
    pub fn new() -> Self {
        Self {
            op: MessageOp::BootRequest,
            htype: HARDWARE_ETHERNET,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            sname: Vec::new(),
            file: Vec::new(),
            options: Vec::new(),
        }
    }

    /// Copy up to `hlen` bytes of `mac` into `chaddr`, zeroing the rest, and set
    /// `hlen` accordingly.
    pub fn set_chaddr(&mut self, mac: &[u8]) {
        let len = mac.len().min(16);
        let mut chaddr = [0u8; 16];
        chaddr[..len].copy_from_slice(&mac[..len]);
        self.chaddr = chaddr;
        self.hlen = len as u8;
    }

    /// The client MAC address: the first `hlen` bytes of `chaddr`.
    pub fn mac(&self) -> &[u8] {
        let n = (self.hlen as usize).min(self.chaddr.len());
        &self.chaddr[..n]
    }

    /// Find an option by code.
    pub fn find_option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|o| o.code() == code)
    }

    /// Append an option, replacing any existing option with the same code so a
    /// message never carries a duplicate.
    pub fn set_option(&mut self, opt: DhcpOption) {
        let code = opt.code();
        self.options.retain(|o| o.code() != code);
        self.options.push(opt);
    }

    /// The DHCP message type (option 53), if present.
    pub fn message_type(&self) -> Option<MessageType> {
        match self.find_option(crate::options::CODE_MESSAGE_TYPE)? {
            DhcpOption::MessageType(t) => Some(*t),
            _ => None,
        }
    }

    /// The Server Identifier option (54), if present.
    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        match self.find_option(crate::options::CODE_SERVER_IDENTIFIER)? {
            DhcpOption::ServerIdentifier(ip) => Some(*ip),
            _ => None,
        }
    }

    /// The Requested IP Address option (50), if present.
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        match self.find_option(crate::options::CODE_REQUESTED_IP_ADDRESS)? {
            DhcpOption::RequestedIpAddress(ip) => Some(*ip),
            _ => None,
        }
    }

    /// The Client Identifier option (61), if present.
    pub fn client_identifier(&self) -> Option<&[u8]> {
        match self.find_option(crate::options::CODE_CLIENT_IDENTIFIER)? {
            DhcpOption::ClientIdentifier(b) => Some(b),
            _ => None,
        }
    }

    /// The IP Address Lease Time option (51), if present.
    pub fn lease_time(&self) -> Option<u32> {
        match self.find_option(crate::options::CODE_LEASE_TIME)? {
            DhcpOption::LeaseTime(v) => Some(*v),
            _ => None,
        }
    }

    /// Encode the message to its on-the-wire byte form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(236 + self.options.len() * 8);
        buf.push(self.op.to_u8());
        buf.push(self.htype);
        buf.push(self.hlen);
        buf.push(self.hops);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.ciaddr.octets());
        buf.extend_from_slice(&self.yiaddr.octets());
        buf.extend_from_slice(&self.siaddr.octets());
        buf.extend_from_slice(&self.giaddr.octets());
        buf.extend_from_slice(&self.chaddr);
        buf.extend(padded(&self.sname, 64));
        buf.extend(padded(&self.file, 128));
        buf.extend_from_slice(&DHCP_MAGIC);
        for opt in &self.options {
            buf.extend(opt.encode());
        }
        buf.push(OPTION_END);
        buf
    }

    /// Decode a message from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DhcpMessage, DecodeError> {
        const HEADER_LEN: usize = 236;
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::TruncatedHeader {
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let op = MessageOp::from_u8(bytes[0]).ok_or(DecodeError::UnknownOp(bytes[0]))?;
        let htype = bytes[1];
        let hlen = bytes[2];
        let hops = bytes[3];
        let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let secs = u16::from_be_bytes([bytes[8], bytes[9]]);
        let flags = u16::from_be_bytes([bytes[10], bytes[11]]);
        let ciaddr = read_ip(&bytes[12..16]);
        let yiaddr = read_ip(&bytes[16..20]);
        let siaddr = read_ip(&bytes[20..24]);
        let giaddr = read_ip(&bytes[24..28]);
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&bytes[28..44]);
        let sname = bytes[44..108].to_vec();
        let file = bytes[108..236].to_vec();

        let mut msg = DhcpMessage {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options: Vec::new(),
        };

        // Magic cookie must sit at offset 236.
        if bytes.len() < HEADER_LEN + 4 || bytes[236..240] != DHCP_MAGIC {
            return Err(DecodeError::BadMagicCookie);
        }

        let mut i = HEADER_LEN + 4;
        while i < bytes.len() {
            let code = bytes[i];
            i += 1;
            match code {
                OPTION_PAD => continue,
                OPTION_END => break,
                c => {
                    if i >= bytes.len() {
                        return Err(DecodeError::TruncatedOption {
                            len: 0,
                            remaining: 0,
                        });
                    }
                    let len = bytes[i] as usize;
                    i += 1;
                    if i + len > bytes.len() {
                        return Err(DecodeError::TruncatedOption {
                            len,
                            remaining: bytes.len() - i,
                        });
                    }
                    let data = &bytes[i..i + len];
                    msg.options.push(DhcpOption::decode(c, data));
                    i += len;
                }
            }
        }
        Ok(msg)
    }
}

fn read_ip(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::from([b[0], b[1], b[2], b[3]])
}

fn padded(field: &[u8], size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(size);
    v.extend_from_slice(field);
    v.resize(size, 0);
    v
}
