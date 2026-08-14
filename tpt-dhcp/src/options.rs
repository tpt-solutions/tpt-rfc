// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DHCP options (RFC 2132) and the message-type discriminator (RFC 2131 §9.1).
//!
//! Options are encoded as TLV tuples: a 1-byte code, a 1-byte length, then
//! `length` value bytes. The `Pad` (0) and `End` (255) codes carry no length.
//! This module provides a typed [`DhcpOption`] covering the options this crate
//! emits/consumes, with everything else preserved losslessly via
//! [`DhcpOption::Other`].

use std::net::Ipv4Addr;

/// Magic cookie that precedes the options field in every DHCP message.
pub const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

/// Option code: `Pad` — a single zero byte used for 32-bit alignment.
pub const OPTION_PAD: u8 = 0;
/// Option code: `End` — terminates the options field.
pub const OPTION_END: u8 = 255;

/// Option code: Subnet Mask (RFC 2132 §3.3).
pub const CODE_SUBNET_MASK: u8 = 1;
/// Option code: Time Offset (RFC 2132 §3.4).
pub const CODE_TIME_OFFSET: u8 = 2;
/// Option code: Router (RFC 2132 §3.5).
pub const CODE_ROUTER: u8 = 3;
/// Option code: Domain Name Server (RFC 2132 §3.8).
pub const CODE_DOMAIN_NAME_SERVER: u8 = 6;
/// Option code: Host Name (RFC 2132 §3.14).
pub const CODE_HOST_NAME: u8 = 12;
/// Option code: Domain Name (RFC 2132 §3.17).
pub const CODE_DOMAIN_NAME: u8 = 15;
/// Option code: Broadcast Address (RFC 2132 §3.13).
pub const CODE_BROADCAST_ADDRESS: u8 = 28;
/// Option code: Requested IP Address (RFC 2132 §9.1).
pub const CODE_REQUESTED_IP_ADDRESS: u8 = 50;
/// Option code: IP Address Lease Time (RFC 2132 §9.2).
pub const CODE_LEASE_TIME: u8 = 51;
/// Option code: DHCP Message Type (RFC 2132 §9.6).
pub const CODE_MESSAGE_TYPE: u8 = 53;
/// Option code: Server Identifier (RFC 2132 §9.7).
pub const CODE_SERVER_IDENTIFIER: u8 = 54;
/// Option code: Parameter Request List (RFC 2132 §9.8).
pub const CODE_PARAMETER_REQUEST_LIST: u8 = 55;
/// Option code: Message (RFC 2132 §9.9).
pub const CODE_MESSAGE: u8 = 56;
/// Option code: Renewal (T1) Time Value (RFC 2132 §9.11).
pub const CODE_RENEWAL_TIME: u8 = 58;
/// Option code: Rebinding (T2) Time Value (RFC 2132 §9.12).
pub const CODE_REBINDING_TIME: u8 = 59;
/// Option code: Vendor Class Identifier (RFC 2132 §9.13).
pub const CODE_VENDOR_CLASS_IDENTIFIER: u8 = 60;
/// Option code: Client Identifier (RFC 2132 §9.14).
pub const CODE_CLIENT_IDENTIFIER: u8 = 61;

/// Lease-time value meaning "infinity" (RFC 2132 §9.2).
pub const LEASE_TIME_INFINITY: u32 = 0xFFFF_FFFF;

/// DHCP message type carried in option 53 (RFC 2131 §9.1, RFC 2132 §9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// DHCPDISCOVER — client broadcasts to locate servers.
    Discover,
    /// DHCPOFFER — server replies with an available address and parameters.
    Offer,
    /// DHCPREQUEST — client requests/confirms an address.
    Request,
    /// DHCPDECLINE — client reports the offered address is already in use.
    Decline,
    /// DHCPACK — server confirms the lease.
    Ack,
    /// DHCPNAK — server refuses the request.
    Nak,
    /// DHCPRELEASE — client relinquishes the address.
    Release,
    /// DHCPINFORM — client asks only for configuration parameters.
    Inform,
}

impl MessageType {
    /// Map a wire value to a [`MessageType`].
    pub fn from_u8(v: u8) -> Option<MessageType> {
        match v {
            1 => Some(MessageType::Discover),
            2 => Some(MessageType::Offer),
            3 => Some(MessageType::Request),
            4 => Some(MessageType::Decline),
            5 => Some(MessageType::Ack),
            6 => Some(MessageType::Nak),
            7 => Some(MessageType::Release),
            8 => Some(MessageType::Inform),
            _ => None,
        }
    }

    /// Map a [`MessageType`] to its wire value.
    pub fn to_u8(self) -> u8 {
        match self {
            MessageType::Discover => 1,
            MessageType::Offer => 2,
            MessageType::Request => 3,
            MessageType::Decline => 4,
            MessageType::Ack => 5,
            MessageType::Nak => 6,
            MessageType::Release => 7,
            MessageType::Inform => 8,
        }
    }
}

/// A single DHCP option, typed where this crate understands it.
///
/// Unknown options are preserved verbatim via [`DhcpOption::Other`] so that a
/// message can be decoded and re-encoded without loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    /// Subnet mask for the client's network (code 1).
    SubnetMask(Ipv4Addr),
    /// Time offset in seconds (code 2).
    TimeOffset(i32),
    /// Default routers (code 3).
    Router(Vec<Ipv4Addr>),
    /// DNS servers (code 6).
    DomainNameServer(Vec<Ipv4Addr>),
    /// Client host name (code 12).
    HostName(String),
    /// Domain name for name resolution (code 15).
    DomainName(String),
    /// Broadcast address (code 28).
    BroadcastAddress(Ipv4Addr),
    /// Address the client would like (code 50).
    RequestedIpAddress(Ipv4Addr),
    /// Lease time in seconds (code 51).
    LeaseTime(u32),
    /// Message type discriminator (code 53).
    MessageType(MessageType),
    /// Server identifier (the server's IP, code 54).
    ServerIdentifier(Ipv4Addr),
    /// Parameter request list: option codes the client wants (code 55).
    ParameterRequestList(Vec<u8>),
    /// Server-supplied error/status message (code 56).
    Message(String),
    /// Renewal (T1) time in seconds (code 58).
    RenewalTime(u32),
    /// Rebinding (T2) time in seconds (code 59).
    RebindingTime(u32),
    /// Vendor class identifier (code 60).
    VendorClassIdentifier(Vec<u8>),
    /// Client identifier (code 61).
    ClientIdentifier(Vec<u8>),
    /// Any other option, preserved verbatim as (code, value).
    Other(u8, Vec<u8>),
}

impl DhcpOption {
    /// The option code for this option.
    pub fn code(&self) -> u8 {
        match self {
            DhcpOption::SubnetMask(_) => CODE_SUBNET_MASK,
            DhcpOption::TimeOffset(_) => CODE_TIME_OFFSET,
            DhcpOption::Router(_) => CODE_ROUTER,
            DhcpOption::DomainNameServer(_) => CODE_DOMAIN_NAME_SERVER,
            DhcpOption::HostName(_) => CODE_HOST_NAME,
            DhcpOption::DomainName(_) => CODE_DOMAIN_NAME,
            DhcpOption::BroadcastAddress(_) => CODE_BROADCAST_ADDRESS,
            DhcpOption::RequestedIpAddress(_) => CODE_REQUESTED_IP_ADDRESS,
            DhcpOption::LeaseTime(_) => CODE_LEASE_TIME,
            DhcpOption::MessageType(_) => CODE_MESSAGE_TYPE,
            DhcpOption::ServerIdentifier(_) => CODE_SERVER_IDENTIFIER,
            DhcpOption::ParameterRequestList(_) => CODE_PARAMETER_REQUEST_LIST,
            DhcpOption::Message(_) => CODE_MESSAGE,
            DhcpOption::RenewalTime(_) => CODE_RENEWAL_TIME,
            DhcpOption::RebindingTime(_) => CODE_REBINDING_TIME,
            DhcpOption::VendorClassIdentifier(_) => CODE_VENDOR_CLASS_IDENTIFIER,
            DhcpOption::ClientIdentifier(_) => CODE_CLIENT_IDENTIFIER,
            DhcpOption::Other(c, _) => *c,
        }
    }

    /// Encode this option to its on-the-wire TLV representation (without the
    /// terminating `End` option, which the message layer appends).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            DhcpOption::MessageType(t) => vec![CODE_MESSAGE_TYPE, 1, t.to_u8()],
            DhcpOption::SubnetMask(ip) => opt_bytes(CODE_SUBNET_MASK, &ip.octets()),
            DhcpOption::TimeOffset(secs) => opt_bytes(CODE_TIME_OFFSET, &secs.to_be_bytes()),
            DhcpOption::Router(addrs) => opt_ipv4_list(CODE_ROUTER, addrs),
            DhcpOption::DomainNameServer(addrs) => opt_ipv4_list(CODE_DOMAIN_NAME_SERVER, addrs),
            DhcpOption::HostName(s) => opt_bytes(CODE_HOST_NAME, s.as_bytes()),
            DhcpOption::DomainName(s) => opt_bytes(CODE_DOMAIN_NAME, s.as_bytes()),
            DhcpOption::BroadcastAddress(ip) => opt_bytes(CODE_BROADCAST_ADDRESS, &ip.octets()),
            DhcpOption::RequestedIpAddress(ip) => {
                opt_bytes(CODE_REQUESTED_IP_ADDRESS, &ip.octets())
            }
            DhcpOption::LeaseTime(secs) => opt_bytes(CODE_LEASE_TIME, &secs.to_be_bytes()),
            DhcpOption::ServerIdentifier(ip) => opt_bytes(CODE_SERVER_IDENTIFIER, &ip.octets()),
            DhcpOption::ParameterRequestList(codes) => {
                opt_bytes(CODE_PARAMETER_REQUEST_LIST, codes)
            }
            DhcpOption::Message(s) => opt_bytes(CODE_MESSAGE, s.as_bytes()),
            DhcpOption::RenewalTime(secs) => opt_bytes(CODE_RENEWAL_TIME, &secs.to_be_bytes()),
            DhcpOption::RebindingTime(secs) => opt_bytes(CODE_REBINDING_TIME, &secs.to_be_bytes()),
            DhcpOption::VendorClassIdentifier(b) => opt_bytes(CODE_VENDOR_CLASS_IDENTIFIER, b),
            DhcpOption::ClientIdentifier(b) => opt_bytes(CODE_CLIENT_IDENTIFIER, b),
            DhcpOption::Other(c, b) => opt_bytes(*c, b),
        }
    }

    /// Leniently decode a single option from its `(code, value)` pair.
    ///
    /// Malformed values for known codes fall back to [`DhcpOption::Other`]
    /// rather than failing the whole message — DHCP receivers are expected to
    /// be tolerant of individual bad options.
    pub fn decode(code: u8, data: &[u8]) -> DhcpOption {
        let ip = |b: &[u8]| {
            if b.len() >= 4 {
                Some(Ipv4Addr::from([b[0], b[1], b[2], b[3]]))
            } else {
                None
            }
        };
        let ip_list = |b: &[u8]| -> Vec<Ipv4Addr> {
            b.chunks_exact(4)
                .map(|c| Ipv4Addr::from([c[0], c[1], c[2], c[3]]))
                .collect()
        };
        match code {
            CODE_SUBNET_MASK => ip(data)
                .map(DhcpOption::SubnetMask)
                .unwrap_or(DhcpOption::Other(code, data.to_vec())),
            CODE_TIME_OFFSET if data.len() == 4 => {
                let v = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                DhcpOption::TimeOffset(v)
            }
            CODE_ROUTER => DhcpOption::Router(ip_list(data)),
            CODE_DOMAIN_NAME_SERVER => DhcpOption::DomainNameServer(ip_list(data)),
            CODE_HOST_NAME => DhcpOption::HostName(String::from_utf8_lossy(data).into_owned()),
            CODE_DOMAIN_NAME => DhcpOption::DomainName(String::from_utf8_lossy(data).into_owned()),
            CODE_BROADCAST_ADDRESS => ip(data)
                .map(DhcpOption::BroadcastAddress)
                .unwrap_or(DhcpOption::Other(code, data.to_vec())),
            CODE_REQUESTED_IP_ADDRESS => ip(data)
                .map(DhcpOption::RequestedIpAddress)
                .unwrap_or(DhcpOption::Other(code, data.to_vec())),
            CODE_LEASE_TIME if data.len() == 4 => {
                let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                DhcpOption::LeaseTime(v)
            }
            CODE_MESSAGE_TYPE if data.len() == 1 => match MessageType::from_u8(data[0]) {
                Some(t) => DhcpOption::MessageType(t),
                None => DhcpOption::Other(code, data.to_vec()),
            },
            CODE_SERVER_IDENTIFIER => ip(data)
                .map(DhcpOption::ServerIdentifier)
                .unwrap_or(DhcpOption::Other(code, data.to_vec())),
            CODE_PARAMETER_REQUEST_LIST => DhcpOption::ParameterRequestList(data.to_vec()),
            CODE_MESSAGE => DhcpOption::Message(String::from_utf8_lossy(data).into_owned()),
            CODE_RENEWAL_TIME if data.len() == 4 => {
                let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                DhcpOption::RenewalTime(v)
            }
            CODE_REBINDING_TIME if data.len() == 4 => {
                let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                DhcpOption::RebindingTime(v)
            }
            CODE_VENDOR_CLASS_IDENTIFIER => DhcpOption::VendorClassIdentifier(data.to_vec()),
            CODE_CLIENT_IDENTIFIER => DhcpOption::ClientIdentifier(data.to_vec()),
            _ => DhcpOption::Other(code, data.to_vec()),
        }
    }
}

fn opt_bytes(code: u8, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(value.len() + 2);
    v.push(code);
    v.push(value.len() as u8);
    v.extend_from_slice(value);
    v
}

fn opt_ipv4_list(code: u8, addrs: &[Ipv4Addr]) -> Vec<u8> {
    let mut value = Vec::with_capacity(addrs.len() * 4);
    for a in addrs {
        value.extend_from_slice(&a.octets());
    }
    opt_bytes(code, &value)
}
