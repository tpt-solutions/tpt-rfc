// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DHCPv6 options (RFC 8415 §21), the DHCP Unique Identifier (DUID, §11), and
//! the Identity Association containers (IA_NA/IA_TA §21.4, IA_PD §21.21).
//!
//! Options are encoded as TLV tuples: a 2-byte code, a 2-byte length, then
//! `length` value bytes (RFC 8415 §21.1). IA options carry *nested* options in
//! their value field (e.g. an [`IaNa`] carries [`IaAddress`] entries), so this
//! module provides shared [`encode_options`] / [`parse_options`] helpers used
//! both at the message level and inside IA containers.
//!
//! Everything this crate does not specially understand is preserved verbatim via
//! [`Dhcpv6Option::Other`], so a message can be decoded and re-encoded without
//! loss.

use std::net::Ipv6Addr;

/// Option code: Client Identifier — a DUID (RFC 8415 §21.2).
pub const OPTION_CLIENTID: u16 = 1;
/// Option code: Server Identifier — a DUID (RFC 8415 §21.3).
pub const OPTION_SERVERID: u16 = 2;
/// Option code: Identity Association for Non-temporary Addresses (§21.4).
pub const OPTION_IA_NA: u16 = 3;
/// Option code: Identity Association for Temporary Addresses (§21.5).
pub const OPTION_IA_TA: u16 = 4;
/// Option code: IA Address — an address bound to an IA (§21.6).
pub const OPTION_IAADDR: u16 = 5;
/// Option code: Option Request Option — list of option codes the client wants (§21.7).
pub const OPTION_ORO: u16 = 6;
/// Option code: Preference — server selection hint (§21.8).
pub const OPTION_PREFERENCE: u16 = 7;
/// Option code: Elapsed Time — centiseconds since client began (§21.9).
pub const OPTION_ELAPSED_TIME: u16 = 8;
/// Option code: Relay Message — wrapped message for relay agents (§21.10).
pub const OPTION_RELAY_MSG: u16 = 9;
/// Option code: Authentication (§21.11).
pub const OPTION_AUTH: u16 = 11;
/// Option code: Server Unicast — address the client may unicast to (§21.12).
pub const OPTION_UNICAST: u16 = 12;
/// Option code: Status Code (§21.13).
pub const OPTION_STATUS_CODE: u16 = 13;
/// Option code: Rapid Commit — request REPLY instead of ADVERTISE (§21.14).
pub const OPTION_RAPID_COMMIT: u16 = 14;
/// Option code: User Class (§21.15).
pub const OPTION_USER_CLASS: u16 = 15;
/// Option code: Vendor Class (§21.16).
pub const OPTION_VENDOR_CLASS: u16 = 16;
/// Option code: Vendor-specific Information (§21.17).
pub const OPTION_VENDOR_OPTS: u16 = 17;
/// Option code: Interface-Id (relay, §21.18).
pub const OPTION_INTERFACE_ID: u16 = 18;
/// Option code: Reconfigure Message — type of message to expect (§21.19).
pub const OPTION_RECONF_MSG: u16 = 19;
/// Option code: Reconfigure Accept — client permits Reconfigure (§21.20).
pub const OPTION_RECONF_ACCEPT: u16 = 20;
/// Option code: DNS Recursive Name Server (RFC 3646 §3).
pub const OPTION_DNS_SERVERS: u16 = 23;
/// Option code: Domain Search List (RFC 3646 §4).
pub const OPTION_DOMAIN_SEARCH: u16 = 24;
/// Option code: Identity Association for Prefix Delegation (§21.21).
pub const OPTION_IA_PD: u16 = 25;
/// Option code: IA Prefix — a delegated prefix bound to an IA_PD (§21.22).
pub const OPTION_IAPREFIX: u16 = 26;

/// DUID type: DUID-LLT — link-layer address plus time (RFC 8415 §11.2).
pub const DUID_LLT: u16 = 1;
/// DUID type: DUID-EN — enterprise-assigned identifier (RFC 8415 §11.3).
pub const DUID_EN: u16 = 2;
/// DUID type: DUID-LL — link-layer address (RFC 8415 §11.4).
pub const DUID_LL: u16 = 3;
/// DUID type: DUID-UUID — RFC 4122 UUID (RFC 6355).
pub const DUID_UUID: u16 = 4;

/// Hardware type for Ethernet (RFC 826 / RFC 8415 §11.4).
pub const HARDWARE_ETHERNET: u16 = 1;

/// Status code: Success (RFC 8415 §21.13).
pub const STATUS_SUCCESS: u16 = 0;
/// Status code: Failure (RFC 8415 §21.13).
pub const STATUS_FAILURE: u16 = 1;
/// Status code: No addresses available (RFC 8415 §21.13).
pub const STATUS_NO_ADDRS_AVAIL: u16 = 2;
/// Status code: Binding not found (RFC 8415 §21.13).
pub const STATUS_NO_BINDING: u16 = 3;
/// Status code: Prefix not on link (RFC 8415 §21.13).
pub const STATUS_NOT_ON_LINK: u16 = 4;
/// Status code: Use multicast (RFC 8415 §21.13).
pub const STATUS_USE_MULTICAST: u16 = 5;
/// Status code: No prefixes available (RFC 8415 §21.13).
pub const STATUS_NO_PREFIX_AVAIL: u16 = 6;
/// Status code: Unknown query type (RFC 8415 §21.13).
pub const STATUS_UNKNOWN_QUERY_TYPE: u16 = 7;
/// Status code: Malformed query (RFC 8415 §21.13).
pub const STATUS_MALFORMED_QUERY: u16 = 8;
/// Status code: Not configured (RFC 8415 §21.13).
pub const STATUS_NOT_CONFIGURED: u16 = 9;
/// Status code: Not allowed (RFC 8415 §21.13).
pub const STATUS_NOT_ALLOWED: u16 = 10;

/// The kind of Identity Association an option refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IaKind {
    /// IA for non-temporary addresses (IA_NA, option 3).
    Na,
    /// IA for temporary addresses (IA_TA, option 4).
    Ta,
    /// IA for prefix delegation (IA_PD, option 25).
    Pd,
}

/// A DHCP Unique Identifier (RFC 8415 §11).
///
/// A DUID uniquely (with high probability) identifies a client or server. This
/// crate understands the four IETF-registered forms and preserves any other form
/// verbatim via [`Duid::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Duid {
    /// DUID-LLT: `hardware-type` + `time` + `link-layer-address` (§11.2).
    Llt {
        /// Hardware type (1 = Ethernet).
        hardware_type: u16,
        /// Seconds since 2000-01-01 (mod 2^32) at DUID creation.
        time: u32,
        /// Link-layer address bytes.
        link_layer: Vec<u8>,
    },
    /// DUID-EN: `enterprise-number` + private `identifier` (§11.3).
    En {
        /// IANA Private Enterprise Number.
        enterprise_number: u32,
        /// Vendor-defined identifier bytes.
        identifier: Vec<u8>,
    },
    /// DUID-LL: `hardware-type` + `link-layer-address` (§11.4).
    Ll {
        /// Hardware type (1 = Ethernet).
        hardware_type: u16,
        /// Link-layer address bytes.
        link_layer: Vec<u8>,
    },
    /// DUID-UUID: a raw 16-byte RFC 4122 UUID (RFC 6355).
    Uuid {
        /// The UUID bytes.
        uuid: [u8; 16],
    },
    /// Any unrecognised DUID, preserved verbatim.
    Other {
        /// The DUID type code.
        duid_type: u16,
        /// The raw DUID value (after the type/length header).
        data: Vec<u8>,
    },
}

impl Duid {
    /// Build a DUID-LL from an Ethernet MAC address (the most common form).
    pub fn from_ethernet_ll(mac: &[u8]) -> Duid {
        Duid::Ll {
            hardware_type: HARDWARE_ETHERNET,
            link_layer: mac.to_vec(),
        }
    }

    /// Encode the DUID, including its 2-byte type and 2-byte length header.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Duid::Llt {
                hardware_type,
                time,
                link_layer,
            } => {
                body.extend(hardware_type.to_be_bytes());
                body.extend(time.to_be_bytes());
                body.extend_from_slice(link_layer);
                encode_duid(DUID_LLT, &body)
            }
            Duid::En {
                enterprise_number,
                identifier,
            } => {
                body.extend(enterprise_number.to_be_bytes());
                body.extend_from_slice(identifier);
                encode_duid(DUID_EN, &body)
            }
            Duid::Ll {
                hardware_type,
                link_layer,
            } => {
                body.extend(hardware_type.to_be_bytes());
                body.extend_from_slice(link_layer);
                encode_duid(DUID_LL, &body)
            }
            Duid::Uuid { uuid } => {
                body.extend_from_slice(uuid);
                encode_duid(DUID_UUID, &body)
            }
            Duid::Other { duid_type, data } => encode_duid(*duid_type, data),
        }
    }

    /// Decode a DUID (including its type/length header) from wire bytes.
    ///
    /// Returns `None` on a structurally malformed DUID; callers typically fall
    /// back to preserving the raw bytes.
    pub fn decode(bytes: &[u8]) -> Option<Duid> {
        if bytes.len() < 4 {
            return None;
        }
        let duid_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + len {
            return None;
        }
        let d = &bytes[4..4 + len];
        Some(match duid_type {
            DUID_LLT => {
                if d.len() < 6 {
                    return None;
                }
                Duid::Llt {
                    hardware_type: u16::from_be_bytes([d[0], d[1]]),
                    time: u32::from_be_bytes([d[2], d[3], d[4], d[5]]),
                    link_layer: d[6..].to_vec(),
                }
            }
            DUID_EN => {
                if d.len() < 4 {
                    return None;
                }
                Duid::En {
                    enterprise_number: u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
                    identifier: d[4..].to_vec(),
                }
            }
            DUID_LL => {
                if d.len() < 2 {
                    return None;
                }
                Duid::Ll {
                    hardware_type: u16::from_be_bytes([d[0], d[1]]),
                    link_layer: d[2..].to_vec(),
                }
            }
            DUID_UUID => {
                if d.len() < 16 {
                    return None;
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&d[0..16]);
                Duid::Uuid { uuid }
            }
            t => Duid::Other {
                duid_type: t,
                data: d.to_vec(),
            },
        })
    }
}

fn encode_duid(duid_type: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.extend(duid_type.to_be_bytes());
    v.extend((data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// An address bound to an Identity Association (OPTION_IAADDR, §21.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaAddress {
    /// The IPv6 address.
    pub address: Ipv6Addr,
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds.
    pub valid_lifetime: u32,
    /// Nested options (typically a Status Code).
    pub options: Vec<Dhcpv6Option>,
}

/// A delegated prefix bound to an IA_PD (OPTION_IAPREFIX, §21.22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPrefix {
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds.
    pub valid_lifetime: u32,
    /// Prefix length in bits (0..=128).
    pub prefix_length: u8,
    /// The IPv6 prefix base address.
    pub prefix: Ipv6Addr,
    /// Nested options (typically a Status Code).
    pub options: Vec<Dhcpv6Option>,
}

/// Identity Association for Non-temporary Addresses (OPTION_IA_NA, §21.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaNa {
    /// Identity Association identifier (chosen by the client).
    pub iaid: u32,
    /// Renewal (T1) timer in seconds (0 = server default).
    pub t1: u32,
    /// Rebinding (T2) timer in seconds (0 = server default).
    pub t2: u32,
    /// Nested options, typically one or more [`Dhcpv6Option::IaAddr`] entries.
    pub options: Vec<Dhcpv6Option>,
}

/// Identity Association for Temporary Addresses (OPTION_IA_TA, §21.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaTa {
    /// Identity Association identifier (chosen by the client).
    pub iaid: u32,
    /// Nested options, typically [`Dhcpv6Option::IaAddr`] entries.
    pub options: Vec<Dhcpv6Option>,
}

/// Identity Association for Prefix Delegation (OPTION_IA_PD, §21.21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPd {
    /// Identity Association identifier (chosen by the client).
    pub iaid: u32,
    /// Renewal (T1) timer in seconds (0 = server default).
    pub t1: u32,
    /// Rebinding (T2) timer in seconds (0 = server default).
    pub t2: u32,
    /// Nested options, typically one or more [`Dhcpv6Option::IaPrefix`] entries.
    pub options: Vec<Dhcpv6Option>,
}

/// Status Code (OPTION_STATUS_CODE, §21.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCode {
    /// One of the `STATUS_*` constants.
    pub code: u16,
    /// Human-readable status message.
    pub message: String,
}

/// A single DHCPv6 option, typed where this crate understands it.
///
/// Unknown options are preserved verbatim via [`Dhcpv6Option::Other`] so that a
/// message can be decoded and re-encoded without loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dhcpv6Option {
    /// Client DUID (option 1).
    ClientId(Duid),
    /// Server DUID (option 2).
    ServerId(Duid),
    /// IA_NA container (option 3).
    IaNa(IaNa),
    /// IA_TA container (option 4).
    IaTa(IaTa),
    /// An address within an IA (option 5).
    IaAddr(IaAddress),
    /// Option Request Option (option 6).
    Oro(Vec<u16>),
    /// Server preference (option 7).
    Preference(u8),
    /// Elapsed time in centiseconds (option 8).
    ElapsedTime(u16),
    /// Server unicast address (option 12).
    Unicast(Ipv6Addr),
    /// Status code (option 13).
    StatusCode(StatusCode),
    /// Rapid commit flag (option 14).
    RapidCommit,
    /// Reconfigure accept flag (option 20).
    ReconfAccept,
    /// Reconfigure message type (option 19).
    ReconfMsg(MessageType),
    /// DNS recursive name servers (option 23).
    DnsServers(Vec<Ipv6Addr>),
    /// Domain search list (option 24).
    DomainSearch(Vec<String>),
    /// IA_PD container (option 25).
    IaPd(IaPd),
    /// A delegated prefix within an IA_PD (option 26).
    IaPrefix(IaPrefix),
    /// Any other option, preserved verbatim as (code, value).
    Other(u16, Vec<u8>),
}

impl Dhcpv6Option {
    /// The option code for this option.
    pub fn code(&self) -> u16 {
        match self {
            Dhcpv6Option::ClientId(_) => OPTION_CLIENTID,
            Dhcpv6Option::ServerId(_) => OPTION_SERVERID,
            Dhcpv6Option::IaNa(_) => OPTION_IA_NA,
            Dhcpv6Option::IaTa(_) => OPTION_IA_TA,
            Dhcpv6Option::IaAddr(_) => OPTION_IAADDR,
            Dhcpv6Option::Oro(_) => OPTION_ORO,
            Dhcpv6Option::Preference(_) => OPTION_PREFERENCE,
            Dhcpv6Option::ElapsedTime(_) => OPTION_ELAPSED_TIME,
            Dhcpv6Option::Unicast(_) => OPTION_UNICAST,
            Dhcpv6Option::StatusCode(_) => OPTION_STATUS_CODE,
            Dhcpv6Option::RapidCommit => OPTION_RAPID_COMMIT,
            Dhcpv6Option::ReconfAccept => OPTION_RECONF_ACCEPT,
            Dhcpv6Option::ReconfMsg(_) => OPTION_RECONF_MSG,
            Dhcpv6Option::DnsServers(_) => OPTION_DNS_SERVERS,
            Dhcpv6Option::DomainSearch(_) => OPTION_DOMAIN_SEARCH,
            Dhcpv6Option::IaPd(_) => OPTION_IA_PD,
            Dhcpv6Option::IaPrefix(_) => OPTION_IAPREFIX,
            Dhcpv6Option::Other(c, _) => *c,
        }
    }

    /// Encode this option to its on-the-wire TLV representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match self {
            Dhcpv6Option::ClientId(d) => data.extend(d.encode()),
            Dhcpv6Option::ServerId(d) => data.extend(d.encode()),
            Dhcpv6Option::IaNa(ia) => {
                data.extend(ia.iaid.to_be_bytes());
                data.extend(ia.t1.to_be_bytes());
                data.extend(ia.t2.to_be_bytes());
                data.extend(encode_options(&ia.options));
            }
            Dhcpv6Option::IaTa(ia) => {
                data.extend(ia.iaid.to_be_bytes());
                data.extend(encode_options(&ia.options));
            }
            Dhcpv6Option::IaAddr(a) => {
                data.extend(a.address.octets());
                data.extend(a.preferred_lifetime.to_be_bytes());
                data.extend(a.valid_lifetime.to_be_bytes());
                data.extend(encode_options(&a.options));
            }
            Dhcpv6Option::Oro(codes) => {
                for c in codes {
                    data.extend(c.to_be_bytes());
                }
            }
            Dhcpv6Option::Preference(p) => data.push(*p),
            Dhcpv6Option::ElapsedTime(t) => data.extend(t.to_be_bytes()),
            Dhcpv6Option::Unicast(ip) => data.extend(ip.octets()),
            Dhcpv6Option::StatusCode(s) => {
                data.extend(s.code.to_be_bytes());
                data.extend_from_slice(s.message.as_bytes());
            }
            Dhcpv6Option::RapidCommit | Dhcpv6Option::ReconfAccept => {}
            Dhcpv6Option::ReconfMsg(m) => data.push(m.to_u8()),
            Dhcpv6Option::DnsServers(servers) => {
                for s in servers {
                    data.extend(s.octets());
                }
            }
            Dhcpv6Option::DomainSearch(names) => {
                for n in names {
                    data.extend(encode_domain_name(n));
                }
            }
            Dhcpv6Option::IaPd(ia) => {
                data.extend(ia.iaid.to_be_bytes());
                data.extend(ia.t1.to_be_bytes());
                data.extend(ia.t2.to_be_bytes());
                data.extend(encode_options(&ia.options));
            }
            Dhcpv6Option::IaPrefix(p) => {
                data.extend(p.preferred_lifetime.to_be_bytes());
                data.extend(p.valid_lifetime.to_be_bytes());
                data.push(p.prefix_length);
                data.extend(p.prefix.octets());
                data.extend(encode_options(&p.options));
            }
            Dhcpv6Option::Other(_, b) => data.extend_from_slice(b),
        }
        let mut out = Vec::with_capacity(data.len() + 4);
        out.extend(self.code().to_be_bytes());
        out.extend((data.len() as u16).to_be_bytes());
        out.extend(data);
        out
    }

    /// Leniently decode a single option from its `(code, value)` pair.
    ///
    /// Malformed values for known codes fall back to [`Dhcpv6Option::Other`]
    /// rather than failing the whole message — DHCPv6 receivers are expected to
    /// be tolerant of individual bad options.
    pub fn decode(code: u16, data: &[u8]) -> Dhcpv6Option {
        match code {
            OPTION_CLIENTID => match Duid::decode(data) {
                Some(d) => Dhcpv6Option::ClientId(d),
                None => Dhcpv6Option::Other(code, data.to_vec()),
            },
            OPTION_SERVERID => match Duid::decode(data) {
                Some(d) => Dhcpv6Option::ServerId(d),
                None => Dhcpv6Option::Other(code, data.to_vec()),
            },
            OPTION_IA_NA if data.len() >= 12 => {
                let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let t1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let t2 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                Dhcpv6Option::IaNa(IaNa {
                    iaid,
                    t1,
                    t2,
                    options: parse_options(&data[12..]),
                })
            }
            OPTION_IA_TA if data.len() >= 4 => {
                let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Dhcpv6Option::IaTa(IaTa {
                    iaid,
                    options: parse_options(&data[4..]),
                })
            }
            OPTION_IAADDR if data.len() >= 24 => {
                let address = Ipv6Addr::from(<[u8; 16]>::try_from(&data[0..16]).unwrap());
                let preferred_lifetime = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
                let valid_lifetime = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
                Dhcpv6Option::IaAddr(IaAddress {
                    address,
                    preferred_lifetime,
                    valid_lifetime,
                    options: parse_options(&data[24..]),
                })
            }
            OPTION_ORO if data.len() % 2 == 0 => {
                let mut codes = Vec::with_capacity(data.len() / 2);
                let mut i = 0;
                while i + 2 <= data.len() {
                    codes.push(u16::from_be_bytes([data[i], data[i + 1]]));
                    i += 2;
                }
                Dhcpv6Option::Oro(codes)
            }
            OPTION_PREFERENCE if data.len() == 1 => Dhcpv6Option::Preference(data[0]),
            OPTION_ELAPSED_TIME if data.len() == 2 => {
                Dhcpv6Option::ElapsedTime(u16::from_be_bytes([data[0], data[1]]))
            }
            OPTION_UNICAST if data.len() == 16 => {
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[0..16]).unwrap());
                Dhcpv6Option::Unicast(ip)
            }
            OPTION_STATUS_CODE if data.len() >= 2 => {
                let code = u16::from_be_bytes([data[0], data[1]]);
                let message = String::from_utf8_lossy(&data[2..]).into_owned();
                Dhcpv6Option::StatusCode(StatusCode { code, message })
            }
            OPTION_RAPID_COMMIT => Dhcpv6Option::RapidCommit,
            OPTION_RECONF_ACCEPT => Dhcpv6Option::ReconfAccept,
            OPTION_RECONF_MSG if data.len() == 1 => match MessageType::from_u8(data[0]) {
                Some(m) => Dhcpv6Option::ReconfMsg(m),
                None => Dhcpv6Option::Other(code, data.to_vec()),
            },
            OPTION_DNS_SERVERS if data.len() % 16 == 0 => {
                let mut servers = Vec::with_capacity(data.len() / 16);
                let mut i = 0;
                while i + 16 <= data.len() {
                    servers.push(Ipv6Addr::from(<[u8; 16]>::try_from(&data[i..i + 16]).unwrap()));
                    i += 16;
                }
                Dhcpv6Option::DnsServers(servers)
            }
            OPTION_DOMAIN_SEARCH => Dhcpv6Option::DomainSearch(decode_domain_names(data)),
            OPTION_IA_PD if data.len() >= 12 => {
                let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let t1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let t2 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                Dhcpv6Option::IaPd(IaPd {
                    iaid,
                    t1,
                    t2,
                    options: parse_options(&data[12..]),
                })
            }
            OPTION_IAPREFIX if data.len() >= 25 => {
                let preferred_lifetime = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let valid_lifetime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let prefix_length = data[8];
                let prefix = Ipv6Addr::from(<[u8; 16]>::try_from(&data[9..25]).unwrap());
                Dhcpv6Option::IaPrefix(IaPrefix {
                    preferred_lifetime,
                    valid_lifetime,
                    prefix_length,
                    prefix,
                    options: parse_options(&data[25..]),
                })
            }
            _ => Dhcpv6Option::Other(code, data.to_vec()),
        }
    }
}

/// Encode a list of options into the wire representation (no surrounding
/// framing).
pub fn encode_options(opts: &[Dhcpv6Option]) -> Vec<u8> {
    let mut v = Vec::new();
    for o in opts {
        v.extend(o.encode());
    }
    v
}

/// Parse a sequence of TLV options from a value field (used both at the message
/// level and inside IA containers).
pub fn parse_options(mut data: &[u8]) -> Vec<Dhcpv6Option> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let code = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            break;
        }
        let opt_data = &data[4..4 + len];
        out.push(Dhcpv6Option::decode(code, opt_data));
        data = &data[4 + len..];
    }
    out
}

fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v
}

fn decode_domain_names(mut data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let mut labels = Vec::new();
        let mut j = 0usize;
        let mut consumed = 0usize;
        loop {
            if j >= data.len() {
                break;
            }
            let len = data[j] as usize;
            if len == 0 {
                j += 1;
                consumed = j;
                break;
            }
            if len > 63 {
                break;
            }
            j += 1;
            if j + len > data.len() {
                break;
            }
            labels.push(String::from_utf8_lossy(&data[j..j + len]).into_owned());
            j += len;
            consumed = j;
        }
        if labels.is_empty() {
            break;
        }
        out.push(labels.join("."));
        data = &data[consumed..];
    }
    out
}

/// DHCPv6 message types (RFC 8415 §7.3, §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// SOLICIT (1) — client locates servers.
    Solicit,
    /// ADVERTISE (2) — server offers configuration.
    Advertise,
    /// REQUEST (3) — client requests configuration.
    Request,
    /// CONFIRM (4) — client confirms addresses are still on-link.
    Confirm,
    /// RENEW (5) — client renews with the leasing server.
    Renew,
    /// REBIND (6) — client rebinds with any server.
    Rebind,
    /// REPLY (7) — server replies with configuration.
    Reply,
    /// RELEASE (8) — client relinquishes resources.
    Release,
    /// DECLINE (9) — client reports a conflict.
    Decline,
    /// RECONFIGURE (10) — server triggers reconfiguration.
    Reconfigure,
    /// INFORMATION-REQUEST (11) — client requests stateless config only.
    InformationRequest,
    /// RELAY-FORW (12) — relay agent forward.
    RelayForw,
    /// RELAY-REPLY (13) — relay agent reply.
    RelayReply,
}

impl MessageType {
    /// Map a wire value to a [`MessageType`].
    pub fn from_u8(v: u8) -> Option<MessageType> {
        match v {
            1 => Some(MessageType::Solicit),
            2 => Some(MessageType::Advertise),
            3 => Some(MessageType::Request),
            4 => Some(MessageType::Confirm),
            5 => Some(MessageType::Renew),
            6 => Some(MessageType::Rebind),
            7 => Some(MessageType::Reply),
            8 => Some(MessageType::Release),
            9 => Some(MessageType::Decline),
            10 => Some(MessageType::Reconfigure),
            11 => Some(MessageType::InformationRequest),
            12 => Some(MessageType::RelayForw),
            13 => Some(MessageType::RelayReply),
            _ => None,
        }
    }

    /// Map a [`MessageType`] to its wire value.
    pub fn to_u8(self) -> u8 {
        match self {
            MessageType::Solicit => 1,
            MessageType::Advertise => 2,
            MessageType::Request => 3,
            MessageType::Confirm => 4,
            MessageType::Renew => 5,
            MessageType::Rebind => 6,
            MessageType::Reply => 7,
            MessageType::Release => 8,
            MessageType::Decline => 9,
            MessageType::Reconfigure => 10,
            MessageType::InformationRequest => 11,
            MessageType::RelayForw => 12,
            MessageType::RelayReply => 13,
        }
    }

    /// Whether this message type is a relay agent message (not handled by the
    /// client/server FSMs in this crate).
    pub fn is_relay(self) -> bool {
        matches!(self, MessageType::RelayForw | MessageType::RelayReply)
    }
}
