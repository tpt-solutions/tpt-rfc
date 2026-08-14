// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RADIUS attributes (Attribute-Value-Pairs).
//!
//! Each attribute is encoded on the wire as `Type (1) | Length (1) | Value (n)`
//! where `Length` covers the two header octets plus the value. This module
//! defines the 1-octet [`AttributeType`] registry from RFC 2865 §5.44 and the
//! generic [`Attribute`] container, with typed accessors and constructors for
//! the attributes this crate handles directly. Vendor-Specific (26) and
//! EAP-Message (79) values are carried opaquely and exposed via helpers.

use std::net::Ipv4Addr;

use crate::error::RadiusError;

/// A RADIUS attribute type (the 1-octet `Type` field of an AVP).
///
/// Only the well-known types from RFC 2865 §5.44 are given named constants;
/// any other type code is still representable via [`AttributeType::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttributeType(pub u8);

impl AttributeType {
    /// Construct an attribute type from a raw code.
    pub const fn new(code: u8) -> AttributeType {
        AttributeType(code)
    }

    /// `User-Name` (1).
    pub const USER_NAME: AttributeType = AttributeType(1);
    /// `User-Password` (2).
    pub const USER_PASSWORD: AttributeType = AttributeType(2);
    /// `CHAP-Password` (3).
    pub const CHAP_PASSWORD: AttributeType = AttributeType(3);
    /// `NAS-IP-Address` (4).
    pub const NAS_IP_ADDRESS: AttributeType = AttributeType(4);
    /// `NAS-Port` (5).
    pub const NAS_PORT: AttributeType = AttributeType(5);
    /// `Service-Type` (6).
    pub const SERVICE_TYPE: AttributeType = AttributeType(6);
    /// `Framed-Protocol` (7).
    pub const FRAMED_PROTOCOL: AttributeType = AttributeType(7);
    /// `Framed-IP-Address` (8).
    pub const FRAMED_IP_ADDRESS: AttributeType = AttributeType(8);
    /// `Framed-IP-Netmask` (9).
    pub const FRAMED_IP_NETMASK: AttributeType = AttributeType(9);
    /// `Framed-Routing` (10).
    pub const FRAMED_ROUTING: AttributeType = AttributeType(10);
    /// `Filter-Id` (11).
    pub const FILTER_ID: AttributeType = AttributeType(11);
    /// `Framed-MTU` (12).
    pub const FRAMED_MTU: AttributeType = AttributeType(12);
    /// `Framed-Compression` (13).
    pub const FRAMED_COMPRESSION: AttributeType = AttributeType(13);
    /// `Login-IP-Host` (14).
    pub const LOGIN_IP_HOST: AttributeType = AttributeType(14);
    /// `Login-Service` (15).
    pub const LOGIN_SERVICE: AttributeType = AttributeType(15);
    /// `Login-TCP-Port` (16).
    pub const LOGIN_TCP_PORT: AttributeType = AttributeType(16);
    /// `Reply-Message` (18).
    pub const REPLY_MESSAGE: AttributeType = AttributeType(18);
    /// `Callback-Number` (19).
    pub const CALLBACK_NUMBER: AttributeType = AttributeType(19);
    /// `Callback-Id` (20).
    pub const CALLBACK_ID: AttributeType = AttributeType(20);
    /// `Framed-Route` (22).
    pub const FRAMED_ROUTE: AttributeType = AttributeType(22);
    /// `Framed-IPX-Network` (23).
    pub const FRAMED_IPX_NETWORK: AttributeType = AttributeType(23);
    /// `State` (24).
    pub const STATE: AttributeType = AttributeType(24);
    /// `Class` (25).
    pub const CLASS: AttributeType = AttributeType(25);
    /// `Vendor-Specific` (26).
    pub const VENDOR_SPECIFIC: AttributeType = AttributeType(26);
    /// `Session-Timeout` (27).
    pub const SESSION_TIMEOUT: AttributeType = AttributeType(27);
    /// `Idle-Timeout` (28).
    pub const IDLE_TIMEOUT: AttributeType = AttributeType(28);
    /// `Termination-Action` (29).
    pub const TERMINATION_ACTION: AttributeType = AttributeType(29);
    /// `Called-Station-Id` (30).
    pub const CALLED_STATION_ID: AttributeType = AttributeType(30);
    /// `Calling-Station-Id` (31).
    pub const CALLING_STATION_ID: AttributeType = AttributeType(31);
    /// `NAS-Identifier` (32).
    pub const NAS_IDENTIFIER: AttributeType = AttributeType(32);
    /// `Proxy-State` (33).
    pub const PROXY_STATE: AttributeType = AttributeType(33);
    /// `Login-LAT-Service` (34).
    pub const LOGIN_LAT_SERVICE: AttributeType = AttributeType(34);
    /// `Login-LAT-Node` (35).
    pub const LOGIN_LAT_NODE: AttributeType = AttributeType(35);
    /// `Login-LAT-Group` (36).
    pub const LOGIN_LAT_GROUP: AttributeType = AttributeType(36);
    /// `Framed-AppleTalk-Link` (37).
    pub const FRAMED_APPLETALK_LINK: AttributeType = AttributeType(37);
    /// `Framed-AppleTalk-Network` (38).
    pub const FRAMED_APPLETALK_NETWORK: AttributeType = AttributeType(38);
    /// `Framed-AppleTalk-Zone` (39).
    pub const FRAMED_APPLETALK_ZONE: AttributeType = AttributeType(39);
    /// `Acct-Status-Type` (RFC 2866, 40).
    pub const ACCT_STATUS_TYPE: AttributeType = AttributeType(40);
    /// `Acct-Delay-Time` (RFC 2866, 41).
    pub const ACCT_DELAY_TIME: AttributeType = AttributeType(41);
    /// `Acct-Input-Octets` (RFC 2866, 42).
    pub const ACCT_INPUT_OCTETS: AttributeType = AttributeType(42);
    /// `Acct-Output-Octets` (RFC 2866, 43).
    pub const ACCT_OUTPUT_OCTETS: AttributeType = AttributeType(43);
    /// `Acct-Session-Id` (RFC 2866, 44).
    pub const ACCT_SESSION_ID: AttributeType = AttributeType(44);
    /// `Acct-Authentic` (RFC 2866, 45).
    pub const ACCT_AUTHENTIC: AttributeType = AttributeType(45);
    /// `Acct-Session-Time` (RFC 2866, 46).
    pub const ACCT_SESSION_TIME: AttributeType = AttributeType(46);
    /// `Acct-Input-Packets` (RFC 2866, 47).
    pub const ACCT_INPUT_PACKETS: AttributeType = AttributeType(47);
    /// `Acct-Output-Packets` (RFC 2866, 48).
    pub const ACCT_OUTPUT_PACKETS: AttributeType = AttributeType(48);
    /// `Acct-Terminate-Cause` (RFC 2866, 49).
    pub const ACCT_TERMINATE_CAUSE: AttributeType = AttributeType(49);
    /// `Acct-Input-Gigawords` (RFC 2866, 52).
    pub const ACCT_INPUT_GIGAWORDS: AttributeType = AttributeType(52);
    /// `Acct-Output-Gigawords` (RFC 2866, 53).
    pub const ACCT_OUTPUT_GIGAWORDS: AttributeType = AttributeType(53);
    /// `Event-Timestamp` (RFC 2869, 55).
    pub const EVENT_TIMESTAMP: AttributeType = AttributeType(55);
    /// `CHAP-Challenge` (60).
    pub const CHAP_CHALLENGE: AttributeType = AttributeType(60);
    /// `NAS-Port-Type` (61).
    pub const NAS_PORT_TYPE: AttributeType = AttributeType(61);
    /// `Port-Limit` (62).
    pub const PORT_LIMIT: AttributeType = AttributeType(62);
    /// `Login-LAT-Port` (63).
    pub const LOGIN_LAT_PORT: AttributeType = AttributeType(63);
    /// `Acct-Interim-Interval` (RFC 2869, 85).
    pub const ACCT_INTERIM_INTERVAL: AttributeType = AttributeType(85);
    /// `EAP-Message` (RFC 3579, 79).
    pub const EAP_MESSAGE: AttributeType = AttributeType(79);
    /// `Message-Authenticator` (RFC 3579, 80).
    pub const MESSAGE_AUTHENTICATOR: AttributeType = AttributeType(80);
}

/// A RADIUS attribute (AVP): a [`type`][`Attribute::type_`], its `Length`, and
/// the raw `Value` octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute type.
    pub type_: AttributeType,
    /// The raw attribute value (not including the 2-octet type/length header).
    pub value: Vec<u8>,
}

impl Attribute {
    /// Create an attribute from a type and value.
    pub fn new(type_: AttributeType, value: impl Into<Vec<u8>>) -> Attribute {
        Attribute {
            type_,
            value: value.into(),
        }
    }

    /// Create an attribute from a raw type code and value.
    pub fn raw(type_code: u8, value: impl Into<Vec<u8>>) -> Attribute {
        Attribute::new(AttributeType(type_code), value)
    }

    /// The 1-octet type code of this attribute.
    pub fn type_code(&self) -> u8 {
        self.type_.0
    }

    /// Borrow the raw value octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Interpret the value as UTF-8 text (e.g. `User-Name`).
    pub fn as_text(&self) -> Result<&str, RadiusError> {
        std::str::from_utf8(&self.value).map_err(|_| RadiusError::InvalidUtf8(self.type_))
    }

    /// Interpret the value as a big-endian `u32` (e.g. `NAS-Port`).
    pub fn as_u32(&self) -> Result<u32, RadiusError> {
        if self.value.len() != 4 {
            return Err(RadiusError::InvalidLength(self.type_));
        }
        Ok(u32::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]))
    }

    /// Interpret the value as an IPv4 address (e.g. `NAS-IP-Address`).
    pub fn as_ipv4(&self) -> Result<Ipv4Addr, RadiusError> {
        if self.value.len() != 4 {
            return Err(RadiusError::InvalidLength(self.type_));
        }
        Ok(Ipv4Addr::new(
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ))
    }

    /// `User-Name` (1) from a string.
    pub fn user_name(name: &str) -> Attribute {
        Attribute::new(AttributeType::USER_NAME, name.as_bytes().to_vec())
    }

    /// `User-Password` (2) from raw hidden octets (use [`crate::Packet`] for hiding).
    pub fn user_password_hidden(value: &[u8]) -> Attribute {
        Attribute::new(AttributeType::USER_PASSWORD, value.to_vec())
    }

    /// `NAS-IP-Address` (4) from an IPv4 address.
    pub fn nas_ip_address(ip: Ipv4Addr) -> Attribute {
        Attribute::new(AttributeType::NAS_IP_ADDRESS, ip.octets().to_vec())
    }

    /// `NAS-Port` (5) from a `u32`.
    pub fn nas_port(port: u32) -> Attribute {
        Attribute::new(AttributeType::NAS_PORT, port.to_be_bytes().to_vec())
    }

    /// `NAS-Identifier` (32) from a string.
    pub fn nas_identifier(id: &str) -> Attribute {
        Attribute::new(AttributeType::NAS_IDENTIFIER, id.as_bytes().to_vec())
    }

    /// `Service-Type` (6) from a `u32`.
    pub fn service_type(value: u32) -> Attribute {
        Attribute::new(AttributeType::SERVICE_TYPE, value.to_be_bytes().to_vec())
    }

    /// `Login-Service` (15) from a `u32`.
    pub fn login_service(value: u32) -> Attribute {
        Attribute::new(AttributeType::LOGIN_SERVICE, value.to_be_bytes().to_vec())
    }

    /// `Login-IP-Host` (14) from an IPv4 address.
    pub fn login_ip_host(ip: Ipv4Addr) -> Attribute {
        Attribute::new(AttributeType::LOGIN_IP_HOST, ip.octets().to_vec())
    }

    /// `Reply-Message` (18) from a string.
    pub fn reply_message(msg: &str) -> Attribute {
        Attribute::new(AttributeType::REPLY_MESSAGE, msg.as_bytes().to_vec())
    }

    /// `State` (24) from arbitrary octets.
    pub fn state(data: &[u8]) -> Attribute {
        Attribute::new(AttributeType::STATE, data.to_vec())
    }

    /// `Vendor-Specific` (26): a 4-octet vendor-id followed by vendor data.
    pub fn vendor_specific(vendor_id: u32, data: &[u8]) -> Attribute {
        let mut value = Vec::with_capacity(4 + data.len());
        value.extend_from_slice(&vendor_id.to_be_bytes());
        value.extend_from_slice(data);
        Attribute::new(AttributeType::VENDOR_SPECIFIC, value)
    }

    /// `Proxy-State` (33) from arbitrary octets.
    pub fn proxy_state(data: &[u8]) -> Attribute {
        Attribute::new(AttributeType::PROXY_STATE, data.to_vec())
    }

    /// `EAP-Message` (79) from a single EAP fragment. Use
    /// [`crate::Packet::add_eap_message`] to split long payloads.
    pub fn eap_message(data: &[u8]) -> Attribute {
        Attribute::new(AttributeType::EAP_MESSAGE, data.to_vec())
    }

    /// `Message-Authenticator` (80) from a 16-octet HMAC tag.
    pub fn message_authenticator(tag: &[u8; 16]) -> Attribute {
        Attribute::new(AttributeType::MESSAGE_AUTHENTICATOR, tag.to_vec())
    }

    /// `Acct-Status-Type` (RFC 2866, 40) from a `u32`.
    pub fn acct_status_type(value: u32) -> Attribute {
        Attribute::new(
            AttributeType::ACCT_STATUS_TYPE,
            value.to_be_bytes().to_vec(),
        )
    }

    /// `Acct-Session-Id` (RFC 2866, 44) from a string.
    pub fn acct_session_id(id: &str) -> Attribute {
        Attribute::new(AttributeType::ACCT_SESSION_ID, id.as_bytes().to_vec())
    }
}

/// Split a `Vendor-Specific` (26) attribute value into its 4-octet vendor id
/// and the remaining vendor-defined data.
pub fn split_vendor_specific(value: &[u8]) -> Option<(u32, &[u8])> {
    if value.len() < 4 {
        return None;
    }
    let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    Some((vendor_id, &value[4..]))
}
