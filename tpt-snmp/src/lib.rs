// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-snmp
//!
//! A clean-room, dual-licensed implementation of SNMP covering **v1**, **v2c**
//! and **v3** with the User-based Security Model (USM), built from the RFCs:
//!
//! - RFC 3411 (architecture), RFC 3412 (message processing), RFC 3413
//!   (applications), RFC 3414 (USM: HMAC-MD5-96 / HMAC-SHA-96 auth and
//!   CBC-DES privacy), RFC 3416 (protocol operations for v2c/v3),
//!   RFC 3417 (transport mappings / BER usage), RFC 3418 (MIB objects).
//! - RFC 3826 (AES-CFB-128 privacy for USM).
//!
//! The design deliberately keeps the wire codec (a small, auditable subset of
//! BER), the SMI syntaxes, and the PDU/USM logic clean-room inside this crate
//! rather than depending on a general-purpose ASN.1 library. Cryptographic
//! primitives are reused where dual-licensed: `hmac`/`sha1`/`sha2` for
//! HMAC-SHA-96, `aes` for AES-CFB-128, while MD5 and DES are implemented
//! here (validated against published test vectors).
//!
//! ## What this crate provides
//!
//! - [`SnmpValue`] — the SMI application syntaxes (Integer, OctetString, OID,
//!   IpAddress, Counter32/64, Gauge32, TimeTicks, Opaque, and the v2
//!   exceptions `noSuchObject`/`noSuchInstance`/`endOfMibView`).
//! - [`VarBind`] / [`VarBindList`] — variable bindings.
//! - [`Pdu`] / [`Message`] — v1/v2c PDUs and community-string messages
//!   (`GetRequest`, `GetNextRequest`, `SetRequest`, `GetBulkRequest`,
//!   `Response`, `InformRequest`, `SNMPv2-Trap`, `Report`, and the v1 `Trap`).
//! - [`V3Message`] / [`v3`] — the SNMPv3 message with USM auth + privacy.
//! - [`Agent`] and [`Manager`] — a minimal agent (server) and manager
//!   (client) around a pluggable [`MibHandler`] and USM users.
//!
//! ## Example
//!
//! ```
//! use tpt_snmp::oid::ObjectIdentifier;
//! use tpt_snmp::value::{SnmpValue, VarBind};
//! use tpt_snmp::mib::InMemoryMib;
//! use tpt_snmp::agent::Agent;
//! use tpt_snmp::manager::Manager;
//!
//! let mut mib = InMemoryMib::new();
//! mib.insert(
//!     ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
//!     SnmpValue::from_str("tpt-snmp agent"),
//! );
//! let mut agent = Agent::new(mib, b"tptengine".to_vec());
//!
//! let mut mgr = Manager::v2c(b"public");
//! let req = mgr.build_get(&ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]));
//! let resp = agent.process(&req).expect("response");
//! let binds = mgr.parse_response(&resp).unwrap();
//! let got = &binds.0[0].value;
//! assert_eq!(got, &SnmpValue::from_str("tpt-snmp agent"));
//! ```
//!
//! For an authenticated + encrypted v3 exchange, register a USM user on the
//! agent (`Agent::add_user`) and create the [`Manager`] with
//! [`Manager::v3`] using the same passwords; the manager performs engine
//! discovery, authentication and (optionally) privacy automatically.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod agent;
mod ber;
pub mod crypto;
pub mod error;
pub mod manager;
pub mod mib;
pub mod oid;
pub mod pdu;
pub mod usm;
pub mod v3;
pub mod value;

pub use agent::Agent;
pub use error::{BerError, SnmpError};
pub use manager::Manager;
pub use mib::{InMemoryMib, MibHandler};
pub use oid::ObjectIdentifier;
pub use pdu::{Message, MessageData, Pdu, PduType, SnmpVersion, TrapV1};
pub use usm::{AuthProtocol, PrivProtocol};
pub use v3::{HeaderData, ScopedPdu, UsmSecurityParameters, V3Data, V3Message};
pub use value::{SnmpValue, VarBind, VarBindList};

/// A decoded SNMP message of any version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpMessage {
    /// A community-string (v1/v2c) message.
    Community(Message),
    /// An SNMPv3 (USM) message.
    V3(V3Message),
}

impl SnmpMessage {
    /// Encode the message to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SnmpMessage::Community(m) => m.encode(),
            SnmpMessage::V3(v) => v.encode(),
        }
    }

    /// Decode a message, dispatching on the `version` field.
    pub fn decode(bytes: &[u8]) -> Result<SnmpMessage, SnmpError> {
        if let Ok(m) = Message::decode(bytes) {
            return Ok(SnmpMessage::Community(m));
        }
        Ok(SnmpMessage::V3(V3Message::decode(bytes)?))
    }
}
