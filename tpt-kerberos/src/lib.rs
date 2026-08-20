// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-kerberos
//!
//! A clean-room, dual-licensed implementation of **Kerberos v5**
//! ([RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)) together with **SPNEGO**
//! ([RFC 4178](https://www.rfc-editor.org/rfc/rfc4178)) GSSAPI mechanism
//! negotiation.
//!
//! The only full-featured Rust Kerberos *client* (`kerbeiros`, from the
//! Himmelblau project) is **AGPL-3.0** — unusable as a dependency or "gap closed"
//! for this dual MIT/Apache-2.0 platform. This crate provides a from-spec, fully
//! auditable client *and* KDC (key-distribution-centre) implementation, built on
//! the AES encryption types of RFC 3962 / RFC 8009.
//!
//! ## What is implemented
//!
//! - The Kerberos v5 ASN.1 wire types (APPLICATION-tagged PDUs) for the AS,
//!   TGS, and AP exchanges (`types`).
//! - The AES encryption types `aes128/aes256-cts-hmac-sha1-96` (17/18, RFC 3962)
//!   and `aes128/aes256-cts-hmac-sha256/384` (19/20, RFC 8009): `string2key`
//!   (PBKDF2), key derivation, AES-CTS, and HMAC checksums (`crypto`).
//! - A client that performs the AS-REQ/AS-REP and TGS-REQ/TGS-REP exchanges and
//!   caches credentials (`client`).
//! - A service side that accepts AP-REQ and validates tickets, optionally
//!   replying with AP-REP (`service`).
//! - An in-memory KDC for testing/self-contained operation (`kdc`).
//! - SPNEGO `NegTokenInit` / `NegTokenResp` GSSAPI negotiation (`spnego`).
//!
//! ## Example (self-contained KDC)
//!
//! ```
//! use tpt_kerberos::client::Client;
//! use tpt_kerberos::kdc::MemoryKdc;
//! use tpt_kerberos::crypto::ENCTYPE_AES256_CTS_HMAC_SHA1_96;
//!
//! let mut kdc = MemoryKdc::new();
//! kdc.add_principal("alice", "EXAMPLE.COM", "secret", ENCTYPE_AES256_CTS_HMAC_SHA1_96).unwrap();
//! kdc.add_service("host/server.example.com", "EXAMPLE.COM", "svcpass", ENCTYPE_AES256_CTS_HMAC_SHA1_96).unwrap();
//!
//! let mut client = Client::new("alice", "EXAMPLE.COM");
//! client.authenticate(&kdc, "secret").unwrap();
//! client.service_ticket(&kdc, "host/server.example.com@EXAMPLE.COM").unwrap();
//! let ap_req = client.make_ap_req("host/server.example.com@EXAMPLE.COM").unwrap();
//! assert!(!ap_req.is_empty());
//! ```
//!
//! ## Interop
//!
//! Interop-testing against a real KDC (MIT Kerberos, Heimdal, Active Directory)
//! is **blocked** in this environment; the crate is instead verified by the
//! in-crate round-trip harness (AS/TGS/AP exchanges against the in-memory KDC)
//! plus known-answer crypto vectors (RFC 3962 / RFC 8009) and SPNEGO wire tests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod asn1;
pub mod client;
pub mod crypto;
pub mod error;
pub mod kdc;
pub mod service;
pub mod spnego;
pub mod types;

pub use error::{Error, Result};

/// Convenience re-exports of the most common enctype constants.
pub use crypto::{
    ENCTYPE_AES128_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA256_128,
    ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES256_CTS_HMAC_SHA384_192,
};

/// Key-usage values (RFC 4120 §7.5.1, RFC 3961 §6).
///
/// These are the canonical RFC 4120 key-usage numbers and are what this crate
/// uses when encrypting/decrypting each `EncryptedData` field. (Interop against
/// a foreign KDC is a separate concern; the in-crate KDC and client agree on
/// these values.)
pub mod key_usage {
    /// AS-REQ PA-ENC-TIMESTAMP (RFC 4120 §5.2.7.2).
    pub const PA_ENC_TIMESTAMP: u32 = 1;
    /// Ticket (both AS-REP TGT and TGS-REP service ticket).
    pub const TICKET: u32 = 2;
    /// AS-REP encrypted part (EncASRepPart).
    pub const AS_REP: u32 = 3;
    /// TGS-REQ KDC-REQ-BODY (enc-authorization-data, when present).
    pub const TGS_REQ_BODY: u32 = 4;
    /// TGS-REP ticket.
    pub const TGS_REP_TICKET: u32 = 6;
    /// AP-REQ authenticator (encrypted with the ticket session key).
    pub const AP_REQ_AUTH: u32 = 7;
    /// AP-REP encrypted part (EncAPRepPart).
    pub const AP_REP: u32 = 8;
    /// TGS-REP encrypted part (EncTGSRepPart).
    pub const TGS_REP: u32 = 8;
    /// GSSAPI MIC (RFC 4121).
    pub const GSS_MIC: u32 = 23;
}
