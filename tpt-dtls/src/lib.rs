// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-dtls
//!
//! A clean-room, dual-licensed implementation of **DTLS 1.3**
//! ([RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)) — the Datagram
//! Transport Layer Security protocol for UDP. DTLS 1.3 is the datagram
//! cousin of TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446));
//! this crate implements the DTLS-specific machinery that TLS 1.3 lacks
//! (explicit epoch/sequence-number records, handshake fragmentation and
//! reassembly, stateless cookie exchange, message-driven retransmission,
//! anti-replay, and Connection IDs per
//! [RFC 9146](https://www.rfc-editor.org/rfc/rfc9146)) on top of a faithful
//! TLS 1.3 key schedule and record protection.
//!
//! No code was copied from any existing DTLS/TLS implementation; every
//! structure is built independently from the RFC text, reusing only
//! dual-licensed *cryptographic primitives* (RustCrypto `sha2`/`hkdf`/
//! `hmac`, `orion` for X25519, `ed25519-compact` for Ed25519, and the
//! RustCrypto `aes-gcm`/`chacha20poly1305` AEADs).
//!
//! ## What is implemented
//!
//! - **Record layer** ([`record`]): DTLS 1.3 record framing with 16-bit
//!   epoch and 48-bit sequence numbers, AEAD seal/open with the
//!   TLS 1.3 additional-data and nonce-construction rules, and an optional
//!   trailing **Connection ID** (RFC 9146).
//! - **Anti-replay** ([`replay`]): a sliding-window checker per epoch
//!   (RFC 9147 §4.4).
//! - **Handshake framing** ([`handshake`]): all DTLS 1.3 handshake message
//!   types with the DTLS fragment-offset/reassembly header, including a
//!   fragment reassembler.
//! - **Stateless cookie exchange** ([`cookie`]): the DTLS HelloRetryRequest
//!   cookie mechanism (RFC 9147 §4.2.3 / §5.2) implemented as an HMAC over
//!   the client's echoed parameters — no server-side state required before
//!   the second ClientHello.
//! - **Retransmission** ([`retransmit`]): the DTLS message-driven
//!   retransmission timer with exponential backoff (RFC 9147 §5.2).
//! - **Key schedule** ([`keyschedule`]): the full TLS 1.3 (EC)DHE key
//!   schedule (HKDF-Extract / ExpandLabel / Derive-Secret / traffic-secret
//!   and key/IV derivation) for SHA-256 and SHA-384 suites.
//! - **Connection** ([`connection`]): a transport-agnostic client/server
//!   state machine that drives the 1-RTT handshake (including the cookie
//!   round-trip), derives handshake and application-traffic keys, and
//!   protects application data. The reference handshake authenticates
//!   peers with **raw public keys** ([RFC 7250](https://www.rfc-editor.org/rfc/rfc7250))
//!   carried in the Certificate message, verifying Ed25519
//!   CertificateVerify signatures directly — keeping the crate self-contained
//!   (no X.509 dependency). A pluggable certificate verifier trait allows
//!   full PKI validation to be layered on later (e.g. via `tpt-x509`).
//!
//! ## Scope notes
//!
//! - 0-RTT early data, post-handshake auth, and session resumption (PSK) are
//!   intentionally out of scope for this release (documented in
//!   `SPEC-NOTES.md`).
//! - The reference handshake uses raw public keys; X.509 certificate path
//!   validation is delegated to a pluggable verifier (the default test
//!   verifier trusts the peer's raw key). Full RFC 5280 validation is a
//!   separate platform crate (`tpt-x509`, Phase 4).
//! - Interop testing against OpenSSL's DTLS 1.3 is **blocked** in this
//!   environment (no OpenSSL toolchain present); conformance is instead
//!   demonstrated by the in-crate end-to-end handshake harness (see
//!   `tests/handshake_integration.rs`).

#![warn(missing_docs)]

pub mod connection;
pub mod cookie;
pub mod crypto;
pub mod error;
pub mod handshake;
pub mod keyschedule;
pub mod record;
pub mod replay;
pub mod retransmit;
pub mod wire;

pub use connection::{
    AcceptAllVerifier, CertVerifier, ClientConfig, Connection, ConnectionRole, ServerConfig,
};
pub use crypto::{CipherSuite, HashAlg};
pub use error::DtlsError;
pub use handshake::{HandshakeMessage, HandshakeType};
pub use record::{ConnectionId, RecordHeader};
pub use replay::ReplayWindow;
