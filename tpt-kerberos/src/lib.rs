//! `tpt-kerberos` — clean-room, dual-licensed (MIT OR Apache-2.0) implementation of
//! **Kerberos v5 (RFC 4120)** and **SPNEGO (RFC 4178)**.
//!
//! This crate provides the cryptographic core (RFC 3961 / RFC 3962 / RFC 8009),
//! the ASN.1 DER wire structures, the client AS-REQ/AS-REP and TGS-REQ/TGS-REP
//! exchanges, service-side AP-REQ/AP-REP validation, and a GSSAPI/SPNEGO
//! negotiation wrapper.
//!
//! See `SPEC-NOTES.md` for the section-by-section conformance status and the
//! test vectors wired into the suite. Interop testing against a real KDC
//! (MIT/Heimdal/Active Directory) is a platform-level gate and is documented as
//! blocked in the current environment.

pub mod asn1;
pub mod client;
pub mod crypto;
pub mod error;
pub mod gssapi;
pub mod messages;

pub use error::{Error, Result};
