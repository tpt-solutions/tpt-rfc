// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clean-room, dual-licensed RFC 6960 Online Certificate Status Protocol
//! (OCSP) — client request/verification and a minimal responder.
//!
//! The crate builds clean-room OCSP request/response logic on top of the
//! dual-licensed RustCrypto ASN.1/`x509-cert` primitives. It provides:
//!
//! * [`CertId`] — construction of the OCSP `CertID` (issuer name/key hashes +
//!   serial number) directly from issuer/subject certificates, or from raw
//!   material.
//! * [`build_request`] / [`decode_request`] — client request construction and
//!   responder-side request parsing, including the standard nonce extension.
//! * [`OcspClient::verify_response`] — parse and cryptographically verify an
//!   `OCSPResponse`, checking the responder signature, the nonce, and the
//!   returned status for an expected certificate.
//! * [`OcspResponder`] + [`CertStatusProvider`] — a minimal OCSP responder that
//!   looks up status via a pluggable trait and signs `BasicOCSPResponse`
//!   structures.
//!
//! Signing/verification support RSASSA-PKCS1-v1_5, ECDSA (P-256/P-384) and
//! Ed25519, all under permissive licenses.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod certid;
pub mod client;
pub mod error;
pub mod hash;
pub mod oids;
pub mod responder;
pub mod signer;
pub mod verify;
pub mod wire;

pub use certid::{CertId, CertStatusValue};
pub use client::{build_request, decode_request, DecodedRequest, OcspClient, RequestOptions, VerifiedResponse};
pub use error::{OcspError, OcspResult};
pub use hash::HashAlgorithm;
pub use responder::{CertStatusProvider, OcspResponder, ProvidedStatus, ResponderIdKind};
pub use signer::SigningKey;
