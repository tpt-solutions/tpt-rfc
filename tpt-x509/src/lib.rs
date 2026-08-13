//! Clean-room, dual-licensed X.509 path validation (RFC 5280).
//!
//! This crate reuses [`x509_cert`] purely for DER decoding and builds a
//! clean-room *validation* engine on top of it: the path-building / path-
//! validation algorithm (RFC 5280 §6.1), basic-constraints / key-usage /
//! extended-key-usage enforcement, name constraints, and CRL revocation
//! checking. Signature verification is performed with dual-licensed
//! RustCrypto primitives (RSA, ECDSA, Ed25519).
//!
//! The gap this closes is `rustls-webpki`, which performs full validation but
//! is ISC-licensed and therefore unusable for consumers who require a
//! permissive MIT/Apache-2.0 license.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cert;
pub mod constraints;
pub mod crl;
pub mod error;
pub mod ocsp;
pub mod validate;
pub mod verify;

pub use cert::{Cert as Certificate, TrustAnchor};
pub use error::ValidationError;
pub use validate::{PathValidator, ValidationConfig};
