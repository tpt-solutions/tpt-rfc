//! Clean-room, dual-licensed (MIT OR Apache-2.0) implementation of
//! **RFC 3161 Time-Stamp Protocol (TSP)**.
//!
//! This crate covers the part of RFC 3161 that is missing under a clean dual
//! license: a **TSA (server) responder** that issues `TimeStampToken`s, plus a
//! **client** that builds requests and fully verifies responses
//! (CMS `SignedData` signature over the signed attributes, `message-digest`/
//! `content-type` consistency, and `TSTInfo` consistency).
//!
//! ```
//! use tpt_tsp::{HashAlgorithm, TimeStampReqBuilder, Tsa, verify_timestamp_response};
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let data = b"document to be timestamped";
//! let req = TimeStampReqBuilder::new(HashAlgorithm::Sha256, data).nonce(1234).build()?;
//! let resp = Tsa::self_signed_demo()?.issue(&req)?;
//! let token = verify_timestamp_response(&resp, Some(&req), None)?;
//! assert_eq!(token.message_imprint(), &sha2::Sha256::digest(data)[..]);
//! # Ok(())
//! # }
//! # let _ = run();
//! ```

mod client;
mod error;
mod hash;
mod oids;
mod signer;
mod tsa;
mod verify;
mod wire;

pub use error::{Result, TspError};
pub use hash::HashAlgorithm;
pub use client::TimeStampReqBuilder;
pub use signer::SigningKey;
pub use tsa::Tsa;
pub use verify::{verify_timestamp_response, VerifiedToken};

/// Re-export of the X.509 certificate type, used for `trust_anchors`.
pub use x509_cert::Certificate;
