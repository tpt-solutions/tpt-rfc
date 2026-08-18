//! Clean-room, dual-licensed RFC 3161 Time-Stamp Protocol (TSP).
//!
//! `tpt-tsp` implements the parts of RFC 3161 that the ecosystem is missing a
//! clean dual-licensed option for (per the `tpt-rfc` survey, `freetsa`
//! covers the *client* reasonably but there is no clean-room MIT/Apache TSA
//! responder):
//!
//! * [`TimestampRequest`] — client-side `TimeStampReq` generation (with
//!   `nonce` / `reqPolicy` / `certReq` options) and parsing.
//! * [`TimestampResponse`] — client-side `TimeStampResp` parsing and
//!   verification (signature chain, `TSTInfo` consistency, nonce match).
//! * [`TimestampAuthority`] — a minimal TSA *responder* that validates a
//!   request, builds the `TSTInfo`, and signs it into a `TimeStampToken`
//!   (a CMS `SignedData`, RFC 3161 §2.4.2 / RFC 5652 §5).
//!
//! All wire encoding is built clean-room on top of the dual-licensed RustCrypto
//! `der`/`spki`/`x509-cert` primitives; no code is copied from existing TSP or
//! CMS implementations.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cert;
pub mod crypto;
pub mod error;
pub mod oids;
pub mod request;
pub mod response;
pub mod token;

pub use crypto::{HashAlgorithm, SigningKey};
pub use error::{TspError, Result};
pub use request::{parse_timestamp_req, MessageImprint, TimestampRequest};
pub use response::{TimestampAuthority, TimestampResponse};
pub use token::{TstInfo, TsaPolicyId};
pub use x509_cert::Certificate;

mod wire;

/// Default policy OID used by the responder when the request omits one.
///
/// `1.2.3.4.1` is the example policy arc reserved by RFC 3161 §2.1.1 for
/// illustrative use; production TSAs should configure their own.
pub const DEFAULT_POLICY: &str = "1.2.3.4.1";
