// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-http-sig
//!
//! A clean-room, dual-licensed (MIT OR Apache-2.0) implementation of
//! [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421).
//!
//! The crate is **framework-agnostic**: it operates on the [`HttpMessage`]
//! trait rather than a specific HTTP library. An in-crate [`Message`] type is
//! provided for convenience and tests, and the optional `http` feature
//! implements [`HttpMessage`] for `http::Request` / `http::Response` (so the
//! crate drops straight into `hyper`, `reqwest`, `axum`, and friends).
//!
//! ## What is covered
//!
//! * All algorithms registered in RFC 9421 §6.2: `hmac-sha256`,
//!   `hmac-sha512`, `rsa-v1_5-sha256`, `rsa-v1_5-sha512`, `rsa-pss-sha256`,
//!   `rsa-pss-sha512`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`,
//!   `ecdsa-p521-sha512`, and `ed25519`.
//! * Derived components: `@method`, `@target-uri`, `@authority`, `@scheme`,
//!   `@request-target`, `@path`, `@query`, `@query-param`, `@status`, and
//!   arbitrary header fields (plus the `req` parameter for signing response
//!   components from a related request).
//! * `Signature-Input` / `Signature` header parsing and serialization.
//! * Signature base construction and verification conforming to the
//!   official RFC 9421 Appendix B test vectors.
//!
//! ## Limitations
//!
//! * The Structured Fields parameters `sf` (strict serialization), `key`
//!   (Dictionary member selection), and `bs` (binary wrapping) are not yet
//!   implemented; using them produces a clear error rather than a wrong
//!   signature.
//! * The `tr` (trailer) parameter is not sourced from a separate trailer
//!   store.
//! * `@target-uri` is not derived from `http::Request` (the full URI would
//!   need to be allocated); use the in-crate [`Message`] type or the
//!   `@authority`/`@path`/`@scheme` components with `http` requests.
//!
//! ## Signing example
//!
//! ```no_run
//! use tpt_http_sig::{Algorithm, ComponentId, HttpMessage, Message, Signer, SigningKey};
//!
//! let mut msg = Message::request("POST", "/foo?param=Value&Pet=dog")
//!     .authority("example.com")
//!     .header("date", "Tue, 20 Apr 2021 02:07:55 GMT")
//!     .header("content-type", "application/json");
//!
//! let key = SigningKey::from_pem(
//!     Algorithm::RsaPssSha512,
//!     include_str!("../tests/data/test-key-rsa-pss.pem"),
//! ).unwrap();
//!
//! let components = [
//!     ComponentId::parse("@authority").unwrap(),
//!     ComponentId::parse("content-type").unwrap(),
//! ];
//! let out = Signer::new(Algorithm::RsaPssSha512, &key)
//!     .label("sig1")
//!     .keyid("test-key-rsa-pss")
//!     .created(1_618_884_473)
//!     .sign(&msg, &components)
//!     .unwrap();
//! // Attach `Signature-Input: sig1=<out.input_value>` and
//! // `Signature: sig1=:<base64 signature>:`.
//! let _ = out;
//! ```
//!
//! ## Verifying example
//!
//! ```no_run
//! use tpt_http_sig::{Algorithm, HttpMessage, Message, Verifier, VerifyingKey};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let msg = Message::request("POST", "/foo")
//!     .authority("example.com")
//!     .header("date", "Tue, 20 Apr 2021 02:07:55 GMT");
//!
//! let key = VerifyingKey::from_pem(
//!     Algorithm::Ed25519,
//!     include_str!("../tests/data/test-key-ed25519.pub.pem"),
//! ).unwrap();
//!
//! let input_value = "(\"@method\" \"@authority\" \"date\");created=1618884473;keyid=\"test-key-ed25519\"";
//! let signature = base64::engine::general_purpose::STANDARD.decode("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==").unwrap();
//!
//! Verifier::new().verify(&msg, input_value, &signature, &key)?;
//! # Ok(())
//! # }
//! ```

pub mod algorithm;
pub mod components;
pub mod error;
pub mod headers;
pub mod message;
mod sf;
pub mod signer;

pub use algorithm::{Algorithm, SigningKey, VerifyingKey};
pub use components::ComponentId;
pub use error::{HttpSigError, Result};
pub use headers::SignatureInput;
pub use message::{HttpMessage, Message, MessageKind};
pub use signer::{build_signature_base, Signer, SignatureOutput, Verifier};
