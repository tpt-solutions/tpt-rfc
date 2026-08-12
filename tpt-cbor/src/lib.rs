// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-cbor
//!
//! A clean-room implementation of **CBOR** ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)),
//! dual-licensed under MIT OR Apache-2.0.
//!
//! The crate provides:
//!
//! - A [`Value`] data model with a direct encoder and decoder.
//! - Configurable decoding ([`DecodeOptions`]) for strict and canonical modes.
//! - Configurable encoding ([`EncodeOptions`]) including deterministic output.
//! - Optional [`serde`] integration behind the `serde` feature.
//!
//! ## Example
//!
//! ```
//! use tpt_cbor::value::{Value, EncodeOptions, DecodeOptions};
//! use tpt_cbor::decoder::decode_value;
//! use tpt_cbor::encoder::to_vec;
//!
//! let v = Value::Array(vec![
//!     Value::Integer(1),
//!     Value::text("hello"),
//!     Value::Bool(true),
//! ]);
//! let bytes = to_vec(&v, &EncodeOptions::default());
//! let back = decode_value(&bytes, DecodeOptions::default()).unwrap();
//! assert_eq!(v, back);
//! ```
//!
//! ## Conformance
//!
//! See `SPEC-NOTES.md` for the section-by-section status and the official
//! RFC 8949 Appendix A test vectors wired into the test suite.

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod value;

#[cfg(feature = "serde")]
pub mod serde;

pub use decoder::{decode_value, Decoder};
pub use encoder::to_vec;
pub use error::{CborError, Result};
pub use value::{DecodeOptions, EncodeOptions, Value};
