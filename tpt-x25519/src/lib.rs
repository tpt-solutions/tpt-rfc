// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-x25519
//!
//! A clean-room, dual-licensed implementation of **X25519** and **X448** key
//! agreement ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)).
//!
//! Both operate on the Montgomery form of Curve25519 (`p = 2^255 - 19`) and
//! Curve448 (`p = 2^448 - 2^224 - 1`). The scalar multiplications are carried
//! out with a **constant-time Montgomery ladder** (no secret-dependent
//! branching or memory access), so the timing profile does not leak scalar or
//! coordinate bits. No code or structure was copied from `x25519-dalek` or any
//! other implementation; this is an independent clean-room construction from
//! the RFC text.
//!
//! ## Quick start
//!
//! ```
//! use tpt_x25519::{StaticSecret, PublicKey};
//!
//! // Alice generates a keypair and derives the shared secret with Bob's
//! // public key (in a real protocol, Bob's public key arrives over the wire).
//! let alice_secret = StaticSecret::random();
//! let alice_public = alice_secret.public_key();
//!
//! let bob_secret = StaticSecret::random();
//! let bob_public = bob_secret.public_key();
//!
//! let alice_shared = alice_secret.diffie_hellman(&bob_public).unwrap();
//! let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```
//!
//! For X448, see the [`x448`] module.

pub mod field255;
pub mod field448;
pub mod x25519;
pub mod x448;
pub mod util;

pub use x25519::{PublicKey, SharedSecret, StaticSecret, x25519};
pub use x448::{X448PublicKey, X448Secret, X448SharedSecret, x448};

/// Errors raised by key-agreement operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The Diffie-Hellman computation produced the all-zero shared secret,
    /// which indicates the peer supplied an invalid (e.g. small-order or
    /// identity) public key. Treat this as a protocol failure.
    #[error("Diffie-Hellman produced the all-zero shared secret (invalid peer key)")]
    ZeroSharedSecret,
}

/// Returns `true` iff every byte of `buf` is zero (constant-time).
pub(crate) fn is_zero(buf: &[u8]) -> bool {
    let mut acc = 0u8;
    for b in buf {
        acc |= *b;
    }
    acc == 0
}
