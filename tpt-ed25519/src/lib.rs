// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-ed25519
//!
//! A clean-room, dual-licensed (MIT OR Apache-2.0) implementation of
//! **Ed25519** — the Edwards-curve Digital Signature Algorithm over
//! Curve25519 — as specified in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
//!
//! Unlike `ed25519-dalek` (BSD-3-Clause) and `ed25519-compact` (MIT), this
//! crate is licensed to satisfy both the MIT-only and Apache-2.0-only crowds.
//! The field, scalar, and group arithmetic are implemented from scratch
//! against the RFC (no third-party Ed25519 code), using only the
//! dual-licensed `sha2` crate for SHA-512.
//!
//! The crate covers the three RFC variants:
//!
//! * **Ed25519** (pure) — [`SigningKey::sign`] / [`VerifyingKey::verify`].
//! * **Ed25519ctx** — [`SigningKey::sign_ctx`] / [`VerifyingKey::verify_ctx`],
//!   carrying a context string.
//! * **Ed25519ph** — [`SigningKey::sign_ph`] / [`VerifyingKey::verify_ph`],
//!   pre-hashing the message with SHA-512.
//!
//! ```
//! use tpt_ed25519::{SigningKey, Signature};
//!
//! let seed = [0x9d; 32]; // 32-byte secret seed
//! let sk = SigningKey::from_bytes(&seed);
//! let vk = sk.verifying_key();
//!
//! let sig = sk.sign(b"hello world");
//! assert!(vk.verify(b"hello world", &sig).is_ok());
//! assert!(vk.verify(b"goodbye", &sig).is_err());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod field;
mod point;
mod scalar;

use sha2::{Digest, Sha512};
use thiserror::Error;

/// The `"SigEd25519 no Ed25519 collisions"` prefix used by the `dom2` string
/// for the Ed25519ctx and Ed25519ph variants (RFC 8032 §5.1).
const DOM_PREFIX: &[u8] = b"SigEd25519 no Ed25519 collisions";

/// Errors produced by Ed25519 verification or key handling.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The signature is malformed or does not verify against the public key.
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
}

/// Result type for Ed25519 operations in this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// An Ed25519 signature: the concatenation of `R` (32 bytes) and `S` (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Create a signature from its 64-byte wire representation.
    pub fn from_bytes(bytes: &[u8; 64]) -> Signature {
        Signature(*bytes)
    }

    /// Return the 64-byte wire representation of the signature.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    /// Borrow the 64-byte wire representation of the signature.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// An Ed25519 verification (public) key: the encoded base-point multiple `[a]B`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    /// Create a verification key from its 32-byte encoded form.
    ///
    /// This does not validate that the bytes are a valid curve point; that
    /// check happens during [`VerifyingKey::verify`], matching RFC 8032
    /// (the formulas are complete, so untrusted public values are safe).
    pub fn from_bytes(bytes: &[u8; 32]) -> VerifyingKey {
        VerifyingKey(*bytes)
    }

    /// Return the 32-byte encoded form of the key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Verify a pure Ed25519 signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        verify_core(message, signature, &self.0, &[])
    }

    /// Verify an Ed25519ctx signature over `message` with the given `context`.
    pub fn verify_ctx(&self, context: &[u8], message: &[u8], signature: &Signature) -> Result<()> {
        let dom = dom_ctx(context);
        verify_core(message, signature, &self.0, &dom)
    }

    /// Verify an Ed25519ph signature. The message is pre-hashed with SHA-512
    /// before verification, per RFC 8032 §5.1.7.
    pub fn verify_ph(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let ph = Sha512::digest(message);
        let dom = dom_ph();
        verify_core(&ph, signature, &self.0, &dom)
    }
}

/// An Ed25519 signing (private) key: a 32-byte secret seed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    /// Create a signing key from its 32-byte secret seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> SigningKey {
        SigningKey(*bytes)
    }

    /// Return the 32-byte secret seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Derive the corresponding verification (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let (a, _prefix) = expand_seed(&self.0);
        let enc = point::base_point_ref().mul_scalar(&a).encode();
        VerifyingKey(enc)
    }

    /// Sign `message` under pure Ed25519 (RFC 8032 §5.1.6, `dom2` empty).
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_with(message, &[])
    }

    /// Sign `message` under Ed25519ctx with the given `context`.
    pub fn sign_ctx(&self, context: &[u8], message: &[u8]) -> Signature {
        let dom = dom_ctx(context);
        self.sign_with_dom(message, &dom)
    }

    /// Sign `message` under Ed25519ph (message is pre-hashed with SHA-512).
    pub fn sign_ph(&self, message: &[u8]) -> Signature {
        let ph = Sha512::digest(message);
        let dom = dom_ph();
        self.sign_with_dom(&ph, &dom)
    }

    /// Pure Ed25519 signing (empty `dom2`).
    fn sign_with(&self, message: &[u8], dom: &[u8]) -> Signature {
        let (a, prefix) = expand_seed(&self.0);
        let base = point::base_point_ref();
        let a_enc = base.mul_scalar(&a).encode();

        let r = hash_mod_l(dom, &prefix, message);
        let r_enc = base.mul_scalar(&r).encode();

        let k = hash_mod_l_3(dom, &r_enc, &a_enc, message);
        let s = r.add_mod(&k.mul_mod(&a));

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_enc);
        sig[32..].copy_from_slice(&s.to_bytes_le());
        Signature(sig)
    }

    /// Signing where the hashed payload is already a pre-hash (Ed25519ph/ctx
    /// share the same machinery once `dom` is fixed).
    fn sign_with_dom(&self, hashed: &[u8], dom: &[u8]) -> Signature {
        self.sign_with(hashed, dom)
    }
}

/// Build the `dom2` string for Ed25519ctx (RFC 8032 §5.1).
fn dom_ctx(context: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(DOM_PREFIX.len() + 2 + context.len());
    d.extend_from_slice(DOM_PREFIX);
    d.push(0); // phflag = 0
    d.push(context.len() as u8);
    d.extend_from_slice(context);
    d
}

/// Build the `dom2` string for Ed25519ph (RFC 8032 §5.1).
fn dom_ph() -> Vec<u8> {
    let mut d = Vec::with_capacity(DOM_PREFIX.len() + 2);
    d.extend_from_slice(DOM_PREFIX);
    d.push(1); // phflag = 1
    d.push(0); // OLEN(context) = 0
    d
}

/// Expand a 32-byte seed into the clamped scalar `a` and the 32-byte `prefix`.
fn expand_seed(seed: &[u8; 32]) -> (scalar::Scalar, [u8; 32]) {
    let h = Sha512::digest(seed);
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&h[i * 8..i * 8 + 8]);
        limbs[i] = u64::from_le_bytes(b);
    }
    // Clamp: clear bits 0..2, clear bit 255, set bit 254 (RFC 8032 §5.1.5).
    limbs[0] &= !0x7u64;
    limbs[3] = (limbs[3] & !(1u64 << 63)) | (1u64 << 62);
    let a = scalar::Scalar::from_limbs_mod_l(limbs);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..64]);
    (a, prefix)
}

/// `SHA-512(dom || prefix || message)` reduced to a scalar mod `L`.
fn hash_mod_l(dom: &[u8], prefix: &[u8; 32], message: &[u8]) -> scalar::Scalar {
    let mut hasher = Sha512::new();
    hasher.update(dom);
    hasher.update(prefix);
    hasher.update(message);
    scalar::Scalar::from_hash_reduce(hasher.finalize().as_slice())
}

/// `SHA-512(dom || r || a || message)` reduced to a scalar mod `L`.
fn hash_mod_l_3(dom: &[u8], r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> scalar::Scalar {
    let mut hasher = Sha512::new();
    hasher.update(dom);
    hasher.update(r);
    hasher.update(a);
    hasher.update(message);
    scalar::Scalar::from_hash_reduce(hasher.finalize().as_slice())
}

/// Core verification shared by all three variants (RFC 8032 §5.1.7).
///
/// `hashed` is the message (pure/ctx) or its SHA-512 pre-hash (ph); `dom` is
/// the `dom2` string for the variant.
fn verify_core(hashed: &[u8], signature: &Signature, pk: &[u8; 32], dom: &[u8]) -> Result<()> {
    let r_enc = &signature.0[..32];
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&signature.0[32..64]);
    let s = scalar::Scalar::from_bytes_le(&sb).ok_or(Error::InvalidSignature)?;
    let a_point = point::Point::decode(pk).ok_or(Error::InvalidSignature)?;
    let mut rb = [0u8; 32];
    rb.copy_from_slice(r_enc);
    let r_point = point::Point::decode(&rb).ok_or(Error::InvalidSignature)?;

    let base = point::base_point_ref();
    let mut hasher = Sha512::new();
    hasher.update(dom);
    hasher.update(r_enc);
    hasher.update(pk);
    hasher.update(hashed);
    let k = scalar::Scalar::from_hash_reduce(&hasher.finalize());

    let sb = base.mul_scalar(&s);
    let ka = a_point.mul_scalar(&k);
    let rhs = r_point.add(&ka);

    if sb.encode() == rhs.encode() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}
