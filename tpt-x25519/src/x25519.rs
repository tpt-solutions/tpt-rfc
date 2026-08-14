// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! X25519 key agreement (RFC 7748 §5, §6.1).
//!
//! The Montgomery ladder runs over the scalar's bits, using a
//! constant-time conditional swap (`cswap`) driven by the secret scalar so
//! the timing profile does not reveal which bits are set.

use crate::field255::FieldElement;
use crate::util::ct_eq_bytes;
use crate::{is_zero, KeyError};

/// `(A - 2) / 4` for the Curve25519 Montgomery curve `A = 486662`.
const A24: FieldElement = FieldElement([
    121665, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/// The X25519 base-point u-coordinate (the integer `9`).
pub(crate) const BASE_POINT: [u8; 32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Clamp an X25519 scalar per RFC 7748 §5: clear the three least significant
/// bits of the first byte and clear/set the two most significant bits of the
/// last byte.
fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Constant-time conditional swap of two field elements.
fn cswap(swap: u8, a: &mut FieldElement, b: &mut FieldElement) {
    let mask = 0u64.wrapping_sub(u64::from(swap));
    for i in 0..a.0.len() {
        let x = a.0[i];
        let y = b.0[i];
        a.0[i] = (x & !mask) | (y & mask);
        b.0[i] = (x & mask) | (y & !mask);
    }
}

/// The RFC 7748 `X25519(k, u)` function: scalar multiplication of the
/// Montgomery curve's u-coordinate, returning the shared x-coordinate as a
/// 32-byte little-endian string.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let k = clamp(scalar);
    let u = FieldElement::from_bytes(point);

    let x1 = u;
    let mut x2 = FieldElement::ONE;
    let mut z2 = FieldElement::ZERO;
    let mut x3 = u;
    let mut z3 = FieldElement::ONE;
    let mut swap = 0u8;

    for t in (0..255).rev() {
        let kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt as u8;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt as u8;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let x3n = da.add(&cb);
        let x3n = x3n.square();
        let z3n = da.sub(&cb);
        let z3n = z3n.square();
        let z3n = x1.mul(&z3n);
        let x2n = aa.mul(&bb);
        let z2n = e.mul(&aa.add(&A24.mul(&e)));

        x2 = x2n;
        z2 = z2n;
        x3 = x3n;
        z3 = z3n;
    }

    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    // Return x2 / z2 = x2 · z2^(p-2).
    let inv = z2.invert();
    let result = x2.mul(&inv);
    result.to_bytes()
}

/// A X25519 static secret scalar.
///
/// Wraps the 32-byte secret and zeroes its contents on drop. The associated
/// public key is obtained with [`StaticSecret::public_key`]. To compute a
/// shared secret use [`StaticSecret::diffie_hellman`].
#[derive(Clone)]
pub struct StaticSecret([u8; 32]);

impl StaticSecret {
    /// Construct a secret from raw bytes (already clamped by [`x25519`] at use).
    pub fn from_bytes(bytes: [u8; 32]) -> StaticSecret {
        StaticSecret(bytes)
    }

    /// Generate a fresh secret from the operating system RNG.
    pub fn random() -> StaticSecret {
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes);
        StaticSecret(bytes)
    }

    /// The raw scalar bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Compute the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519(&self.0, &BASE_POINT))
    }

    /// Perform X25519 Diffie-Hellman, returning the shared secret.
    ///
    /// Returns [`KeyError::ZeroSharedSecret`] if the result is all-zero, which
    /// signals an invalid peer public key (e.g. a small-order point). Use
    /// [`StaticSecret::diffie_hellman_unchecked`] if you must accept that case.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, KeyError> {
        let secret = SharedSecret(x25519(&self.0, &peer.0));
        if secret.is_zero() {
            Err(KeyError::ZeroSharedSecret)
        } else {
            Ok(secret)
        }
    }

    /// Like [`StaticSecret::diffie_hellman`] but never rejects an all-zero
    /// result. Prefer the checked variant unless you have a specific reason.
    pub fn diffie_hellman_unchecked(&self, peer: &PublicKey) -> SharedSecret {
        SharedSecret(x25519(&self.0, &peer.0))
    }
}

impl Drop for StaticSecret {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.0);
    }
}

/// A X25519 public key (a Montgomery u-coordinate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Construct a public key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> PublicKey {
        PublicKey(bytes)
    }

    /// The raw u-coordinate bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Borrow the raw u-coordinate bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality of two public keys.
    pub fn ct_eq(&self, other: &PublicKey) -> bool {
        ct_eq_bytes(&self.0, &other.0)
    }
}

/// A X25519 shared secret resulting from Diffie-Hellman.
///
/// The bytes are zeroed on drop.
#[derive(Clone)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// The raw shared-secret bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Borrow the raw shared-secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality of two shared secrets.
    pub fn ct_eq(&self, other: &SharedSecret) -> bool {
        ct_eq_bytes(&self.0, &other.0)
    }

    /// Returns `true` if the shared secret is all-zero.
    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.0);
    }
}

/// Get cryptographically-secure random bytes via the platform RNG.
#[cfg(feature = "getrandom")]
fn getrandom(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("RNG failure");
}

/// Get cryptographically-secure random bytes.
///
/// Without the `getrandom` feature this is intentionally unavailable so the
/// crate can be built deterministically; the conformance suite always uses
/// explicit keys and never relies on it.
#[cfg(not(feature = "getrandom"))]
fn getrandom(_buf: &mut [u8]) {
    panic!("getrandom feature disabled; cannot generate random secret");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point_public_key() {
        // RFC 7748 Appendix A.1: the public key for the all-zero scalar.
        let zero = [0u8; 32];
        let pk = x25519(&zero, &BASE_POINT);
        assert_eq!(
            pk,
            hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10f44204a256ecdc")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn clamp_clears_and_sets() {
        let k = [0xFFu8; 32];
        let c = clamp(&k);
        assert_eq!(c[0] & 7, 0);
        assert_eq!(c[31] & 128, 0);
        assert_eq!(c[31] & 64, 64);
    }
}
