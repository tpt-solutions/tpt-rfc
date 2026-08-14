// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! X448 key agreement (RFC 7748 §5, §6.2).
//!
//! Same Montgomery ladder as X25519 but over the Curve448 prime
//! `2^448 - 2^224 - 1`, a 56-byte coordinate, and the constant
//! `a24 = 39081` ((A-2)/4 with A = 156326).

use crate::field448::FieldElement;
use crate::util::ct_eq_bytes;
use crate::{is_zero, KeyError};

/// `(A - 2) / 4` for the Curve448 Montgomery curve `A = 156326`.
const A24: FieldElement = FieldElement([
    39081, 0, 0, 0, 0, 0, 0, 0,
]);

/// The X448 base-point u-coordinate (the integer `5`).
pub(crate) const BASE_POINT: [u8; 56] = {
    let mut b = [0u8; 56];
    b[0] = 5;
    b
};

/// Clamp an X448 scalar per RFC 7748 §5: clear the two least significant bits
/// of the first byte and clear/set the top two bits of the last byte.
fn clamp(scalar: &[u8; 56]) -> [u8; 56] {
    let mut k = *scalar;
    k[0] &= 252;
    k[55] &= 127;
    k[55] |= 64;
    k
}

fn cswap(swap: u8, a: &mut FieldElement, b: &mut FieldElement) {
    let mask = 0u64.wrapping_sub(u64::from(swap));
    for i in 0..a.0.len() {
        let x = a.0[i];
        let y = b.0[i];
        a.0[i] = (x & !mask) | (y & mask);
        b.0[i] = (x & mask) | (y & !mask);
    }
}

/// The RFC 7748 `X448(k, u)` function: scalar multiplication of the
/// Montgomery curve's u-coordinate, returning the shared x-coordinate as a
/// 56-byte little-endian string.
pub fn x448(scalar: &[u8; 56], point: &[u8; 56]) -> [u8; 56] {
    let k = clamp(scalar);
    let u = FieldElement::from_bytes(point);

    let x1 = u;
    let mut x2 = FieldElement::ONE;
    let mut z2 = FieldElement::ZERO;
    let mut x3 = u;
    let mut z3 = FieldElement::ONE;
    let mut swap = 0u8;

    for t in (0..448).rev() {
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

    let inv = z2.invert();
    let result = x2.mul(&inv);
    result.to_bytes()
}

/// A X448 static secret scalar.
#[derive(Clone)]
pub struct X448Secret([u8; 56]);

impl X448Secret {
    pub fn from_bytes(bytes: [u8; 56]) -> X448Secret {
        X448Secret(bytes)
    }

    pub fn random() -> X448Secret {
        let mut bytes = [0u8; 56];
        getrandom(&mut bytes);
        X448Secret(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        self.0
    }

    pub fn public_key(&self) -> X448PublicKey {
        X448PublicKey(x448(&self.0, &BASE_POINT))
    }

    /// Perform X448 Diffie-Hellman, returning the shared secret.
    ///
    /// Returns [`KeyError::ZeroSharedSecret`] if the result is all-zero, which
    /// signals an invalid peer public key. See
    /// [`X448Secret::diffie_hellman_unchecked`].
    pub fn diffie_hellman(&self, peer: &X448PublicKey) -> Result<X448SharedSecret, KeyError> {
        let secret = X448SharedSecret(x448(&self.0, &peer.0));
        if secret.is_zero() {
            Err(KeyError::ZeroSharedSecret)
        } else {
            Ok(secret)
        }
    }

    /// Like [`X448Secret::diffie_hellman`] but never rejects an all-zero result.
    pub fn diffie_hellman_unchecked(&self, peer: &X448PublicKey) -> X448SharedSecret {
        X448SharedSecret(x448(&self.0, &peer.0))
    }
}

impl Drop for X448Secret {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.0);
    }
}

/// A X448 public key (a Montgomery u-coordinate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X448PublicKey([u8; 56]);

impl X448PublicKey {
    pub fn from_bytes(bytes: [u8; 56]) -> X448PublicKey {
        X448PublicKey(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }

    pub fn ct_eq(&self, other: &X448PublicKey) -> bool {
        ct_eq_bytes(&self.0, &other.0)
    }
}

/// A X448 shared secret.
#[derive(Clone)]
pub struct X448SharedSecret([u8; 56]);

impl X448SharedSecret {
    pub fn to_bytes(&self) -> [u8; 56] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }

    pub fn ct_eq(&self, other: &X448SharedSecret) -> bool {
        ct_eq_bytes(&self.0, &other.0)
    }

    /// Returns `true` if the shared secret is all-zero.
    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
    }
}

impl Drop for X448SharedSecret {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.0);
    }
}

#[cfg(feature = "getrandom")]
fn getrandom(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("RNG failure");
}

#[cfg(not(feature = "getrandom"))]
fn getrandom(_buf: &mut [u8]) {
    panic!("getrandom feature disabled; cannot generate random secret");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point_public_key() {
        // RFC 7748 Appendix A.2: public key for the all-zero scalar.
        let zero = [0u8; 56];
        let pk = x448(&zero, &BASE_POINT);
        assert_eq!(
            pk,
            hex::decode(
                "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
                 4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
            )
            .unwrap()
            .as_slice()
        );
    }

    #[test]
    fn clamp_clears_and_sets() {
        let k = [0xFFu8; 56];
        let c = clamp(&k);
        assert_eq!(c[0] & 3, 0);
        assert_eq!(c[55] & 128, 0);
        assert_eq!(c[55] & 64, 64);
    }
}
