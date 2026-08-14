// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scalar arithmetic modulo `L`, the order of the edwards25519 base point:
//! `L = 2^252 + 27742317777372353535851937790883648493`.

/// The edwards25519 group order `L`.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// Lexicographic `>=` over a 4-limb little-endian number compared against `L`.
fn ge_l(a: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > L[i] {
            return true;
        }
        if a[i] < L[i] {
            return false;
        }
    }
    true
}

/// Reduce an arbitrary little-endian limb array modulo `L` using binary division.
fn mod_l(input: &[u64]) -> [u64; 4] {
    let nbits = input.len() * 64;
    let mut r = [0u64; 4];
    for bit in (0..nbits).rev() {
        // Shift r left by one bit.
        let mut carry = 0u64;
        for i in 0..4 {
            let nb = (r[i] << 1) | carry;
            carry = r[i] >> 63;
            r[i] = nb;
        }
        // Add the current input bit.
        let limb = bit / 64;
        let b = (input[limb] >> (bit % 64)) & 1;
        if b == 1 {
            let mut c = 1u128;
            for i in 0..4 {
                let s = r[i] as u128 + c;
                r[i] = s as u64;
                c = s >> 64;
            }
        }
        // Conditional subtract L (reduces below L).
        if ge_l(&r) {
            let mut borrow = 0i128;
            for i in 0..4 {
                let x = r[i] as i128 - L[i] as i128 - borrow;
                if x < 0 {
                    r[i] = (x + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    r[i] = x as u64;
                    borrow = 0;
                }
            }
        }
    }
    r
}

/// A scalar in `[0, L)`, stored as four little-endian 64-bit limbs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Scalar {
    limbs: [u64; 4],
}

impl Scalar {
    /// Reduce an already-built 4-limb value modulo `L`.
    pub(crate) fn from_limbs_mod_l(limbs: [u64; 4]) -> Scalar {
        Scalar { limbs: mod_l(&limbs) }
    }

    /// Interpret a 64-byte little-endian hash as an integer and reduce mod `L`.
    pub(crate) fn from_hash_reduce(hash: &[u8]) -> Scalar {
        let mut limbs = [0u64; 8];
        for i in 0..8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&hash[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        Scalar { limbs: mod_l(&limbs) }
    }

    /// Canonical parse of a 32-byte little-endian scalar; rejects values `>= L`.
    pub(crate) fn from_bytes_le(bytes: &[u8; 32]) -> Option<Scalar> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        if ge_l(&limbs) {
            return None;
        }
        Some(Scalar { limbs })
    }

    /// Encode the scalar as 32 little-endian bytes.
    pub(crate) fn to_bytes_le(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        out
    }

    /// Return bit `i` (0 or 1) of the scalar.
    pub(crate) fn bit(&self, i: usize) -> u8 {
        ((self.limbs[i / 64] >> (i % 64)) & 1) as u8
    }

    /// `(self + other) mod L`.
    pub(crate) fn add_mod(&self, other: &Scalar) -> Scalar {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.limbs[i] as u128 + other.limbs[i] as u128 + carry;
            r[i] = s as u64;
            carry = s >> 64;
        }
        Scalar { limbs: mod_l(&r) }
    }

    /// `(self * other) mod L`.
    pub(crate) fn mul_mod(&self, other: &Scalar) -> Scalar {
        let mut acc = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let idx = i + j;
                if idx < 8 {
                    let s = acc[idx] as u128
                        + (self.limbs[i] as u128) * (other.limbs[j] as u128)
                        + carry;
                    acc[idx] = s as u64;
                    carry = s >> 64;
                }
            }
            let mut k = i + 4;
            let mut c = carry;
            while c > 0 && k < 8 {
                let s = acc[k] as u128 + c;
                acc[k] = s as u64;
                c = s >> 64;
                k += 1;
            }
        }
        Scalar { limbs: mod_l(&acc) }
    }
}
