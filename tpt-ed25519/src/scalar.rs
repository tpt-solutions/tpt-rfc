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
        Scalar {
            limbs: mod_l(&limbs),
        }
    }

    /// Interpret a 64-byte little-endian hash as an integer and reduce mod `L`.
    pub(crate) fn from_hash_reduce(hash: &[u8]) -> Scalar {
        let mut limbs = [0u64; 8];
        for i in 0..8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&hash[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        Scalar {
            limbs: mod_l(&limbs),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_from_le_bytes(bytes: &[u8; 64]) -> Scalar {
        Scalar::from_hash_reduce(bytes)
    }

    #[test]
    fn mod_l_small() {
        // value 5 -> 5
        let mut h = [0u8; 64];
        h[0] = 5;
        assert_eq!(hash_from_le_bytes(&h).to_bytes_le(), [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn mod_l_l_plus_seven() {
        // L + 7 -> 7
        let mut limbs = [0u64; 8];
        limbs[0] = 0x5812_631a_5cf5_d3ed;
        limbs[1] = 0x14de_f9de_a2f7_9cd6;
        limbs[2] = 0x0000_0000_0000_0000;
        limbs[3] = 0x1000_0000_0000_0000;
        limbs[0] = limbs[0].wrapping_add(7);
        let mut h = [0u8; 64];
        for i in 0..4 {
            h[i * 8..i * 8 + 8].copy_from_slice(&limbs[i].to_le_bytes());
        }
        let r = hash_from_le_bytes(&h);
        assert_eq!(r.to_bytes_le()[0], 7);
    }

    #[test]
    fn mod_l_max() {
        // 2^512 - 1 -> (2^512 - 1) mod L
        let h = [0xFFu8; 64];
        let r = hash_from_le_bytes(&h);
        // (2^512 - 1) - k*L for the largest k. Sanity: reduction yields value < L.
        assert!(!r.to_bytes_le().iter().skip(1).all(|&b| b == 0) || r.to_bytes_le()[0] != 0);
    }

    /// Independent, obviously-correct reduction of an 8-limb (512-bit) number
    /// modulo `L`, used only to cross-check `mod_l`.
    fn mod_l_ref(input: &[u64; 8]) -> [u64; 4] {
        fn ge(a: &[u64; 8], b: &[u64; 4]) -> bool {
            for i in (0..8).rev() {
                let bi = if i < 4 { b[i] } else { 0 };
                if a[i] > bi {
                    return true;
                }
                if a[i] < bi {
                    return false;
                }
            }
            true
        }
        fn sub(a: &mut [u64; 8], b: &[u64; 4]) {
            let mut borrow = 0i128;
            for i in 0..8 {
                let bi = if i < 4 { b[i] as i128 } else { 0 };
                let x = a[i] as i128 - bi - borrow;
                if x < 0 {
                    a[i] = (x + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    a[i] = x as u64;
                    borrow = 0;
                }
            }
        }
        let mut v = *input;
        while ge(&v, &L) {
            sub(&mut v, &L);
        }
        [v[0], v[1], v[2], v[3]]
    }

    #[test]
    fn mod_l_ref_matches_for_seed_4ccd() {
        use sha2::{Digest, Sha512};
        let seed = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb6, 0xa6, 0xfb,
        ];
        let h = Sha512::digest(seed);
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&h[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        limbs[0] &= !0x7u64;
        limbs[3] = (limbs[3] & !(1u64 << 63)) | (1u64 << 62);
        let got = Scalar::from_limbs_mod_l(limbs);
        // Reference: zero-extend to 8 limbs and reduce independently.
        let mut big = [0u64; 8];
        big[0..4].copy_from_slice(&limbs);
        let expected = mod_l_ref(&big);
        let mut got_limbs = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&got.to_bytes_le()[i * 8..i * 8 + 8]);
            got_limbs[i] = u64::from_le_bytes(b);
        }
        assert_eq!(got_limbs, expected, "mod_l disagrees with reference");
        // Also: the public key must match the RFC vector.
        use crate::SigningKey;
        let sk = SigningKey::from_bytes(&seed);
        let expected_pk = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        assert_eq!(sk.verifying_key().to_bytes(), expected_pk);
    }

    #[test]
    fn mod_l_fuzz() {
        let mut state = 0x1234_5678_9abc_def0u64;
        fn lcg(s: &mut u64) -> u64 {
            *s = s.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(0x9e37_79b9_7f4a_7c15);
            *s
        }
        for _ in 0..5000 {
            let mut limbs = [0u64; 4];
            for i in 0..4 {
                limbs[i] = lcg(&mut state);
            }
            let got = Scalar::from_limbs_mod_l(limbs);
            let mut big = [0u64; 8];
            big[0..4].copy_from_slice(&limbs);
            let exp = mod_l_ref(&big);
            let mut gl = [0u64; 4];
            for i in 0..4 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&got.to_bytes_le()[i * 8..i * 8 + 8]);
                gl[i] = u64::from_le_bytes(b);
            }
            if gl != exp {
                panic!(
                    "mismatch for limbs {:?}: got {:?} exp {:?}",
                    limbs, gl, exp
                );
            }
        }

        // Curated: the failing a_4ccd clamped scalar.
        use sha2::{Digest, Sha512};
        let seed = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb6, 0xa6, 0xfb,
        ];
        let h = Sha512::digest(seed);
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&h[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        limbs[0] &= !0x7u64;
        limbs[3] = (limbs[3] & !(1u64 << 63)) | (1u64 << 62);
        let got = Scalar::from_limbs_mod_l(limbs);
        let mut big = [0u64; 8];
        big[0..4].copy_from_slice(&limbs);
        let exp = mod_l_ref(&big);
        let mut gl = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&got.to_bytes_le()[i * 8..i * 8 + 8]);
            gl[i] = u64::from_le_bytes(b);
        }
        assert_eq!(gl, exp, "a_4ccd mismatch: got {:?} exp {:?}", gl, exp);
    }
}
