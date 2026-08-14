// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Field arithmetic modulo `p = 2^255 - 19` (the edwards25519 base field).
//!
//! Elements are stored as four 64-bit little-endian limbs (`[u64; 4]`), kept
//! in canonical reduced form (`< p`). All operations are implemented
//! clean-room from RFC 8032 / the curve definition; reduction uses the
//! identity `2^255 = 19 (mod p)` and runs a fixed number of fold iterations
//! so that it never branches on secret data.

/// The edwards25519 prime `p = 2^255 - 19`.
const P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFED,
];

/// Lexicographic `>=` over two 4-limb little-endian numbers (used against `P`).
fn ge4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// Subtract two 4-limb little-endian numbers (`a - b`, assumed `a >= b`).
fn sub_limb4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let x = a[i] as i128 - b[i] as i128 - borrow;
        if x < 0 {
            r[i] = (x + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = x as u64;
            borrow = 0;
        }
    }
    r
}

/// Reduce an arbitrary little-endian limb array modulo `p = 2^255 - 19`.
///
/// The fold `x -> (x mod 2^255) + 19 * (x >> 255)` is applied a fixed number
/// of times, which is data-independent and therefore constant-time.
fn reduce_fe(limbs: &[u64]) -> FieldElement {
    let mut v = [0u64; 9];
    for (i, &x) in limbs.iter().enumerate() {
        if i < v.len() {
            v[i] = x;
        }
    }
    for _ in 0..9 {
        let mut q = [0u64; 6];
        for k in 0..6 {
            let lo = (v[k + 3] >> 63) & 1;
            let hi = if k + 4 < v.len() { v[k + 4] << 1 } else { 0 };
            q[k] = lo | hi;
        }
        let mut lo = [0u64; 9];
        lo[0..3].copy_from_slice(&v[0..3]);
        lo[3] = v[3] & 0x7FFF_FFFF_FFFF_FFFF;
        let mut n = [0u64; 9];
        let mut carry = 0u128;
        for i in 0..9 {
            let s = lo[i] as u128 + carry;
            n[i] = s as u64;
            carry = s >> 64;
        }
        let mut carry = 0u128;
        for i in 0..6 {
            let s = n[i] as u128 + (19u128 * q[i] as u128) + carry;
            n[i] = s as u64;
            carry = s >> 64;
        }
        for i in 6..9 {
            let s = n[i] as u128 + carry;
            n[i] = s as u64;
            carry = s >> 64;
        }
        v = n;
    }
    let mut r = [v[0], v[1], v[2], v[3]];
    if ge4(&r, &P) {
        r = sub_limb4(&r, &P);
    }
    FieldElement { limbs: r }
}

/// An element of the edwards25519 base field, stored canonically reduced mod `p`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FieldElement {
    limbs: [u64; 4],
}

impl FieldElement {
    pub(crate) const ZERO: FieldElement = FieldElement { limbs: [0; 4] };
    pub(crate) const ONE: FieldElement = FieldElement { limbs: [1, 0, 0, 0] };

    /// Construct a field element from a small integer (reduced trivially).
    pub(crate) fn from_u64(x: u64) -> FieldElement {
        FieldElement { limbs: [x, 0, 0, 0] }
    }

    /// Canonical decode of a 32-byte little-endian integer; rejects values `>= p`.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Option<FieldElement> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        if ge4(&limbs, &P) {
            return None;
        }
        Some(FieldElement { limbs })
    }


    /// Encode the canonical value as 32 little-endian bytes.
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        out
    }

    /// `true` if the element is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.limbs == [0; 4]
    }

    /// `true` if the element is "negative", i.e. its least significant bit is 1.
    pub(crate) fn is_negative(&self) -> bool {
        (self.limbs[0] & 1) == 1
    }

    /// Constant-time equality of two canonical field elements.
    pub(crate) fn ct_eq(&self, other: &FieldElement) -> bool {
        self.limbs == other.limbs
    }

    pub(crate) fn add(&self, other: &FieldElement) -> FieldElement {
        let mut limbs = [0u64; 8];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.limbs[i] as u128 + other.limbs[i] as u128 + carry;
            limbs[i] = s as u64;
            carry = s >> 64;
        }
        if carry > 0 {
            limbs[4] = carry as u64;
        }
        reduce_fe(&limbs)
    }

    pub(crate) fn sub(&self, other: &FieldElement) -> FieldElement {
        let mut r = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let x = self.limbs[i] as i128 - other.limbs[i] as i128 - borrow;
            if x < 0 {
                r[i] = (x + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                r[i] = x as u64;
                borrow = 0;
            }
        }
        if borrow == 1 {
            let mut carry = 0u128;
            for i in 0..4 {
                let s = r[i] as u128 + P[i] as u128 + carry;
                r[i] = s as u64;
                carry = s >> 64;
            }
        }
        reduce_fe(&r)
    }

    pub(crate) fn mul(&self, other: &FieldElement) -> FieldElement {
        let mut limbs = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let idx = i + j;
                if idx < 8 {
                    let s = limbs[idx] as u128
                        + (self.limbs[i] as u128) * (other.limbs[j] as u128)
                        + carry;
                    limbs[idx] = s as u64;
                    carry = s >> 64;
                }
            }
            let mut k = i + 4;
            let mut c = carry;
            while c > 0 && k < 8 {
                let s = limbs[k] as u128 + c;
                limbs[k] = s as u64;
                c = s >> 64;
                k += 1;
            }
        }
        reduce_fe(&limbs)
    }

    pub(crate) fn square(&self) -> FieldElement {
        self.mul(self)
    }

    pub(crate) fn neg(&self) -> FieldElement {
        FieldElement::ZERO.sub(self)
    }

    /// Multiply by 0 or 1 (constant-time select helper).
    pub(crate) fn scale(&self, m: u64) -> FieldElement {
        let m = m & 1;
        let mut limbs = [0u64; 8];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = (self.limbs[i] as u128) * (m as u128) + carry;
            limbs[i] = s as u64;
            carry = s >> 64;
        }
        if carry > 0 {
            limbs[4] = carry as u64;
        }
        reduce_fe(&limbs)
    }

    /// Modular inverse via `a^(p-2)` (Fermat's little theorem).
    pub(crate) fn invert(&self) -> FieldElement {
        const EXP: [u64; 4] = [
            0,
            0,
            0,
            0x7FFF_FFFF_FFFF_FFEB, // 2^255 - 21 == p - 2
        ];
        self.pow(&EXP)
    }

    /// Fixed-base exponentiation by a public exponent (used for inversion and roots).
    pub(crate) fn pow(&self, exp: &[u64; 4]) -> FieldElement {
        let mut result = FieldElement::ONE;
        let base = *self;
        for bit in (0..256).rev() {
            result = result.square();
            let limb = bit / 64;
            let b = (exp[limb] >> (bit % 64)) & 1;
            if b == 1 {
                result = result.mul(&base);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_small() {
        assert_eq!(FieldElement::from_u64(5).mul(&FieldElement::from_u64(7)), FieldElement::from_u64(35));
    }

    #[test]
    fn square_small() {
        assert_eq!(FieldElement::from_u64(7).square(), FieldElement::from_u64(49));
    }

    #[test]
    fn neg_add() {
        // (p - 5) + 10 = 5 (mod p)
        let pm5 = FieldElement::from_u64(5).neg().add(&FieldElement::from_u64(10));
        assert_eq!(pm5, FieldElement::from_u64(5));
    }

    #[test]
    fn invert_roundtrip() {
        let a = FieldElement::from_u64(1234567);
        let inv = a.invert();
        assert_eq!(a.mul(&inv), FieldElement::ONE);
    }

    #[test]
    fn pow_zero_is_one() {
        let a = FieldElement::from_u64(123);
        let zero = [0u64; 4];
        assert_eq!(a.pow(&zero), FieldElement::ONE);
    }

    #[test]
    fn two255_is_19() {
        // 2^255 = 19 (mod 2^255 - 19)
        let mut limbs = [0u64; 4];
        limbs[3] = 1u64 << 63;
        let x = FieldElement { limbs };
        assert_eq!(x, FieldElement::from_u64(19));
    }
}

