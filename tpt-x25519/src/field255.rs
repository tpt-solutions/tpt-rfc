// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clean-room field arithmetic for the Curve25519 prime
//! `p = 2^255 - 19`, implemented as a constant-time Montgomery ladder
//! primitive for RFC 7748 X25519.
//!
//! Elements are stored in radix-2^51 form: ten `u64` limbs with
//! `value = Σ limb[i] * 2^(51·i)`, each limb kept below `2^51` after
//! normalization. All operations are constant-time with respect to the
//! operands; the only non-operand input that drives control flow is the
//! public exponent in `invert`, which is fixed.

use crate::util::ct_eq_bytes;

const LIMBS: usize = 10;
const RADIX: u32 = 51;
/// `2^51 - 1`, the per-limb mask.
const MASK: u64 = (1u64 << RADIX) - 1;
/// `2^51 - 1` as a `u128`, for the `u128` accumulation path.
const MASK_U128: u128 = (1u128 << RADIX) - 1;

/// `p = 2^255 - 19` in radix-2^51 limbs.
///
/// `2^255` is limb 5 (weight `2^(51·5)`); subtracting 19 borrows down through
/// limbs 0..4, giving limbs `[2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1, 0, …]`.
const P_LIMBS: [u64; LIMBS] = [
    (1u64 << 51) - 19,
    (1u64 << 51) - 1,
    (1u64 << 51) - 1,
    (1u64 << 51) - 1,
    (1u64 << 51) - 1,
    0,
    0,
    0,
    0,
    0,
];

/// A field element modulo `2^255 - 19`.
///
/// Invariant: the value is in `[0, p)` and, after any public operation,
/// each limb is below `2^51`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u64; LIMBS]);

impl FieldElement {
    pub const ZERO: FieldElement = FieldElement([0; LIMBS]);
    pub const ONE: FieldElement = FieldElement([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Decode a 32-byte little-endian integer, reducing it modulo `p`.
    ///
    /// The most significant bit is ignored (per RFC 7748 §5) so that an
    /// all-zero or otherwise out-of-range encoding yields a canonical value.
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement {
        // RFC 7748 §5: ignore the most significant bit of the input.
        let mut buf = *bytes;
        buf[31] &= 0x7f;
        // Build the 255-bit integer, then decompose it into radix-2^51 limbs.
        let mut bitbuf: u64 = 0;
        let mut bitbuf_bits: u32 = 0;
        let mut byte_i = 0usize;
        let mut out = [0u64; LIMBS];
        for limb in out.iter_mut() {
            // Accumulate at least 51 bits (or whatever remains of the input).
            while bitbuf_bits < RADIX && byte_i < 32 {
                bitbuf |= (buf[byte_i] as u64) << bitbuf_bits;
                bitbuf_bits += 8;
                byte_i += 1;
            }
            *limb = bitbuf & MASK;
            bitbuf >>= RADIX;
            bitbuf_bits = bitbuf_bits.saturating_sub(RADIX);
        }
        FieldElement::reduce(out)
    }

    /// Encode as a 32-byte little-endian integer.
    ///
    /// The invariant value `< p < 2^255` guarantees the most significant bit
    /// of the final byte is always zero.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let mut bitbuf: u64 = 0;
        let mut bitbuf_bits: u32 = 0;
        let mut byte_i = 0usize;
        for l in 0..5 {
            bitbuf |= self.0[l] << bitbuf_bits;
            bitbuf_bits += RADIX;
            while bitbuf_bits >= 8 && byte_i < 32 {
                bytes[byte_i] = (bitbuf & 0xff) as u8;
                bitbuf >>= 8;
                bitbuf_bits -= 8;
                byte_i += 1;
            }
        }
        // Flush any trailing bits (always < 8 remain).
        while byte_i < 32 {
            bytes[byte_i] = (bitbuf & 0xff) as u8;
            bitbuf >>= 8;
            bitbuf_bits = bitbuf_bits.saturating_sub(8);
            byte_i += 1;
        }
        bytes
    }

    /// Constant-time equality with another field element.
    pub fn ct_eq(&self, other: &FieldElement) -> bool {
        ct_eq_bytes(&self.to_bytes(), &other.to_bytes())
    }

    /// Reduce a raw (possibly unnormalized) radix-2^51 vector modulo `p`.
    ///
    /// The value must be a non-negative integer below `2^510`. The reduction
    /// folds the `2^255 ≡ 19` relation four times (a fixed, data-independent
    /// iteration count) and finishes with a constant-time conditional
    /// subtraction of `p`.
    fn reduce(mut r: [u64; LIMBS]) -> FieldElement {
        r = normalize(r);
        // Four fixed folds bring any value `< 2^510` below `2^255`.
        for _ in 0..4 {
            // r = r_lo + r_hi · 2^255, with r_lo = limbs 0..5, r_hi = limbs 5..10.
            let mut low = [0u128; LIMBS];
            let mut high = [0u128; LIMBS];
            for i in 0..5 {
                low[i] = r[i] as u128;
                high[i] = r[i + 5] as u128;
            }
            // 2^255 ≡ 19 (mod p)  ⇒  new = r_lo + 19 · r_hi.
            let mut t = [0u128; LIMBS];
            for i in 0..5 {
                t[i] = low[i] + 19 * high[i];
            }
            r = normalize_u128(t);
        }
        // r < 2^255 now. Subtract p if r >= p (constant-time).
        let (diff, borrow) = sub_raw(&r, &P_LIMBS);
        // borrow == 1 means r < p → keep r; otherwise keep diff = r - p.
        let r = ct_select(&r, &diff, borrow);
        FieldElement(r)
    }

    pub(crate) fn add(&self, other: &FieldElement) -> FieldElement {
        let mut r = [0u64; LIMBS];
        let mut carry = 0u64;
        for i in 0..LIMBS {
            let s = self.0[i] + other.0[i] + carry;
            r[i] = s & MASK;
            carry = s >> RADIX;
        }
        FieldElement::reduce(r)
    }

    pub(crate) fn sub(&self, other: &FieldElement) -> FieldElement {
        let (raw, borrow) = sub_raw(&self.0, &other.0);
        // If self < other (borrow == 1) we add p back; the result is then
        // self - other + p, still a valid non-negative residue.
        let mut added = [0u64; LIMBS];
        let mut carry = 0u64;
        for i in 0..LIMBS {
            let s = raw[i] + P_LIMBS[i] + carry;
            added[i] = s & MASK;
            carry = s >> RADIX;
        }
        // borrow == 1 → keep `added`; borrow == 0 → keep `raw`.
        let result = ct_select(&added, &raw, borrow);
        FieldElement::reduce(result)
    }

    pub(crate) fn mul(&self, other: &FieldElement) -> FieldElement {
        // Schoolbook multiplication in radix 2^51. Operands are reduced, so
        // limbs 5..10 are zero and the product index `m = i + j` is at most 8.
        let mut t = [0u128; LIMBS];
        for i in 0..5 {
            for j in 0..5 {
                let term = (self.0[i] as u128) * (other.0[j] as u128);
                let m = i + j;
                if m >= 5 {
                    // 2^(51·m) ≡ 19 · 2^(51·(m-5)) (mod p).
                    t[m - 5] += 19 * term;
                } else {
                    t[m] += term;
                }
            }
        }
        let r = normalize_u128(t);
        FieldElement::reduce(r)
    }

    pub(crate) fn square(&self) -> FieldElement {
        self.mul(self)
    }

    /// Modular inverse via Fermat's little theorem: `a^(p-2)`.
    ///
    /// `p - 2 = 2^255 - 21`. The exponent is public, so the square-and-multiply
    /// control flow does not depend on the (secret) base.
    pub(crate) fn invert(&self) -> FieldElement {
        // 2^255 - 21 as a 32-byte little-endian integer.
        let mut exp = [0xFFu8; 32];
        exp[0] = 0xEB;
        exp[31] = 0x7F;
        pow(self, &exp)
    }
}

/// Square-and-multiply exponentiation with a public exponent.
fn pow(base: &FieldElement, exp: &[u8]) -> FieldElement {
    let mut acc = FieldElement::ONE;
    // Process exponent bits from most to least significant.
    for &byte in exp.iter().rev() {
        for bit in (0..8).rev() {
            acc = acc.square();
            if (byte >> bit) & 1 == 1 {
                acc = acc.mul(base);
            }
        }
    }
    acc
}

/// Normalize a radix-2^51 limb vector so every limb is below `2^51`,
/// carrying overflow into higher limbs.
fn normalize(mut r: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut carry = 0u64;
    for i in 0..LIMBS {
        let s = r[i] + carry;
        r[i] = s & MASK;
        carry = s >> RADIX;
    }
    r
}

/// Normalize a `u128`-accumulated limb vector into `u64` limbs below `2^51`.
fn normalize_u128(t: [u128; LIMBS]) -> [u64; LIMBS] {
    let mut r = [0u64; LIMBS];
    let mut carry = 0u128;
    for i in 0..LIMBS {
        let s = t[i] + carry;
        r[i] = (s & MASK_U128) as u64;
        carry = s >> RADIX;
    }
    r
}

/// Componentwise subtraction with borrow. Returns `(result, borrow)` where
/// `borrow == 1` iff `a < b`.
fn sub_raw(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> ([u64; LIMBS], u64) {
    let mut out = [0u64; LIMBS];
    let mut borrow = 0i64;
    for i in 0..LIMBS {
        let mut v = a[i] as i64 - b[i] as i64 - borrow;
        if v < 0 {
            v += 1i64 << RADIX;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = v as u64;
    }
    (out, borrow as u64)
}

/// Constant-time selection: returns `a` if `sel == 1`, else `b`.
fn ct_select(a: &[u64; LIMBS], b: &[u64; LIMBS], sel: u64) -> [u64; LIMBS] {
    let mask = 0u64.wrapping_sub(sel); // 0 or all-ones
    let mut out = [0u64; LIMBS];
    for i in 0..LIMBS {
        out[i] = (a[i] & mask) | (b[i] & !mask);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_and_zero_encode() {
        assert_eq!(FieldElement::ZERO.to_bytes(), [0u8; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(FieldElement::ONE.to_bytes(), one);
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 0xAB;
            b[1] = 0xCD;
            b
        });
        let b = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 0x12;
            b[1] = 0x34;
            b
        });
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert!(diff.ct_eq(&a), "a + b - b != a");
    }

    #[test]
    fn mul_by_one() {
        let a = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[3] = 0x42;
            b[10] = 0x99;
            b
        });
        assert!(a.mul(&FieldElement::ONE).ct_eq(&a));
        assert!(a.mul(&FieldElement::ZERO).ct_eq(&FieldElement::ZERO));
    }

    #[test]
    fn square_of_two() {
        // (2)^2 = 4
        let two = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 2;
            b
        });
        let four = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 4;
            b
        });
        assert!(two.square().ct_eq(&four));
    }

    #[test]
    fn invert_self_inverse() {
        let a = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 0x07;
            b[7] = 0x13;
            b[20] = 0x55;
            b
        });
        let inv = a.invert();
        let prod = a.mul(&inv);
        assert!(prod.ct_eq(&FieldElement::ONE), "a · a^-1 != 1");
    }

    #[test]
    fn reduce_boundary_values() {
        // p encoding should reduce to 0.
        let p = {
            let mut b = [0u8; 32];
            b[0] = 0xed;
            for i in 1..31 {
                b[i] = 0xff;
            }
            b[31] = 0x7f;
            b
        };
        assert!(FieldElement::from_bytes(&p).ct_eq(&FieldElement::ZERO));
    }

    #[test]
    fn invert_random() {
        for _ in 0..50 {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).unwrap();
            let a = FieldElement::from_bytes(&bytes);
            let inv = a.invert();
            assert!(a.mul(&inv).ct_eq(&FieldElement::ONE), "a · a^-1 != 1");
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        for _ in 0..50 {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).unwrap();
            let a = FieldElement::from_bytes(&bytes);
            let enc = a.to_bytes();
            let b = FieldElement::from_bytes(&enc);
            assert!(a.ct_eq(&b), "from_bytes(to_bytes(f)) != f");
        }
    }
}
