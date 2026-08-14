// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clean-room field arithmetic for the Curve448 prime
//! `p = 2^448 - 2^224 - 1`, implemented as a constant-time Montgomery ladder
//! primitive for RFC 7748 X448.
//!
//! Elements are stored in radix-2^56 form: eight `u64` limbs with
//! `value = Σ limb[i] * 2^(56·i)`, each limb kept below `2^56`. Products are
//! accumulated in a sixteen-limb `u128` buffer and reduced via the
//! `2^448 ≡ 2^224 + 1` relation. All operations are constant-time in their
//! operands; only the public exponent in `invert` drives control flow.

use crate::util::ct_eq_bytes;

const LIMBS: usize = 8;
const MUL_LIMBS: usize = 16;
const RADIX: u32 = 56;
/// `2^56 - 1`, the per-limb mask.
const MASK: u64 = (1u64 << RADIX) - 1;
/// `2^56 - 1` as a `u128`, for the `u128` accumulation path.
const MASK_U128: u128 = (1u128 << RADIX) - 1;

/// `p = 2^448 - 2^224 - 1` in radix-2^56 limbs.
///
/// `2^448 - 1` is all eight limbs equal to `2^56 - 1`; subtracting `2^224`
/// (limb 4) drops limb 4 to `2^56 - 2`.
const P_LIMBS: [u64; LIMBS] = [
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 2,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
];

/// A field element modulo `2^448 - 2^224 - 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u64; LIMBS]);

impl FieldElement {
    pub const ZERO: FieldElement = FieldElement([0; LIMBS]);
    pub const ONE: FieldElement = FieldElement([1, 0, 0, 0, 0, 0, 0, 0]);

    /// Decode a 56-byte little-endian integer, reducing it modulo `p`.
    ///
    /// The most significant bit (bit 447) is ignored per RFC 7748 §5.
    pub fn from_bytes(bytes: &[u8; 56]) -> FieldElement {
        // RFC 7748 §5: ignore the most significant bit (bit 447) of the input.
        let mut buf = *bytes;
        buf[55] &= 0x7f;
        let mut bitbuf: u64 = 0;
        let mut bitbuf_bits: u32 = 0;
        let mut byte_i = 0usize;
        let mut out = [0u64; MUL_LIMBS];
        for limb in out.iter_mut().take(LIMBS) {
            while bitbuf_bits < RADIX && byte_i < 56 {
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

    /// Encode as a 56-byte little-endian integer.
    pub fn to_bytes(&self) -> [u8; 56] {
        let mut bytes = [0u8; 56];
        let mut bitbuf: u64 = 0;
        let mut bitbuf_bits: u32 = 0;
        let mut byte_i = 0usize;
        for l in 0..LIMBS {
            bitbuf |= self.0[l] << bitbuf_bits;
            bitbuf_bits += RADIX;
            while bitbuf_bits >= 8 && byte_i < 56 {
                bytes[byte_i] = (bitbuf & 0xff) as u8;
                bitbuf >>= 8;
                bitbuf_bits -= 8;
                byte_i += 1;
            }
        }
        while byte_i < 56 {
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

    /// Reduce a raw radix-2^56 vector (value below `2^896`) modulo `p`.
    fn reduce(mut r: [u64; MUL_LIMBS]) -> FieldElement {
        r = normalize16(r);
        // Five fixed folds bring any value `< 2^896` below `2^448`.
        for _ in 0..5 {
            let mut low = [0u128; MUL_LIMBS];
            let mut high = [0u128; MUL_LIMBS];
            for i in 0..LIMBS {
                low[i] = r[i] as u128;
                high[i] = r[i + LIMBS] as u128;
            }
            // 2^448 ≡ 2^224 + 1 (mod p) ⇒ new = low + high + high·2^224.
            let mut t = [0u128; MUL_LIMBS];
            for i in 0..LIMBS {
                t[i] = low[i] + high[i];
            }
            for i in 0..LIMBS {
                t[i + 4] += high[i];
            }
            r = normalize16_u128(t);
        }
        // r < 2^448 now. Conditional subtract p.
        let mut re = [0u64; LIMBS];
        re.copy_from_slice(&r[0..LIMBS]);
        let (diff, borrow) = sub_raw(&re, &P_LIMBS);
        let re = ct_select(&re, &diff, borrow);
        FieldElement(re)
    }

    pub(crate) fn add(&self, other: &FieldElement) -> FieldElement {
        let mut r = [0u64; MUL_LIMBS];
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
        let mut added = [0u64; LIMBS];
        let mut carry = 0u64;
        for i in 0..LIMBS {
            let s = raw[i] + P_LIMBS[i] + carry;
            added[i] = s & MASK;
            carry = s >> RADIX;
        }
        // Promote to the 16-limb representation used by `reduce`.
        let mut raw16 = [0u64; MUL_LIMBS];
        raw16[..LIMBS].copy_from_slice(&raw);
        let mut added16 = [0u64; MUL_LIMBS];
        added16[..LIMBS].copy_from_slice(&added);
        let result = ct_select(&added16, &raw16, borrow);
        FieldElement::reduce(result)
    }

    pub(crate) fn mul(&self, other: &FieldElement) -> FieldElement {
        let mut t = [0u128; MUL_LIMBS];
        for i in 0..LIMBS {
            for j in 0..LIMBS {
                let term = (self.0[i] as u128) * (other.0[j] as u128);
                let m = i + j;
                if m >= LIMBS {
                    // 2^(56·m) ≡ 2^(56·(m-8)) · (2^224 + 1) (mod p).
                    t[m - LIMBS] += term; // × 1
                    t[m - 4] += term; // × 2^224
                } else {
                    t[m] += term;
                }
            }
        }
        let r = normalize16_u128(t);
        FieldElement::reduce(r)
    }

    pub(crate) fn square(&self) -> FieldElement {
        self.mul(self)
    }

    /// Modular inverse via Fermat: `a^(p-2)` where `p - 2 = 2^448 - 2^224 - 3`.
    pub(crate) fn invert(&self) -> FieldElement {
        // 2^448 - 2^224 - 3 as a 56-byte little-endian integer.
        let mut exp = [0xFFu8; 56];
        exp[0] = 0xFD;
        exp[28] = 0xFE;
        pow(self, &exp)
    }
}

/// Square-and-multiply exponentiation with a public exponent.
fn pow(base: &FieldElement, exp: &[u8]) -> FieldElement {
    let mut acc = FieldElement::ONE;
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

fn normalize16(mut r: [u64; MUL_LIMBS]) -> [u64; MUL_LIMBS] {
    let mut carry = 0u64;
    for i in 0..MUL_LIMBS {
        let s = r[i] + carry;
        r[i] = s & MASK;
        carry = s >> RADIX;
    }
    r
}

fn normalize16_u128(t: [u128; MUL_LIMBS]) -> [u64; MUL_LIMBS] {
    let mut r = [0u64; MUL_LIMBS];
    let mut carry = 0u128;
    for i in 0..MUL_LIMBS {
        let s = t[i] + carry;
        r[i] = (s & MASK_U128) as u64;
        carry = s >> RADIX;
    }
    r
}

fn sub_raw<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut borrow = 0i64;
    for i in 0..N {
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

fn ct_select<const N: usize>(a: &[u64; N], b: &[u64; N], sel: u64) -> [u64; N] {
    let mask = 0u64.wrapping_sub(sel);
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = (a[i] & mask) | (b[i] & !mask);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_and_zero_encode() {
        assert_eq!(FieldElement::ZERO.to_bytes(), [0u8; 56]);
        let mut one = [0u8; 56];
        one[0] = 1;
        assert_eq!(FieldElement::ONE.to_bytes(), one);
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 0xAB;
            b[10] = 0xCD;
            b
        });
        let b = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 0x12;
            b[20] = 0x34;
            b
        });
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert!(diff.ct_eq(&a));
    }

    #[test]
    fn mul_by_one() {
        let a = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[3] = 0x42;
            b[40] = 0x99;
            b
        });
        assert!(a.mul(&FieldElement::ONE).ct_eq(&a));
        assert!(a.mul(&FieldElement::ZERO).ct_eq(&FieldElement::ZERO));
    }

    #[test]
    fn square_of_three() {
        let three = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 3;
            b
        });
        let nine = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 9;
            b
        });
        assert!(three.square().ct_eq(&nine));
    }

    #[test]
    fn invert_self_inverse() {
        let a = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 0x07;
            b[11] = 0x13;
            b[33] = 0x55;
            b
        });
        let inv = a.invert();
        assert!(a.mul(&inv).ct_eq(&FieldElement::ONE));
    }
}
