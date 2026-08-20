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

/// `p` represented in the full 16-limb working vector (limbs 8..15 zero,
/// since `p < 2^448`). Used by `reduce`'s final conditional subtraction over
/// the full vector.
const P_LIMBS_FULL: [u64; MUL_LIMBS] = [
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 2,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    (1u64 << 56) - 1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
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
        // Repeatedly fold the high 2^448-multiple into the low part using
        // `2^448 ≡ 2^224 + 1 (mod p)`. After enough folds the value is
        // strictly below 2^448, so limbs 8..15 are zero.
        for _ in 0..6 {
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
        // r < 2^448 now, so limbs 8..15 are zero. Conditional subtract of p
        // over the full limb vector (mirrors field255). A single subtract is
        // enough because r < 2^448 < 2p.
        let (diff, borrow) = sub_raw(&r, &P_LIMBS_FULL);
        let r = ct_select(&r, &diff, borrow);
        // The canonical value lives in limbs 0..LIMBS (limbs 8..15 are zero).
        let mut out = [0u64; LIMBS];
        out.copy_from_slice(&r[0..LIMBS]);
        FieldElement(out)
    }

    pub(crate) fn add(&self, other: &FieldElement) -> FieldElement {
        let mut r = [0u64; MUL_LIMBS];
        let mut carry = 0u64;
        for i in 0..MUL_LIMBS {
            let si = if i < LIMBS { self.0[i] } else { 0 };
            let oi = if i < LIMBS { other.0[i] } else { 0 };
            let s = si + oi + carry;
            r[i] = s & MASK;
            carry = s >> RADIX;
        }
        FieldElement::reduce(r)
    }

    pub(crate) fn sub(&self, other: &FieldElement) -> FieldElement {
        // Constant-time subtraction modulo p. Compute (self + p - other),
        // which is guaranteed to lie in [0, 2p) with no borrow; a single
        // conditional subtraction inside `reduce` canonicalizes it to [0, p).
        let mut r = [0u64; MUL_LIMBS];
        let mut carry = 0u64;
        for i in 0..MUL_LIMBS {
            let si = if i < LIMBS { self.0[i] } else { 0 };
            let pi = if i < LIMBS { P_LIMBS[i] } else { 0 };
            let s = si + pi + carry;
            r[i] = s & MASK;
            carry = s >> RADIX;
        }
        let mut borrow = 0i64;
        for i in 0..MUL_LIMBS {
            let oi = if i < LIMBS { other.0[i] } else { 0 };
            let mut v = r[i] as i64 - oi as i64 - borrow;
            if v < 0 {
                v += 1i64 << RADIX;
                borrow = 1;
            } else {
                borrow = 0;
            }
            r[i] = v as u64;
        }
        FieldElement::reduce(r)
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
        let prod = a.mul(&inv);
        // Associativity with high-limb inputs:
        let a2 = a.mul(&a);
        let a3_l = a2.mul(&a);
        let a3_r = a.mul(&a2);
        eprintln!("DBG448 assoc_eq={}", a3_l.ct_eq(&a3_r));
        eprintln!("DBG448 a.one={:?}", a.mul(&FieldElement::ONE).to_bytes());
        eprintln!("DBG448 prod={:?}", prod.to_bytes());
        assert!(prod.ct_eq(&FieldElement::ONE));
    }

    fn rand_fe() -> FieldElement {
        let mut bytes = [0u8; 56];
        getrandom::getrandom(&mut bytes).unwrap();
        FieldElement::from_bytes(&bytes)
    }

    #[test]
    fn random_add_sub_identity() {
        for _ in 0..200 {
            let x = rand_fe();
            let y = rand_fe();
            assert!(x.add(&y).sub(&y).ct_eq(&x), "x+y-y != x");
            assert!(x.sub(&y).add(&y).ct_eq(&x), "x-y+y != x");
        }
    }

    #[test]
    fn random_mul_associative() {
        for _ in 0..200 {
            let x = rand_fe();
            let y = rand_fe();
            let z = rand_fe();
            let lhs = x.mul(&y).mul(&z);
            let rhs = x.mul(&y.mul(&z));
            assert!(lhs.ct_eq(&rhs), "x*y*z != x*(y*z)");
        }
    }

    #[test]
    fn random_mul_distributive() {
        for _ in 0..200 {
            let x = rand_fe();
            let y = rand_fe();
            let z = rand_fe();
            let lhs = x.mul(&y.add(&z));
            let rhs = x.mul(&y).add(&x.mul(&z));
            assert!(lhs.ct_eq(&rhs), "x*(y+z) != x*y+x*z");
        }
    }

    #[test]
    fn random_mul_commutes() {
        for _ in 0..200 {
            let x = rand_fe();
            let y = rand_fe();
            assert!(x.mul(&y).ct_eq(&y.mul(&x)), "x*y != y*x");
        }
    }

    // ---- Independent reference big-integer field over p = 2^448 - 2^224 - 1
    // (radix 2^32, 14 limbs). Used only to cross-check our limb arithmetic.
    mod ref_bn {
        // p limbs (little-endian radix 2^32): all 0xFFFFFFFF except limb 7
        // (bit 224) and limb 0 (bit 0) cleared.
        pub fn p_limbs() -> [u32; 14] {
            let mut p = [0xFFFF_FFFFu32; 14];
            p[0] &= !1u32;
            p[7] &= !1u32;
            p
        }
        pub fn from_bytes(b: &[u8; 56]) -> [u32; 14] {
            let mut limbs = [0u32; 14];
            for (i, chunk) in b.chunks(4).enumerate() {
                let mut v = 0u32;
                for (j, c) in chunk.iter().enumerate() {
                    v |= (*c as u32) << (8 * j);
                }
                limbs[i] = v;
            }
            limbs
        }
        pub fn to_bytes(l: &[u32; 14]) -> [u8; 56] {
            let mut b = [0u8; 56];
            for (i, chunk) in b.chunks_mut(4).enumerate() {
                let v = l[i];
                for (j, c) in chunk.iter_mut().enumerate() {
                    *c = (v >> (8 * j)) as u8;
                }
            }
            b
        }
        pub fn add(a: &[u32; 14], b: &[u32; 14]) -> [u32; 14] {
            let mut r = [0u32; 14];
            let mut carry = 0u64;
            for i in 0..14 {
                let s = a[i] as u64 + b[i] as u64 + carry;
                r[i] = s as u32;
                carry = s >> 32;
            }
            let _ = carry;
            r
        }
        pub fn sub(a: &[u32; 14], b: &[u32; 14]) -> [u32; 14] {
            let mut r = [0u32; 14];
            let mut borrow = 0i64;
            for i in 0..14 {
                let mut v = a[i] as i64 - b[i] as i64 - borrow;
                if v < 0 {
                    v += 1i64 << 32;
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                r[i] = v as u32;
            }
            r
        }
        // Reduce a 28-limb (radix 2^32) product mod p using 2^448 == 2^224 + 1.
        pub fn mod_p(v: &mut [u32; 28]) {
            // 2^448 == 2^224 + 1; 2^224 == 2^(32*7).
            loop {
                let mut any_high = false;
                for i in 14..28 {
                    if v[i] != 0 {
                        any_high = true;
                    }
                }
                if !any_high {
                    break;
                }
                // new = L + H*(2^224 + 1)  where L = limbs 0..13, H = limbs 14..27.
                let mut w = [0u32; 28];
                w[0..14].copy_from_slice(&v[0..14]);
                // w += H  (the +1 term), into limbs 0..14
                let mut carry = 0u64;
                for i in 0..14 {
                    let s = w[i] as u64 + v[i + 14] as u64 + carry;
                    w[i] = s as u32;
                    carry = s >> 32;
                }
                let _ = carry;
                // w += H << 7  (the 2^224 term), into limbs 7..21
                let mut carry = 0u64;
                for i in 0..14 {
                    let s = w[i + 7] as u64 + v[i + 14] as u64 + carry;
                    w[i + 7] = s as u32;
                    carry = s >> 32;
                }
                let _ = carry;
                *v = w;
            }
            // final conditional subtract of p (value now < 2^448)
            let p = p_limbs();
            let mut ge = false;
            for i in (0..14).rev() {
                if v[i] != p[i] {
                    ge = v[i] > p[i];
                    break;
                }
                ge = true;
            }
            if ge {
                let mut borrow = 0i64;
                for i in 0..14 {
                    let mut x = v[i] as i64 - p[i] as i64 - borrow;
                    if x < 0 {
                        x += 1i64 << 32;
                        borrow = 1;
                    } else {
                        borrow = 0;
                    }
                    v[i] = x as u32;
                }
            }
        }
        pub fn mul(a: &[u32; 14], b: &[u32; 14]) -> [u32; 14] {
            let mut t = [0u128; 28];
            for i in 0..14 {
                for j in 0..14 {
                    t[i + j] += (a[i] as u128) * (b[j] as u128);
                }
            }
            let mut v = [0u32; 28];
            let mut carry = 0u128;
            for i in 0..28 {
                let s = t[i] + carry;
                v[i] = s as u32;
                carry = s >> 32;
            }
            let _ = carry;
            mod_p(&mut v);
            let mut out = [0u32; 14];
            out.copy_from_slice(&v[0..14]);
            out
        }
        pub fn pow(mut base: [u32; 14], exp: &[u8; 56]) -> [u32; 14] {
            let mut acc = [0u32; 14];
            acc[0] = 1;
            for &byte in exp.iter().rev() {
                for bit in (0..8).rev() {
                    acc = mul(&acc, &acc);
                    if (byte >> bit) & 1 == 1 {
                        acc = mul(&acc, &base);
                    }
                }
            }
            acc
        }
    }

    #[test]
    fn fermat_sweep() {
        let two = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 2;
            b
        });
        let three = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 3;
            b
        });
        let six = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 6;
            b
        });
        let four = FieldElement::from_bytes(&{
            let mut b = [0u8; 56];
            b[0] = 4;
            b
        });
        eprintln!("DBG 2*3==6: {}", two.mul(&three).ct_eq(&six));
        eprintln!("DBG 2^2==4: {}", two.square().ct_eq(&four));

        // For a=2 the inverse is (p+1)/2 = 2^447 - 2^223.
        let mut expected_inv = [0u8; 56];
        expected_inv[27] = 0x80;
        for i in 28..55 {
            expected_inv[i] = 0xFF;
        }
        expected_inv[55] = 0x7F;
        eprintln!("DBG two.inv   ={:?}", two.invert().to_bytes());
        eprintln!("DBG expected  ={:?}", expected_inv);
        eprintln!("DBG inv_match={}", two.invert().to_bytes() == expected_inv);
        for v in [2u8, 3, 5, 7, 0x13, 0x55] {
            let mut b = [0u8; 56];
            b[0] = v;
            let a = FieldElement::from_bytes(&b);
            let inv = a.invert();
            let prod = a.mul(&inv);
            let ok = prod.ct_eq(&FieldElement::ONE);
            eprintln!("DBG fermat v={} ok={} prod0={}", v, ok, prod.to_bytes()[0]);
            assert!(ok, "fermat failed for v={}", v);
        }
    }
}
