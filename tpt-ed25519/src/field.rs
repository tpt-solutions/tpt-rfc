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
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
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

/// Right-shift a 9-limb little-endian number by 255 bits.
///
/// `255 = 192 + 63`: drop the low 3 limbs, then shift the remainder right by
/// 63 bits. The result fits in 6 limbs.
fn shr255(x: &[u64; 9]) -> [u64; 6] {
    let mut y = [0u64; 6];
    for i in 0..6 {
        y[i] = x[i + 3];
    }
    let mut r = [0u64; 6];
    for i in 0..6 {
        let lo = y[i] >> 63;
        let hi = if i + 1 < 6 { y[i + 1] << 1 } else { 0 };
        r[i] = lo | hi;
    }
    r
}

/// Reduce an arbitrary little-endian limb array modulo `p = 2^255 - 19`.
///
/// The fold `x -> (x mod 2^255) + 19 * (x >> 255)` is applied a fixed number
/// of times, which is data-independent and therefore constant-time. Five
/// iterations suffice to bring any 512-bit product below `2^255`; two
/// conditional subtractions then produce the canonical representative.
fn reduce_fe(limbs: &[u64]) -> FieldElement {
    let mut v = [0u64; 9];
    for (i, &x) in limbs.iter().enumerate() {
        if i < 9 {
            v[i] = x;
        }
    }
    for _ in 0..5 {
        let a = [v[0], v[1], v[2], v[3] & 0x7FFF_FFFF_FFFF_FFFF];
        let b = shr255(&v);
        let mut prod = [0u64; 7];
        let mut carry = 0u128;
        for i in 0..6 {
            let s = carry + 19u128 * (b[i] as u128);
            prod[i] = s as u64;
            carry = s >> 64;
        }
        prod[6] = carry as u64;
        v = [0u64; 9];
        let mut c = 0u128;
        for i in 0..9 {
            let ai = if i < 4 { a[i] as u128 } else { 0 };
            let pi = if i < 7 { prod[i] as u128 } else { 0 };
            let s = c + ai + pi;
            v[i] = s as u64;
            c = s >> 64;
        }
    }
    let mut r = [v[0], v[1], v[2], v[3]];
    if ge4(&r, &P) {
        r = sub_limb4(&r, &P);
    }
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
    pub(crate) const ONE: FieldElement = FieldElement {
        limbs: [1, 0, 0, 0],
    };

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
            let si = self.limbs[i] as u128;
            for j in 0..4 {
                let idx = i + j;
                if idx < 8 {
                    let s = limbs[idx] as u128 + si * (other.limbs[j] as u128) + carry;
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
            0xFFFF_FFFF_FFFF_FFEB,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x7FFF_FFFF_FFFF_FFFF, // 2^255 - 21 == p - 2
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
        assert_eq!(
            FieldElement::from_u64(5).mul(&FieldElement::from_u64(7)),
            FieldElement::from_u64(35)
        );
    }

    #[test]
    fn square_small() {
        assert_eq!(
            FieldElement::from_u64(7).square(),
            FieldElement::from_u64(49)
        );
    }

    #[test]
    fn neg_add() {
        // (p - 5) + 10 = 5 (mod p)
        let pm5 = FieldElement::from_u64(5)
            .neg()
            .add(&FieldElement::from_u64(10));
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
    fn pow_small_exponents() {
        let two = FieldElement::from_u64(2);
        let five = FieldElement::from_u64(5);
        assert_eq!(two.pow(&[3, 0, 0, 0]), FieldElement::from_u64(8));
        assert_eq!(five.pow(&[2, 0, 0, 0]), FieldElement::from_u64(25));
        assert_eq!(two.pow(&[10, 0, 0, 0]), FieldElement::from_u64(1024));
    }

    #[test]
    fn invert_small() {
        let a = FieldElement::from_u64(2);
        let inv = a.invert();
        assert_eq!(a.mul(&inv), FieldElement::ONE, "2 * 2^-1");
    }

    #[test]
    fn two255_is_19() {
        // 2^255 = 19 (mod 2^255 - 19); route the raw limb value through reduce.
        let mut limbs = [0u64; 4];
        limbs[3] = 1u64 << 63;
        let x = reduce_fe(&limbs);
        assert_eq!(x, FieldElement::from_u64(19));
    }

    #[test]
    fn reduce_wraps() {
        // 2^255 - 1 = 18 (mod 2^255 - 19)
        let big = [0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF, 0, 0, 0, 0];
        let r = reduce_fe(&big);
        assert_eq!(r, FieldElement::from_u64(18), "2^255-1 mod p");
    }

    #[test]
    fn invert_roundtrip_many() {
        for v in [1u64, 2, 3, 1234567, 0xFFFF_FFFF_FFFF_FFFE, u64::MAX] {
            let a = FieldElement::from_u64(v);
            let inv = a.invert();
            assert_eq!(a.mul(&inv), FieldElement::ONE, "invert roundtrip for {v}");
        }
    }

    #[test]
    fn fuzz_field_identities() {
        let mut s = 0x1234_5678_9abc_def0u64;
        fn lcg(st: &mut u64) -> u64 {
            *st = st.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(0x9e37_79b9_7f4a_7c15);
            *st
        }
        fn rand_fe(st: &mut u64) -> FieldElement {
            let mut limbs = [0u64; 4];
            for i in 0..4 {
                limbs[i] = lcg(st);
            }
            // reduce an arbitrary 4-limb number mod p
            FieldElement::from_bytes(&{
                let mut b = [0u8; 32];
                for i in 0..4 {
                    b[i * 8..i * 8 + 8].copy_from_slice(&limbs[i].to_le_bytes());
                }
                b
            })
            .unwrap_or(FieldElement::ZERO)
        }
        for _ in 0..20000 {
            let a = rand_fe(&mut s);
            let b = rand_fe(&mut s);
            let c = rand_fe(&mut s);
            // associativity of add
            assert_eq!(a.add(&b).add(&c), a.add(&b.add(&c)), "add assoc");
            // associativity of mul
            assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)), "mul assoc");
            // distributivity
            assert_eq!(
                a.mul(&b.add(&c)),
                a.mul(&b).add(&a.mul(&c)),
                "distributive"
            );
            // add/sub roundtrip
            assert_eq!(a.add(&b).sub(&b), a, "add/sub roundtrip");
            // invert
            if !a.is_zero() {
                assert_eq!(a.mul(&a.invert()), FieldElement::ONE, "invert");
            }
        }
    }

    fn ref_ge9(a: &[u64; 9], b: &[u64; 9]) -> bool {
        for i in (0..9).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    fn ref_mod_p(limbs8: &[u64; 8]) -> [u64; 4] {
        let mut v = [0u64; 9];
        v[..8].copy_from_slice(limbs8);
        let mut pbits = 0usize;
        for i in (0..4).rev() {
            if P[i] != 0 {
                pbits = i * 64 + 63 - P[i].leading_zeros() as usize;
                break;
            }
        }
        loop {
            let mut hi = 0;
            for i in (0..9).rev() {
                if v[i] != 0 {
                    hi = i * 64 + 63 - v[i].leading_zeros() as usize;
                    break;
                }
            }
            if hi < pbits {
                break;
            }
            let sh = hi - pbits;
            let mut pp = [0u64; 9];
            let limb = sh / 64;
            let bit = sh % 64;
            for i in 0..4 {
                let lo = P[i] << bit;
                if limb + i < 9 {
                    pp[limb + i] |= lo;
                }
                if bit > 0 && limb + i + 1 < 9 {
                    pp[limb + i + 1] |= P[i] >> (64 - bit);
                }
            }
            if !ref_ge9(&v, &pp) {
                break;
            }
            let mut borrow = 0i128;
            for i in 0..9 {
                let pv = pp[i];
                let x = v[i] as i128 - pv as i128 - borrow;
                if x < 0 {
                    v[i] = (x + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    v[i] = x as u64;
                    borrow = 0;
                }
            }
        }
        [v[0], v[1], v[2], v[3]]
    }

    fn raw8(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
        let mut p = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let idx = i + j;
                if idx < 8 {
                    let s = p[idx] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
                    p[idx] = s as u64;
                    carry = s >> 64;
                }
            }
            let mut k = i + 4;
            let mut c = carry;
            while c > 0 && k < 8 {
                let s = p[k] as u128 + c;
                p[k] = s as u64;
                c = s >> 64;
                k += 1;
            }
        }
        p
    }

    #[test]
    fn x_squared_matches_curve_equation() {
        let y = FieldElement::from_u64(4).mul(&FieldElement::from_u64(5).invert());
        let d = FieldElement::from_u64(121665)
            .neg()
            .mul(&FieldElement::from_u64(121666).invert());
        let y2 = y.square();
        let den = y2.mul(&d).add(&FieldElement::ONE);
        let x2 = y2.sub(&FieldElement::ONE).mul(&den.invert());
        assert_eq!(
            x2.mul(&den),
            y2.sub(&FieldElement::ONE),
            "x^2*(1+d*y^2) != y^2-1"
        );
    }
    #[test]
    fn curve_equation_holds() {
        // For the base point y = 4/5, the recovered x must satisfy
        // -x^2 + y^2 == 1 + d*x^2*y^2 (mod p).
        let y = FieldElement::from_u64(4).mul(&FieldElement::from_u64(5).invert());
        let d = FieldElement::from_u64(121665)
            .neg()
            .mul(&FieldElement::from_u64(121666).invert());
        let y2 = y.square();
        let den = y2.mul(&d).add(&FieldElement::ONE);
        let x2 = y2.sub(&FieldElement::ONE).mul(&den.invert());
        let lhs = y2.sub(&x2);
        let rhs = FieldElement::ONE.add(&d.mul(&x2));
        assert_eq!(lhs, rhs, "base x^2 fails curve equation");
    }

    #[test]
    fn ref_mul_matches() {
        let mut s = 0x1234_5678_9abc_def0u64;
        fn lcg(st: &mut u64) -> u64 {
            *st = st
                .wrapping_mul(0x2545_f491_4f6c_dd1d)
                .wrapping_add(0x9e37_79b9_7f4a_7c15);
            *st
        }
        for _ in 0..2000 {
            let mut la = [0u64; 4];
            let mut lb = [0u64; 4];
            for i in 0..4 {
                la[i] = lcg(&mut s);
                lb[i] = lcg(&mut s);
            }
            let fa = FieldElement { limbs: la };
            let fb = FieldElement { limbs: lb };
            let mut prod = [0u64; 8];
            for i in 0..4 {
                let mut carry = 0u128;
                let si = la[i] as u128;
                for j in 0..4 {
                    let idx = i + j;
                    if idx < 8 {
                        let sv = si * (lb[j] as u128) + carry;
                        let s = prod[idx] as u128 + sv;
                        prod[idx] = s as u64;
                        carry = s >> 64;
                    }
                }
                let mut k = i + 4;
                let mut c = carry;
                while c > 0 && k < 8 {
                    let s = prod[k] as u128 + c;
                    prod[k] = s as u64;
                    c = s >> 64;
                    k += 1;
                }
            }
            assert_eq!(prod, raw8(&la, &lb), "schoolbook product mismatch");
            let got = fa.mul(&fb).limbs;
            let exp = ref_mod_p(&raw8(&la, &lb));
            let red = reduce_fe(&prod);
            assert_eq!(red.limbs, exp, "reduce_fe mismatch prod={:?}", prod);
            assert_eq!(got, exp, "mul mismatch la={:?} lb={:?}", la, lb);
        }
    }

    #[test]
    fn reduce_fe_simple() {
        let mut p256 = [0u64; 8];
        p256[4] = 1; // 2^256
        let r = reduce_fe(&p256);
        assert_eq!(r.limbs, [38, 0, 0, 0], "2^256 mod p != 38");
        let mut p255 = [0u64; 8];
        p255[3] = 1 << 63; // 2^255
        let r2 = reduce_fe(&p255);
        assert_eq!(r2.limbs, [19, 0, 0, 0], "2^255 mod p != 19");
        let mut pm1 = [0u64; 8];
        pm1[0] = 0xFFFFFFFFFFFFFFFF;
        pm1[1] = 0xFFFFFFFFFFFFFFFF;
        pm1[2] = 0xFFFFFFFFFFFFFFFF;
        pm1[3] = 0x7FFFFFFFFFFFFFFF;
        let r3 = reduce_fe(&pm1);
        assert_eq!(r3.limbs, [18, 0, 0, 0], "2^255-1 mod p != 18");
        let pp = raw8(&P, &P);
        assert_eq!(reduce_fe(&pp).limbs, [361, 0, 0, 0], "reduce_fe(p*p) != 361");
        assert_eq!(ref_mod_p(&pp), [361, 0, 0, 0], "ref_mod_p(p*p) != 361");
    }
}
