// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 group operations on the edwards25519 curve, using extended
//! homogeneous coordinates `(X, Y, Z, T)` with `x = X/Z`, `y = Y/Z`,
//! `x*y = T/Z` and `a = -1` (RFC 8032 §5.1.4).

use crate::field::FieldElement;
use crate::scalar::Scalar;
use std::sync::OnceLock;

/// Exponent `(p+3)/8` used for square-root recovery (RFC 8032 §5.1.3).
const EXP_P_PLUS3_DIV8: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0FFF_FFFF_FFFF_FFFF,
];
/// Exponent `(p-1)/4`, whose result is a square root of `-1` (RFC 8032 §5.1.1).
const EXP_P_MINUS1_DIV4: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFB,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x1FFF_FFFF_FFFF_FFFF,
];

/// Compute the curve constant `d = -121665 / 121666 (mod p)`.
fn curve_d() -> FieldElement {
    let neg_num = FieldElement::from_u64(121665).neg(); // -121665
    let den = FieldElement::from_u64(121666);
    neg_num.mul(&den.invert())
}

/// Compute a square root of `-1` modulo `p`, i.e. `2^((p-1)/4)`.
fn sqrt_minus1() -> FieldElement {
    FieldElement::from_u64(2).pow(&EXP_P_MINUS1_DIV4)
}

/// Recover the `x` coordinate from `y` and the sign of `x` (RFC 8032 §5.1.3).
fn recover_x(y: &FieldElement, sign: u8) -> Option<FieldElement> {
    let one = FieldElement::ONE;
    let y2 = y.square();
    let den = curve_d().mul(&y2).add(&one);
    let x2 = y2.sub(&one).mul(&den.invert());
    if x2.is_zero() {
        return if sign != 0 {
            None
        } else {
            Some(FieldElement::ZERO)
        };
    }
    let mut x = x2.pow(&EXP_P_PLUS3_DIV8);
    if !x.square().ct_eq(&x2) {
        x = x.mul(&sqrt_minus1());
        if !x.square().ct_eq(&x2) {
            return None;
        }
    }
    if x.is_negative() != (sign != 0) {
        x = x.neg();
    }
    Some(x)
}

/// A point on the edwards25519 curve in extended homogeneous coordinates.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    const IDENTITY: Point = Point {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// Build a point from affine `(x, y)` with `Z = 1`.
    fn from_affine(x: FieldElement, y: FieldElement) -> Point {
        Point {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(&y),
        }
    }

    /// Complete extended-coordinate addition (RFC 8032 §5.1.4).
    pub(crate) fn add(&self, other: &Point) -> Point {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&other.t).mul(&curve_d());
        let d = self.z.mul(&other.z);
        let e = self
            .x
            .add(&self.y)
            .mul(&other.x.add(&other.y))
            .sub(&a)
            .sub(&b);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.sub(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn double(&self) -> Point {
        self.add(self)
    }

    /// Constant-time selection: returns `b` if `mask` (0 or 1) is 1, else `a`.
    fn ct_select(a: &Point, b: &Point, mask: u64) -> Point {
        let m = mask & 1;
        Point {
            x: a.x.add(&b.x.sub(&a.x).scale(m)),
            y: a.y.add(&b.y.sub(&a.y).scale(m)),
            z: a.z.add(&b.z.sub(&a.z).scale(m)),
            t: a.t.add(&b.t.sub(&a.t).scale(m)),
        }
    }

    /// Constant-time scalar multiplication `[s] * self` (double-and-add).
    pub(crate) fn mul_scalar(&self, s: &Scalar) -> Point {
        let mut q = Point::IDENTITY;
        for bit in (0..256).rev() {
            q = q.double();
            let addp = q.add(self);
            q = Point::ct_select(&q, &addp, s.bit(bit) as u64);
        }
        q
    }

    /// Encode the point to its 32-byte canonical form (RFC 8032 §5.1.2).
    pub(crate) fn encode(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut out = y.to_bytes();
        if x.is_negative() {
            out[31] |= 0x80;
        }
        out
    }

    /// Decode a 32-byte string to a curve point, or `None` if invalid (§5.1.3).
    pub(crate) fn decode(bytes: &[u8; 32]) -> Option<Point> {
        let mut yb = *bytes;
        let sign = (yb[31] >> 7) & 1;
        yb[31] &= 0x7f;
        let y = FieldElement::from_bytes(&yb)?;
        let x = recover_x(&y, sign)?;
        Some(Point::from_affine(x, y))
    }
}

/// Compute the standard edwards25519 base point `B` (`y = 4/5`).
fn base_point() -> Point {
    let y = FieldElement::from_u64(4).mul(&FieldElement::from_u64(5).invert());
    let x = recover_x(&y, 0).expect("edwards25519 base point recovers");
    Point::from_affine(x, y)
}

/// Lazily-initialised, process-wide base point `B`.
pub(crate) fn base_point_ref() -> &'static Point {
    static B: OnceLock<Point> = OnceLock::new();
    B.get_or_init(base_point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::Scalar;

    #[test]
    fn scalar_mult_order_is_identity() {
        let b = base_point_ref();
        let l = Scalar::from_limbs_mod_l([
            0x5812_631a_5cf5_d3ed,
            0x14de_f9de_a2f7_9cd6,
            0x0000_0000_0000_0000,
            0x1000_0000_0000_0000,
        ]);
        let r = b.mul_scalar(&l);
        let enc = r.encode();
        // Identity encodes as y = 1 (little-endian), x sign bit 0.
        assert_eq!(enc[0], 1);
        for i in 1..31 {
            assert_eq!(enc[i], 0);
        }
        assert_eq!(enc[31], 0);
    }

    #[test]
    fn scalar_mult_two_equals_double() {
        let b = base_point_ref();
        let two = Scalar::from_limbs_mod_l([2, 0, 0, 0]);
        let r = b.mul_scalar(&two);
        assert_eq!(r.encode(), b.add(b).encode());
    }

    #[test]
    fn scalar_mult_seed_4ccd_pubkey() {
        use crate::SigningKey;
        // Seed 4ccd... must yield public key 3d4017c3...
        let seed = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb6, 0xa6, 0xfb,
        ];
        let sk = SigningKey::from_bytes(&seed);
        let enc = sk.verifying_key().to_bytes();
        let expected = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        assert_eq!(enc, expected);
    }

    #[test]
    fn scalar_mult_vs_naive() {
        let b = base_point_ref();
        let mut acc = Point::IDENTITY;
        for n in 1u64..257 {
            acc = acc.add(b);
            let s = Scalar::from_limbs_mod_l([n, 0, 0, 0]);
            let got = b.mul_scalar(&s);
            assert_eq!(got.encode(), acc.encode(), "mismatch at n={n}");
        }
    }

    /// Independent LSB-first scalar multiplication, used to cross-check `mul_scalar`.
    fn mul_scalar_lsb(p: &Point, s: &Scalar) -> Point {
        let mut result = Point::IDENTITY;
        let mut addend = *p;
        for bit in 0..256 {
            if s.bit(bit) == 1 {
                result = result.add(&addend);
            }
            addend = addend.add(&addend);
        }
        result
    }

    #[test]
    fn scalar_mult_lsb_matches_msf_and_rfc() {
        use crate::SigningKey;
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
        let a = Scalar::from_limbs_mod_l(limbs);
        let b = base_point_ref();
        let msb = b.mul_scalar(&a);
        let lsb = mul_scalar_lsb(&b, &a);
        let expected = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        assert_eq!(msb.encode(), expected, "MSB mul_scalar wrong");
        assert_eq!(lsb.encode(), expected, "LSB mul_scalar wrong");
        let _ = SigningKey::from_bytes(&seed);
    }

    /// Independent affine-coordinate scalar multiplication (standard Edwards
    /// addition, a = -1), used to cross-check `mul_scalar`.
    fn affine_mul_scalar(s: &Scalar) -> [u8; 32] {
        let d = curve_d();
        let bp = base_point_ref();
        let zinv = bp.z.invert();
        let mut x = bp.x.mul(&zinv);
        let mut y = bp.y.mul(&zinv);
        // identity affine: (0, 1)
        let mut rx = FieldElement::ZERO;
        let mut ry = FieldElement::ONE;
        for bit in 0..256 {
            if s.bit(bit) == 1 {
                // add (rx,ry) + (x,y)
                let numx = rx.mul(&y).add(&x.mul(&ry));
                let denx = FieldElement::ONE.add(&d.mul(&rx).mul(&x).mul(&ry).mul(&y));
                let numy = ry.mul(&y).add(&rx.mul(&x));
                let deny = FieldElement::ONE.sub(&d.mul(&rx).mul(&x).mul(&ry).mul(&y));
                let nx = numx.mul(&denx.invert());
                let ny = numy.mul(&deny.invert());
                rx = nx;
                ry = ny;
            }
            // double (x,y)
            let numx = x.mul(&y).add(&x.mul(&y));
            let denx = FieldElement::ONE.add(&d.mul(&x).mul(&x).mul(&y).mul(&y));
            let numy = y.mul(&y).sub(&x.mul(&x));
            let deny = FieldElement::ONE.sub(&d.mul(&x).mul(&x).mul(&y).mul(&y));
            x = numx.mul(&denx.invert());
            y = numy.mul(&deny.invert());
        }
        let mut out = ry.to_bytes();
        if x.is_negative() {
            out[31] |= 0x80;
        }
        out
    }

    #[test]
    fn large_scalar_consistency() {
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
        let a = Scalar::from_limbs_mod_l(limbs);
        let b = base_point_ref();
        let a_plus_1 = a.add_mod(&Scalar::from_limbs_mod_l([1, 0, 0, 0]));
        let lhs = b.mul_scalar(&a).add(b);
        let rhs = b.mul_scalar(&a_plus_1);
        assert_eq!(lhs.encode(), rhs.encode(), "large scalar consistency broken");
    }

    fn on_curve(p: &Point) -> bool {
        let zinv = p.z.invert();
        let x = p.x.mul(&zinv);
        let y = p.y.mul(&zinv);
        let lhs = y.square().sub(&x.square());
        let rhs = FieldElement::ONE.add(&curve_d().mul(&x.square()).mul(&y.square()));
        lhs == rhs
    }

    #[test]
    fn doubling_stays_on_curve() {
        let b = base_point_ref();
        assert!(on_curve(&b.add(&b)), "[2]B off curve");
        assert!(
            on_curve(&b.mul_scalar(&Scalar::from_limbs_mod_l([3, 0, 0, 0]))),
            "[3]B off curve"
        );
        let seed = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb6, 0xa6, 0xfb,
        ];
        use sha2::{Digest, Sha512};
        let h = Sha512::digest(seed);
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut bb = [0u8; 8];
            bb.copy_from_slice(&h[i * 8..i * 8 + 8]);
            limbs[i] = u64::from_le_bytes(bb);
        }
        limbs[0] &= !0x7u64;
        limbs[3] = (limbs[3] & !(1u64 << 63)) | (1u64 << 62);
        let a = Scalar::from_limbs_mod_l(limbs);
        assert!(on_curve(&base_point_ref().mul_scalar(&a)), "[a]B off curve");
    }

    #[test]
    fn affine_mul_scalar_vs_rfc() {
        use sha2::{Digest, Sha512};
        let seeds: [([u8; 32], [u8; 32]); 2] = [
            (
                [
                    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec,
                    0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c,
                    0xf6, 0xed, 0x4f, 0xb6, 0xa6, 0xfb,
                ],
                [
                    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
                    0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55,
                    0xf1, 0x2a, 0xf4, 0x66, 0x0c,
                ],
            ),
            (
                [
                    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
                    0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac,
                    0x03, 0x1c, 0xae, 0x7f, 0x60,
                ],
                [
                    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                    0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a,
                    0x68, 0xf7, 0x07, 0x51, 0x1a,
                ],
            ),
        ];
        for (seed, expected_pk) in seeds {
            let h = Sha512::digest(seed);
            let mut limbs = [0u64; 4];
            for i in 0..4 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&h[i * 8..i * 8 + 8]);
                limbs[i] = u64::from_le_bytes(b);
            }
            limbs[0] &= !0x7u64;
            limbs[3] = (limbs[3] & !(1u64 << 63)) | (1u64 << 62);
            let a = Scalar::from_limbs_mod_l(limbs);
            let got = base_point_ref().mul_scalar(&a).encode();
            let aff = affine_mul_scalar(&a);
            assert_eq!(got, expected_pk, "mul_scalar != RFC pubkey");
            assert_eq!(aff, expected_pk, "affine mul_scalar != RFC pubkey");
        }
    }

    #[test]
    fn tmp_modl() {
        let b = base_point_ref();
        for n in [3u64, 4, 5, 6, 7] {
            let s = crate::scalar::Scalar::from_limbs_mod_l([n, 0, 0, 0]);
            let got = b.mul_scalar(&s).encode();
            eprintln!("[{}]B = {:?}", n, got);
        }
    }

    #[test]
    fn tmp_probe() {
        let y = FieldElement::from_u64(4).mul(&FieldElement::from_u64(5).invert());
        let d = curve_d();
        let y2 = y.square();
        let den = d.mul(&y2).add(&FieldElement::ONE);
        let x2 = y2.sub(&FieldElement::ONE).mul(&den.invert());
        let sm1 = sqrt_minus1();
        let xp = x2.pow(&EXP_P_PLUS3_DIV8);
        eprintln!("d    = {:?}", d.to_bytes());
        eprintln!("y2   = {:?}", y2.to_bytes());
        eprintln!("den  = {:?}", den.to_bytes());
        eprintln!("x2   = {:?}", x2.to_bytes());
        eprintln!("sm1  = {:?}", sm1.to_bytes());
        eprintln!("xp   = {:?}", xp.to_bytes());
        eprintln!("xp^2 = {:?}", xp.square().to_bytes());
        eprintln!("BASE y = {:?}", y.to_bytes());
        let seed = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
            0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb6,
            0xa6, 0xfb,
        ];
        let sk = crate::SigningKey::from_bytes(&seed);
        let b = base_point_ref();
        let d2 = b.add(b);
        eprintln!("[2]B = {:?}", d2.encode());
        let (a, _p) = crate::expand_seed(&seed);
        eprintln!("a    = {:?}", a.to_bytes_le());
        eprintln!("PK = {:?}", sk.verifying_key().to_bytes());
        eprintln!("OC base = {}", on_curve(&b));
        eprintln!("OC d2   = {}", on_curve(&b.add(&b)));
    }
}
