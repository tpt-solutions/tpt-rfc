// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 group operations on the edwards25519 curve, using extended
//! homogeneous coordinates `(X, Y, Z, T)` with `x = X/Z`, `y = Y/Z`,
//! `x*y = T/Z` and `a = -1` (RFC 8032 §5.1.4).

use crate::field::FieldElement;
use crate::scalar::Scalar;
use std::sync::OnceLock;

/// Exponent `(p+3)/8` used for square-root recovery (RFC 8032 §5.1.3).
const EXP_P_PLUS3_DIV8: [u64; 4] = [0, 0, 0, 0x0FFF_FFFF_FFFF_FFFE];
/// Exponent `(p-1)/4`, whose result is a square root of `-1` (RFC 8032 §5.1.1).
const EXP_P_MINUS1_DIV4: [u64; 4] = [0, 0, 0, 0x1FFF_FFFF_FFFF_FFFB];

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
        return if sign != 0 { None } else { Some(FieldElement::ZERO) };
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
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self
            .t
            .mul(&other.t)
            .mul(&curve_d())
            .mul(&FieldElement::from_u64(2));
        let d = self.z.mul(&other.z).mul(&FieldElement::from_u64(2));
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
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
