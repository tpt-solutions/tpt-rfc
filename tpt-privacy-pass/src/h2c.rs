//! Clean-room RFC 9380 (Hashing to Elliptic Curves) implementation for the
//! NIST P-256 and P-384 prime-order groups, used by RFC 9497 (OPRF/VOPRF/POPRF)
//! and RFC 9576 (Privacy Pass).
//!
//! This module implements, from the specification only (no code copied from
//! `hash2curve`/`voprf`/etc.):
//!
//! * `expand_message_xmd` (RFC 9380 §5.3.1) — the XMD expander built on a
//!   Merkle-Damgård hash (`sha2::Sha256` / `sha2::Sha384`);
//! * `hash_to_field` (RFC 9380 §5.2) — field-element derivation with the
//!   bias-controlled `L = ceil((ceil(log2 p) + k) / 8)` byte length;
//! * `map_to_curve` (RFC 9380 §6.6.2, Simplified SWU) — the Optimized
//!   Shallue-van de Woestijne-Ulas map for short Weierstrass curves with
//!   `A = -3` (both P-256 and P-384 use `Z = -1`);
//! * `hash_to_curve` (RFC 9380 §3) — `Q0 + Q1` with cofactor clearing (the
//!   P-256 / P-384 cofactors are both `1`, so clearing is the identity).
//!
//! All primitives are dual-licensed (MIT/Apache-2.0): `p256` / `p384` /
//! `elliptic-curve` / `sha2` (RustCrypto). Field arithmetic, `inv0`, `sqrt`,
//! `sgn0` and the SSWU map are written here directly against the `ff` field
//! traits — this crate intentionally does *not* depend on `hash2curve`, which
//! only ships an `elliptic-curve` 0.14 generation and would force an
//! incompatible `elliptic-curve` version split against the `p256`/`p384` 0.x
//! that the rest of the platform pins.

use core::ops::{Add, Mul, Neg, Sub};

use digest::Digest;
use elliptic_curve::{
    ff::{Field, FromUniformBytes, PrimeField},
    group::GroupOps,
    sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytes, PrimeCurve, ProjectivePoint, Scalar,
};

/// NIST P-256 base/scalar field `L` (bytes): `ceil((256 + 128) / 8) = 48`.
pub const P256_L: usize = 48;
/// NIST P-384 base/scalar field `L` (bytes): `ceil((384 + 192) / 8) = 72`.
pub const P384_L: usize = 72;

/// NIST P-256 `SHA-256` input block size (bytes).
pub const P256_S: usize = 64;
/// NIST P-384 `SHA-384` input block size (bytes).
pub const P384_S: usize = 128;

/// NIST P-256 curve constant `B` (big-endian, 32 bytes).
pub const P256_B: &[u8] = &[
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

/// NIST P-384 curve constant `B` (big-endian, 48 bytes).
pub const P384_B: &[u8] = &[
    0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
    0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
    0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
];

/// A hash-to-curve suite: bundles the per-curve field constants and the
/// expander hash with the byte-length parameters required by RFC 9380.
pub trait H2CCurve: PrimeCurve + CurveArithmetic {
    /// Bytes per field element (`L` in RFC 9380 §5.2).
    const L: usize;
    /// Hash input block size in bytes (`s` in RFC 9380 §5.3.1).
    const S_BLOCK: usize;
    /// The expander hash (`H` in RFC 9380 §5.3.1).
    type Hash: Digest;
    /// Curve `A` coefficient (`-3` for both NIST P-curves).
    fn field_a() -> Self::FieldElement;
    /// Curve `B` constant.
    fn field_b() -> Self::FieldElement;
    /// SSWU `Z` constant (`-1` for both NIST P-curves).
    fn field_z() -> Self::FieldElement;
}

/// `inv0(x)`: multiplicative inverse extended so `inv0(0) = 0` (RFC 9380 §4).
fn inv0<F: Field>(x: F) -> F {
    x.invert().unwrap_or(F::ZERO)
}

/// `sgn0(x)` for a prime field: `x mod 2` (RFC 9380 §4.1, `sgn0_m_eq_1`).
fn sgn0<F: PrimeField>(x: &F) -> bool {
    let repr = x.to_repr();
    let bytes = repr.as_ref();
    (bytes[bytes.len() - 1] & 1) == 1
}

/// `expand_message_xmd` (RFC 9380 §5.3.1) over hash `H`.
fn expand_message_xmd<H: Digest>(msg: &[u8], dst: &[u8], len_in_bytes: usize, s_in_bytes: usize) -> Vec<u8> {
    let b = H::output_size();
    let ell = (len_in_bytes + b - 1) / b;
    assert!(ell <= 255 && len_in_bytes <= 65535 && dst.len() <= 255);

    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let z_pad = vec![0u8; s_in_bytes];
    let l_i = (len_in_bytes as u16).to_be_bytes();

    let mut msg_prime = Vec::with_capacity(z_pad.len() + msg.len() + 2 + 1 + dst_prime.len());
    msg_prime.extend_from_slice(&z_pad);
    msg_prime.extend_from_slice(msg);
    msg_prime.extend_from_slice(&l_i);
    msg_prime.push(0u8);
    msg_prime.extend_from_slice(&dst_prime);

    let b0 = H::new().chain_update(&msg_prime).finalize();
    let b0 = b0.as_ref().to_vec();

    let mut b_prev = H::new()
        .chain_update(&b0)
        .chain_update([1u8])
        .chain_update(&dst_prime)
        .finalize();
    let mut b_prev = b_prev.as_ref().to_vec();

    let mut out = Vec::with_capacity(ell * b);
    out.extend_from_slice(&b_prev);

    for i in 2..=ell {
        let mut xored = b0.clone();
        for (x, y) in xored.iter_mut().zip(b_prev.iter()) {
            *x ^= *y;
        }
        b_prev = H::new()
            .chain_update(&xored)
            .chain_update([i as u8])
            .chain_update(&dst_prime)
            .finalize();
        b_prev = b_prev.as_ref().to_vec();
        out.extend_from_slice(&b_prev);
    }

    out.truncate(len_in_bytes);
    out
}

/// `hash_to_field` (RFC 9380 §5.2): derive `count` field elements of type `F`.
fn hash_to_field<F: FromUniformBytes<L>, const L: usize>(uniform_bytes: &[u8], count: usize) -> Vec<F> {
    (0..count)
        .map(|i| {
            let tv = &uniform_bytes[L * i..L * (i + 1)];
            let mut arr = [0u8; L];
            arr.copy_from_slice(tv);
            F::from_uniform_bytes(&arr)
        })
        .collect()
}

/// `map_to_curve` — Simplified SWU (RFC 9380 §6.6.2) for `y^2 = x^3 + A x + B`.
///
/// Returns the affine `(x, y)` of the mapped point.
fn map_to_curve_sswu<F: Field + PrimeField>(u: F, a: F, b: F, z: F) -> (F, F) {
    let one = F::ONE;
    let tv1 = u.square() * z;
    let tv2 = tv1.square() + tv1;
    let tv3 = (tv2 + one) * b;
    let tv4 = tv3 * a;
    let tv4 = inv0(tv4);
    let mut x1 = -(b * tv4);
    if bool::from(x1.is_zero()) {
        // Exceptional case (RFC 9380 §6.6.2 step 10): x1 = B / (Z * A).
        x1 = b * inv0(z * a);
    }
    let gx1 = x1.square() * x1 + a * x1 + b;
    let x2 = tv1 * x1;
    let gx2 = x2.square() * x2 + a * x2 + b;

    let y1 = gx1.sqrt();
    let y2 = gx2.sqrt();
    let (x, mut y) = if y1.is_some().into() {
        (x1, y1.unwrap())
    } else {
        (x2, y2.unwrap())
    };
    if sgn0(&u) != sgn0(&y) {
        y = -y;
    }
    (x, y)
}

/// Build a projective group point from an SSWU-mapped affine `(x, y)`.
fn map_to_point<C>(u: &C::FieldElement, a: C::FieldElement, b: C::FieldElement, z: C::FieldElement) -> ProjectivePoint<C>
where
    C: PrimeCurve + CurveArithmetic,
    C::FieldElement: Field + PrimeField,
{
    let (x, y) = map_to_curve_sswu(*u, a, b, z);
    let xb = x.to_repr();
    let yb = y.to_repr();
    let mut buf = Vec::with_capacity(1 + 2 * xb.as_ref().len());
    buf.push(0x04);
    buf.extend_from_slice(xb.as_ref());
    buf.extend_from_slice(yb.as_ref());
    let ep = EncodedPoint::<C::FieldBytesSize>::from_bytes(&buf).expect("valid uncompressed point");
    let aff = AffinePoint::<C>::from_encoded_point(&ep)
        .into_option()
        .expect("mapped point lies on the curve");
    ProjectivePoint::<C>::from(aff)
}

/// `hash_to_curve` (RFC 9380 §3): returns `(Q0, Q1, P)` where `P = Q0 + Q1`
/// (cofactor clearing is the identity for P-256 / P-384).
///
/// `L` is the per-field `hash_to_field` byte length and `S` the expander
/// hash's input block size (see [`H2CCurve`]).
pub fn hash_to_curve<C: H2CCurve, const L: usize, const S: usize>(
    msg: &[u8],
    dst: &[u8],
) -> (ProjectivePoint<C>, ProjectivePoint<C>, ProjectivePoint<C>)
where
    C::FieldElement: Field + PrimeField + FromUniformBytes<L>,
{
    let uniform = expand_message_xmd::<C::Hash>(msg, dst, 2 * L, S);
    let u = hash_to_field::<C::FieldElement, L>(&uniform, 2);
    let a = C::field_a();
    let b = C::field_b();
    let z = C::field_z();
    let q0 = map_to_point::<C>(&u[0], a, b, z);
    let q1 = map_to_point::<C>(&u[1], a, b, z);
    let p = q0 + q1;
    (q0, q1, p)
}

/// `hash_to_field` over the scalar field — used by RFC 9497 `HashToScalar`.
pub fn hash_to_scalar<C: H2CCurve, const L: usize, const S: usize>(msg: &[u8], dst: &[u8]) -> Scalar<C>
where
    C::Scalar: PrimeField + FromUniformBytes<L>,
{
    let uniform = expand_message_xmd::<C::Hash>(msg, dst, L, S);
    let mut arr = [0u8; L];
    arr.copy_from_slice(&uniform[..L]);
    Scalar::<C>::from_uniform_bytes(&arr)
}

/// Return the uncompressed `(x, y)` affine bytes of a projective point
/// (used by the conformance tests).
pub fn affine_xy<C: PrimeCurve + CurveArithmetic>(p: ProjectivePoint<C>) -> (Vec<u8>, Vec<u8>) {
    let aff = p.to_affine();
    let ep = aff.to_encoded_point(false);
    (
        ep.x().expect("non-identity point").to_vec(),
        ep.y().expect("non-identity point").to_vec(),
    )
}
