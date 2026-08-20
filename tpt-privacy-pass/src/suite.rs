//! Ciphersuite abstraction over RFC 9497 prime-order groups.
//!
//! This module defines the [`Suite`] trait together with its two concrete
//! backends — [`NistP256`] and [`NistP384`] reused from RustCrypto — and the
//! small serialization helpers used throughout the crate. All primitives are
//! dual-licensed (MIT/Apache-2.0): `p256`, `p384`, `elliptic-curve`,
//! `hash2curve` (RFC 9380 `hash_to_curve`) and `sha2`.

use p256::elliptic_curve::ff::PrimeField;
use p256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use p256::elliptic_curve::sec1::ModulusSize;
use p256::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytes, Group, PrimeCurve, ProjectivePoint};
use sha2::{Digest, Sha256, Sha384};

pub use p256::NistP256;
pub use p384::NistP384;

use crate::error::OprfError;
use crate::h2c::{H2CCurve, P256_B, P256_L, P256_S, P384_B, P384_L, P384_S};

/// Canonical group-element type for a [`Suite`] (the curve's projective
/// point, which is what `GroupDigest::hash_from_bytes` yields).
pub type Point<C> = ProjectivePoint<C>;

/// Canonical scalar type for a [`Suite`] (the RFC 9497 §2.1 scalar field
/// element, i.e. `p256::elliptic_curve::Scalar<C>`).
pub type Scalar<C> = p256::elliptic_curve::Scalar<C>;

/// A Privacy Pass / OPRF ciphersuite: a prime-order group (P-256 or P-384)
/// paired with a hash function, exactly as defined in RFC 9497 §4.
///
/// Both [`NistP256`] (P-256 / SHA-256, `SUITE_ID = "P256-SHA256"`) and
/// [`NistP384`] (P-384 / SHA-384, `SUITE_ID = "P384-SHA384"`) implement this
/// trait directly; `hash2curve` already supplies their `GroupDigest`
/// (`HashToGroup`) and RustCrypto supplies `CurveArithmetic` / `PrimeCurve`.
pub trait Suite: CurveArithmetic + PrimeCurve
where
    Self::FieldBytesSize: ModulusSize,
{
    /// The protocol hash function (`Hash` in RFC 9497): SHA-256 for
    /// P-256 and SHA-384 for P-384. Also used as the expand-message hash.
    type Hash: Digest + Default;

    /// Ciphersuite identifier string, e.g. `"P256-SHA256"`.
    const SUITE_ID: &'static str;
    /// `Nh`: length in bytes of the OPRF output (= hash output length).
    const NH: usize;
    /// `Ne`: length in bytes of a serialized group element (compressed
    /// SEC1 point).
    const NE: usize;
    /// `Ns`: length in bytes of a serialized scalar.
    const NS: usize;
    /// `L`: number of bytes produced by `hash_to_field` for the scalar
    /// field (RFC 9380). 48 for P-256, 72 for P-384.
    const L: usize;

    /// `HashToScalar` (RFC 9497 §2.1 / RFC 9380 `hash_to_field`).
    ///
    /// Maps `input` to a scalar using the supplied domain-separation tag
    /// `dst` (e.g. `"HashToScalar-OPRFV1-01-P256-SHA256"`).
    fn hash_to_scalar(input: &[u8], dst: &[u8]) -> Scalar<Self>;

    /// `HashToGroup` (RFC 9497 §2.1 / RFC 9380 `hash_to_curve`, SSWU RO).
    fn hash_to_group(input: &[u8], dst: &[u8]) -> Result<Point<Self>, OprfError>;

    /// The OPRF/VOPRF/POPRF context string, per RFC 9497 §3.1:
    /// `"OPRFV1-" || I2OSP(mode,1) || "-" || identifier`.
    fn context_string(mode: u8) -> String {
        format!("OPRFV1-{:02x}-{}", mode, Self::SUITE_ID)
    }
}

/// Domain-separation tag for `HashToGroup` under the given mode.
pub(crate) fn dst_group<C: Suite + ?Sized>(mode: u8) -> Vec<u8> {
    format!("HashToGroup-{}", C::context_string(mode)).into_bytes()
}

/// Domain-separation tag for `HashToScalar` under the given mode.
pub(crate) fn dst_scalar<C: Suite + ?Sized>(mode: u8) -> Vec<u8> {
    format!("HashToScalar-{}", C::context_string(mode)).into_bytes()
}

// ---------------------------------------------------------------------------
// Suite: NistP256 (P256-SHA256)
// ---------------------------------------------------------------------------

impl Suite for NistP256 {
    type Hash = Sha256;
    const SUITE_ID: &'static str = "P256-SHA256";
    const NH: usize = 32;
    const NE: usize = 33;
    const NS: usize = 32;
    const L: usize = 48;

    fn hash_to_scalar(input: &[u8], dst: &[u8]) -> Scalar<Self> {
        crate::h2c::hash_to_scalar::<NistP256, P256_L, P256_S>(input, dst)
    }

    fn hash_to_group(input: &[u8], dst: &[u8]) -> Result<Point<Self>, OprfError> {
        let (_q0, _q1, p) = crate::h2c::hash_to_curve::<NistP256, P256_L, P256_S>(input, dst);
        Ok(p)
    }
}

impl H2CCurve for NistP256 {
    const L: usize = P256_L;
    const S_BLOCK: usize = P256_S;
    type Hash = Sha256;

    fn field_a() -> Self::FieldElement {
        -(Self::FieldElement::ONE + Self::FieldElement::ONE + Self::FieldElement::ONE)
    }

    fn field_b() -> Self::FieldElement {
        Self::FieldElement::from_repr(FieldBytes::<Self>::clone_from_slice(P256_B))
            .expect("valid P-256 B constant")
    }

    fn field_z() -> Self::FieldElement {
        -Self::FieldElement::ONE
    }
}

// ---------------------------------------------------------------------------
// Suite: NistP384 (P384-SHA384)
// ---------------------------------------------------------------------------

impl Suite for NistP384 {
    type Hash = Sha384;
    const SUITE_ID: &'static str = "P384-SHA384";
    const NH: usize = 48;
    const NE: usize = 49;
    const NS: usize = 48;
    const L: usize = 72;

    fn hash_to_scalar(input: &[u8], dst: &[u8]) -> Scalar<Self> {
        crate::h2c::hash_to_scalar::<NistP384, P384_L, P384_S>(input, dst)
    }

    fn hash_to_group(input: &[u8], dst: &[u8]) -> Result<Point<Self>, OprfError> {
        let (_q0, _q1, p) = crate::h2c::hash_to_curve::<NistP384, P384_L, P384_S>(input, dst);
        Ok(p)
    }
}

impl H2CCurve for NistP384 {
    const L: usize = P384_L;
    const S_BLOCK: usize = P384_S;
    type Hash = Sha384;

    fn field_a() -> Self::FieldElement {
        -(Self::FieldElement::ONE + Self::FieldElement::ONE + Self::FieldElement::ONE)
    }

    fn field_b() -> Self::FieldElement {
        Self::FieldElement::from_repr(FieldBytes::<Self>::clone_from_slice(P384_B))
            .expect("valid P-384 B constant")
    }

    fn field_z() -> Self::FieldElement {
        -Self::FieldElement::ONE
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a scalar to its canonical big-endian `Ns`-byte encoding
/// (`SerializeScalar` in RFC 9497 §2.1).
pub(crate) fn serialize_scalar<C: Suite + ?Sized>(s: &Scalar<C>) -> Vec<u8> {
    s.to_repr().as_slice().to_vec()
}

/// Deserialize a scalar, rejecting wrong-length or out-of-range values.
pub(crate) fn deserialize_scalar<C: Suite + ?Sized>(b: &[u8]) -> Result<Scalar<C>, OprfError> {
    if b.len() != C::NS {
        return Err(OprfError::InvalidScalar);
    }
    let fb = FieldBytes::<C>::clone_from_slice(b);
    Option::from(Scalar::<C>::from_repr(fb)).ok_or(OprfError::InvalidScalar)
}

/// Serialize a group element using the compressed SEC1 encoding
/// (`SerializeElement` in RFC 9497 §2.1): `0x02|0x03 || x-coordinate`.
///
/// Uses [`AffineCoordinates`] rather than the `ModulusSize`-gated
/// `ToSec1Point` path so the generic [`Suite`] bound stays simple.
pub(crate) fn serialize_element<C: Suite + ?Sized>(p: &Point<C>) -> Vec<u8> {
    let aff = p.to_affine();
    let x = aff.x();
    let tag: u8 = 0x02u8 | (u8::from(aff.y_is_odd()));
    let mut out = Vec::with_capacity(1 + x.as_ref().len());
    out.push(tag);
    out.extend_from_slice(x.as_ref());
    out
}

/// Deserialize a group element, rejecting wrong-length, invalid, or
/// identity points (`DeserializeElement` in RFC 9497 §2.1).
pub(crate) fn deserialize_element<C: Suite + ?Sized>(b: &[u8]) -> Result<Point<C>, OprfError> {
    if b.len() != C::NE {
        return Err(OprfError::InvalidElement);
    }
    let tag = b[0];
    if tag & 0xFE != 0x02 {
        return Err(OprfError::InvalidElement);
    }
    let y_is_odd = p256::elliptic_curve::subtle::Choice::from(tag & 0x01);
    let x = FieldBytes::<C>::clone_from_slice(&b[1..]);
    let aff = AffinePoint::<C>::decompress(&x, y_is_odd).into_option();
    let aff = aff.ok_or(OprfError::InvalidElement)?;
    let pt = Point::<C>::from(aff);
    if bool::from(pt.is_identity()) {
        return Err(OprfError::InvalidElement);
    }
    Ok(pt)
}

/// A 16-bit big-endian length prefix (`I2OSP(len, 2) || x`).
pub(crate) fn len_prefixed(x: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + x.len());
    v.extend_from_slice(&(x.len() as u16).to_be_bytes());
    v.extend_from_slice(x);
    v
}
