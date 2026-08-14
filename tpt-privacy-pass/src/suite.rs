//! Ciphersuite abstraction over RFC 9497 prime-order groups.
//!
//! This module defines the [`Suite`] trait together with its two concrete
//! backends — [`NistP256`] and [`NistP384`] reused from RustCrypto — and the
//! small serialization helpers used throughout the crate. All primitives are
//! dual-licensed (MIT/Apache-2.0): `p256`, `p384`, `elliptic-curve`,
//! `hash2curve` (RFC 9380 `hash_to_curve`) and `sha2`.

use core::num::NonZeroU16;
use elliptic_curve::bigint::{U256, U384, U512, U768};
use elliptic_curve::ff::PrimeField;
use elliptic_curve::{
    sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    CurveArithmetic, FieldBytes, Group, PrimeCurve, ProjectivePoint,
};
use hash2curve::{ExpandMsg, ExpandMsgXmd, Expander, GroupDigest};
use p256::NistP256;
use p384::NistP384;
use sha2::{Digest, Sha256, Sha384};

use crate::error::OprfError;

/// Canonical group-element type for a [`Suite`] (the curve's projective
/// point, which is what `GroupDigest::hash_from_bytes` yields).
pub type Point<C> = ProjectivePoint<C>;

/// Canonical scalar type for a [`Suite`] (the RFC 9497 §2.1 scalar field
/// element, i.e. `elliptic_curve::Scalar<C>`).
pub type Scalar<C> = elliptic_curve::Scalar<C>;

/// A Privacy Pass / OPRF ciphersuite: a prime-order group (P-256 or P-384)
/// paired with a hash function, exactly as defined in RFC 9497 §4.
///
/// Both [`NistP256`] (P-256 / SHA-256, `SUITE_ID = "P256-SHA256"`) and
/// [`NistP384`] (P-384 / SHA-384, `SUITE_ID = "P384-SHA384"`) implement this
/// trait directly; `hash2curve` already supplies their `GroupDigest`
/// (`HashToGroup`) and RustCrypto supplies `CurveArithmetic` / `PrimeCurve`.
pub trait Suite: GroupDigest + CurveArithmetic + PrimeCurve {
    /// The protocol hash function (`Hash` in RFC 9497): SHA-256 for
    /// P-256 and SHA-384 for P-384. Also used as the expand-message hash.
    type Hash: Digest + Default + FixedOutput + BlockSizeUser + HashMarker;

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
        let expander = ExpandMsgXmd::<Sha256>::expand_message(&[input], &[dst], u16_len(Self::L as u16))
            .expect("expand_message");
        let mut buf = [0u8; 48];
        expander.fill_bytes(&mut buf).expect("expand_message fill");
        let wide = U512::from_be_slice(&buf);
        let reduced = wide.rem_vartime(&NistP256::ORDER);
        let fb = FieldBytes::<Self>::clone_from_slice(&reduced.to_be_bytes());
        Option::from(Scalar::<Self>::from_repr(fb)).expect("reduced scalar in range")
    }

    fn hash_to_group(input: &[u8], dst: &[u8]) -> Result<Point<Self>, OprfError> {
        <Self as GroupDigest>::hash_from_bytes(&[input], &[dst]).map_err(|_| OprfError::InvalidElement)
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
        let expander = ExpandMsgXmd::<Sha384>::expand_message(&[input], &[dst], u16_len(Self::L as u16))
            .expect("expand_message");
        let mut buf = [0u8; 72];
        expander.fill_bytes(&mut buf).expect("expand_message fill");
        let wide = U768::from_be_slice(&buf);
        let reduced = wide.rem_vartime(&NistP384::ORDER);
        let fb = FieldBytes::<Self>::clone_from_slice(&reduced.to_be_bytes());
        Option::from(Scalar::<Self>::from_repr(fb)).expect("reduced scalar in range")
    }

    fn hash_to_group(input: &[u8], dst: &[u8]) -> Result<Point<Self>, OprfError> {
        <Self as GroupDigest>::hash_from_bytes(&[input], &[dst]).map_err(|_| OprfError::InvalidElement)
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
/// (`SerializeElement` in RFC 9497 §2.1).
pub(crate) fn serialize_element<C: Suite + ?Sized>(p: &Point<C>) -> Vec<u8> {
    p.to_encoded_point(true).as_bytes().to_vec()
}

/// Deserialize a group element, rejecting wrong-length, invalid, or
/// identity points (`DeserializeElement` in RFC 9497 §2.1).
pub(crate) fn deserialize_element<C: Suite + ?Sized>(b: &[u8]) -> Result<Point<C>, OprfError> {
    if b.len() != C::NE {
        return Err(OprfError::InvalidElement);
    }
    let ep = EncodedPoint::<C>::from_bytes(b).map_err(|_| OprfError::InvalidElement)?;
    let pt = Point::<C>::from_encoded_point(&ep);
    let pt = Option::from(pt).ok_or(OprfError::InvalidElement)?;
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

/// Build a `NonZeroU16` length for `expand_message` (lengths here are
/// always non-zero).
fn u16_len(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v).expect("non-zero length")
}
