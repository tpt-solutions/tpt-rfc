//! OPRF / VOPRF / POPRF core (RFC 9497) and the DLEQ proof system.
//!
//! This module implements the three protocol variants — OPRF (mode `0x00`),
//! VOPRF (mode `0x01`) and POPRF (mode `0x02`) — over any [`Suite`]. It is
//! a clean-room implementation of RFC 9497 §3: `Blind`, `BlindEvaluate`,
//! `Finalize`, `Evaluate`, the DLEQ `GenerateProof`/`VerifyProof` batching
//! construction of §2.2, and deterministic key generation (`DeriveKeyPair`,
//! §3.2.1).

use crate::error::OprfError;
use crate::suite::*;
use digest::Digest;
use elliptic_curve::{
    ff::{Field, PrimeField},
    group::GroupOps,
    FieldBytes, Group,
};

type ScalarE<C> = Scalar<C>;
type PointE<C> = Point<C>;

/// A DLEQ proof: a pair of scalars `(c, s)` per RFC 9497 §2.2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Proof<C: Suite> {
    /// Challenge scalar `c`.
    pub c: ScalarE<C>,
    /// Response scalar `s`.
    pub s: ScalarE<C>,
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Generate a fresh non-zero scalar (`RandomScalar` in RFC 9497 §2.1),
/// using the operating system CSPRNG.
pub fn random_scalar<C: Suite>() -> ScalarE<C> {
    loop {
        let mut buf = [0u8; 64];
        getrandom::getrandom(&mut buf).expect("getrandom failure");
        let fb = FieldBytes::<C>::clone_from_slice(&buf[..C::NS]);
        if let Some(sp) = ScalarE::<C>::from_repr(fb).into_option() {
            if !bool::from(sp.is_zero()) {
                return sp;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OPRF (mode 0x00)
// ---------------------------------------------------------------------------

/// Blind an input (`Blind` in RFC 9497 §3.3.1).
///
/// Returns the blinding scalar (kept secret by the client) and the blinded
/// group element. `mode` selects the context string (use `0x00` for OPRF,
/// `0x01` for VOPRF, `0x02` for POPRF — the DST differs per mode).
pub fn blind<C: Suite>(input: &[u8], blind_scalar: &ScalarE<C>, mode: u8) -> PointE<C> {
    let dst = dst_group::<C>(mode);
    let ie = C::hash_to_group(input, &dst).expect("hash_to_group");
    ie * *blind_scalar
}

/// Server-side evaluation (`BlindEvaluate` in RFC 9497 §3.3.1).
pub fn blind_evaluate<C: Suite>(sk: &ScalarE<C>, blinded: &PointE<C>) -> PointE<C> {
    *blinded * *sk
}

/// Client-side finalization (`Finalize` in RFC 9497 §3.3.1).
pub fn finalize<C: Suite>(
    input: &[u8],
    blind: &ScalarE<C>,
    evaluated: &PointE<C>,
    mode: u8,
) -> Vec<u8> {
    let n = *evaluated * Option::from(blind.invert()).expect("blind invertible");
    let unblinded = serialize_element::<C>(&n);
    finalize_hash::<C>(input, &unblinded, None, mode)
}

/// Direct evaluation by a party holding the private key (`Evaluate` in
/// RFC 9497 §3.3.1).
pub fn evaluate<C: Suite>(sk: &ScalarE<C>, input: &[u8], mode: u8) -> Vec<u8> {
    let dst = dst_group::<C>(mode);
    let ie = C::hash_to_group(input, &dst).expect("hash_to_group");
    let ev = ie * *sk;
    let unblinded = serialize_element::<C>(&ev);
    finalize_hash::<C>(input, &unblinded, None, mode)
}

// ---------------------------------------------------------------------------
// VOPRF (mode 0x01)
// ---------------------------------------------------------------------------

/// Server-side evaluation with a DLEQ proof (`BlindEvaluate` in
/// RFC 9497 §3.3.2).
pub fn blind_evaluate_voprf<C: Suite>(
    sk: &ScalarE<C>,
    pk: &PointE<C>,
    blinded: &PointE<C>,
) -> (PointE<C>, Proof<C>) {
    let evaluated = *blinded * *sk;
    let proof = generate_proof::<C>(
        sk,
        &PointE::<C>::generator(),
        pk,
        &[*blinded],
        &[evaluated],
        0x01,
    );
    (evaluated, proof)
}

/// Client-side finalization with proof verification (`Finalize` in
/// RFC 9497 §3.3.2). Errors with [`OprfError::ProofVerification`] if the
/// supplied proof does not verify.
pub fn finalize_voprf<C: Suite>(
    input: &[u8],
    blind: &ScalarE<C>,
    evaluated: &PointE<C>,
    blinded: &PointE<C>,
    pk: &PointE<C>,
    proof: &Proof<C>,
) -> Result<Vec<u8>, OprfError> {
    if !verify_proof::<C>(
        &PointE::<C>::generator(),
        pk,
        &[*blinded],
        &[*evaluated],
        proof,
        0x01,
    ) {
        return Err(OprfError::ProofVerification);
    }
    let n = *evaluated * Option::from(blind.invert()).expect("blind invertible");
    let unblinded = serialize_element::<C>(&n);
    Ok(finalize_hash::<C>(input, &unblinded, None, 0x01))
}

// ---------------------------------------------------------------------------
// POPRF (mode 0x02)
// ---------------------------------------------------------------------------

/// Frame the public `info` as `"Info" || I2OSP(len(info),2) || info`
/// (RFC 9497 §3.3.3).
fn frame_info(info: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + info.len());
    v.extend_from_slice(b"Info");
    v.extend_from_slice(&(info.len() as u16).to_be_bytes());
    v.extend_from_slice(info);
    v
}

/// Client-side blinding with public metadata (`Blind` in RFC 9497 §3.3.3).
///
/// Returns `(blinded_element, tweaked_key)`, where `tweaked_key` is kept
/// locally and passed to [`finalize_poprf`].
pub fn blind_poprf<C: Suite>(
    input: &[u8],
    info: &[u8],
    pk: &PointE<C>,
    blind: &ScalarE<C>,
) -> (PointE<C>, PointE<C>) {
    let framed = frame_info(info);
    let m = C::hash_to_scalar(&framed, &dst_scalar::<C>(0x02));
    let t = PointE::<C>::generator() * m;
    let tweaked = t + *pk;
    assert!(
        !bool::from(tweaked.is_identity()),
        "tweaked key is identity"
    );
    let dst = dst_group::<C>(0x02);
    let ie = C::hash_to_group(input, &dst).expect("hash_to_group");
    let blinded_element = ie * *blind;
    (blinded_element, tweaked)
}

/// Server-side evaluation with a DLEQ proof (`BlindEvaluate` in
/// RFC 9497 §3.3.3).
pub fn blind_evaluate_poprf<C: Suite>(
    sk: &ScalarE<C>,
    blinded: &PointE<C>,
    info: &[u8],
) -> (PointE<C>, Proof<C>) {
    let framed = frame_info(info);
    let m = C::hash_to_scalar(&framed, &dst_scalar::<C>(0x02));
    let t = *sk + m;
    assert!(!bool::from(t.is_zero()), "POPRF inverse of zero");
    let t_inv = t.invert().into_option().expect("t invertible");
    let evaluated: PointE<C> = *blinded * t_inv;
    let tweaked_key = PointE::<C>::generator() * t;
    let proof = generate_proof::<C>(
        &t,
        &PointE::<C>::generator(),
        &tweaked_key,
        &[*evaluated],
        &[*blinded],
        0x02,
    );
    (evaluated, proof)
}

/// Client-side finalization with proof verification (`Finalize` in
/// RFC 9497 §3.3.3).
pub fn finalize_poprf<C: Suite>(
    input: &[u8],
    blind: &ScalarE<C>,
    evaluated: &PointE<C>,
    blinded: &PointE<C>,
    proof: &Proof<C>,
    info: &[u8],
    tweaked: &PointE<C>,
) -> Result<Vec<u8>, OprfError> {
    if !verify_proof::<C>(
        &PointE::<C>::generator(),
        tweaked,
        &[*evaluated],
        &[*blinded],
        proof,
        0x02,
    ) {
        return Err(OprfError::ProofVerification);
    }
    let n = *evaluated * Option::from(blind.invert()).expect("blind invertible");
    let unblinded = serialize_element::<C>(&n);
    Ok(finalize_hash::<C>(input, &unblinded, Some(info), 0x02))
}

/// Direct evaluation by a party holding the private key (`Evaluate` in
/// RFC 9497 §3.3.3), binding the public `info`.
pub fn evaluate_poprf<C: Suite>(sk: &ScalarE<C>, input: &[u8], info: &[u8]) -> Vec<u8> {
    let framed = frame_info(info);
    let m = C::hash_to_scalar(&framed, &dst_scalar::<C>(0x02));
    let t = *sk + m;
        let t_inv = t.invert().into_option().expect("t invertible");
    let dst = dst_group::<C>(0x02);
    let ie = C::hash_to_group(input, &dst).expect("hash_to_group");
    let ev = ie * t_inv;
    let unblinded = serialize_element::<C>(&ev);
    finalize_hash::<C>(input, &unblinded, Some(info), 0x02)
}

// ---------------------------------------------------------------------------
// Shared finalize hash
// ---------------------------------------------------------------------------

/// The `hashInput` hash used by every `Finalize` / `Evaluate` (RFC 9497
/// §3.3). POPRF (`mode == 0x02`) additionally binds `info`.
fn finalize_hash<C: Suite>(
    input: &[u8],
    unblinded: &[u8],
    info: Option<&[u8]>,
    mode: u8,
) -> Vec<u8> {
    let mut h = C::Hash::new();
    h.update(len_prefixed(input));
    if mode == 0x02 {
        let info = info.unwrap_or(&[]);
        h.update(len_prefixed(info));
    }
    h.update(len_prefixed(unblinded));
    h.update(b"Finalize");
    let out = h.finalize();
    out.to_vec()
}

// ---------------------------------------------------------------------------
// DLEQ proofs (RFC 9497 §2.2)
// ---------------------------------------------------------------------------

/// Generate a DLEQ proof (`GenerateProof` in RFC 9497 §2.2.1).
pub fn generate_proof<C: Suite>(
    k: &ScalarE<C>,
    a: &PointE<C>,
    b: &PointE<C>,
    c: &[PointE<C>],
    d: &[PointE<C>],
    mode: u8,
) -> Proof<C> {
    generate_proof_rng::<C>(k, a, b, c, d, mode, &random_scalar::<C>())
}

/// Generate a DLEQ proof with an explicit `r` (used to reproduce the
/// deterministic RFC 9497 test vectors).
pub fn generate_proof_rng<C: Suite>(
    k: &ScalarE<C>,
    a: &PointE<C>,
    b: &PointE<C>,
    c: &[PointE<C>],
    d: &[PointE<C>],
    mode: u8,
    r: &ScalarE<C>,
) -> Proof<C> {
    let (m, z) = compute_composites_fast::<C>(k, b, c, d, mode);
    let t2 = *a * *r;
    let t3 = m * *r;
    let bm = serialize_element::<C>(b);
    let a0 = serialize_element::<C>(&m);
    let a1 = serialize_element::<C>(&z);
    let a2 = serialize_element::<C>(&t2);
    let a3 = serialize_element::<C>(&t3);
    let ct = challenge_transcript(&bm, &a0, &a1, &a2, &a3);
    let dst = dst_scalar::<C>(mode);
    let chal = C::hash_to_scalar(&ct, &dst);
    let s = *r - (chal * *k);
    Proof { c: chal, s }
}

/// Verify a DLEQ proof (`VerifyProof` in RFC 9497 §2.2.2).
pub fn verify_proof<C: Suite>(
    a: &PointE<C>,
    b: &PointE<C>,
    c: &[PointE<C>],
    d: &[PointE<C>],
    proof: &Proof<C>,
    mode: u8,
) -> bool {
    let (m, z) = compute_composites::<C>(b, c, d, mode);
    let chal = &proof.c;
    let s = &proof.s;
    let t2 = (a * s) + (b * chal);
    let t3 = (m * *s) + (z * *chal);
    let bm = serialize_element::<C>(b);
    let a0 = serialize_element::<C>(&m);
    let a1 = serialize_element::<C>(&z);
    let a2 = serialize_element::<C>(&t2);
    let a3 = serialize_element::<C>(&t3);
    let ct = challenge_transcript(&bm, &a0, &a1, &a2, &a3);
    let dst = dst_scalar::<C>(mode);
    let expected = C::hash_to_scalar(&ct, &dst);
    expected == *chal
}

/// `ComputeCompositesFast` (RFC 9497 §2.2.1) — server side, knows `k`.
fn compute_composites_fast<C: Suite>(
    k: &ScalarE<C>,
    b: &PointE<C>,
    c: &[PointE<C>],
    d: &[PointE<C>],
    mode: u8,
) -> (PointE<C>, PointE<C>) {
    let seed = seed_for::<C>(b, mode);
    let mut m = PointE::<C>::identity();
    for i in 0..c.len() {
        let ci = serialize_element::<C>(&c[i]);
        let di = serialize_element::<C>(&d[i]);
        let ct = composite_transcript(&seed, i as u16, &ci, &di);
        let di_scalar = C::hash_to_scalar(&ct, &dst_scalar::<C>(mode));
        m = m + (c[i] * di_scalar);
    }
    let z = m * *k;
    (m, z)
}

/// `ComputeComposites` (RFC 9497 §2.2.2) — verifier side.
fn compute_composites<C: Suite>(
    b: &PointE<C>,
    c: &[PointE<C>],
    d: &[PointE<C>],
    mode: u8,
) -> (PointE<C>, PointE<C>) {
    let seed = seed_for::<C>(b, mode);
    let mut m = PointE::<C>::identity();
    let mut z = PointE::<C>::identity();
    for i in 0..c.len() {
        let ci = serialize_element::<C>(&c[i]);
        let di = serialize_element::<C>(&d[i]);
        let ct = composite_transcript(&seed, i as u16, &ci, &di);
        let di_scalar = C::hash_to_scalar(&ct, &dst_scalar::<C>(mode));
        m = m + (c[i] * di_scalar);
        z = z + (d[i] * di_scalar);
    }
    (m, z)
}

/// Derive the `seed` used by `ComputeComposites` (RFC 9497 §2.2).
fn seed_for<C: Suite>(b: &PointE<C>, mode: u8) -> Vec<u8> {
    let ctx = C::context_string(mode);
    let seed_dst = format!("Seed-{}", ctx).into_bytes();
    let bm = serialize_element::<C>(b);
    let mut seed_transcript = Vec::with_capacity(2 + bm.len() + 2 + seed_dst.len());
    seed_transcript.extend_from_slice(&(bm.len() as u16).to_be_bytes());
    seed_transcript.extend_from_slice(&bm);
    seed_transcript.extend_from_slice(&(seed_dst.len() as u16).to_be_bytes());
    seed_transcript.extend_from_slice(&seed_dst);
    C::Hash::new()
        .chain_update(&seed_transcript)
        .finalize()
        .to_vec()
}

/// Build one `Composite` transcript entry (RFC 9497 §2.2).
fn composite_transcript(seed: &[u8], index: u16, ci: &[u8], di: &[u8]) -> Vec<u8> {
    let mut ct = Vec::new();
    ct.extend_from_slice(&(seed.len() as u16).to_be_bytes());
    ct.extend_from_slice(seed);
    ct.extend_from_slice(&index.to_be_bytes());
    ct.extend_from_slice(&(ci.len() as u16).to_be_bytes());
    ct.extend_from_slice(ci);
    ct.extend_from_slice(&(di.len() as u16).to_be_bytes());
    ct.extend_from_slice(di);
    ct.extend_from_slice(b"Composite");
    ct
}

/// Build the `Challenge` transcript (RFC 9497 §2.2).
fn challenge_transcript(bm: &[u8], a0: &[u8], a1: &[u8], a2: &[u8], a3: &[u8]) -> Vec<u8> {
    let mut ct = Vec::new();
    for x in [bm, a0, a1, a2, a3] {
        ct.extend_from_slice(&(x.len() as u16).to_be_bytes());
        ct.extend_from_slice(x);
    }
    ct.extend_from_slice(b"Challenge");
    ct
}

/// Serialize a proof as `SerializeScalar(c) || SerializeScalar(s)`.
pub fn serialize_proof<C: Suite>(p: &Proof<C>) -> Vec<u8> {
    let mut v = serialize_scalar::<C>(&p.c);
    v.extend_from_slice(&serialize_scalar::<C>(&p.s));
    v
}

/// Deserialize a proof (length `2 * Ns`).
pub fn deserialize_proof<C: Suite>(b: &[u8]) -> Result<Proof<C>, OprfError> {
    if b.len() != 2 * C::NS {
        return Err(OprfError::InvalidScalar);
    }
    let c = deserialize_scalar::<C>(&b[..C::NS])?;
    let s = deserialize_scalar::<C>(&b[C::NS..])?;
    Ok(Proof { c, s })
}

// ---------------------------------------------------------------------------
// Deterministic key generation (RFC 9497 §3.2.1)
// ---------------------------------------------------------------------------

/// Deterministically derive an issuer key pair from a seed and info
/// (`DeriveKeyPair` in RFC 9497 §3.2.1). `mode` selects the context string
/// (e.g. `0x00` for the OPRF-mode test vectors, `0x01` for Privacy Pass
/// VOPRF issuance per RFC 9578 §5.5).
pub fn derive_key_pair<C: Suite>(seed: &[u8], info: &[u8], mode: u8) -> (ScalarE<C>, PointE<C>) {
    let ctx = C::context_string(mode);
    let dst = format!("DeriveKeyPair{}", ctx).into_bytes();
    let mut derive_input = Vec::with_capacity(seed.len() + 2 + info.len());
    derive_input.extend_from_slice(seed);
    derive_input.extend_from_slice(&(info.len() as u16).to_be_bytes());
    derive_input.extend_from_slice(info);

    let mut counter: u8 = 0;
    let mut sk = ScalarE::<C>::ZERO;
    loop {
        assert!(counter <= 255, "DeriveKeyPair counter exhausted");
        let mut input = derive_input.clone();
        input.extend_from_slice(&counter.to_be_bytes());
        let s = C::hash_to_scalar(&input, &dst);
        counter += 1;
        if !bool::from(s.is_zero()) {
            sk = s;
            break;
        }
    }
    let pk = PointE::<C>::generator() * sk;
    (sk, pk)
}
