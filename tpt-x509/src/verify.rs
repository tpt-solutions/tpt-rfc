//! Signature verification dispatch using dual-licensed RustCrypto primitives.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::{Certificate, SubjectPublicKeyInfo};

use crate::error::ValidationError;

// Algorithm OIDs (RFC 3279 / RFC 4055 / RFC 8410).
pub(crate) const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub(crate) const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub(crate) const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
pub(crate) const SHA512_RSA: &str = "1.2.840.113549.1.1.13";
pub(crate) const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
#[allow(dead_code)]
pub(crate) const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
#[allow(dead_code)]
pub(crate) const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
#[allow(dead_code)]
pub(crate) const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
pub(crate) const ED25519: &str = "1.3.101.112";
// Named curves.
pub(crate) const P256: &str = "1.2.840.10045.3.1.7";
pub(crate) const P384: &str = "1.3.132.0.34";

fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}

/// Verify that `cert`'s `signature` was produced by the private key
/// corresponding to `issuer_spki`.
///
/// The signed data is the DER encoding of the certificate's `tbsCertificate`.
pub fn verify_signature(
    cert: &Certificate,
    issuer_spki: &SubjectPublicKeyInfo,
) -> Result<(), ValidationError> {
    let signed_data = cert
        .tbs_certificate()
        .to_der()
        .map_err(ValidationError::Encoding)?;
    let sig_raw = cert.signature().raw_bytes();
    verify_signature_raw(
        &signed_data,
        sig_raw,
        issuer_spki,
        cert.signature_algorithm().oid,
    )
    .map_err(|reason| ValidationError::Signature {
        issuer: format!("serial={}", cert.tbs_certificate().serial_number()),
        reason,
    })
}

/// Verify a raw signature `sig` over `signed_data` using `issuer_spki` and the
/// signature scheme identified by `sig_oid`.
///
/// This is algorithm-agnostic and is used both for certificates and for CRLs.
pub fn verify_signature_raw(
    signed_data: &[u8],
    sig: &[u8],
    issuer_spki: &SubjectPublicKeyInfo,
    sig_oid: ObjectIdentifier,
) -> Result<(), String> {
    let key_oid = issuer_spki.algorithm.oid;
    match key_oid {
        k if k == oid(RSA_ENCRYPTION) => verify_rsa(issuer_spki, sig_oid, signed_data, sig),
        k if k == oid(EC_PUBLIC_KEY) => verify_ecdsa(issuer_spki, sig_oid, signed_data, sig),
        k if k == oid(ED25519) => verify_ed25519(issuer_spki, signed_data, sig),
        other => Err(format!("unsupported public key algorithm {other}")),
    }
}

fn verify_rsa(
    spki: &SubjectPublicKeyInfo,
    sig_oid: ObjectIdentifier,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    use sha2::Digest;
    use sha2::{Sha256, Sha384, Sha512};

    // `subject_public_key` is the DER encoding of the PKCS#1 RSAPublicKey.
    #[derive(der::Sequence)]
    struct RsaPubKeyDer<'a> {
        modulus: der::asn1::UintRef<'a>,
        public_exponent: der::asn1::UintRef<'a>,
    }

    let raw = spki.subject_public_key.raw_bytes();
    let pk = RsaPubKeyDer::from_der(raw).map_err(|e| format!("bad RSA public key: {e}"))?;
    let modulus = pk.modulus.as_bytes();
    let exponent = pk.public_exponent.as_bytes();
    let digest = match sig_oid {
        o if o == oid(SHA256_RSA) => Sha256::digest(msg).to_vec(),
        o if o == oid(SHA384_RSA) => Sha384::digest(msg).to_vec(),
        o if o == oid(SHA512_RSA) => Sha512::digest(msg).to_vec(),
        o => return Err(format!("unsupported RSA signature scheme {o}")),
    };
    let t = digest_info(sig_oid, &digest)?;

    // RSA public-key operation: m = s^e mod n, implemented in clean room over
    // big-endian byte arrays (no `rsa`/bignum dependency).
    let s = bn_reduce(sig, modulus);
    let m = bn_modpow(&s, exponent, modulus);
    let k = modulus.len(); // modulus byte length
    pkcs1_v15_check(&m, &t)
}

// --- Minimal big-endian arbitrary-precision helpers (for RSA only) ----------

use std::cmp::Ordering;

fn bn_trim(v: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < v.len() - 1 && v[start] == 0 {
        start += 1;
    }
    &v[start..]
}

fn bn_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let a = bn_trim(a);
    let b = bn_trim(b);
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

/// `a - b` where `a >= b`, big-endian. Panics if `a < b` (callers guarantee it).
fn bn_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; a.len()];
    let mut borrow = 0i32;
    for i in (0..a.len()).rev() {
        let av = a[i] as i32;
        let bv = if i >= a.len() - b.len() {
            b[i - (a.len() - b.len())] as i32
        } else {
            0
        };
        let mut d = av - bv - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u8;
    }
    bn_trim(&out).to_vec()
}

fn bn_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; a.len() + b.len()];
    for i in (0..a.len()).rev() {
        let mut carry = 0u32;
        for j in (0..b.len()).rev() {
            let t = out[i + j + 1] as u32 + (a[i] as u32) * (b[j] as u32) + carry;
            out[i + j + 1] = (t & 0xff) as u8;
            carry = t >> 8;
        }
        out[i] = (out[i] as u32 + carry) as u8;
    }
    out
}

/// Reduce `v` modulo `modulus` (which is `>=` every intermediate `v`).
fn bn_reduce(v: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut v = bn_trim(v).to_vec();
    while bn_cmp(&v, modulus) != Ordering::Less {
        v = bn_sub(&v, modulus);
    }
    let mut out = vec![0u8; modulus.len().saturating_sub(v.len())];
    out.extend_from_slice(&v);
    out
}

/// `base^exp mod modulus` via textbook square-and-multiply.
fn bn_modpow(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; modulus.len()];
    result[modulus.len() - 1] = 1; // result = 1
    let base = bn_reduce(base, modulus);
    for &byte in exp {
        for bit in (0..8).rev() {
            result = bn_reduce(&bn_mul(&result, &result), modulus);
            if (byte >> bit) & 1 == 1 {
                result = bn_reduce(&bn_mul(&result, &base), modulus);
            }
        }
    }
    result
}

/// Build the DER `DigestInfo` T value for the hash algorithm `sig_oid`.
fn digest_info(sig_oid: ObjectIdentifier, digest: &[u8]) -> Result<Vec<u8>, String> {
    let prefix: &[u8] = match sig_oid {
        o if o == oid(SHA256_RSA) => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        o if o == oid(SHA384_RSA) => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        o if o == oid(SHA512_RSA) => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        o => return Err(format!("unsupported RSA signature scheme {o}")),
    };
    let mut t = prefix.to_vec();
    t.extend_from_slice(digest);
    Ok(t)
}

/// EMSA-PKCS1-v1_5 check of the decoded signature block `em` against the
/// expected `DigestInfo` T value.
fn pkcs1_v15_check(em: &[u8], t: &[u8]) -> Result<(), String> {
    if em.len() < 11 + t.len() {
        return Err("RSA block too short".to_string());
    }
    if em[0] != 0x00 || em[1] != 0x01 {
        return Err("bad RSA signature leading bytes".to_string());
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xFF {
        i += 1;
    }
    // At least 8 bytes of 0xFF padding (RFC 8017 §9.2).
    if i - 2 < 8 || em[i] != 0x00 {
        return Err("bad RSA PS padding".to_string());
    }
    let rest = &em[i + 1..];
    if rest != t {
        return Err("RSA digest mismatch".to_string());
    }
    Ok(())
}

fn verify_ecdsa(
    spki: &SubjectPublicKeyInfo,
    _sig_oid: ObjectIdentifier,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk};
    use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Vk};

    let raw = spki.subject_public_key.raw_bytes();

    match ec_curve(spki)? {
        Curve::P256 => {
            // hash is implied by the curve (SHA-256)
            let vk = P256Vk::from_sec1_bytes(raw).map_err(|e| e.to_string())?;
            let sig = P256Sig::from_slice(sig).map_err(|e| format!("bad ECDSA sig: {e}"))?;
            vk.verify(msg, &sig)
                .map_err(|e| format!("P-256 verification failed: {e}"))
        }
        Curve::P384 => {
            let vk = P384Vk::from_sec1_bytes(raw).map_err(|e| e.to_string())?;
            let sig = P384Sig::from_slice(sig).map_err(|e| format!("bad ECDSA sig: {e}"))?;
            vk.verify(msg, &sig)
                .map_err(|e| format!("P-384 verification failed: {e}"))
        }
    }
}

fn verify_ed25519(spki: &SubjectPublicKeyInfo, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    use ed25519_compact::{PublicKey, Signature};

    let raw = spki.subject_public_key.raw_bytes();
    if raw.len() != 32 {
        return Err(format!("Ed25519 public key must be 32 bytes, got {}", raw.len()));
    }
    let pk = PublicKey::from_slice(raw).map_err(|e| format!("bad Ed25519 key: {e:?}"))?;
    let sig = Signature::from_slice(sig)
        .map_err(|e| format!("bad Ed25519 signature: {e:?}"))?;
    pk.verify(msg, &sig)
        .map_err(|e| format!("Ed25519 verification failed: {e:?}"))
}

enum Curve {
    P256,
    P384,
}

fn ec_curve(spki: &SubjectPublicKeyInfo) -> Result<Curve, String> {
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| "EC public key missing curve parameters".to_string())?;
    // The parameters are a named-curve OID; re-encode and decode it.
    let der = params.to_der().map_err(|e| e.to_string())?;
    let curve_oid = ObjectIdentifier::from_der(&der).map_err(|e| e.to_string())?;
    match curve_oid {
        c if c == oid(P256) => Ok(Curve::P256),
        c if c == oid(P384) => Ok(Curve::P384),
        other => Err(format!("unsupported curve {other}")),
    }
}
