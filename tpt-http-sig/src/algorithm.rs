// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature algorithms, key material, and the cryptographic sign/verify
//! primitives defined by RFC 9421 §3.3.

use crate::error::{HttpSigError, Result};
use sha2::{Digest, Sha256, Sha512};

/// The signature algorithms registered in the "HTTP Signature Algorithms"
/// registry (RFC 9421 §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// `hmac-sha256` — HMAC using SHA-256 (symmetric).
    HmacSha256,
    /// `hmac-sha512` — HMAC using SHA-512 (symmetric).
    HmacSha512,
    /// `rsa-v1_5-sha256` — RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// `rsa-v1_5-sha512` — RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// `rsa-pss-sha256` — RSASSA-PSS with SHA-256 (salt length 32).
    RsaPssSha256,
    /// `rsa-pss-sha512` — RSASSA-PSS with SHA-512 (salt length 64).
    RsaPssSha512,
    /// `ecdsa-p256-sha256` — ECDSA on P-256 with SHA-256.
    EcdsaP256Sha256,
    /// `ecdsa-p384-sha384` — ECDSA on P-384 with SHA-384.
    EcdsaP384Sha384,
    /// `ecdsa-p521-sha512` — ECDSA on P-521 with SHA-512.
    EcdsaP521Sha512,
    /// `ed25519` — Ed25519 (RFC 8032), pure (no prehash).
    Ed25519,
}

impl Algorithm {
    /// The registry string identifying this algorithm.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::HmacSha256 => "hmac-sha256",
            Algorithm::HmacSha512 => "hmac-sha512",
            Algorithm::RsaPkcs1Sha256 => "rsa-v1_5-sha256",
            Algorithm::RsaPkcs1Sha512 => "rsa-v1_5-sha512",
            Algorithm::RsaPssSha256 => "rsa-pss-sha256",
            Algorithm::RsaPssSha512 => "rsa-pss-sha512",
            Algorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Algorithm::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            Algorithm::EcdsaP521Sha512 => "ecdsa-p521-sha512",
            Algorithm::Ed25519 => "ed25519",
        }
    }

    /// Parse an algorithm from its registry string (case-sensitive per the
    /// registry).
    pub fn from_name(s: &str) -> Result<Self> {
        match s {
            "hmac-sha256" => Ok(Algorithm::HmacSha256),
            "hmac-sha512" => Ok(Algorithm::HmacSha512),
            "rsa-v1_5-sha256" => Ok(Algorithm::RsaPkcs1Sha256),
            "rsa-v1_5-sha512" => Ok(Algorithm::RsaPkcs1Sha512),
            "rsa-pss-sha256" => Ok(Algorithm::RsaPssSha256),
            "rsa-pss-sha512" => Ok(Algorithm::RsaPssSha512),
            "ecdsa-p256-sha256" => Ok(Algorithm::EcdsaP256Sha256),
            "ecdsa-p384-sha384" => Ok(Algorithm::EcdsaP384Sha384),
            "ecdsa-p521-sha512" => Ok(Algorithm::EcdsaP521Sha512),
            "ed25519" => Ok(Algorithm::Ed25519),
            other => Err(HttpSigError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// Whether this algorithm is symmetric (HMAC) rather than asymmetric.
    pub fn is_symmetric(self) -> bool {
        matches!(self, Algorithm::HmacSha256 | Algorithm::HmacSha512)
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for Algorithm {
    type Err = HttpSigError;
    fn from_str(s: &str) -> Result<Self> {
        Algorithm::from_name(s)
    }
}

/// A private key suitable for signing with a particular [`Algorithm`].
#[derive(Debug)]
#[non_exhaustive]
pub enum SigningKey {
    /// Shared secret for HMAC-based algorithms.
    Hmac(Vec<u8>),
    /// RSA private key used with RSA-PSS algorithms.
    RsaPss(rsa::RsaPrivateKey),
    /// RSA private key used with RSA-PKCS1-v1_5 algorithms.
    RsaPkcs1(rsa::RsaPrivateKey),
    /// ECDSA P-256 private key.
    EcP256(p256::ecdsa::SigningKey),
    /// ECDSA P-384 private key.
    EcP384(p384::ecdsa::SigningKey),
    /// ECDSA P-521 private key.
    EcP521(p521::ecdsa::SigningKey),
    /// Ed25519 private key.
    Ed25519(ed25519_compact::SecretKey),
}

/// A public key (or shared secret) suitable for verifying a signature.
#[derive(Debug)]
#[non_exhaustive]
pub enum VerifyingKey {
    /// Shared secret for HMAC-based algorithms.
    Hmac(Vec<u8>),
    /// RSA public key used with RSA-PSS algorithms.
    RsaPss(rsa::RsaPublicKey),
    /// RSA public key used with RSA-PKCS1-v1_5 algorithms.
    RsaPkcs1(rsa::RsaPublicKey),
    /// ECDSA P-256 public key.
    EcP256(p256::ecdsa::VerifyingKey),
    /// ECDSA P-384 public key.
    EcP384(p384::ecdsa::VerifyingKey),
    /// ECDSA P-521 public key.
    EcP521(p521::ecdsa::VerifyingKey),
    /// Ed25519 public key.
    Ed25519(ed25519_compact::PublicKey),
}

impl SigningKey {
    /// The algorithm family this key belongs to.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            SigningKey::Hmac(_) => Algorithm::HmacSha256,
            SigningKey::RsaPss(_) => Algorithm::RsaPssSha512,
            SigningKey::RsaPkcs1(_) => Algorithm::RsaPkcs1Sha256,
            SigningKey::EcP256(_) => Algorithm::EcdsaP256Sha256,
            SigningKey::EcP384(_) => Algorithm::EcdsaP384Sha384,
            SigningKey::EcP521(_) => Algorithm::EcdsaP521Sha512,
            SigningKey::Ed25519(_) => Algorithm::Ed25519,
        }
    }

    /// Construct an HMAC signing key from a raw shared secret.
    pub fn hmac(secret: impl Into<Vec<u8>>) -> Self {
        SigningKey::Hmac(secret.into())
    }

    /// Parse a signing key from PEM, choosing the concrete key type from the
    /// supplied [`Algorithm`].
    pub fn from_pem(alg: Algorithm, pem: &str) -> Result<Self> {
        let (tag, der) = decode_pem(pem)?;
        match alg {
            Algorithm::HmacSha256 | Algorithm::HmacSha512 => Err(HttpSigError::Key(
                "HMAC keys are raw shared secrets, not PEM-encoded".into(),
            )),
            Algorithm::Ed25519 => {
                let sk = ed25519_compact::SecretKey::from_pkcs8(&der)
                    .map_err(|e| HttpSigError::Key(format!("ed25519: {e}")))?;
                Ok(SigningKey::Ed25519(sk))
            }
            Algorithm::EcdsaP256Sha256 => {
                let sk = parse_p256_private(&tag, &der)?;
                Ok(SigningKey::EcP256(sk.into()))
            }
            Algorithm::EcdsaP384Sha384 => {
                let sk = parse_p384_private(&tag, &der)?;
                Ok(SigningKey::EcP384(sk.into()))
            }
            Algorithm::EcdsaP521Sha512 => {
                let sk = parse_p521_private(&tag, &der)?;
                Ok(SigningKey::EcP521(sk.into()))
            }
            Algorithm::RsaPssSha256 | Algorithm::RsaPssSha512 => {
                let sk = parse_rsa_private(&tag, &der)?;
                Ok(SigningKey::RsaPss(sk))
            }
            Algorithm::RsaPkcs1Sha256 | Algorithm::RsaPkcs1Sha512 => {
                let sk = parse_rsa_private(&tag, &der)?;
                Ok(SigningKey::RsaPkcs1(sk))
            }
        }
    }

    /// Sign the given signature base, returning the raw signature bytes.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            SigningKey::Hmac(secret) => match self.algorithm() {
                Algorithm::HmacSha256 => hmac_sign::<Sha256>(secret, msg),
                Algorithm::HmacSha512 => hmac_sign::<Sha512>(secret, msg),
                _ => unreachable!(),
            },
            SigningKey::RsaPss(key) => match self.algorithm() {
                Algorithm::RsaPssSha256 => rsa_pss_sign::<Sha256>(key, msg, 32),
                Algorithm::RsaPssSha512 => rsa_pss_sign::<Sha512>(key, msg, 64),
                _ => unreachable!(),
            },
            SigningKey::RsaPkcs1(key) => match self.algorithm() {
                Algorithm::RsaPkcs1Sha256 => rsa_pkcs1_sign::<Sha256>(key, msg),
                Algorithm::RsaPkcs1Sha512 => rsa_pkcs1_sign::<Sha512>(key, msg),
                _ => unreachable!(),
            },
            SigningKey::EcP256(key) => ecdsa_sign(key, msg),
            SigningKey::EcP384(key) => ecdsa_sign(key, msg),
            SigningKey::EcP521(key) => ecdsa_sign(key, msg),
            SigningKey::Ed25519(key) => Ok(key.sign(msg, None).as_ref().to_vec()),
        }
    }
}

impl VerifyingKey {
    /// The algorithm family this key belongs to.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            VerifyingKey::Hmac(_) => Algorithm::HmacSha256,
            VerifyingKey::RsaPss(_) => Algorithm::RsaPssSha512,
            VerifyingKey::RsaPkcs1(_) => Algorithm::RsaPkcs1Sha256,
            VerifyingKey::EcP256(_) => Algorithm::EcdsaP256Sha256,
            VerifyingKey::EcP384(_) => Algorithm::EcdsaP384Sha384,
            VerifyingKey::EcP521(_) => Algorithm::EcdsaP521Sha512,
            VerifyingKey::Ed25519(_) => Algorithm::Ed25519,
        }
    }

    /// Construct an HMAC verifying key from a raw shared secret.
    pub fn hmac(secret: impl Into<Vec<u8>>) -> Self {
        VerifyingKey::Hmac(secret.into())
    }

    /// Parse a verifying key from PEM, choosing the concrete key type from
    /// the supplied [`Algorithm`].
    pub fn from_pem(alg: Algorithm, pem: &str) -> Result<Self> {
        let (tag, der) = decode_pem(pem)?;
        match alg {
            Algorithm::HmacSha256 | Algorithm::HmacSha512 => Err(HttpSigError::Key(
                "HMAC keys are raw shared secrets, not PEM-encoded".into(),
            )),
            Algorithm::Ed25519 => {
                let pk = ed25519_compact::PublicKey::from_der(&der)
                    .map_err(|e| HttpSigError::Key(format!("ed25519: {e}")))?;
                Ok(VerifyingKey::Ed25519(pk))
            }
            Algorithm::EcdsaP256Sha256 => {
                let pk = parse_p256_public(&der)?;
                Ok(VerifyingKey::EcP256(pk.into()))
            }
            Algorithm::EcdsaP384Sha384 => {
                let pk = parse_p384_public(&der)?;
                Ok(VerifyingKey::EcP384(pk.into()))
            }
            Algorithm::EcdsaP521Sha512 => {
                let pk = parse_p521_public(&der)?;
                Ok(VerifyingKey::EcP521(pk.into()))
            }
            Algorithm::RsaPssSha256 | Algorithm::RsaPssSha512 => {
                let pk = rsa::RsaPublicKey::from_public_key_der(&der)
                    .map_err(|e| HttpSigError::Key(format!("rsa: {e}")))?;
                Ok(VerifyingKey::RsaPss(pk))
            }
            Algorithm::RsaPkcs1Sha256 | Algorithm::RsaPkcs1Sha512 => {
                let pk = rsa::RsaPublicKey::from_public_key_der(&der)
                    .map_err(|e| HttpSigError::Key(format!("rsa: {e}")))?;
                Ok(VerifyingKey::RsaPkcs1(pk))
            }
        }
    }

    /// Verify `sig` over `msg`. Returns `Ok(())` if valid.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        match self {
            VerifyingKey::Hmac(secret) => match self.algorithm() {
                Algorithm::HmacSha256 => hmac_verify::<Sha256>(secret, msg, sig),
                Algorithm::HmacSha512 => hmac_verify::<Sha512>(secret, msg, sig),
                _ => unreachable!(),
            },
            VerifyingKey::RsaPss(key) => match self.algorithm() {
                Algorithm::RsaPssSha256 => rsa_pss_verify::<Sha256>(key, msg, sig, 32),
                Algorithm::RsaPssSha512 => rsa_pss_verify::<Sha512>(key, msg, sig, 64),
                _ => unreachable!(),
            },
            VerifyingKey::RsaPkcs1(key) => match self.algorithm() {
                Algorithm::RsaPkcs1Sha256 => rsa_pkcs1_verify::<Sha256>(key, msg, sig),
                Algorithm::RsaPkcs1Sha512 => rsa_pkcs1_verify::<Sha512>(key, msg, sig),
                _ => unreachable!(),
            },
            VerifyingKey::EcP256(key) => ecdsa_verify(key, msg, sig),
            VerifyingKey::EcP384(key) => ecdsa_verify(key, msg, sig),
            VerifyingKey::EcP521(key) => ecdsa_verify(key, msg, sig),
            VerifyingKey::Ed25519(key) => {
                let s = ed25519_compact::Signature::from_slice(sig)
                    .map_err(|e| HttpSigError::Verify(format!("ed25519: {e}")))?;
                key.verify(msg, &s)
                    .map_err(|_| HttpSigError::Verify("ed25519 signature invalid".into()))
            }
        }
    }
}

// --- PEM decoding -----------------------------------------------------------

fn decode_pem(pem_str: &str) -> Result<(String, Vec<u8>)> {
    let p = pem::parse(pem_str.as_bytes()).map_err(|e| HttpSigError::Key(e.to_string()))?;
    Ok((p.tag().to_string(), p.contents().to_vec()))
}

// --- HMAC -------------------------------------------------------------------

fn hmac_sign<D: Digest>(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use hmac::Mac;
    type HmacD<D2> = hmac::Hmac<D2>;
    let mut mac = HmacD::<D>::new_from_slice(key)
        .map_err(|e| HttpSigError::Key(format!("hmac key: {e}")))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_verify<D: Digest>(key: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use hmac::Mac;
    type HmacD<D2> = hmac::Hmac<D2>;
    let mut mac = HmacD::<D>::new_from_slice(key)
        .map_err(|e| HttpSigError::Key(format!("hmac key: {e}")))?;
    mac.update(msg);
    mac.verify_slice(sig)
        .map_err(|_| HttpSigError::Verify("HMAC signature mismatch".into()))
}

// --- RSA --------------------------------------------------------------------

fn parse_rsa_private(tag: &str, der: &[u8]) -> Result<rsa::RsaPrivateKey> {
    if tag == "RSA PRIVATE KEY" {
        rsa::RsaPrivateKey::from_pkcs1(der).map_err(|e| HttpSigError::Key(format!("rsa: {e}")))
    } else {
        rsa::RsaPrivateKey::from_pkcs8(der).map_err(|e| HttpSigError::Key(format!("rsa: {e}")))
    }
}

fn rsa_pss_sign<D: Digest>(key: &rsa::RsaPrivateKey, msg: &[u8], salt: usize) -> Result<Vec<u8>> {
    let scheme = rsa::Pss::new::<D>().with_salt_len(salt);
    key.sign(scheme, msg)
        .map_err(|e| HttpSigError::Sign(format!("rsa-pss: {e}")))
}

fn rsa_pss_verify<D: Digest>(
    key: &rsa::RsaPublicKey,
    msg: &[u8],
    sig: &[u8],
    salt: usize,
) -> Result<()> {
    let scheme = rsa::Pss::new::<D>().with_salt_len(salt);
    key.verify(scheme, msg, sig)
        .map_err(|_| HttpSigError::Verify("rsa-pss signature invalid".into()))
}

fn rsa_pkcs1_sign<D: Digest>(key: &rsa::RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    let scheme = rsa::Pkcs1v15Sign::new::<D>();
    key.sign(scheme, msg)
        .map_err(|e| HttpSigError::Sign(format!("rsa-pkcs1: {e}")))
}

fn rsa_pkcs1_verify<D: Digest>(key: &rsa::RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    let scheme = rsa::Pkcs1v15Sign::new::<D>();
    key.verify(scheme, msg, sig)
        .map_err(|_| HttpSigError::Verify("rsa-pkcs1 signature invalid".into()))
}

// --- ECDSA ------------------------------------------------------------------

fn ecdsa_sign<C>(key: &ecdsa::SigningKey<C>, msg: &[u8]) -> Result<Vec<u8>>
where
    C: elliptic_curve::Curve + ecdsa::hazmat::DigestPrimitive,
{
    use ecdsa::signature::Signer;
    let sig: ecdsa::Signature<C> = key.sign(msg);
    Ok(sig.to_vec())
}

fn ecdsa_verify<C>(key: &ecdsa::VerifyingKey<C>, msg: &[u8], sig: &[u8]) -> Result<()>
where
    C: elliptic_curve::Curve + ecdsa::hazmat::DigestPrimitive,
{
    use ecdsa::signature::{SignatureEncoding, Verifier};
    let sig = ecdsa::Signature::<C>::from_bytes(sig)
        .map_err(|_| HttpSigError::Verify("malformed ECDSA signature".into()))?;
    key.verify(msg, &sig)
        .map_err(|_| HttpSigError::Verify("ECDSA signature invalid".into()))
}

/// Minimal DER TLV reader over a byte slice. Returns `(tag, value)`.
fn read_tlv(b: &[u8], i: &mut usize) -> Result<(u8, &[u8])> {
    if *i >= b.len() {
        return Err(HttpSigError::Key("unexpected end of DER".into()));
    }
    let tag = b[*i];
    *i += 1;
    if *i >= b.len() {
        return Err(HttpSigError::Key("truncated DER length".into()));
    }
    let mut len = b[*i] as usize;
    *i += 1;
    if len & 0x80 != 0 {
        let n = (len & 0x7f) as usize;
        len = 0;
        for _ in 0..n {
            if *i >= b.len() {
                return Err(HttpSigError::Key("truncated DER length".into()));
            }
            len = (len << 8) | b[*i] as usize;
            *i += 1;
        }
    }
    if *i + len > b.len() {
        return Err(HttpSigError::Key("DER length exceeds buffer".into()));
    }
    let data = &b[*i..*i + len];
    *i += len;
    Ok((tag, data))
}

/// Extract the raw private scalar from a SEC1 `ECPrivateKey` DER structure
/// (used for the legacy `-----BEGIN EC PRIVATE KEY-----` form).
fn sec1_scalar(der: &[u8]) -> Result<Vec<u8>> {
    let (tag, seq) = read_tlv(der, &mut 0)?;
    if tag != 0x30 {
        return Err(HttpSigError::Key("expected SEQUENCE for ECPrivateKey".into()));
    }
    let mut i = 0;
    let (t1, _) = read_tlv(seq, &mut i)?;
    if t1 != 0x02 {
        return Err(HttpSigError::Key("expected INTEGER version in ECPrivateKey".into()));
    }
    let (t2, scalar) = read_tlv(seq, &mut i)?;
    if t2 != 0x04 {
        return Err(HttpSigError::Key("expected OCTET STRING privateKey in ECPrivateKey".into()));
    }
    Ok(scalar.to_vec())
}

fn parse_p256_private(tag: &str, der: &[u8]) -> Result<p256::SecretKey> {
    if tag == "EC PRIVATE KEY" {
        let scalar = sec1_scalar(der)?;
        p256::SecretKey::from_slice(&scalar)
            .map_err(|e| HttpSigError::Key(format!("p256 ec: {e}")))
    } else {
        p256::SecretKey::from_pkcs8_der(der).map_err(|e| HttpSigError::Key(format!("p256 pkcs8: {e}")))
    }
}

fn parse_p384_private(tag: &str, der: &[u8]) -> Result<p384::SecretKey> {
    if tag == "EC PRIVATE KEY" {
        let scalar = sec1_scalar(der)?;
        p384::SecretKey::from_slice(&scalar)
            .map_err(|e| HttpSigError::Key(format!("p384 ec: {e}")))
    } else {
        p384::SecretKey::from_pkcs8_der(der).map_err(|e| HttpSigError::Key(format!("p384 pkcs8: {e}")))
    }
}

fn parse_p521_private(tag: &str, der: &[u8]) -> Result<p521::SecretKey> {
    if tag == "EC PRIVATE KEY" {
        let scalar = sec1_scalar(der)?;
        p521::SecretKey::from_slice(&scalar)
            .map_err(|e| HttpSigError::Key(format!("p521 ec: {e}")))
    } else {
        p521::SecretKey::from_pkcs8_der(der).map_err(|e| HttpSigError::Key(format!("p521 pkcs8: {e}")))
    }
}

fn parse_p256_public(der: &[u8]) -> Result<p256::PublicKey> {
    let spki = spki::SubjectPublicKeyInfo::from_der(der)
        .map_err(|e| HttpSigError::Key(format!("spki: {e}")))?;
    let raw = spki.subject_public_key.raw_bytes();
    p256::PublicKey::from_sec1_bytes(raw).map_err(|e| HttpSigError::Key(format!("p256 pub: {e}")))
}

fn parse_p384_public(der: &[u8]) -> Result<p384::PublicKey> {
    let spki = spki::SubjectPublicKeyInfo::from_der(der)
        .map_err(|e| HttpSigError::Key(format!("spki: {e}")))?;
    let raw = spki.subject_public_key.raw_bytes();
    p384::PublicKey::from_sec1_bytes(raw).map_err(|e| HttpSigError::Key(format!("p384 pub: {e}")))
}

fn parse_p521_public(der: &[u8]) -> Result<p521::PublicKey> {
    let spki = spki::SubjectPublicKeyInfo::from_der(der)
        .map_err(|e| HttpSigError::Key(format!("spki: {e}")))?;
    let raw = spki.subject_public_key.raw_bytes();
    p521::PublicKey::from_sec1_bytes(raw).map_err(|e| HttpSigError::Key(format!("p521 pub: {e}")))
}
