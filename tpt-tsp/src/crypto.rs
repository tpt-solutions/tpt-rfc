//! Cryptographic primitives for TSP: hashing and signing / verification key
//! handling, reused from the same dual-licensed RustCrypto primitives as
//! `tpt-cms`. Clean-room: no code is copied from existing implementations.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha2_010::{Sha256 as Sha256_010, Sha384 as Sha384_010, Sha512 as Sha512_010};

use crate::error::{TspError, Result};
use crate::oids;
use crate::wire;

// ===========================================================================
// Digest algorithms
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Hash algorithms supported for `messageImprint` and CMS signed attributes.
pub enum HashAlgorithm {
    /// SHA-1 (deprecated; retained for interop only).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// The OID identifying this hash algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        oids::oid(match self {
            HashAlgorithm::Sha1 => oids::SHA1,
            HashAlgorithm::Sha256 => oids::SHA256,
            HashAlgorithm::Sha384 => oids::SHA384,
            HashAlgorithm::Sha512 => oids::SHA512,
        })
    }

    /// Map a hash-algorithm OID to a `HashAlgorithm`.
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        let s = oid.to_string();
        match s.as_str() {
            oids::SHA1 => Ok(HashAlgorithm::Sha1),
            oids::SHA256 => Ok(HashAlgorithm::Sha256),
            oids::SHA384 => Ok(HashAlgorithm::Sha384),
            oids::SHA512 => Ok(HashAlgorithm::Sha512),
            _ => Err(TspError::UnsupportedHash(s)),
        }
    }

    /// Compute the digest of `data` with this algorithm.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha1 => {
                use sha1::Digest as Sha1Digest;
                sha1::Sha1::digest(data).to_vec()
            }
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// The digest output length in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

// `sha1` is pulled in as its own dependency for the deprecated SHA-1 option.

// ===========================================================================
// Signing / verification key abstractions
// ===========================================================================

use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use p384::ecdsa::signature::hazmat::{PrehashSigner as P384PrehashSigner, PrehashVerifier as P384PrehashVerifier};
use rsa::RsaPublicKey as RsaPub;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};

/// A private signing key usable for the TSA `TimeStampToken`.
#[derive(Clone)]
pub enum SigningKey {
    /// ECDSA over NIST P-256 (with SHA-256).
    EcdsaP256(P256SigningKey),
    /// ECDSA over NIST P-384 (with SHA-384).
    EcdsaP384(P384SigningKey),
    /// RSA PKCS#1 v1.5 (with SHA-256).
    Rsa(RsaPrivateKey),
    /// Ed25519 (pure EdDSA, no pre-hash).
    Ed25519(ed25519_compact::SecretKey),
}

/// A public key extracted from a certificate's `SubjectPublicKeyInfo`.
pub(crate) enum PublicKey {
    Rsa(RsaPublicKey),
    EcdsaP256(P256VerifyingKey),
    EcdsaP384(P384VerifyingKey),
    Ed25519(ed25519_compact::PublicKey),
}

impl SigningKey {
    /// Sign `digest` (the hash of the SignedAttributes SET, or the message for
    /// Ed25519) returning the signature algorithm OID and the raw signature.
    pub fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
        match self {
            SigningKey::EcdsaP256(key) => {
                if hash != HashAlgorithm::Sha256 {
                    return Err(TspError::Crypto(
                        "ECDSA P-256 must be used with SHA-256".into(),
                    ));
                }
                let sig: P256Signature = key
                    .sign_prehash(digest)
                    .map_err(|e| TspError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA256), sig.to_vec()))
            }
            SigningKey::EcdsaP384(key) => {
                if hash != HashAlgorithm::Sha384 {
                    return Err(TspError::Crypto(
                        "ECDSA P-384 must be used with SHA-384".into(),
                    ));
                }
                let sig: P384Signature = key
                    .sign_prehash(digest)
                    .map_err(|e| TspError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA384), sig.to_vec()))
            }
            SigningKey::Rsa(key) => {
                let padding = match hash {
                    HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256_010>(),
                    HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384_010>(),
                    HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512_010>(),
                    _ => Pkcs1v15Sign::new::<Sha256_010>(),
                };
                let sig = key
                    .sign(padding, digest)
                    .map_err(|e| TspError::Crypto(e.to_string()))?;
                let oid = match hash {
                    HashAlgorithm::Sha256 => oids::SHA256_RSA,
                    HashAlgorithm::Sha384 => oids::SHA384_RSA,
                    HashAlgorithm::Sha512 => oids::SHA512_RSA,
                    HashAlgorithm::Sha1 => oids::SHA256_RSA,
                };
                Ok((oids::oid(oid), sig))
            }
            SigningKey::Ed25519(key) => {
                let sig = key.sign(digest, None);
                Ok((oids::oid(oids::ED25519), sig.to_vec()))
            }
        }
    }

    /// Demo P-256 key from a fixed seed (tests/examples only).
    pub fn demo_p256(seed: [u8; 32]) -> SigningKey {
        SigningKey::EcdsaP256(P256SigningKey::from_bytes((&seed).into()).unwrap())
    }

    /// Demo P-384 key from a fixed seed (tests/examples only).
    pub fn demo_p384(seed: [u8; 48]) -> SigningKey {
        SigningKey::EcdsaP384(P384SigningKey::from_bytes((&seed).into()).unwrap())
    }

    /// Demo RSA-2048 key (tests/examples only).
    pub fn demo_rsa(rng: &mut impl rand_core::CryptoRngCore) -> SigningKey {
        SigningKey::Rsa(RsaPrivateKey::new(rng, 2048).unwrap())
    }

    /// Demo Ed25519 key from a fixed seed (tests/examples only).
    pub fn demo_ed25519(seed: [u8; 32]) -> SigningKey {
        SigningKey::Ed25519(ed25519_compact::SecretKey::from_slice(&seed).unwrap())
    }
}

/// Extract the public key from an `x509_cert` SubjectPublicKeyInfo.
pub(crate) fn public_key_from_spki(
    spki: &spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString>,
) -> Result<PublicKey> {
    let alg = spki.algorithm.oid.to_string();
    let params_der = spki.algorithm.parameters.as_ref().map(|p| p.value().to_vec());
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| TspError::Crypto("missing subject public key".into()))?;
    match alg.as_str() {
        oids::RSA_ENCRYPTION => {
            let spki_der = spki
                .to_der()
                .map_err(|e| TspError::Crypto(format!("spki der: {e}")))?;
            let pubkey = RsaPub::from_public_key_der(&spki_der)
                .map_err(|e| TspError::Crypto(format!("RSA pubkey: {e}")))?;
            Ok(PublicKey::Rsa(pubkey))
        }
        oids::EC_PUBLIC_KEY => {
            let curve = params_der.ok_or_else(|| TspError::Crypto("EC key missing curve OID".into()))?;
            let full = wire::tlv(0x06, &curve);
            let curve_oid: ObjectIdentifier = ObjectIdentifier::from_der(&full)
                .map_err(|e| TspError::Crypto(format!("EC curve OID: {e}")))?;
            match curve_oid.to_string().as_str() {
                oids::P256 => {
                    let pk = p256::PublicKey::from_sec1_bytes(key_bytes)
                        .map_err(|e| TspError::Crypto(format!("P-256 pubkey: {e}")))?;
                    Ok(PublicKey::EcdsaP256(pk.into()))
                }
                oids::P384 => {
                    let pk = p384::PublicKey::from_sec1_bytes(key_bytes)
                        .map_err(|e| TspError::Crypto(format!("P-384 pubkey: {e}")))?;
                    Ok(PublicKey::EcdsaP384(pk.into()))
                }
                other => Err(TspError::UnsupportedCurve(other.into())),
            }
        }
        oids::ED25519 => {
            let pk = ed25519_compact::PublicKey::from_slice(key_bytes)
                .map_err(|e| TspError::Crypto(format!("Ed25519 pubkey: {e}")))?;
            Ok(PublicKey::Ed25519(pk))
        }
        other => Err(TspError::UnsupportedKey(other.to_string())),
    }
}

/// Map a CMS signature-algorithm OID to its digest (None for pure EdDSA).
pub(crate) fn sig_alg_hash(alg_oid: &ObjectIdentifier) -> Result<HashAlgorithm> {
    let s = alg_oid.to_string();
    match s.as_str() {
        oids::SHA256_RSA | oids::ECDSA_SHA256 => Ok(HashAlgorithm::Sha256),
        oids::SHA384_RSA | oids::ECDSA_SHA384 => Ok(HashAlgorithm::Sha384),
        oids::SHA512_RSA | oids::ECDSA_SHA512 => Ok(HashAlgorithm::Sha512),
        oids::ED25519 => Err(TspError::Crypto("Ed25519 has no prehash".into())),
        _ => Err(TspError::UnsupportedSignature(s)),
    }
}

/// Verify a signature over `message` (the hash bytes for RSA/ECDSA, or the raw
/// message for Ed25519) using `pubkey` and the signature algorithm `alg_oid`.
pub(crate) fn verify_signature(
    alg_oid: &ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
    pubkey: &PublicKey,
) -> Result<()> {
    let s = alg_oid.to_string();
    match s.as_str() {
        oids::SHA256_RSA | oids::SHA384_RSA | oids::SHA512_RSA => {
            let hash = sig_alg_hash(alg_oid)?;
            let padding = match hash {
                HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256_010>(),
                HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384_010>(),
                HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512_010>(),
                HashAlgorithm::Sha1 => Pkcs1v15Sign::new::<Sha256_010>(),
            };
            if let PublicKey::Rsa(pk) = pubkey {
                pk.verify(padding, message, signature)
                    .map_err(|e| TspError::Signature(e.to_string()))?;
                Ok(())
            } else {
                Err(TspError::Signature("algorithm/public key mismatch".into()))
            }
        }
        oids::ECDSA_SHA256 => {
            if let PublicKey::EcdsaP256(pk) = pubkey {
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| TspError::Signature(e.to_string()))?;
                pk.verify_prehash(message, &sig)
                    .map_err(|e| TspError::Signature(e.to_string()))?;
                Ok(())
            } else {
                Err(TspError::Signature("algorithm/public key mismatch".into()))
            }
        }
        oids::ECDSA_SHA384 => {
            if let PublicKey::EcdsaP384(pk) = pubkey {
                let sig = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| TspError::Signature(e.to_string()))?;
                pk.verify_prehash(message, &sig)
                    .map_err(|e| TspError::Signature(e.to_string()))?;
                Ok(())
            } else {
                Err(TspError::Signature("algorithm/public key mismatch".into()))
            }
        }
        oids::ED25519 => {
            if let PublicKey::Ed25519(pk) = pubkey {
                let sig = ed25519_compact::Signature::from_slice(signature)
                    .map_err(|e| TspError::Signature(format!("{e}")))?;
                pk.verify(message, &sig)
                    .map_err(|e| TspError::Signature(format!("{e}")))?;
                Ok(())
            } else {
                Err(TspError::Signature("algorithm/public key mismatch".into()))
            }
        }
        _ => Err(TspError::UnsupportedSignature(s)),
    }
}
