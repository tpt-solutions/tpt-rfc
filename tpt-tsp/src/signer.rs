//! Private-key abstraction for signing `SignedData` tokens, supporting the
//! signature algorithms deployed by real RFC 3161 time-stamp authorities.

use const_oid::ObjectIdentifier;
use der::Encode;
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPrivateKey;
use sha2::{Sha256, Sha384, Sha512};
use sha2_010::{Sha256 as Sha256010, Sha384 as Sha384010, Sha512 as Sha512010};

use crate::error::{Result, TspError};
use crate::hash::HashAlgorithm;
use crate::oids;

/// A private signing key usable by a TSA.
pub enum SigningKey {
    /// ECDSA on the NIST P-256 curve (paired with SHA-256).
    EcdsaP256(P256SigningKey),
    /// ECDSA on the NIST P-384 curve (paired with SHA-384).
    EcdsaP384(P384SigningKey),
    /// RSASSA-PKCS1-v1_5 (SHA-256/384/512 chosen by the digest algorithm).
    Rsa(RsaPrivateKey),
    /// Ed25519 (pure EdDSA).
    Ed25519(ed25519_compact::SecretKey),
}

impl SigningKey {
    /// Produce a signature over `digest` (the hash of the CMS signed attributes)
    /// using `hash` as the digest algorithm, returning the signature algorithm
    /// OID that identities the scheme.
    pub fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
        match self {
            SigningKey::EcdsaP256(key) => {
                if hash != HashAlgorithm::Sha256 {
                    return Err(TspError::Crypto(
                        "ECDSA P-256 must be used with SHA-256".into(),
                    ));
                }
                let sig: P256Signature =
                    key.sign_prehash(digest).map_err(|e| TspError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA256), sig.to_vec()))
            }
            SigningKey::EcdsaP384(key) => {
                if hash != HashAlgorithm::Sha384 {
                    return Err(TspError::Crypto(
                        "ECDSA P-384 must be used with SHA-384".into(),
                    ));
                }
                let sig: P384Signature =
                    key.sign_prehash(digest).map_err(|e| TspError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA384), sig.to_vec()))
            }
            SigningKey::Rsa(key) => {
                let padding = match hash {
                    HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256010>(),
                    HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384010>(),
                    HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512010>(),
                };
                let sig = key
                    .sign(padding, digest)
                    .map_err(|e| TspError::Crypto(e.to_string()))?;
                let oid = match hash {
                    HashAlgorithm::Sha256 => oids::SHA256_RSA,
                    HashAlgorithm::Sha384 => oids::SHA384_RSA,
                    HashAlgorithm::Sha512 => oids::SHA512_RSA,
                };
                Ok((oids::oid(oid), sig))
            }
            SigningKey::Ed25519(key) => {
                let sig = key.sign(digest, None);
                Ok((oids::oid(oids::ED25519), sig.to_vec()))
            }
        }
    }

    /// Generate a fresh, deterministic P-256 signing key (for tests/examples).
    pub fn demo_p256(seed: [u8; 32]) -> SigningKey {
        SigningKey::EcdsaP256(P256SigningKey::from_bytes(&seed).unwrap())
    }
}

/// Helper: least-significant-byte-trimmed big-endian encoding of a small integer
/// (used for `version`, `nonce`, and `serialNumber` INTEGER fields).
pub(crate) fn uint_be(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    bytes
}
