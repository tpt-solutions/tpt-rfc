// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Private-key abstraction for signing OCSP `BasicOCSPResponse` structures.

use const_oid::ObjectIdentifier;
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPrivateKey;
use sha2::{Sha256, Sha384, Sha512};

use crate::error::{OcspError, OcspResult};
use crate::hash::HashAlgorithm;
use crate::oids;

/// A private signing key usable by an OCSP responder.
#[derive(Clone)]
pub enum SigningKey {
    /// ECDSA on the NIST P-256 curve (paired with SHA-256).
    EcdsaP256(P256SigningKey),
    /// ECDSA on the NIST P-384 curve (paired with SHA-384).
    EcdsaP384(P384SigningKey),
    /// RSASSA-PKCS1-v1_5 (SHA-256/384/512 chosen by the digest algorithm).
    Rsa(RsaPrivateKey),
    /// Ed25519 (pure EdDSA, signed over the raw `tbsResponseData`).
    Ed25519(ed25519_compact::SecretKey),
}

impl SigningKey {
    /// Produce a signature over `tbs` (the `tbsResponseData` DER bytes) using
    /// `hash` as the digest algorithm, returning the signature algorithm OID
    /// that identifies the scheme.
    pub fn sign_response(
        &self,
        hash: HashAlgorithm,
        tbs: &[u8],
    ) -> OcspResult<(ObjectIdentifier, Vec<u8>)> {
        match self {
            SigningKey::EcdsaP256(key) => {
                if hash != HashAlgorithm::Sha256 {
                    return Err(OcspError::Crypto(
                        "ECDSA P-256 must be used with SHA-256".into(),
                    ));
                }
                let digest = hash.digest(tbs);
                let sig: P256Signature = key
                    .sign_prehash(&digest)
                    .map_err(|e| OcspError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA256), sig.to_vec()))
            }
            SigningKey::EcdsaP384(key) => {
                if hash != HashAlgorithm::Sha384 {
                    return Err(OcspError::Crypto(
                        "ECDSA P-384 must be used with SHA-384".into(),
                    ));
                }
                let digest = hash.digest(tbs);
                let sig: P384Signature = key
                    .sign_prehash(&digest)
                    .map_err(|e| OcspError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA384), sig.to_vec()))
            }
            SigningKey::Rsa(key) => {
                let digest = hash.digest(tbs);
                let (oid, sig) = match hash {
                    HashAlgorithm::Sha256 => {
                        let sig = key
                            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
                            .map_err(|e| OcspError::Crypto(e.to_string()))?;
                        (oids::oid(oids::SHA256_RSA), sig)
                    }
                    HashAlgorithm::Sha384 => {
                        let sig = key
                            .sign(Pkcs1v15Sign::new::<Sha384>(), &digest)
                            .map_err(|e| OcspError::Crypto(e.to_string()))?;
                        (oids::oid(oids::SHA384_RSA), sig)
                    }
                    HashAlgorithm::Sha512 => {
                        let sig = key
                            .sign(Pkcs1v15Sign::new::<Sha512>(), &digest)
                            .map_err(|e| OcspError::Crypto(e.to_string()))?;
                        (oids::oid(oids::SHA512_RSA), sig)
                    }
                    HashAlgorithm::Sha1 => return Err(OcspError::UnsupportedHash("SHA-1".into())),
                };
                Ok((oid, sig))
            }
            SigningKey::Ed25519(key) => {
                let sig = key.sign(tbs, None);
                Ok((oids::oid(oids::ED25519), sig.as_slice().to_vec()))
            }
        }
    }
}
