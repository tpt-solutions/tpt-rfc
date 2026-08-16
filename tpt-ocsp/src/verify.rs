// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature verification and OCSP extension helpers.

use const_oid::ObjectIdentifier;
use der::{asn1::AnyRef, Decode};
use ecdsa::signature::hazmat::PrehashVerifier;
use sha1::{Digest as _, Sha1};
use spki::SubjectPublicKeyInfoRef;

use crate::error::{OcspError, OcspResult};
use crate::hash::HashAlgorithm;
use crate::oids;
use crate::wire::Extension;

/// A `NULL` `AlgorithmIdentifier` parameter, returned as an `AnyRef` so it can
/// be borrowed by `AlgorithmIdentifierRef.parameters`.
pub(crate) fn null_params() -> Option<AnyRef<'static>> {
    // `NULL` ::= [UNIVERSAL 5] IMPLICIT ... : tag 0x05, length 0x00.
    AnyRef::from_der(&[0x05, 0x00]).ok()
}

/// Build the standard OCSP nonce `Extension` (`id-pkix-ocsp-nonce`), borrowing
/// `nonce` for the lifetime of the returned extension.
pub(crate) fn build_nonce_ext<'a>(nonce: &'a [u8]) -> Extension<'a> {
    Extension {
        extn_id: oids::oid(oids::OCSP_NONCE),
        critical: false,
        extn_value: der::asn1::OctetStringRef::new(nonce).expect("nonce fits in an OCTET STRING"),
    }
}

/// Extract the nonce bytes (if any) from an `Extensions` collection.
pub(crate) fn extract_nonce(exts: &Option<Vec<Extension>>) -> Option<Vec<u8>> {
    let exts = exts.as_ref()?;
    for ext in exts {
        if ext.extn_id == oids::oid(oids::OCSP_NONCE) {
            return Some(ext.extn_value.as_bytes().to_vec());
        }
    }
    None
}

/// Verify a signature over `tbs` against the public key described by `spki`,
/// using the signature scheme identified by `sig_alg_oid`.
pub(crate) fn verify_signature(
    spki: SubjectPublicKeyInfoRef<'_>,
    sig_alg_oid: &ObjectIdentifier,
    tbs: &[u8],
    signature: &[u8],
) -> OcspResult<()> {
    let hash = match sig_alg_oid {
        o if *o == oids::oid(oids::ECDSA_SHA256) => HashAlgorithm::Sha256,
        o if *o == oids::oid(oids::ECDSA_SHA384) => HashAlgorithm::Sha384,
        o if *o == oids::oid(oids::ECDSA_SHA512) => HashAlgorithm::Sha512,
        o if *o == oids::oid(oids::SHA256_RSA) => HashAlgorithm::Sha256,
        o if *o == oids::oid(oids::SHA384_RSA) => HashAlgorithm::Sha384,
        o if *o == oids::oid(oids::SHA512_RSA) => HashAlgorithm::Sha512,
        o if *o == oids::oid(oids::ED25519) => HashAlgorithm::Sha256, // unused
        _ => return Err(OcspError::UnsupportedSignature(sig_alg_oid.to_string())),
    };
    let digest = hash.digest(tbs);

    let key_oid = spki.algorithm.oid;

    if *key_oid == oids::oid(oids::RSA_ENCRYPTION) {
        let pubkey = rsa::RsaPublicKey::try_from(spki)
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let sig = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| OcspError::Signature(e.to_string()))?;
        match hash {
            HashAlgorithm::Sha256 => {
                rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pubkey)
                    .verify_prehash(&digest, &sig)
                    .map_err(|e| OcspError::Signature(e.to_string()))
            }
            HashAlgorithm::Sha384 => {
                rsa::pkcs1v15::VerifyingKey::<Sha384>::new(pubkey)
                    .verify_prehash(&digest, &sig)
                    .map_err(|e| OcspError::Signature(e.to_string()))
            }
            HashAlgorithm::Sha512 => {
                rsa::pkcs1v15::VerifyingKey::<Sha512>::new(pubkey)
                    .verify_prehash(&digest, &sig)
                    .map_err(|e| OcspError::Signature(e.to_string()))
            }
            HashAlgorithm::Sha1 => Err(OcspError::UnsupportedHash("SHA-1".into())),
        }
    } else if *key_oid == oids::oid(oids::EC_PUBLIC_KEY) {
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| OcspError::Crypto("missing EC point".into()))?;
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .map(|p| ObjectIdentifier::from_der(p.as_bytes()))
            .transpose()
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let curve_str = curve.as_ref().map(|c| c.to_string());
        match curve_str.as_deref() {
            Some(oids::P256) => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|e| OcspError::Crypto(e.to_string()))?;
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .map_err(|e| OcspError::Signature(e.to_string()))?;
                vk.verify_prehash(&digest, &sig)
                    .map_err(|e| OcspError::Signature(e.to_string()))
            }
            Some(oids::P384) => {
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|e| OcspError::Crypto(e.to_string()))?;
                let sig = p384::ecdsa::Signature::from_der(signature)
                    .map_err(|e| OcspError::Signature(e.to_string()))?;
                vk.verify_prehash(&digest, &sig)
                    .map_err(|e| OcspError::Signature(e.to_string()))
            }
            Some(other) => Err(OcspError::UnsupportedKey(other.to_string())),
            None => Err(OcspError::UnsupportedKey("EC without curve".into())),
        }
    } else if *key_oid == oids::oid(oids::ED25519) {
        let key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| OcspError::Crypto("missing Ed25519 key".into()))?;
        let pubkey = ed25519_compact::PublicKey::from_slice(key_bytes)
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let sig = ed25519_compact::Signature::from_slice(signature)
            .map_err(|e| OcspError::Signature(e.to_string()))?;
        pubkey
            .verify(tbs, &sig)
            .map_err(|e| OcspError::Signature(e.to_string()))
    } else {
        Err(OcspError::UnsupportedKey(key_oid.to_string()))
    }
}
