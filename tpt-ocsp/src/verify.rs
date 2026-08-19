// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature verification and OCSP extension helpers.

use const_oid::ObjectIdentifier;
use der::{asn1::{AnyRef, OctetString}, Decode, Encode};
use ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use rsa::Pkcs1v15Sign;
use sha2::{Sha256, Sha384, Sha512};
use spki::SubjectPublicKeyInfoOwned;

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
pub(crate) fn build_nonce_ext(nonce: &[u8]) -> Extension {
    Extension {
        extn_id: oids::oid(oids::OCSP_NONCE),
        critical: false,
        extn_value: OctetString::new(nonce.to_vec()).expect("nonce fits in an OCTET STRING"),
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
    spki: &SubjectPublicKeyInfoOwned,
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
        // `rsa` 0.9 is built against `spki` 0.7 while the rest of the stack uses
        // `spki` 0.8, so we parse the SPKI from its DER bytes rather than going
        // through `spki`'s public-key types.
        let spki_der = spki
            .to_der()
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let pubkey = rsa::RsaPublicKey::from_public_key_der(&spki_der)
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        match hash {
            HashAlgorithm::Sha256 => pubkey
                .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
                .map_err(|e| OcspError::Signature(e.to_string())),
            HashAlgorithm::Sha384 => pubkey
                .verify(Pkcs1v15Sign::new::<Sha384>(), &digest, signature)
                .map_err(|e| OcspError::Signature(e.to_string())),
            HashAlgorithm::Sha512 => pubkey
                .verify(Pkcs1v15Sign::new::<Sha512>(), &digest, signature)
                .map_err(|e| OcspError::Signature(e.to_string())),
            HashAlgorithm::Sha1 => Err(OcspError::UnsupportedHash("SHA-1".into())),
        }
    } else if *key_oid == oids::oid(oids::EC_PUBLIC_KEY) {
        let point = spki.subject_public_key.raw_bytes();
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| OcspError::Crypto("EC public key missing curve parameters".into()))?;
        let der = curve
            .to_der()
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let curve_oid: ObjectIdentifier = ObjectIdentifier::from_der(&der)
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let curve_str = curve_oid.to_string();
        match curve_str.as_str() {
            oids::P256 => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|e| OcspError::Crypto(e.to_string()))?;
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .map_err(|e| OcspError::Signature(e.to_string()))?;
                vk.verify_prehash(&digest, &sig)
                    .map_err(|e| OcspError::Signature(e.to_string()))
            }
            oids::P384 => {
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|e| OcspError::Crypto(e.to_string()))?;
                let sig = p384::ecdsa::Signature::from_der(signature)
                    .map_err(|e| OcspError::Signature(e.to_string()))?;
                vk.verify_prehash(&digest, &sig)
                    .map_err(|e| OcspError::Signature(e.to_string()))
            }
            other => Err(OcspError::UnsupportedKey(other.to_string())),
        }
    } else if *key_oid == oids::oid(oids::ED25519) {
        let key_bytes = spki.subject_public_key.raw_bytes();
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
