//! Integration tests for `tpt-cms`. Certificates are generated in clean room at
//! test time by hand-assembling X.509 `Certificate` DER (using the `der` 0.8 +
//! `x509-cert` 0.3 types the crate already depends on) and signing with
//! dual-licensed RustCrypto keys. No external test vectors or network access
//! are required.
//!
//! NOTE: in this dependency graph `rsa` 0.9 / `ecdsa` 0.17 / `p256` 0.14 resolve
//! to `spki` 0.7 while `x509-cert` 0.3 uses `spki` 0.8, so the `x509-cert`
//! *builder* (which bridges those trait versions) cannot be used here. We
//! therefore construct certificates directly from DER, which depends only on
//! `x509-cert` 0.3 / `der` 0.8 and is fully self-consistent — DER bytes are
//! version-agnostic, so the cross-version boundary is never crossed.

use std::str::FromStr;
use std::time::Duration;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::SignatureEncoding;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::SecretKey as P256SecretKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::Digest;
use sha2::Sha256;
use sha2_010::Digest as Digest010;
use sha2_010::Sha256 as Sha256010;
use x509_cert::Certificate;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use rand_core::OsRng;

use tpt_cms::*;

const ID_DATA: &str = "1.2.840.113549.1.7.1";

// OIDs used when assembling self-signed certificates.
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const P256_CURVE: &str = "1.2.840.10045.3.1.7";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const SHA256_RSA: &str = "1.2.840.113549.1.1.11";

// ---------------------------------------------------------------------------
// Minimal DER TLV helpers (local to the test; independent of the crate's own
// `wire` module so the crate-under-test stays the unit under test).
// ---------------------------------------------------------------------------

fn enc_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut b = (n as u128).to_be_bytes().to_vec();
        while b.len() > 1 && b[0] == 0 {
            b.remove(0);
        }
        let mut out = vec![0x80 | b.len() as u8];
        out.extend_from_slice(&b);
        out
    }
}

fn seq_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&enc_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    seq_tag(0x30, &content)
}

fn oid(oid_str: &str) -> Vec<u8> {
    ObjectIdentifier::new_unwrap(oid_str).to_der().unwrap()
}

fn alg_id(oid_str: &str, params: Option<&[u8]>) -> Vec<u8> {
    match params {
        Some(p) => seq(&[&oid(oid_str), p]),
        None => seq(&[&oid(oid_str)]),
    }
}

fn null_der() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = vec![0x00]; // unused-bits count
    body.extend_from_slice(content);
    seq_tag(0x03, &body)
}

/// DER-encode an INTEGER from its big-endian magnitude bytes (handles the
/// DER sign rule: strip leading zeros, prepend 0x00 if the high bit is set).
fn integer_der(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    while v.len() > 1 && v[0] == 0 {
        v.remove(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0x00);
    }
    seq_tag(0x02, &v)
}

// ---------------------------------------------------------------------------
// Self-signed certificate construction (DER, v1, no extensions).
// ---------------------------------------------------------------------------

fn valid_now() -> Validity {
    Validity::from_now(Duration::new(3600 * 24 * 365 * 10, 0)).unwrap()
}

fn build_self_signed_p256(seed: u8, serial: u64, cn: &str) -> (SigningKey, Certificate) {
    let mut bytes = [0x11u8; 32];
    bytes[0] = seed;
    let key = P256SigningKey::from_slice(&bytes).unwrap();

    let issuer = Name::from_str(cn).unwrap().to_der().unwrap();
    let subject = Name::from_str(cn).unwrap().to_der().unwrap();
    let validity = valid_now().to_der().unwrap();
    let serial_der = SerialNumber::from(serial).to_der().unwrap();

    let pubkey = key.verifying_key().to_sec1_bytes().to_vec();
    let spki = seq(&[
        &alg_id(EC_PUBLIC_KEY, Some(&oid(P256_CURVE))),
        &bit_string(&pubkey),
    ]);

    let tbs = seq(&[
        &serial_der,
        &alg_id(ECDSA_SHA256, None),
        &issuer,
        &validity,
        &subject,
        &spki,
    ]);

    // ECDSA over the SHA-256 digest of the TBS (the raw r||s signature, as CMS
    // stores it).
    let tbs_digest = Sha256::digest(&tbs);
    let sig: p256::ecdsa::Signature = key.sign_prehash(&tbs_digest).unwrap();
    let sig_bytes = sig.to_vec();

    let cert_der = seq(&[&tbs, &alg_id(ECDSA_SHA256, None), &bit_string(&sig_bytes)]);
    let cert = Certificate::from_der(&cert_der).unwrap();
    (SigningKey::EcdsaP256(key), cert)
}

fn build_self_signed_rsa(serial: u64, cn: &str) -> (RsaPrivateKey, Certificate) {
    let mut rng = OsRng;
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    // Build the RSAPublicKey DER (SEQUENCE { modulus, publicExponent }) from
    // the public key parts (avoids depending on `pkcs1` feature-gated helpers).
    let pubkey = key.to_public_key();
    let modulus = pubkey.n().to_bytes_be();
    let exponent = pubkey.e().to_bytes_be();
    let pubkey_der = seq(&[&integer_der(&modulus), &integer_der(&exponent)]);

    let issuer = Name::from_str(cn).unwrap().to_der().unwrap();
    let subject = Name::from_str(cn).unwrap().to_der().unwrap();
    let validity = valid_now().to_der().unwrap();
    let serial_der = SerialNumber::from(serial).to_der().unwrap();

    let spki = seq(&[
        &alg_id(RSA_ENCRYPTION, Some(&null_der())),
        &bit_string(&pubkey_der),
    ]);

    let tbs = seq(&[
        &serial_der,
        &alg_id(SHA256_RSA, Some(&null_der())),
        &issuer,
        &validity,
        &subject,
        &spki,
    ]);

    // RSASSA-PKCS#1-v1_5 over the SHA-256 digest of the TBS.
    let tbs_digest = Sha256010::digest(&tbs);
    let sig = key
        .sign(Pkcs1v15Sign::new::<Sha256010>(), &tbs_digest)
        .unwrap();

    let cert_der = seq(&[&tbs, &alg_id(SHA256_RSA, Some(&null_der())), &bit_string(&sig)]);
    let cert = Certificate::from_der(&cert_der).unwrap();
    (key, cert)
}

fn p256_secret(k: &SigningKey) -> P256SecretKey {
    match k {
        SigningKey::EcdsaP256(s) => P256SecretKey::from_bytes(&s.to_bytes()).unwrap(),
        _ => panic!("not p256"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn signed_data_p256_round_trip() {
    let (key, cert) = build_self_signed_p256(1, 100, "CN=CMS Test P256,O=TPT,C=US");
    let content = b"the quick brown fox".to_vec();
    let der = build_signed_data(
        &ObjectIdentifier::new_unwrap(ID_DATA),
        &content,
        &[CmsSigner::new(key, cert.clone())],
        &[],
    )
    .unwrap();
    let verified = verify_signed_data(&der, &[cert]).unwrap();
    assert_eq!(verified.content, content);
    assert_eq!(verified.signer_count, 1);
}

#[test]
fn signed_data_multi_signer() {
    let (k1, c1) = build_self_signed_p256(2, 101, "CN=Signer One,O=TPT,C=US");
    let (k2, c2) = build_self_signed_p256(3, 102, "CN=Signer Two,O=TPT,C=US");
    let content = b"multi-signer content".to_vec();
    let der = build_signed_data(
        &ObjectIdentifier::new_unwrap(ID_DATA),
        &content,
        &[
            CmsSigner::new(k1, c1.clone()),
            CmsSigner::new(k2, c2.clone()),
        ],
        &[],
    )
    .unwrap();
    let verified = verify_signed_data(&der, &[c1, c2]).unwrap();
    assert_eq!(verified.content, content);
    assert_eq!(verified.signer_count, 2);
}

#[test]
fn enveloped_data_rsa_round_trip() {
    let (key, cert) = build_self_signed_rsa(200, "CN=CMS RSA,O=TPT,C=US");
    let cert_for_open = cert.clone();
    let plaintext = b"secret via RSA key transport".to_vec();
    let der = build_enveloped_data(
        &plaintext,
        ContentEncryption::Aes256Cbc,
        &[RecipientSpec::KeyTransRsa { cert, oaep: false }],
    )
    .unwrap();
    let opened =
        open_enveloped_data(&der, &[RecipientPrivateKey::Rsa(key, cert_for_open)]).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn enveloped_data_ecdh_round_trip() {
    let (key, cert) = build_self_signed_p256(5, 201, "CN=CMS ECDH,O=TPT,C=US");
    let cert_for_open = cert.clone();
    let plaintext = b"secret via ECDH key agreement".to_vec();
    let der = build_enveloped_data(
        &plaintext,
        ContentEncryption::Aes128Cbc,
        &[RecipientSpec::KeyAgreeEcdh {
            cert,
            wrap: KeyWrap::Aes128Wrap,
        }],
    )
    .unwrap();
    let opened = open_enveloped_data(
        &der,
        &[RecipientPrivateKey::EcdhP256(
            p256_secret(&key),
            cert_for_open,
        )],
    )
    .unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn digested_data_round_trip() {
    let content = b"digest me".to_vec();
    let der = build_digested_data(&content, HashAlgorithm::Sha256).unwrap();
    let out = verify_digested_data(&der).unwrap();
    assert_eq!(out, content);
}

#[test]
fn encrypted_data_round_trip() {
    let content = b"symmetrically encrypted".to_vec();
    let key = [0x42u8; 32];
    let der = build_encrypted_data(&content, ContentEncryption::Aes256Cbc, &key).unwrap();
    let out = decrypt_encrypted_data(&der, &key).unwrap();
    assert_eq!(out, content);
}
