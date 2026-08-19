//! Integration tests for `tpt-cms`. Certificates are generated in clean room at
//! test time using the `x509-cert` builder plus dual-licensed RustCrypto signing
//! keys. No external test vectors or network access are required.

use std::str::FromStr;
use std::time::Duration;

use const_oid::ObjectIdentifier;
use p256::ecdsa::SigningKey as P256SigningKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use sha2_010::Sha256 as Sha256010;
use signature::{Keypair, Signer, SignatureEncoding, Verifier};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::ext::Extension;
use x509_cert::ext::ToExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Certificate;

use tpt_cms::*;

const ID_DATA: &str = "1.2.840.113549.1.7.1";

// ---------------------------------------------------------------------------
// RSA signature adapter for the x509-cert builder
// ---------------------------------------------------------------------------
// `rsa` 0.9's signer does not implement the `signature`-crate `Signer` trait,
// so we wrap it. The digest is computed with `sha2` 0.11 (matching the rest of
// the workspace) but the RSA padding is selected with a `digest` 0.10 hash type
// (via `sha2_010`) because `rsa` 0.9 pins that version. The `signature` crate
// 2.x uses `SignatureEncoding` (not the removed `Signature` trait).

struct RsaSig(Vec<u8>);
impl SignatureEncoding for RsaSig {
    type Repr = Vec<u8>;
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn from_bytes(bytes: &Vec<u8>) -> std::result::Result<Self, signature::Error> {
        Ok(RsaSig(bytes.clone()))
    }
}
impl SignatureBitStringEncoding for RsaSig {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::new(0, self.0.clone())
    }
}

#[derive(Clone)]
struct RsaVerifyingKey(rsa::RsaPublicKey);
impl EncodePublicKey for RsaVerifyingKey {
    fn to_public_key_der(&self) -> der::Result<spki::Document> {
        self.0.to_public_key_der()
    }
}
impl Verifier<RsaSig> for RsaVerifyingKey {
    fn verify(&self, msg: &[u8], sig: &RsaSig) -> std::result::Result<(), signature::Error> {
        self.0
            .verify(Pkcs1v15Sign::new::<Sha256010>(), msg, &sig.0)
            .map_err(|_| signature::Error::new())
    }
}

struct RsaSigner(RsaPrivateKey);
impl Keypair for RsaSigner {
    type VerifyingKey = RsaVerifyingKey;
    fn verifying_key(&self) -> RsaVerifyingKey {
        RsaVerifyingKey(self.0.to_public_key())
    }
}
impl DynSignatureAlgorithmIdentifier for RsaSigner {
    fn signature_algorithm_identifier(&self) -> der::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: None,
        })
    }
}
impl Signer<RsaSig> for RsaSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<RsaSig, signature::Error> {
        let digest = Sha256::digest(msg);
        let sig = self
            .0
            .sign(Pkcs1v15Sign::new::<Sha256010>(), &digest)
            .map_err(|_| signature::Error::new())?;
        Ok(RsaSig(sig))
    }
}

// ---------------------------------------------------------------------------
// Minimal certificate profile
// ---------------------------------------------------------------------------

struct TestProfile {
    subject: Name,
    issuer: Name,
    ca: bool,
}

impl BuilderProfile for TestProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        _spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::certificate::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut exts = Vec::new();
        exts.push(
            BasicConstraints {
                ca: self.ca,
                path_len_constraint: None,
            }
            .to_extension(&self.subject, &[])?,
        );
        exts.push(
            KeyUsage(if self.ca {
                KeyUsages::KeyCertSign | KeyUsages::CRLSign
            } else {
                KeyUsages::DigitalSignature
            })
            .to_extension(&self.subject, &[])?,
        );
        Ok(exts)
    }
}

fn name(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn valid_now() -> Validity {
    Validity::from_now(Duration::new(3600 * 24 * 365 * 10, 0)).unwrap()
}

fn build_self_signed_p256(seed: u8, serial: u64, cn: &str) -> (SigningKey, Certificate) {
    let mut bytes = [0x11u8; 32];
    bytes[0] = seed;
    let key = P256SigningKey::from_slice(&bytes).unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
    let profile = TestProfile {
        subject: name(cn),
        issuer: name(cn),
        ca: true,
    };
    // `p256::ecdsa::SigningKey` directly implements the x509-cert builder traits
    // (with the `spki` feature), so no adapter is needed here.
    let builder =
        CertificateBuilder::new(profile, SerialNumber::from(serial), valid_now(), spki).unwrap();
    let cert = builder
        .build::<_, p256::ecdsa::Signature>(&key)
        .unwrap();
    (SigningKey::EcdsaP256(key), cert)
}

fn build_self_signed_rsa(serial: u64, cn: &str) -> (RsaPrivateKey, Certificate) {
    let mut rng = rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(key.to_public_key()).unwrap();
    let profile = TestProfile {
        subject: name(cn),
        issuer: name(cn),
        ca: true,
    };
    let builder =
        CertificateBuilder::new(profile, SerialNumber::from(serial), valid_now(), spki).unwrap();
    let wrapped = RsaSigner(key.clone());
    let cert = builder.build::<_, RsaSig>(&wrapped).unwrap();
    (key, cert)
}

fn p256_secret(k: &SigningKey) -> p256::SecretKey {
    match k {
        SigningKey::EcdsaP256(s) => p256::SecretKey::from_bytes(s.to_bytes()).unwrap(),
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
