//! Integration tests for the RFC 5280 path-validation engine.
//!
//! Certificates are generated in clean room at test time using the `x509-cert`
//! builder plus dual-licensed RustCrypto signing keys (P-256). No external
//! test vectors or network access are required.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use const_oid::ObjectIdentifier;
use der::asn1::Ia5String;
use flagset::FlagSet;
use p256::ecdsa::SigningKey;
use signature::{Error as SigError, Keypair, Signer};
use spki::{
    AlgorithmIdentifier, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use x509_cert::spki::SubjectPublicKeyInfo;
use x509_cert::{
    builder::profile::BuilderProfile,
    builder::{Builder, CertificateBuilder},
    ext::{
        pkix::constraints::name::GeneralSubtree,
        pkix::name::GeneralName,
        pkix::{
            BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, NameConstraints,
            SubjectAltName,
        },
        Extension, ToExtension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    Certificate,
};

use tpt_x509::{
    cert::TrustAnchor,
    validate::{PathValidator, ValidationConfig},
};

const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";

// --- Test-only signing adapter ------------------------------------------------
//
// `x509_cert`'s `CertificateBuilder::build` requires the signature type to
// implement `spki::SignatureBitStringEncoding`. The stock `ecdsa` impl is
// gated behind associated-type bounds that are not satisfiable with the
// `NistP256`/`crypto-bigint` versions in this workspace, so we wrap the P-256
// signer and provide the trait impl directly (the underlying signature is a
// real, deterministic RFC 6979 ECDSA-P256 signature over SHA-256).

/// A P-256 ECDSA signature wrapper that carries its DER encoding.
struct EcdsaSig(p256::ecdsa::Signature);

impl spki::SignatureBitStringEncoding for EcdsaSig {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::new(0, self.0.to_vec())
    }
}

/// A `Signer`/`Keypair` adapter around `p256::ecdsa::SigningKey`.
struct EcdsaSigner(p256::ecdsa::SigningKey);

impl Keypair for EcdsaSigner {
    type VerifyingKey = p256::ecdsa::VerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

impl DynSignatureAlgorithmIdentifier for EcdsaSigner {
    fn signature_algorithm_identifier(
        &self,
    ) -> der::Result<spki::AlgorithmIdentifier<der::asn1::Any>> {
        self.0
            .signature_algorithm_identifier()
            .map_err(spki::Error::from)
    }
}

impl Signer<EcdsaSig> for EcdsaSigner {
    fn try_sign(&self, msg: &[u8]) -> Result<EcdsaSig, SigError> {
        Ok(EcdsaSig(self.0.sign(msg)))
    }
}

/// A flexible test certificate profile.
struct TestProfile {
    subject: Name,
    issuer: Name,
    ca: bool,
    path_len: Option<u8>,
    key_usage: Option<FlagSet<KeyUsages>>,
    eku: Option<Vec<ObjectIdentifier>>,
    san: Option<Vec<GeneralName>>,
    name_constraints: Option<NameConstraints>,
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
                path_len_constraint: self.path_len,
            }
            .to_extension(&self.subject, &[])?,
        );
        if let Some(ku) = self.key_usage {
            exts.push(KeyUsage(ku).to_extension(&self.subject, &exts)?);
        }
        if let Some(eku) = &self.eku {
            exts.push(ExtendedKeyUsage(eku.clone()).to_extension(&self.subject, &exts)?);
        }
        if let Some(san) = &self.san {
            exts.push(SubjectAltName(san.clone()).to_extension(&self.subject, &exts)?);
        }
        if let Some(nc) = &self.name_constraints {
            exts.push(nc.to_extension(&self.subject, &exts)?);
        }
        Ok(exts)
    }
}

fn name(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn dns(s: &str) -> GeneralName {
    GeneralName::DnsName(der::asn1::Ia5String::new(s).unwrap())
}

fn signer(seed: u8) -> SigningKey {
    let mut bytes = [0x11u8; 32];
    bytes[0] = seed;
    SigningKey::from_slice(&bytes).unwrap()
}

fn valid_now() -> Validity {
    Validity::from_now(Duration::new(3600 * 24 * 365 * 10, 0)).unwrap()
}

fn build_p256(profile: TestProfile, signer: &SigningKey, serial: u64) -> Certificate {
    let spki = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap();
    let mut builder =
        CertificateBuilder::new(profile, SerialNumber::from(serial),
        validity, spki).unwrap();
    let wrapped = EcdsaSigner(signer.clone());
    builder.build::<_, EcdsaSig>(&wrapped).unwrap()
}

fn root_profile(issuer_name: &str, nc: Option<NameConstraints>) -> TestProfile {
    TestProfile {
        subject: name(issuer_name),
        issuer: name(issuer_name),
        ca: true,
        path_len: None,
        key_usage: Some(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        eku: None,
        san: None,
        name_constraints: nc,
    }
}

fn leaf_profile(subject: &str, issuer: &str, eku: Vec<ObjectIdentifier>, san: &str) -> TestProfile {
    TestProfile {
        subject: name(subject),
        issuer: name(issuer),
        ca: false,
        path_len: None,
        key_usage: Some(KeyUsages::DigitalSignature.into()),
        eku: Some(eku),
        san: Some(vec![dns(san)]),
        name_constraints: None,
    }
}

#[test]
fn valid_root_leaf_chain() {
    let root_key = signer(1);
    let leaf_key = signer(2);

    let root = build_p256(root_profile("CN=Test Root,O=TPT,C=US", None), &root_key, 1);
    let leaf = build_p256(
        leaf_profile(
            "CN=leaf.example.com,O=TPT,C=US",
            "CN=Test Root,O=TPT,C=US",
            vec![ObjectIdentifier::new_unwrap(SERVER_AUTH)],
            "leaf.example.com",
        ),
        &leaf_key,
        2,
        valid_now(),
    );

    let anchor = TrustAnchor::from_cert(&root).unwrap();
    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        intermediates: vec![],
        required_eku: Some(ObjectIdentifier::new_unwrap(SERVER_AUTH)),
        ..Default::default()
    };
    let validator = PathValidator::new(config);
    let path = validator
        .validate(&leaf)
        .expect("valid chain should validate");
    assert_eq!(path.len(), 2);
}

#[test]
fn issuer_missing_ca_bit_is_rejected() {
    let root_key = signer(1);
    let leaf_key = signer(2);
    let root = build_p256(
        TestProfile {
            subject: name("CN=Bad Root,O=TPT,C=US"),
            issuer: name("CN=Bad Root,O=TPT,C=US"),
            ca: false,
            path_len: None,
            key_usage: Some(KeyUsages::KeyCertSign.into()),
            eku: None,
            san: None,
            name_constraints: None,
        },
        &root_key,
        1,
        valid_now(),
    );
    let leaf = build_p256(
        leaf_profile(
            "CN=leaf,O=TPT,C=US",
            "CN=Bad Root,O=TPT,C=US",
            vec![],
            "leaf.example.com",
        ),
        &leaf_key,
        2,
        valid_now(),
    );

    let anchor = TrustAnchor::from_cert(&root).unwrap();
    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        ..Default::default()
    };
    let validator = PathValidator::new(config);
    assert!(validator.validate(&leaf).is_err());
}

#[test]
fn expired_certificate_is_rejected() {
    let root_key = signer(1);
    let leaf_key = signer(2);
    let root = build_p256(root_profile("CN=Root,O=TPT,C=US", None), &root_key, 1);
    let leaf = build_p256(
        leaf_profile(
            "CN=old,O=TPT,C=US",
            "CN=Root,O=TPT,C=US",
            vec![ObjectIdentifier::new_unwrap(SERVER_AUTH)],
            "old.example.com",
        ),
        &leaf_key,
        2,
        valid_now(),
    );

    // Evaluate the path 20 years in the future: every cert is expired.
    let future = SystemTime::now() + Duration::from_secs(20 * 365 * 24 * 3600);
    let anchor = TrustAnchor::from_cert(&root).unwrap();
    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        time: future,
        ..Default::default()
    };
    let validator = PathValidator::new(config);
    assert!(validator.validate(&leaf).is_err());
}

#[test]
fn eku_mismatch_is_rejected() {
    let root_key = signer(1);
    let leaf_key = signer(2);
    let root = build_p256(root_profile("CN=Root,O=TPT,C=US", None), &root_key, 1);
    let leaf = build_p256(
        leaf_profile(
            "CN=leaf,O=TPT,C=US",
            "CN=Root,O=TPT,C=US",
            vec![ObjectIdentifier::new_unwrap(CODE_SIGNING)],
            "leaf.example.com",
        ),
        &leaf_key,
        2,
        valid_now(),
    );

    let anchor = TrustAnchor::from_cert(&root).unwrap();
    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        required_eku: Some(ObjectIdentifier::new_unwrap(SERVER_AUTH)),
        ..Default::default()
    };
    let validator = PathValidator::new(config);
    assert!(validator.validate(&leaf).is_err());
}

#[test]
fn name_constraint_violation_is_rejected() {
    let root_key = signer(1);
    let leaf_key = signer(2);
    let nc = NameConstraints {
        permitted_subtrees: Some(vec![GeneralSubtree {
            base: dns("example.com"),
            minimum: 0,
            maximum: None,
        }]),
        excluded_subtrees: None,
    };
    let root = build_p256(root_profile("CN=Root,O=TPT,C=US", Some(nc)), &root_key, 1);

    // Leaf SAN is outside the permitted DNS tree.
    let leaf = build_p256(
        leaf_profile(
            "CN=leaf.evil.com,O=TPT,C=US",
            "CN=Root,O=TPT,C=US",
            vec![ObjectIdentifier::new_unwrap(SERVER_AUTH)],
            "leaf.evil.com",
        ),
        &leaf_key,
        2,
        valid_now(),
    );

    let anchor = TrustAnchor::from_cert(&root).unwrap();
    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        required_eku: Some(ObjectIdentifier::new_unwrap(SERVER_AUTH)),
        ..Default::default()
    };
    let validator = PathValidator::new(config);
    assert!(validator.validate(&leaf).is_err());
}

#[test]
fn name_constraint_satisfied_is_accepted() {
    let root_key = signer(1);
    let leaf_key = signer(2);
    let nc = NameConstraints {
        permitted_subtrees: Some(vec![GeneralSubtree {
            base: dns("example.com"),
            minimum: 0,
            maximum: None,
        }]),
        excluded_subtrees: None,
    };
    let root = build_p256(root_profile("CN=Root,O=TPT,C=US", Some(nc)), &root_key, 1);

    let leaf = build_p256(
        leaf_profile(
            "CN=leaf.example.com,O=TPT,C=US",
            "CN=Root,O=TPT,C=US",
            vec![ObjectIdentifier::new_unwrap(SERVER_AUTH)],
            "leaf.example.com",
        ),
        &leaf_key,
        2,
        valid_now(),
    );

    let anchor = TrustAnchor::from_cert(&root).unwrap();
    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        required_eku: Some(ObjectIdentifier::new_unwrap(SERVER_AUTH)),
        ..Default::default()
    };
    let validator = PathValidator::new(config);
    assert!(validator.validate(&leaf).is_ok());
}

#[test]
fn intermediate_chain_is_validated() {
    let root_key = signer(1);
    let int_key = signer(2);
    let leaf_key = signer(3);

    let root = build_p256(root_profile("CN=Root,O=TPT,C=US", None), &root_key, 1);
    let intermediate = build_p256(
        TestProfile {
            subject: name("CN=Intermediate,O=TPT,C=US"),
            issuer: name("CN=Root,O=TPT,C=US"),
            ca: true,
            path_len: None,
            key_usage: Some(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            eku: None,
            san: None,
            name_constraints: None,
        },
        &int_key,
        2,
        valid_now(),
    );
    let leaf = build_p256(
        leaf_profile(
            "CN=leaf.example.com,O=TPT,C=US",
            "CN=Intermediate,O=TPT,C=US",
            vec![ObjectIdentifier::new_unwrap(SERVER_AUTH)],
            "leaf.example.com",
        ),
        &leaf_key,
        3,
        valid_now(),
    );

    let anchor = TrustAnchor::from_cert(&root).unwrap();
    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        intermediates: vec![intermediate],
        required_eku: Some(ObjectIdentifier::new_unwrap(SERVER_AUTH)),
        ..Default::default()
    };
    let validator = PathValidator::new(config);
    let path = validator
        .validate(&leaf)
        .expect("3-cert chain should validate");
    assert_eq!(path.len(), 3);
}

