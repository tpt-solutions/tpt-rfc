//! Round-trip tests for RFC 6960 OCSP: build a self-signed CA, issue an
//! `OCSPRequest`, have a responder sign a `BasicOCSPResponse`, and verify it
//! end-to-end with the OCSP client.

use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use p256::ecdsa::SigningKey as P256SigningKey;
use rand::rngs::OsRng;
use x509_cert::builder::profile::cabf;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfo;
use x509_cert::time::Validity;

use tpt_ocsp::{
    build_request, decode_request, CertId, CertStatusProvider, CertStatusValue, HashAlgorithm,
    OcspClient, OcspResponder, ProvidedStatus, RequestOptions, ResponderIdKind, SigningKey,
};

/// A trivial provider that always returns the configured status.
#[derive(Clone)]
struct FixedProvider(ProvidedStatus);

impl CertStatusProvider for FixedProvider {
    fn status(&self, _cert_id: &CertId) -> tpt_ocsp::OcspResult<ProvidedStatus> {
        Ok(self.0.clone())
    }
}

/// Build a self-signed P-256 CA certificate, returning its DER and the matching
/// `SigningKey`.
fn make_p256_ca() -> (Vec<u8>, SigningKey) {
    let signer = P256SigningKey::random(&mut OsRng);
    let subject = Name::from_str("C=US,O=TPT-Solutions,CN=Test OCSP CA").unwrap();
    let profile = cabf::Root::new(false, subject).unwrap();
    let spki = SubjectPublicKeyInfo::from_key(signer.verifying_key());
    let serial = SerialNumber::from(1u32);
    let validity = Validity::from_now(Duration::new(3600, 0)).unwrap();
    let mut builder = CertificateBuilder::new(profile, serial, validity, spki).unwrap();
    let cert = builder
        .build::<_, p256::ecdsa::Signature>(&signer)
        .unwrap();
    let cert_der = cert.to_der().unwrap();
    (cert_der, SigningKey::EcdsaP256(signer))
}

/// Build a self-signed RSA CA certificate, returning its DER and the matching
/// `SigningKey`.
fn make_rsa_ca() -> (Vec<u8>, SigningKey) {
    let rsa_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let rsa_signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key.clone());
    let subject = Name::from_str("C=US,O=TPT-Solutions,CN=Test OCSP RSA CA").unwrap();
    let profile = cabf::Root::new(false, subject).unwrap();
    let spki = SubjectPublicKeyInfo::from_key(rsa_signer.verifying_key());
    let serial = SerialNumber::from(7u32);
    let validity = Validity::from_now(Duration::new(3600, 0)).unwrap();
    let mut builder = CertificateBuilder::new(profile, serial, validity, spki).unwrap();
    let cert = builder
        .build::<_, rsa::pkcs1v15::Signature>(&rsa_signer)
        .unwrap();
    let cert_der = cert.to_der().unwrap();
    (cert_der, SigningKey::Rsa(rsa_key))
}

/// Build a `CertId` for an arbitrary serial issued by `issuer_cert_der`.
fn cert_id_for(issuer_cert_der: &[u8], serial: u32) -> CertId {
    let serial_bytes = serial.to_be_bytes().to_vec();
    CertId::from_issuer_and_serial(HashAlgorithm::Sha256, issuer_cert_der, &serial_bytes).unwrap()
}

#[test]
fn request_round_trip() {
    let (ca_der, _) = make_p256_ca();
    let cert_id = cert_id_for(&ca_der, 1234);
    let opts = RequestOptions {
        nonce: Some(vec![0x10, 0x20, 0x30, 0x40]),
    };
    let req_der = build_request(&cert_id, &opts).unwrap();
    let decoded = decode_request(&req_der).unwrap();
    assert_eq!(decoded.cert_id, cert_id);
    assert_eq!(decoded.nonce, opts.nonce);
    // Without a nonce.
    let req_der2 = build_request(&cert_id, &RequestOptions::default()).unwrap();
    let decoded2 = decode_request(&req_der2).unwrap();
    assert_eq!(decoded2.cert_id, cert_id);
    assert!(decoded2.nonce.is_none());
}

fn run_responder_scenario(
    ca_der: &[u8],
    signer: &SigningKey,
    responder_id: ResponderIdKind,
    status: ProvidedStatus,
    expected: CertStatusValue,
    use_nonce: bool,
) {
    let cert_id = cert_id_for(ca_der, 1234);
    let nonce = if use_nonce {
        Some(vec![0xAA, 0xBB, 0xCC, 0xDD])
    } else {
        None
    };
    let opts = RequestOptions {
        nonce: nonce.clone(),
    };
    let req_der = build_request(&cert_id, &opts).unwrap();

    let responder =
        OcspResponder::new(ca_der, signer.clone(), HashAlgorithm::Sha256, responder_id).unwrap();
    let provider = FixedProvider(status);
    let resp_der = responder.respond(&provider, &req_der).unwrap();

    let mut client = OcspClient::new();
    client.add_trust_anchor(ca_der);
    let verified = client
        .verify_response(&resp_der, &cert_id, nonce.as_deref())
        .unwrap();
    assert_eq!(verified.status, expected);
    assert_eq!(verified.nonce, nonce);
}

#[test]
fn ecdsa_good() {
    let (ca_der, signer) = make_p256_ca();
    run_responder_scenario(
        &ca_der,
        &signer,
        ResponderIdKind::ByName,
        ProvidedStatus::Good,
        CertStatusValue::Good,
        true,
    );
}

#[test]
fn ecdsa_revoked() {
    let (ca_der, signer) = make_p256_ca();
    let revocation_time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    run_responder_scenario(
        &ca_der,
        &signer,
        ResponderIdKind::ByName,
        ProvidedStatus::Revoked {
            revocation_time,
            reason: Some(4),
        },
        CertStatusValue::Revoked {
            revocation_time,
            reason: Some(4),
        },
        true,
    );
}

#[test]
fn ecdsa_unknown() {
    let (ca_der, signer) = make_p256_ca();
    run_responder_scenario(
        &ca_der,
        &signer,
        ResponderIdKind::ByName,
        ProvidedStatus::Unknown,
        CertStatusValue::Unknown,
        false,
    );
}

#[test]
fn rsa_good() {
    let (ca_der, signer) = make_rsa_ca();
    run_responder_scenario(
        &ca_der,
        &signer,
        ResponderIdKind::ByName,
        ProvidedStatus::Good,
        CertStatusValue::Good,
        true,
    );
}

#[test]
fn ecdsa_bykey_responder_id() {
    let (ca_der, signer) = make_p256_ca();
    run_responder_scenario(
        &ca_der,
        &signer,
        ResponderIdKind::ByKey,
        ProvidedStatus::Good,
        CertStatusValue::Good,
        true,
    );
}

#[test]
fn wrong_nonce_is_rejected() {
    let (ca_der, signer) = make_p256_ca();
    let cert_id = cert_id_for(&ca_der, 1234);
    let opts = RequestOptions {
        nonce: Some(vec![1, 2, 3, 4]),
    };
    let req_der = build_request(&cert_id, &opts).unwrap();
    let responder = OcspResponder::new(
        &ca_der,
        signer,
        HashAlgorithm::Sha256,
        ResponderIdKind::ByName,
    )
    .unwrap();
    let resp_der = responder
        .respond(&FixedProvider(ProvidedStatus::Good), &req_der)
        .unwrap();

    let mut client = OcspClient::new();
    client.add_trust_anchor(&ca_der);
    // Supply a different nonce -> must be rejected.
    let result = client.verify_response(&resp_der, &cert_id, Some(&[9, 9, 9, 9]));
    assert!(result.is_err());
}

#[test]
fn untrusted_responder_is_rejected() {
    let (ca_der, signer) = make_p256_ca();
    let cert_id = cert_id_for(&ca_der, 1234);
    let opts = RequestOptions {
        nonce: Some(vec![1, 2, 3, 4]),
    };
    let req_der = build_request(&cert_id, &opts).unwrap();
    let responder = OcspResponder::new(
        &ca_der,
        signer,
        HashAlgorithm::Sha256,
        ResponderIdKind::ByName,
    )
    .unwrap();
    let resp_der = responder
        .respond(&FixedProvider(ProvidedStatus::Good), &req_der)
        .unwrap();

    // Client with NO trust anchors.
    let client = OcspClient::new();
    let result = client.verify_response(&resp_der, &cert_id, Some(&[1, 2, 3, 4]));
    assert!(result.is_err());
}
