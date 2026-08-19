//! Round-trip tests for RFC 6960 OCSP: build a self-signed CA, issue an
//! `OCSPRequest`, have a responder sign a `BasicOCSPResponse`, and verify it
//! end-to-end with the OCSP client.
//!
//! Test certificates are minted with `rcgen` (dev-only) because the
//! `x509-cert` 0.3 `CertificateBuilder` is built against `spki` 0.7/`der` 0.7
//! and its trait bounds cannot be satisfied by the `spki` 0.8/`der` 0.8 types
//! this crate targets. The private keys are extracted as PKCS#8 DER and wrapped
//! in the crate's `SigningKey`.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

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

/// Generate a self-signed P-256 CA certificate and matching `SigningKey`.
fn make_p256_ca() -> (Vec<u8>, SigningKey) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test OCSP CA");
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2034, 1, 1);
    let kp = KeyPair::generate().unwrap();
    let cert = params.self_signed(&kp).unwrap();
    let cert_der = cert.der().to_vec();
    let key_der = kp.serialize_der();
    let secret: p256::SecretKey = p256::pkcs8::DecodePrivateKey::from_pkcs8_der(&key_der).unwrap();
    let signer = SigningKey::EcdsaP256(secret.into());
    (cert_der, signer)
}

/// Build a `CertId` for an arbitrary serial issued by `issuer_cert_der`.
fn cert_id_for(issuer_cert_der: &[u8], serial: u32) -> CertId {
    let serial_bytes = serial.to_be_bytes().to_vec();
    CertId::from_issuer_and_serial(HashAlgorithm::Sha256, issuer_cert_der, &serial_bytes).unwrap()
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
    use std::time::{Duration, UNIX_EPOCH};
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
    let responder =
        OcspResponder::new(&ca_der, signer, HashAlgorithm::Sha256, ResponderIdKind::ByName)
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
    let responder =
        OcspResponder::new(&ca_der, signer, HashAlgorithm::Sha256, ResponderIdKind::ByName)
            .unwrap();
    let resp_der = responder
        .respond(&FixedProvider(ProvidedStatus::Good), &req_der)
        .unwrap();

    // Client with NO trust anchors.
    let client = OcspClient::new();
    let result = client.verify_response(&resp_der, &cert_id, Some(&[1, 2, 3, 4]));
    assert!(result.is_err());
}
