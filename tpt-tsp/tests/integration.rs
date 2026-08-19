//! Integration tests for `tpt-tsp`: client request build/parse, TSA responder,
//! token round-trip, and client-side verification with trust-anchor chaining.
//!
//! A self-signed TSA certificate is generated in-process for each supported key
//! type (no external TSA or network required). This mirrors the in-crate
//! client↔server harness pattern used elsewhere in the `tpt-rfc` workspace
//! (interop against a real public TSA is left as a `#[ignore]`d live test).

use const_oid::ObjectIdentifier;
use der::asn1::BitString;
use der::{Decode, Encode};
use x509_cert::Certificate;

use rsa::pkcs8::EncodePublicKey;
use tpt_tsp::crypto::{HashAlgorithm, SigningKey};
use tpt_tsp::oids;
use tpt_tsp::parse_timestamp_req;
use tpt_tsp::response::{TimestampAuthority, TimestampResponse};
use tpt_tsp::token::{TstInfo, TsaPolicyId};
use tpt_tsp::{TimestampRequest, DEFAULT_POLICY};

// --- self-signed cert generation ------------------------------------------


fn spki_rsa(pk: &rsa::RsaPublicKey) -> spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> {
    let doc = pk.to_public_key_der().unwrap();
    spki::SubjectPublicKeyInfo::from_der(doc.as_bytes()).unwrap()
}

// Local minimal DER helpers (x509-cert 0.3 hides TbsCertificate/Certificate
// struct fields behind its builder, so we assemble the cert DER by hand).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    use der::Encode;
    let mut out = vec![tag];
    out.extend_from_slice(&der::Length::try_from(content.len()).unwrap().to_der().unwrap());
    out.extend_from_slice(content);
    out
}
fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flatten().cloned().collect();
    tlv(0x30, &content)
}
fn der_set(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    let content: Vec<u8> = sorted.iter().flatten().cloned().collect();
    tlv(0x31, &content)
}
fn der_int(v: u64) -> Vec<u8> {
    let mut b = v.to_be_bytes().to_vec();
    while b.len() > 1 && b[0] == 0 {
        b.remove(0);
    }
    if let Some(&f) = b.first() {
        if f & 0x80 != 0 {
            b.insert(0, 0);
        }
    }
    tlv(0x02, &b)
}
fn der_oid(oid: &str) -> Vec<u8> {
    ObjectIdentifier::new_unwrap(oid).to_der().unwrap()
}
fn der_algid(oid: &str, params: Option<&[u8]>) -> Vec<u8> {
    let mut p = vec![der_oid(oid)];
    if let Some(prm) = params {
        p.push(prm.to_vec());
    }
    der_seq(&p)
}
fn der_bitstring(bytes: &[u8]) -> Vec<u8> {
    let mut c = vec![0x00];
    c.extend_from_slice(bytes);
    tlv(0x03, &c)
}
fn der_name(cn: &str) -> Vec<u8> {
    let atv = der_seq(&[der_oid("2.5.4.3"), tlv(0x0C, cn.as_bytes())]);
    let rdn = der_set(&[atv]);
    der_seq(&[rdn])
}
fn der_validity(not_before: &der::DateTime, not_after: &der::DateTime) -> Vec<u8> {
    let nb = der::asn1::GeneralizedTime::from(*not_before).to_der().unwrap();
    let na = der::asn1::GeneralizedTime::from(*not_after).to_der().unwrap();
    der_seq(&[nb, na])
}

fn build_cert(key: &SigningKey) -> Certificate {
    let spki_der = match key {
        SigningKey::Ed25519(sk) => {
            let spki = spki::SubjectPublicKeyInfo {
                algorithm: spki::AlgorithmIdentifierOwned {
                    oid: ObjectIdentifier::new_unwrap(oids::ED25519),
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(sk.public_key().as_slice()).unwrap(),
            };
            spki.to_der().unwrap()
        }
        SigningKey::Rsa(rk) => {
            let doc = rk.to_public_key().to_public_key_der().unwrap();
            let spki = spki::SubjectPublicKeyInfo::<der::asn1::Any, der::asn1::BitString>::from_der(doc.as_bytes()).unwrap();
            spki.to_der().unwrap()
        }
        _ => unreachable!("test harness only builds Ed25519/RSA self-signed certs"),
    };
    let (sig_oid, sig_params): (&str, Option<&[u8]>) = match key {
        SigningKey::Ed25519(_) => (oids::ED25519, None),
        SigningKey::Rsa(_) => (oids::SHA256_RSA, Some(&[0x05, 0x00])),
        _ => unreachable!(),
    };

    let now = der::DateTime::try_from(std::time::SystemTime::now()).unwrap();
    let later = der::DateTime::try_from(
        std::time::SystemTime::now() + std::time::Duration::new(3600 * 24 * 365, 0),
    )
    .unwrap();

    // TBSCertificate (version [0] EXPLICIT v3, then fields).
    let version = tlv(0xA0, &der_int(2));
    let serial = der_int(1);
    let sig_alg = der_algid(sig_oid, sig_params);
    let issuer = der_name("CN=tpt-tsp Test TSA");
    let validity = der_validity(&now, &later);
    let subject = der_name("CN=tpt-tsp Test TSA");
    let tbs = der_seq(&[version, serial, sig_alg.clone(), issuer, validity, subject, spki_der]);

    let sig = match key {
        SigningKey::Ed25519(sk) => sk.sign(&tbs, None).to_vec(),
        SigningKey::Rsa(rk) => {
            use rsa::pkcs1v15::Pkcs1v15Sign;
            use sha2_010::{Digest as _, Sha256};
            rk.sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&tbs)).unwrap()
        }
        _ => unreachable!(),
    };

    let cert = der_seq(&[tbs, der_algid(sig_oid, sig_params), der_bitstring(&sig)]);
    eprintln!("CERT DER len={} hex={:02x?}", cert.len(), &cert);
    Certificate::from_der(&cert).unwrap_or_else(|e| panic!("cert parse err {:?}\nhex={:02x?}", e, &cert))
}

// --- round-trip + verification per key type --------------------------------

fn round_trip(key: SigningKey) {
    let cert = build_cert(&key);
    let policy: TsaPolicyId = ObjectIdentifier::new_unwrap(DEFAULT_POLICY);
    let tsa = TimestampAuthority { signer: key, cert: cert.clone(), policy };

    let msg = b"the quick brown fox jumps over the lazy dog";
    let req = TimestampRequest::new(HashAlgorithm::Sha256, msg)
        .with_nonce(0xDEAD_BEEF_CAFE_BABE)
        .with_policy(policy);
    let req_der = req.to_der();

    // The responder parses its own request.
    let resp = tsa.respond(&req_der).unwrap();
    assert!(resp.is_success(), "expected granted status");
    let resp_der = resp.to_der();

    // Client parses and verifies the response, chaining to the self-signed anchor.
    let parsed = TimestampResponse::from_der(&resp_der).unwrap();
    let anchors = vec![cert.clone()];
    let tst = parsed.verify(&parse_timestamp_req(&req_der).unwrap(), &anchors).unwrap();

    // TSTInfo consistency.
    assert_eq!(tst.policy, policy);
    assert_eq!(tst.nonce, Some(0xDEAD_BEEF_CAFE_BABE));
    assert_eq!(tst.message_imprint.hash_algorithm, HashAlgorithm::Sha256);
    assert_eq!(tst.message_imprint.hashed_message, HashAlgorithm::Sha256.digest(msg));

    // Re-encoding the verified TSTInfo is stable.
    let tst2 = TstInfo::from_der(&tst.to_der()).unwrap();
    assert_eq!(tst2, tst);
}

#[test]
fn round_trip_ed25519() {
    round_trip(SigningKey::demo_ed25519([7u8; 32]));
}

#[test]
fn round_trip_rsa() {
    let mut rng = rand_core::OsRng;
    round_trip(SigningKey::demo_rsa(&mut rng));
}

// --- negative tests --------------------------------------------------------

#[test]
fn verify_fails_on_nonce_mismatch() {
    let key = SigningKey::demo_ed25519([7u8; 32]);
    let cert = build_cert(&key);
    let policy: TsaPolicyId = ObjectIdentifier::new_unwrap(DEFAULT_POLICY);
    let tsa = TimestampAuthority { signer: key, cert: cert.clone(), policy };

    let req = TimestampRequest::new(HashAlgorithm::Sha256, b"hello")
        .with_nonce(1234)
        .with_policy(policy);
    let resp = tsa.respond(&req.to_der()).unwrap();

    // Client sends a DIFFERENT nonce expectation.
    let bad_req = TimestampRequest::new(HashAlgorithm::Sha256, b"hello")
        .with_nonce(9999)
        .with_policy(policy);
    let anchors = vec![cert];
    let err = resp.verify(&bad_req, &anchors).unwrap_err();
    assert!(matches!(err, tpt_tsp::TspError::NonceMismatch));
}

#[test]
fn reject_status_is_not_success() {
    let key = SigningKey::demo_ed25519([7u8; 32]);
    let cert = build_cert(&key);
    let tsa = TimestampAuthority {
        signer: key,
        cert,
        policy: ObjectIdentifier::new_unwrap(DEFAULT_POLICY),
    };
    let resp = tsa.reject(2, Some("policy violated"));
    assert!(!resp.is_success());
    let err = resp.verify(&TimestampRequest::new(HashAlgorithm::Sha256, b"x"), &[]).unwrap_err();
    assert!(matches!(err, tpt_tsp::TspError::PkiStatus(2)));
}

#[test]
fn request_round_trips_through_der() {
    let policy: TsaPolicyId = ObjectIdentifier::new_unwrap(DEFAULT_POLICY);
    let req = TimestampRequest::new(HashAlgorithm::Sha512, b"payload")
        .with_nonce(42)
        .with_policy(policy)
        .with_cert_req(true);
    let parsed = parse_timestamp_req(&req.to_der()).unwrap();
    assert_eq!(parsed.hash_algorithm(), HashAlgorithm::Sha512);
    assert_eq!(parsed.nonce(), Some(42));
    assert_eq!(parsed.policy(), Some(&policy));
    assert!(parsed.cert_req());
    assert_eq!(parsed.hashed_message(), HashAlgorithm::Sha512.digest(b"payload"));
}
