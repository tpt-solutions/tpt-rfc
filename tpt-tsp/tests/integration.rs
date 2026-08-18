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
use sha2::{Digest, Sha256, Sha384};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Version;
use x509_cert::{Certificate, TbsCertificate};

use p256::ecdsa::signature::hazmat::PrehashSigner as P256Prehash;
use p384::ecdsa::signature::hazmat::PrehashSigner as P384Prehash;
use rsa::pkcs8::EncodePublicKey;

use tpt_tsp::crypto::{HashAlgorithm, SigningKey};
use tpt_tsp::oids;
use tpt_tsp::parse_timestamp_req;
use tpt_tsp::response::{TimestampAuthority, TimestampResponse};
use tpt_tsp::token::{TstInfo, TsaPolicyId};
use tpt_tsp::{TimestampRequest, DEFAULT_POLICY};

// --- self-signed cert generation ------------------------------------------

fn spki_ed25519(pk: &ed25519_compact::PublicKey) -> spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> {
    spki::SubjectPublicKeyInfo {
        algorithm: spki::AlgorithmIdentifier {
            oid: ObjectIdentifier::new_unwrap(oids::ED25519),
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(pk.as_slice()).unwrap(),
    }
}

fn spki_rsa(pk: &rsa::RsaPublicKey) -> spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> {
    let doc = pk.to_public_key_der().unwrap();
    spki::SubjectPublicKeyInfo::from_der(doc.as_bytes()).unwrap()
}

fn spki_p256(pk: &p256::ecdsa::VerifyingKey) -> spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let ec = ObjectIdentifier::new_unwrap(oids::EC_PUBLIC_KEY);
    let curve = ObjectIdentifier::new_unwrap(oids::P256);
    let params = der::Any::from_der(&curve.to_der().unwrap()).unwrap();
    let point = pk.to_affine().to_encoded_point(false);
    spki::SubjectPublicKeyInfo {
        algorithm: spki::AlgorithmIdentifier { oid: ec, parameters: Some(params) },
        subject_public_key: BitString::from_bytes(point.as_bytes()).unwrap(),
    }
}

fn spki_p384(pk: &p384::ecdsa::VerifyingKey) -> spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    let ec = ObjectIdentifier::new_unwrap(oids::EC_PUBLIC_KEY);
    let curve = ObjectIdentifier::new_unwrap(oids::P384);
    let params = der::Any::from_der(&curve.to_der().unwrap()).unwrap();
    let point = pk.to_affine().to_encoded_point(false);
    spki::SubjectPublicKeyInfo {
        algorithm: spki::AlgorithmIdentifier { oid: ec, parameters: Some(params) },
        subject_public_key: BitString::from_bytes(point.as_bytes()).unwrap(),
    }
}

fn build_cert(key: &SigningKey) -> Certificate {
    let spki = match key {
        SigningKey::Ed25519(sk) => spki_ed25519(&sk.public_key()),
        SigningKey::Rsa(rk) => spki_rsa(&rk.to_public_key()),
        SigningKey::EcdsaP256(sk) => spki_p256(&sk.verifying_key()),
        SigningKey::EcdsaP384(sk) => spki_p384(&sk.verifying_key()),
    };
    let sig_oid = match key {
        SigningKey::Ed25519(_) => ObjectIdentifier::new_unwrap(oids::ED25519),
        SigningKey::Rsa(_) => ObjectIdentifier::new_unwrap(oids::SHA256_RSA),
        SigningKey::EcdsaP256(_) => ObjectIdentifier::new_unwrap(oids::ECDSA_SHA256),
        SigningKey::EcdsaP384(_) => ObjectIdentifier::new_unwrap(oids::ECDSA_SHA384),
    };

    let name: Name = "CN=tpt-tsp Test TSA".parse().unwrap();
    let validity = Validity::from_now(std::time::Duration::new(3600 * 24 * 365, 0)).unwrap();

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(1u8),
        signature: spki::AlgorithmIdentifier { oid: sig_oid.clone(), parameters: None },
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        extensions: None,
        issuer_unique_id: None,
        subject_unique_id: None,
    };
    let tbs_der = tbs.to_der().unwrap();

    let sig = match key {
        SigningKey::Ed25519(sk) => sk.sign(&tbs_der, None).to_vec(),
        SigningKey::Rsa(rk) => {
            use rsa::pkcs1v15::Pkcs1v15Sign;
            use sha2_010::{Digest as _, Sha256};
            rk.sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&tbs_der)).unwrap()
        }
        SigningKey::EcdsaP256(sk) => {
            sk.sign_prehash(&Sha256::digest(&tbs_der)).unwrap().to_vec()
        }
        SigningKey::EcdsaP384(sk) => {
            sk.sign_prehash(&Sha384::digest(&tbs_der)).unwrap().to_vec()
        }
    };

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: spki::AlgorithmIdentifier { oid: sig_oid, parameters: None },
        signature: BitString::from_bytes(&sig).unwrap(),
    };
    // Round-trip through DER so the stored structures are canonical.
    Certificate::from_der(&cert.to_der().unwrap()).unwrap()
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

#[test]
fn round_trip_p256() {
    round_trip(SigningKey::demo_p256([11u8; 32]));
}

#[test]
fn round_trip_p384() {
    round_trip(SigningKey::demo_p384([13u8; 48]));
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
