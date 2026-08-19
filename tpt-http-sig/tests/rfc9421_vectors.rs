// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Official RFC 9421 Appendix B test vectors.
//!
//! These validate signature-base construction and verification against the
//! published examples (test-request / test-response messages and the
//! test-key-* keys). RSA-PSS and ECDSA signatures are randomized, so those
//! cases assert that the *provided* signature verifies (which proves the
//! signature base matches the RFC). HMAC and Ed25519 are deterministic, so
//! those cases additionally assert that the locally produced signature byte
//! sequence equals the published one.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tpt_http_sig::{
    Algorithm, ComponentId, HttpMessage, Message, SigningKey, SfParam, Verifier, VerifyingKey,
    build_signature_base,
};

fn request_message() -> Message {
    Message::request("POST", "/foo?param=Value&Pet=dog")
        .header("host", "example.com")
        .header("date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .header("content-type", "application/json")
        .header(
            "content-digest",
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        )
        .header("content-length", "18")
}

fn response_message() -> Message {
    Message::response(200)
        .header("date", "Tue, 20 Apr 2021 02:07:56 GMT")
        .header("content-type", "application/json")
        .header(
            "content-digest",
            "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
        )
        .header("content-length", "23")
}

fn comps(items: &[&str]) -> Vec<ComponentId> {
    items
        .iter()
        .map(|s| ComponentId::parse(s).expect("valid component id"))
        .collect()
}

fn shared_secret() -> Vec<u8> {
    let b64 = std::fs::read_to_string("tests/data/test-shared-secret.txt").unwrap();
    STANDARD.decode(b64.trim()).unwrap()
}

// ---------------------------------------------------------------------------
// B.2.1 — Minimal Signature Using rsa-pss-sha512 (empty covered components)
// ---------------------------------------------------------------------------

#[test]
fn b21_rsa_pss_minimal_verifies() {
    let msg = request_message();
    let key = VerifyingKey::from_pem(
        Algorithm::RsaPssSha512,
        &std::fs::read_to_string("tests/data/test-key-rsa-pss.public.pem").unwrap(),
    )
    .unwrap();
    let input = "();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"";
    let sig = "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem\
LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG\
52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx\
2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6\
UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3\
+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==";
    let sig = sig.replace('\\', "").replace('\n', "");
    let sig = STANDARD.decode(sig).unwrap();
    Verifier::new().verify(&msg, input, &sig, &key).unwrap();
}

// ---------------------------------------------------------------------------
// B.2.2 — Selective Covered Components Using rsa-pss-sha512
// ---------------------------------------------------------------------------

#[test]
fn b22_rsa_pss_selective_verifies() {
    let msg = request_message();
    let key = VerifyingKey::from_pem(
        Algorithm::RsaPssSha512,
        &std::fs::read_to_string("tests/data/test-key-rsa-pss.public.pem").unwrap(),
    )
    .unwrap();
    let input = "(\"@authority\" \"content-digest\" \"@query-param\";name=\"Pet\")\
;created=1618884473;keyid=\"test-key-rsa-pss\";tag=\"header-example\"";
    let sig = "LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ\
EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT\
8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA\
RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd\
4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK\
UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==";
    let sig = sig.replace('\\', "").replace('\n', "");
    let sig = STANDARD.decode(sig).unwrap();
    Verifier::new().verify(&msg, input, &sig, &key).unwrap();
}

// ---------------------------------------------------------------------------
// B.2.3 — Full Coverage Using rsa-pss-sha512
// ---------------------------------------------------------------------------

#[test]
fn b23_rsa_pss_full_verifies() {
    let msg = request_message();
    let key = VerifyingKey::from_pem(
        Algorithm::RsaPssSha512,
        &std::fs::read_to_string("tests/data/test-key-rsa-pss.public.pem").unwrap(),
    )
    .unwrap();
    let input = "(\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \
\"content-type\" \"content-digest\" \"content-length\")\
;created=1618884473;keyid=\"test-key-rsa-pss\"";
    let sig = "bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB\
iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU\
xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1\
pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9\
bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z\
JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==";
    let sig = sig.replace('\\', "").replace('\n', "");
    let sig = STANDARD.decode(sig).unwrap();
    Verifier::new().verify(&msg, input, &sig, &key).unwrap();
}

// ---------------------------------------------------------------------------
// B.2.4 — Signing a Response Using ecdsa-p256-sha256
// ---------------------------------------------------------------------------

#[test]
fn b24_ecdsa_p256_response_verifies() {
    let msg = response_message();
    let key = VerifyingKey::from_pem(
        Algorithm::EcdsaP256Sha256,
        &std::fs::read_to_string("tests/data/test-key-ecc-p256.public.pem").unwrap(),
    )
    .unwrap();
    let input = "(\"@status\" \"content-type\" \"content-digest\" \
\"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"";
    let sig = "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK\
ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==";
    let sig = sig.replace('\\', "").replace('\n', "");
    let sig = STANDARD.decode(sig).unwrap();
    Verifier::new().verify(&msg, input, &sig, &key).unwrap();
}

// ---------------------------------------------------------------------------
// B.2.5 — Signing a Request Using hmac-sha256 (deterministic)
// ---------------------------------------------------------------------------

#[test]
fn b25_hmac_sha256_verifies() {
    let msg = request_message();
    let secret = shared_secret();
    let key = VerifyingKey::hmac(secret.clone());
    let input = "(\"date\" \"@authority\" \"content-type\")\
;created=1618884473;keyid=\"test-shared-secret\"";
    let sig = "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=";
    let sig = STANDARD.decode(sig).unwrap();
    Verifier::new().verify(&msg, input, &sig, &key).unwrap();
}

#[test]
fn b25_hmac_sha256_exact_signature() {
    let msg = request_message();
    let secret = shared_secret();
    let key = SigningKey::hmac(secret);
    let components = comps(&["date", "@authority", "content-type"]);
    let params = vec![
        ("created".into(), SfParam::Int(1618884473)),
        ("keyid".into(), SfParam::Str("test-shared-secret".into())),
    ];
    let base = build_signature_base(&components, &params, &msg, None).unwrap();
    let sig = key.sign(base.as_bytes()).unwrap();
    assert_eq!(
        STANDARD.encode(&sig),
        "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="
    );
}

// ---------------------------------------------------------------------------
// B.2.6 — Signing a Request Using ed25519 (deterministic)
// ---------------------------------------------------------------------------

#[test]
fn b26_ed25519_verifies() {
    let msg = request_message();
    let key = VerifyingKey::from_pem(
        Algorithm::Ed25519,
        &std::fs::read_to_string("tests/data/test-key-ed25519.public.pem").unwrap(),
    )
    .unwrap();
    let input = "(\"date\" \"@method\" \"@path\" \"@authority\" \
\"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
    let sig = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1\
u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
    let sig = sig.replace('\\', "").replace('\n', "");
    let sig = STANDARD.decode(sig).unwrap();
    Verifier::new().verify(&msg, input, &sig, &key).unwrap();
}

#[test]
fn b26_ed25519_exact_signature() {
    let msg = request_message();
    let key = SigningKey::from_pem(
        Algorithm::Ed25519,
        &std::fs::read_to_string("tests/data/test-key-ed25519.private.pem").unwrap(),
    )
    .unwrap();
    let components = comps(&[
        "date",
        "@method",
        "@path",
        "@authority",
        "content-type",
        "content-length",
    ]);
    let params = vec![
        ("created".into(), SfParam::Int(1618884473)),
        ("keyid".into(), SfParam::Str("test-key-ed25519".into())),
    ];
    let base = build_signature_base(&components, &params, &msg, None).unwrap();
    let sig = key.sign(base.as_bytes()).unwrap();
    assert_eq!(
        STANDARD.encode(&sig),
        "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
    );
}

// ---------------------------------------------------------------------------
// Sign + verify round trips (covers the signing paths end-to-end).
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_rsa_pss_sign_verify() {
    let msg = request_message();
    let key = SigningKey::from_pem(
        Algorithm::RsaPssSha512,
        &std::fs::read_to_string("tests/data/test-key-rsa-pss.private.pem").unwrap(),
    )
    .unwrap();
    let pubkey = VerifyingKey::from_pem(
        Algorithm::RsaPssSha512,
        &std::fs::read_to_string("tests/data/test-key-rsa-pss.public.pem").unwrap(),
    )
    .unwrap();
    let components = comps(&["date", "@authority", "content-type"]);
    let out = tpt_http_sig::Signer::new(Algorithm::RsaPssSha512, &key)
        .label("sig1")
        .created(1618884473)
        .sign(&msg, &components)
        .unwrap();
    // The produced input value includes the `alg` parameter; strip it to the
    // form the verifier expects (verifier ignores alg, but the round trip
    // must still verify with the *produced* input value).
    let input = out.input_value.clone();
    Verifier::new()
        .verify(&msg, &input, &out.signature, &pubkey)
        .unwrap();
}

#[test]
fn roundtrip_ecdsa_p256_sign_verify() {
    let msg = response_message();
    let key = SigningKey::from_pem(
        Algorithm::EcdsaP256Sha256,
        &std::fs::read_to_string("tests/data/test-key-ecc-p256.private.pem").unwrap(),
    )
    .unwrap();
    let pubkey = VerifyingKey::from_pem(
        Algorithm::EcdsaP256Sha256,
        &std::fs::read_to_string("tests/data/test-key-ecc-p256.public.pem").unwrap(),
    )
    .unwrap();
    let components = comps(&["@status", "content-type", "content-digest", "content-length"]);
    let out = tpt_http_sig::Signer::new(Algorithm::EcdsaP256Sha256, &key)
        .label("sig1")
        .created(1618884473)
        .sign(&msg, &components)
        .unwrap();
    Verifier::new()
        .verify(&msg, &out.input_value, &out.signature, &pubkey)
        .unwrap();
}

#[test]
fn roundtrip_hmac_sign_verify() {
    let msg = request_message();
    let secret = shared_secret();
    let key = SigningKey::hmac(secret.clone());
    let pubkey = VerifyingKey::hmac(secret);
    let components = comps(&["date", "@authority", "content-type"]);
    let out = tpt_http_sig::Signer::new(Algorithm::HmacSha256, &key)
        .label("sig1")
        .created(1618884473)
        .sign(&msg, &components)
        .unwrap();
    Verifier::new()
        .verify(&msg, &out.input_value, &out.signature, &pubkey)
        .unwrap();
}

#[test]
fn roundtrip_ed25519_sign_verify() {
    let msg = request_message();
    let key = SigningKey::from_pem(
        Algorithm::Ed25519,
        &std::fs::read_to_string("tests/data/test-key-ed25519.private.pem").unwrap(),
    )
    .unwrap();
    let pubkey = VerifyingKey::from_pem(
        Algorithm::Ed25519,
        &std::fs::read_to_string("tests/data/test-key-ed25519.public.pem").unwrap(),
    )
    .unwrap();
    let components = comps(&["date", "@authority", "content-type"]);
    let out = tpt_http_sig::Signer::new(Algorithm::Ed25519, &key)
        .label("sig1")
        .created(1618884473)
        .sign(&msg, &components)
        .unwrap();
    Verifier::new()
        .verify(&msg, &out.input_value, &out.signature, &pubkey)
        .unwrap();
}
