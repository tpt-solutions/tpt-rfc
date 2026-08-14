// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS 1.3 key-schedule tests, cross-checked against the reference `hkdf`
//! crate and validated for internal consistency.

use hkdf::Hkdf;
use sha2::Sha256;
use tpt_dtls::crypto::{CipherSuite, HashAlg};
use tpt_dtls::keyschedule::KeySchedule;

#[test]
fn expand_label_matches_reference_hkdf() {
    let ks = KeySchedule::new(HashAlg::Sha256);
    let prk = [0xabu8; 32];

    // Our ExpandLabel("derived", "", 32).
    let got = ks.expand_label(&prk, "derived", &[], 32);

    // Reference: HKDF-Expand(prk, info, 32) where
    // info = length(2) || "tls13 derived" || context.
    let h = Hkdf::<Sha256>::from_prk(&prk).unwrap();
    let mut info = Vec::new();
    info.extend_from_slice(&(32u16).to_be_bytes());
    info.extend_from_slice(b"tls13 derived");
    info.extend_from_slice(&[]);
    let mut okm = [0u8; 32];
    h.expand(&info, &mut okm).unwrap();

    assert_eq!(got, okm.to_vec());
}

#[test]
fn derive_secret_and_traffic_keys_lengths() {
    let suite = CipherSuite::TlsAes128GcmSha256;
    let ks = KeySchedule::new(suite.hash_alg());
    let prk = [0xcd_u8; 32];
    let transcript = vec![0u8; 10];

    let secret = ks.derive_secret(&prk, "c hs traffic", &transcript);
    assert_eq!(secret.len(), 32);

    let (key, iv) = ks.derive_traffic_keys(&secret, suite.key_len(), suite.iv_len());
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 12);
}

#[test]
fn sha384_key_schedule_lengths() {
    let suite = CipherSuite::TlsAes256GcmSha384;
    let ks = KeySchedule::new(suite.hash_alg());
    assert_eq!(suite.hash_alg().output_len(), 48);
    let prk = [0xee_u8; 48];
    let secret = ks.derive_secret(&prk, "s ap traffic", &vec![1u8; 5]);
    assert_eq!(secret.len(), 48);
}
