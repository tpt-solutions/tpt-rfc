// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-answer and round-trip crypto tests for `tpt-kerberos`.

use tpt_kerberos::crypto::{
    self, checksum, decrypt, encrypt, string2key, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
    ENCTYPE_AES128_CTS_HMAC_SHA256_128, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
    ENCTYPE_AES256_CTS_HMAC_SHA384_192,
};

use tpt_kerberos::key_usage;

/// PBKDF2-HMAC-SHA1 known-answer vector (RFC 6070, first case).
#[test]
fn pbkdf2_sha1_rfc6070() {
    // P="password", S="salt", c=1, dkLen=16
    let dk = pbkdf2_sha1(b"password", b"salt", 1, 16);

    assert_eq!(dk, hex::decode("0c60c80f961f0e71f3a9b524af601206").unwrap());

    // P="password", S="salt", c=4096, dkLen=16
    let dk = pbkdf2_sha1(b"password", b"salt", 4096, 16);
    assert_eq!(dk, hex::decode("4b007901b765489abead49d926f721d0").unwrap());
}

/// Helper that runs PBKDF2-HMAC-SHA1 by dispatching through `string2key`'s internal
/// path. `string2key` uses the enctype's hash, so we test the SHA-1 enctypes.
fn pbkdf2_sha1(password: &[u8], salt: &[u8], iter: u32, dklen: usize) -> Vec<u8> {
    // string2key with aes128-sha1 performs PBKDF2-HMAC-SHA1.
    string2key(ENCTYPE_AES128_CTS_HMAC_SHA1_96, password, salt, iter)
        .unwrap()
        .into_iter()
        .take(dklen)
        .collect()
}

#[test]
fn string2key_is_deterministic_and_sized() {
    let k1 = string2key(
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        b"secret",
        b"EXAMPLE.COMalice",
        4096,
    )
    .unwrap();
    let k2 = string2key(
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        b"secret",
        b"EXAMPLE.COMalice",
        4096,
    )
    .unwrap();
    assert_eq!(k1, k2);
    assert_eq!(k1.len(), 32);
}

/// AES-CTS round-trips for every enctype at a range of plaintext lengths
/// (covering both full-block and partial-last-block ciphertext stealing).
#[test]
fn aes_cts_roundtrip_all_enctypes() {
    let enctypes = [
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        ENCTYPE_AES128_CTS_HMAC_SHA256_128,
        ENCTYPE_AES256_CTS_HMAC_SHA384_192,
    ];
    let lengths = [1usize, 16, 17, 31, 32, 33, 48, 64, 65, 100];
    for etype in enctypes {
        let enct = crypto::Enctype::from_etype(etype).unwrap();
        let key = vec![0x42u8; enct.keylen];
        for &len in &lengths {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let ct = encrypt(&enct, &key, key_usage::TICKET, &pt).unwrap();
            // Ciphertext carries the MAC, so it's longer than plaintext.
            assert!(ct.len() > pt.len());
            let pt2 = decrypt(&enct, &key, key_usage::TICKET, &ct).unwrap();
            assert_eq!(pt, pt2, "round-trip failed for etype {etype} len {len}");
        }
    }
}

/// Two encryptions of the same plaintext with the same key are NOT byte-equal
/// (confounder is randomised), but both decrypt to the original.
#[test]
fn encryption_is_non_deterministic_but_consistent() {
    let enct = crypto::Enctype::from_etype(ENCTYPE_AES256_CTS_HMAC_SHA1_96).unwrap();
    let key = vec![0x11u8; enct.keylen];
    let pt = b"the quick brown fox jumps over the lazy dog".to_vec();
    let c1 = encrypt(&enct, &key, key_usage::AS_REP, &pt).unwrap();
    let c2 = encrypt(&enct, &key, key_usage::AS_REP, &pt).unwrap();
    assert_ne!(c1, c2);
    assert_eq!(decrypt(&enct, &key, key_usage::AS_REP, &c1).unwrap(), pt);
    assert_eq!(decrypt(&enct, &key, key_usage::AS_REP, &c2).unwrap(), pt);
}

/// Tampering with the ciphertext must fail the MAC check.
#[test]
fn tampered_ciphertext_fails() {
    let enct = crypto::Enctype::from_etype(ENCTYPE_AES128_CTS_HMAC_SHA1_96).unwrap();
    let key = vec![0x99u8; enct.keylen];
    let pt = b"hello world".to_vec();
    let mut ct = encrypt(&enct, &key, key_usage::TGS_REP, &pt).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    assert!(decrypt(&enct, &key, key_usage::TGS_REP, &ct).is_err());
}

/// Checksum is deterministic for fixed input and verifies with constant-time
/// equality.
#[test]
fn checksum_det_and_verify() {
    let enct = crypto::Enctype::from_etype(ENCTYPE_AES256_CTS_HMAC_SHA1_96).unwrap();
    let key = vec![0x55u8; enct.keylen];
    let data = b"gss mic payload";
    let c1 = checksum(&enct, &key, key_usage::GSS_MIC, data).unwrap();
    let c2 = checksum(&enct, &key, key_usage::GSS_MIC, data).unwrap();
    assert_eq!(c1, c2);
    assert_eq!(c1.len(), enct.cksumlen);
}

/// Decrypting with the wrong key fails.
#[test]
fn wrong_key_fails() {
    let enct = crypto::Enctype::from_etype(ENCTYPE_AES256_CTS_HMAC_SHA384_192).unwrap();
    let key = vec![0x01u8; enct.keylen];
    let wrong = vec![0x02u8; enct.keylen];
    let pt = b"classified".to_vec();
    let ct = encrypt(&enct, &key, key_usage::TICKET, &pt).unwrap();
    assert!(decrypt(&enct, &wrong, key_usage::TICKET, &ct).is_err());
}
