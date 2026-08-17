// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Official RFC 8032 Appendix A test vectors for Ed25519, Ed25519ctx and
//! Ed25519ph. These are authoritative known-answer tests: a correct
//! implementation must reproduce every signature exactly.

use tpt_ed25519::{Signature, SigningKey, VerifyingKey};

fn h(x: &str) -> Vec<u8> {
    hex::decode(x).expect("valid hex fixture")
}

#[test]
fn rfc8032_ed25519_empty() {
    let sk = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sig = h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    assert_eq!(sk.verifying_key().to_bytes(), vk.to_bytes());
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign(b"").as_bytes(), sig.as_bytes());
    assert!(vk.verify(b"", &sig).is_ok());
}

#[test]
fn rfc8032_ed25519_one_byte() {
    let sk = h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb6a6fb");
    let pk = h("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let sig = h("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("72");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign(&msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify(&msg, &sig).is_ok());
}

#[test]
fn rfc8032_ed25519_two_bytes() {
    let sk = h("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let pk = h("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let sig = h("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("af82");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign(&msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify(&msg, &sig).is_ok());
}

#[test]
fn rfc8032_ed25519_1023_bytes() {
    let sk = h("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
    let pk = h("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
    let sig = h("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h(include_str!("msg1023.hex").trim());
    assert_eq!(msg.len(), 1023);
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign(&msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify(&msg, &sig).is_ok());
}

#[test]
fn rfc8032_ed25519_sha256_abc() {
    // Message is SHA-256("abc") per the RFC vector.
    let sk = h("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    let pk = h("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let sig = h("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign(&msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify(&msg, &sig).is_ok());
}

#[test]
fn rfc8032_ed25519ctx_foo() {
    let sk = h("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6");
    let pk = h("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292");
    let sig = h("55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("f726936d19c800494e3fdaff20b276a8");
    let ctx = h("666f6f");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign_ctx(&ctx, &msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify_ctx(&ctx, &msg, &sig).is_ok());
    // The same bytes under pure Ed25519 must NOT verify (different dom2).
    assert!(vk.verify(&msg, &sig).is_err());
}

#[test]
fn rfc8032_ed25519ctx_bar() {
    let sk = h("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6");
    let pk = h("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292");
    let sig = h("fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("f726936d19c800494e3fdaff20b276a8");
    let ctx = h("626172");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign_ctx(&ctx, &msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify_ctx(&ctx, &msg, &sig).is_ok());
}

#[test]
fn rfc8032_ed25519ctx_foo2() {
    let sk = h("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6");
    let pk = h("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292");
    let sig = h("8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc64908922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("508e9e6882b979fea900f62adceaca35");
    let ctx = h("666f6f");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign_ctx(&ctx, &msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify_ctx(&ctx, &msg, &sig).is_ok());
}

#[test]
fn rfc8032_ed25519ctx_foo3() {
    let sk = h("ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560");
    let pk = h("0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772");
    let sig = h("21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("f726936d19c800494e3fdaff20b276a8");
    let ctx = h("666f6f");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign_ctx(&ctx, &msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify_ctx(&ctx, &msg, &sig).is_ok());
}

#[test]
fn rfc8032_ed25519ph_abc() {
    let sk = h("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    let pk = h("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let sig = h("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406");
    let sk = SigningKey::from_bytes(sk.as_slice().try_into().unwrap());
    let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap());
    let msg = h("616263");
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    assert_eq!(sk.sign_ph(&msg).as_bytes(), sig.as_bytes());
    assert!(vk.verify_ph(&msg, &sig).is_ok());
    // Pre-hashed message under pure Ed25519 must NOT verify.
    assert!(vk.verify(&msg, &sig).is_err());
}
