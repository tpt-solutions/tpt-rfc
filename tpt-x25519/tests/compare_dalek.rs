// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-validation of `tpt-x25519` against `x25519-dalek` (a reference
//! implementation) and the official RFC 7748 Appendix A test vectors.
//!
//! `x25519-dalek` is used here ONLY as a conformance oracle. It is a
//! dev-dependency and is never compiled into the published `tpt-x25519`
//! crate, which stays clean-room and dual-licensed (MIT OR Apache-2.0).

use tpt_x25519::{x25519, StaticSecret, PublicKey};

fn arr(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

#[test]
fn rfc7748_appendix_a_x25519() {
    // RFC 7748 §5.2 / Appendix A.1
    let zero = [0u8; 32];
    let base = [9u8; 32];
    let mine_zero = x25519(&zero, &base);
    let dalek_zero = x25519_dalek::x25519(zero, base);
    eprintln!("DBG zero: mine={:?}", mine_zero);
    eprintln!("DBG zero: dalek={:?}", dalek_zero);
    assert_eq!(mine_zero, dalek_zero);

    let a = arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a224f1f3d1838");
    let b = arr("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177dfa50b3285f5");
    let base = [9u8; 32];

    let a_pub = x25519(&a, &base);
    assert_eq!(
        a_pub,
        arr("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b407557dfde8")
    );
    let b_pub = x25519(&b, &base);
    assert_eq!(
        b_pub,
        arr("3eb7a8921200c08e792a7d1d6972f410e3a670a8e49d0141e1952c4b7daa3831")
    );

    // Shared secret: both orders must agree.
    let shared_ab = x25519(&a, &b_pub);
    let shared_ba = x25519(&b, &a_pub);
    let expected = arr("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(shared_ab, expected);
    assert_eq!(shared_ba, expected);
}

#[test]
fn matches_dalek() {
    let base = [9u8; 32];

    // RFC vector a must match dalek's free `x25519` function.
    let a = arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a224f1f3d1838");
    let mine = x25519(&a, &base);
    let dalek = x25519_dalek::x25519(a, base);
    assert_eq!(mine, dalek);

    for _ in 0..25 {
        let mut scalar = [0u8; 32];
        getrandom::getrandom(&mut scalar).unwrap();

        // Public keys must agree.
        let mine_pub = StaticSecret::from_bytes(scalar).public_key().to_bytes();
        let dalek_pub = x25519_dalek::x25519(scalar, base);
        assert_eq!(mine_pub, dalek_pub);

        // Shared secrets must agree in both directions.
        let mine_shared = x25519(&scalar, &dalek_pub);
        let dalek_shared = x25519_dalek::x25519(scalar, mine_pub);
        assert_eq!(mine_shared, dalek_shared);

        // Exercise the typed API end-to-end too.
        let peer = PublicKey::from_bytes(dalek_pub);
        let typed_shared = StaticSecret::from_bytes(scalar)
            .diffie_hellman(&peer)
            .unwrap();
        assert_eq!(typed_shared.to_bytes(), mine_shared);
    }
}
