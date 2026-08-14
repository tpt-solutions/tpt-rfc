// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stateless cookie tests.

use tpt_dtls::cookie::CookieMaker;
use tpt_dtls::handshake::ClientHello;

#[test]
fn cookie_verifies_for_same_params() {
    let maker = CookieMaker::new([0x42u8; 32]);
    let ch = ClientHello {
        random: [1u8; 32],
        session_id: vec![],
        cipher_suites: vec![0x1301],
        groups: vec![29],
        sig_algs: vec![0x0807],
        key_share: vec![],
        cookie: None,
        connection_id: None,
    };
    let cookie = maker.from_hello(b"client-addr", &ch);
    // The same client (same address + random) produces a matching cookie.
    assert!(maker.verify(b"client-addr", &ch.random, &cookie));
}

#[test]
fn cookie_rejects_tampered_address() {
    let maker = CookieMaker::new([0x42u8; 32]);
    let ch = ClientHello {
        random: [1u8; 32],
        session_id: vec![],
        cipher_suites: vec![0x1301],
        groups: vec![29],
        sig_algs: vec![0x0807],
        key_share: vec![],
        cookie: None,
        connection_id: None,
    };
    let cookie = maker.from_hello(b"client-addr", &ch);
    // A different source address must not validate.
    assert!(!maker.verify(b"other-addr", &ch.random, &cookie));
}

#[test]
fn cookie_rejects_tampered_random() {
    let maker = CookieMaker::new([0x42u8; 32]);
    let mut ch = ClientHello {
        random: [1u8; 32],
        session_id: vec![],
        cipher_suites: vec![0x1301],
        groups: vec![29],
        sig_algs: vec![0x0807],
        key_share: vec![],
        cookie: None,
        connection_id: None,
    };
    let cookie = maker.from_hello(b"addr", &ch);
    ch.random = [2u8; 32];
    assert!(!maker.verify(b"addr", &ch.random, &cookie));
}
