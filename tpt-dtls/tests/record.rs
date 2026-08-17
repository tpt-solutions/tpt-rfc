// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Record-layer tests: header codec, cleartext records, protected-record
//! round-trip, and Connection-ID handling.

use tpt_dtls::crypto::CipherSuite;
use tpt_dtls::record::{
    build_cleartext, build_protected, open_protected, split_datagram, ConnectionId,
    DTLS_LEGACY_VERSION, RecordHeader, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE,
};
use tpt_dtls::wire::Writer;

#[test]
fn header_round_trip() {
    let h = RecordHeader {
        content_type: CONTENT_APPLICATION_DATA,
        version: DTLS_LEGACY_VERSION,
        epoch: 2,
        sequence: 0x0102_0304_0506,
        length: 42,
    };
    let mut w = Writer::new();
    h.encode(&mut w);
    let buf = w.into_inner();
    assert_eq!(buf.len(), 13);
    let (h2, tail) = RecordHeader::decode(&buf).unwrap();
    assert_eq!(h, h2);
    assert!(tail.is_empty());
}

#[test]
fn cleartext_record_splits() {
    let dgram = build_cleartext(CONTENT_HANDSHAKE, 0, 0, b"hello");
    let (h, body, cid) = split_datagram(&dgram, 0).unwrap();
    assert_eq!(h.epoch, 0);
    assert_eq!(h.content_type, CONTENT_HANDSHAKE);
    assert_eq!(body, b"hello");
    assert!(cid.is_none());
}

#[test]
fn protected_record_round_trip() {
    let suite = CipherSuite::TlsAes128GcmSha256;
    let key = vec![0x11u8; suite.key_len()];
    let iv = vec![0x22u8; suite.iv_len()];

    let dgram = build_protected(
        suite,
        &key,
        &iv,
        1,
        7,
        CONTENT_APPLICATION_DATA,
        CONTENT_HANDSHAKE,
        b"top secret payload",
        None,
    )
    .unwrap();

    let (header, body, _cid) = split_datagram(&dgram, 0).unwrap();
    assert_eq!(header.epoch, 1);
    assert_eq!(header.sequence, 7);
    assert_eq!(header.content_type, CONTENT_APPLICATION_DATA);

    let (inner, content) = open_protected(suite, &key, &iv, &header, &body, None).unwrap();
    assert_eq!(inner, CONTENT_HANDSHAKE);
    assert_eq!(content, b"top secret payload");
}

#[test]
fn protected_record_with_cid() {
    let suite = CipherSuite::TlsAes128GcmSha256;
    let key = vec![0x33u8; suite.key_len()];
    let iv = vec![0x44u8; suite.iv_len()];
    let cid = ConnectionId::new(vec![0xaa, 0xbb]).unwrap();

    let dgram = build_protected(
        suite,
        &key,
        &iv,
        2,
        1,
        CONTENT_APPLICATION_DATA,
        CONTENT_APPLICATION_DATA,
        b"app data",
        Some(&cid),
    )
    .unwrap();

    // The record length excludes the trailing CID.
    let (header, _body, _tail) = split_datagram(&dgram, 0).unwrap();
    assert_eq!(header.length as usize, suite.tag_len() + b"app data".len());

    // Receiver expects a 2-byte CID.
    let (header, body, got_cid) = split_datagram(&dgram, 2).unwrap();
    let (inner, content) = open_protected(suite, &key, &iv, &header, &body, got_cid.as_ref())
        .unwrap();
    assert_eq!(inner, CONTENT_APPLICATION_DATA);
    assert_eq!(content, b"app data");
    assert_eq!(got_cid.unwrap().as_bytes(), &[0xaa, 0xbb]);
}

#[test]
fn chacha_round_trip() {
    let suite = CipherSuite::TlsChacha20Poly1305Sha256;
    let key = vec![0x55u8; suite.key_len()];
    let iv = vec![0x66u8; suite.iv_len()];
    let dgram = build_protected(
        suite, &key, &iv, 1, 3, CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE,
        b"integrity", None,
    )
    .unwrap();
    let (header, body, _cid) = split_datagram(&dgram, 0).unwrap();
    let (inner, content) = open_protected(suite, &key, &iv, &header, &body, None).unwrap();
    assert_eq!(inner, CONTENT_HANDSHAKE);
    assert_eq!(content, b"integrity");
}

#[test]
fn tampered_record_fails() {
    let suite = CipherSuite::TlsChacha20Poly1305Sha256;
    let key = vec![0x55u8; suite.key_len()];
    let iv = vec![0x66u8; suite.iv_len()];
    let mut dgram = build_protected(
        suite,
        &key,
        &iv,
        1,
        0,
        CONTENT_APPLICATION_DATA,
        CONTENT_HANDSHAKE,
        b"integrity",
        None,
    )
    .unwrap();
    // Flip a byte in the ciphertext body.
    let last = dgram.len() - 1;
    dgram[last] ^= 0x01;
    let (header, body, _cid) = split_datagram(&dgram, 0).unwrap();
    assert!(open_protected(suite, &key, &iv, &header, &body, None).is_err());
}
