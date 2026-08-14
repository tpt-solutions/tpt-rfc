// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handshake message codec and DTLS fragmentation/reassembly tests.

use tpt_dtls::crypto::CipherSuite;
use tpt_dtls::handshake::{
    fragment_message, Certificate, CertificateVerify, ClientHello, EncryptedExtensions,
    Finished, HandshakeBody, HandshakeMessage, HandshakeType, KeyShareEntry, Reassembler,
    ServerHello, HRR_RANDOM,
};

fn sample_ch() -> ClientHello {
    ClientHello {
        random: [9u8; 32],
        session_id: vec![],
        cipher_suites: vec![CipherSuite::TlsAes128GcmSha256.code()],
        groups: vec![29],
        sig_algs: vec![0x0807],
        key_share: vec![KeyShareEntry {
            group: 29,
            key_exchange: vec![1, 2, 3, 4],
        }],
        cookie: None,
        connection_id: None,
    }
}

#[test]
fn client_hello_round_trip() {
    let msg = HandshakeMessage::new(HandshakeBody::ClientHello(sample_ch()), 0);
    let bytes = msg.encode();
    let parsed = HandshakeMessage::decode(&bytes).unwrap();
    assert_eq!(parsed.msg_type, HandshakeType::ClientHello);
    assert_eq!(parsed.message_seq, 0);
    match &parsed.body {
        HandshakeBody::ClientHello(c) => assert_eq!(c.key_share[0].key_exchange, vec![1, 2, 3, 4]),
        _ => panic!("wrong body"),
    }
}

#[test]
fn server_hello_round_trip() {
    let sh = ServerHello {
        random: [3u8; 32],
        session_id_echo: vec![],
        cipher_suite: CipherSuite::TlsAes128GcmSha256.code(),
        key_share: Some(KeyShareEntry {
            group: 29,
            key_exchange: vec![9, 8, 7, 6],
        }),
        connection_id: None,
        cookie: None,
    };
    let msg = HandshakeMessage::new(HandshakeBody::ServerHello(sh), 1);
    let parsed = HandshakeMessage::decode(&msg.encode()).unwrap();
    match &parsed.body {
        HandshakeBody::ServerHello(s) => {
            assert_eq!(s.key_share.as_ref().unwrap().key_exchange, vec![9, 8, 7, 6]);
            assert!(!s.is_hello_retry_request());
        }
        _ => panic!("wrong body"),
    }
}

#[test]
fn hrr_is_detected() {
    let hrr = ServerHello {
        random: HRR_RANDOM,
        session_id_echo: vec![],
        cipher_suite: CipherSuite::TlsAes128GcmSha256.code(),
        key_share: None,
        connection_id: None,
        cookie: Some(vec![1, 2, 3]),
    };
    assert!(hrr.is_hello_retry_request());
}

#[test]
fn certificate_and_verify_round_trip() {
    let cert = HandshakeMessage::new(
        HandshakeBody::Certificate(Certificate {
            request_context: vec![],
            cert_data: vec![0xab; 32],
        }),
        3,
    );
    let p = HandshakeMessage::decode(&cert.encode()).unwrap();
    match &p.body {
        HandshakeBody::Certificate(c) => assert_eq!(c.cert_data, vec![0xab; 32]),
        _ => panic!("wrong body"),
    }

    let cv = HandshakeMessage::new(
        HandshakeBody::CertificateVerify(CertificateVerify {
            algorithm: 0x0807,
            signature: vec![7u8; 64],
        }),
        4,
    );
    let p = HandshakeMessage::decode(&cv.encode()).unwrap();
    match &p.body {
        HandshakeBody::CertificateVerify(v) => assert_eq!(v.signature, vec![7u8; 64]),
        _ => panic!("wrong body"),
    }
}

#[test]
fn finished_round_trip() {
    let f = HandshakeMessage::new(
        HandshakeBody::Finished(Finished {
            verify_data: vec![5u8; 32],
        }),
        5,
    );
    let p = HandshakeMessage::decode(&f.encode()).unwrap();
    match &p.body {
        HandshakeBody::Finished(x) => assert_eq!(x.verify_data, vec![5u8; 32]),
        _ => panic!("wrong body"),
    }
}

#[test]
fn fragment_and_reassemble() {
    let ee = HandshakeMessage::new(HandshakeBody::EncryptedExtensions(EncryptedExtensions::default()), 2);
    let full = ee.encode();
    // Fragment into 5-byte chunks.
    let frags = fragment_message(&full, 2, 5);
    assert!(frags.len() > 1);

    // The first fragment's header carries total length and offset 0.
    let mut r = tpt_dtls::wire::Reader::new(&frags[0]);
    let _ty = r.read_u8().unwrap();
    let total = r.read_u24().unwrap();
    let _seq = r.read_u16().unwrap();
    let off = r.read_u24().unwrap();
    let len = r.read_u24().unwrap();
    assert_eq!(total as usize, full.len());
    assert_eq!(off, 0);
    assert_eq!(len as usize, (full.len()).min(5));

    // Reassemble via the Reassembler.
    let mut reass = Reassembler::new(2, total);
    for f in &frags {
        let mut rr = tpt_dtls::wire::Reader::new(f);
        let _ty = rr.read_u8().unwrap();
        let _total = rr.read_u24().unwrap();
        let _seq = rr.read_u16().unwrap();
        let offset = rr.read_u24().unwrap();
        let flen = rr.read_u24().unwrap();
        let data = rr.read_bytes(flen as usize).unwrap();
        if let Some(complete) = reass.add(offset, data).unwrap() {
            assert_eq!(complete, full);
        }
    }
    assert!(reass.complete());
    let complete = reass.add(0, &full).unwrap();
    assert_eq!(complete.unwrap(), full);
}
