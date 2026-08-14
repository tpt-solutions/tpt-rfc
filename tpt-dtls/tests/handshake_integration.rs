// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end DTLS 1.3 handshake over an in-memory datagram channel,
//! exercising the stateless-cookie round trip, X25519 key agreement, Ed25519
//! CertificateVerify, the TLS 1.3 key schedule, and application-data
//! protection. The two `Connection`s are driven as coroutines; datagrams are
//! ferried between them (optionally dropped to exercise retransmission).

use tpt_dtls::crypto::{CipherSuite, Ed25519KeyPair};
use tpt_dtls::handshake::{group, sigscheme};
use tpt_dtls::{
    AcceptAllVerifier, ClientConfig, Connection, DtlsError, ServerConfig,
};

fn client_cfg(identity: Ed25519KeyPair) -> ClientConfig {
    ClientConfig {
        cipher_suites: vec![CipherSuite::TlsAes128GcmSha256],
        groups: vec![group::X25519],
        sig_algs: vec![sigscheme::ED25519],
        identity,
        connection_id: None,
        server_verifier: Box::new(AcceptAllVerifier),
    }
}

fn server_cfg(identity: Ed25519KeyPair) -> ServerConfig {
    ServerConfig {
        cipher_suites: vec![CipherSuite::TlsAes128GcmSha256],
        groups: vec![group::X25519],
        sig_algs: vec![sigscheme::ED25519],
        identity,
        cookie_secret: [0x07u8; 32],
        client_address: b"mem-client".to_vec(),
        client_verifier: Box::new(AcceptAllVerifier),
        connection_id: None,
    }
}

/// Drive both endpoints to completion. `drop_first_client_flight` simulates
/// loss of the very first ClientHello to exercise retransmission.
fn run_handshake(drop_first_client_flight: bool) -> (Connection, Connection) {
    let mut client = Connection::new_client(client_cfg(Ed25519KeyPair::from_seed(&[1u8; 32]).unwrap())).unwrap();
    let mut server = Connection::new_server(server_cfg(Ed25519KeyPair::from_seed(&[2u8; 32]).unwrap())).unwrap();

    client.start().unwrap();
    let mut first_client_flight = client.take_output();

    if drop_first_client_flight {
        // Simulate loss: retransmit on timer expiry.
        match client.tick(std::time::Duration::from_millis(200)) {
            tpt_dtls::retransmit::RetransmitEvent::Retransmit => {
                first_client_flight = client.take_output();
            }
            _ => panic!("expected retransmit"),
        }
    }

    server.process_datagram(&first_client_flight).unwrap();
    let hrr = server.take_output();
    client.process_datagram(&hrr).unwrap();

    let ch2 = client.take_output();
    server.process_datagram(&ch2).unwrap();

    let server_flight = server.take_output();
    client.process_datagram(&server_flight).unwrap();

    let client_flight = client.take_output();
    server.process_datagram(&client_flight).unwrap();

    assert!(client.is_connected());
    assert!(server.is_connected());
    (client, server)
}

#[test]
fn handshake_completes_with_cookie() {
    let (client, server) = run_handshake(false);
    assert_eq!(client.cipher_suite(), CipherSuite::TlsAes128GcmSha256);
    assert_eq!(server.cipher_suite(), CipherSuite::TlsAes128GcmSha256);
}

#[test]
fn handshake_survives_first_flight_loss() {
    // The client retransmits its first ClientHello; the server still issues a
    // cookie and the handshake completes.
    let _ = run_handshake(true);
}

#[test]
fn application_data_round_trips() {
    let (mut client, mut server) = run_handshake(false);

    client.send_app_data(b"hello from client").unwrap();
    let ct = client.take_output();
    server.process_datagram(&ct).unwrap();
    assert_eq!(server.recv_app_data().unwrap(), b"hello from client");

    server.send_app_data(b"hello from server").unwrap();
    let ct = server.take_output();
    client.process_datagram(&ct).unwrap();
    assert_eq!(client.recv_app_data().unwrap(), b"hello from server");
}

#[test]
fn wrong_cookie_is_rejected() {
    let mut client = Connection::new_client(client_cfg(Ed25519KeyPair::from_seed(&[1u8; 32]).unwrap())).unwrap();
    let mut server = Connection::new_server(server_cfg(Ed25519KeyPair::from_seed(&[2u8; 32]).unwrap())).unwrap();

    client.start().unwrap();
    let ch1 = client.take_output();
    server.process_datagram(&ch1).unwrap();
    let hrr = server.take_output();

    client.process_datagram(&hrr).unwrap();
    let mut ch2 = client.take_output();

    // Corrupt the cookie in the second ClientHello.
    // Find the cookie extension (type 0x002c) and flip a byte.
    let _ = &mut ch2;
    // Re-parse is unnecessary: simply tamper the last record's body tail.
    let last = ch2.len() - 1;
    ch2[last] ^= 0xff;
    // The server should reject the mismatched cookie.
    let res = server.process_datagram(&ch2);
    assert!(matches!(res, Err(DtlsError::CookieMismatch)));
}

#[test]
fn chacha20poly1305_suite_handshake() {
    let mut client = Connection::new_client(ClientConfig {
        cipher_suites: vec![CipherSuite::TlsChacha20Poly1305Sha256],
        groups: vec![group::X25519],
        sig_algs: vec![sigscheme::ED25519],
        identity: Ed25519KeyPair::from_seed(&[3u8; 32]).unwrap(),
        connection_id: None,
        server_verifier: Box::new(AcceptAllVerifier),
    })
    .unwrap();
    let mut server = Connection::new_server(ServerConfig {
        cipher_suites: vec![CipherSuite::TlsChacha20Poly1305Sha256],
        groups: vec![group::X25519],
        sig_algs: vec![sigscheme::ED25519],
        identity: Ed25519KeyPair::from_seed(&[4u8; 32]).unwrap(),
        cookie_secret: [0x09u8; 32],
        client_address: b"c".to_vec(),
        client_verifier: Box::new(AcceptAllVerifier),
        connection_id: None,
    })
    .unwrap();

    client.start().unwrap();
    server.process_datagram(&client.take_output()).unwrap();
    client.process_datagram(&server.take_output()).unwrap();
    server.process_datagram(&client.take_output()).unwrap();
    client.process_datagram(&server.take_output()).unwrap();
    server.process_datagram(&client.take_output()).unwrap();

    assert!(client.is_connected());
    assert!(server.is_connected());
}
