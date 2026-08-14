// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for `tpt-radius`, including the RFC 2865 §7.1 example
//! vectors and a client/server round trip.

use std::net::Ipv4Addr;
use std::sync::Arc;

use tpt_radius::accounting::AcctStatusType;
use tpt_radius::attribute::{Attribute, AttributeType};
use tpt_radius::client::Client;
use tpt_radius::memory::MemoryBackend;
use tpt_radius::packet::{Packet, PacketCode};
use tpt_radius::server::{AuthDecision, AuthRequest, Server};

fn from_hex(s: &str) -> Vec<u8> {
    let s = s.replace(|c: char| c.is_whitespace(), "");
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

#[test]
fn decode_rfc_2865_access_request() {
    // RFC 2865 §7.1 — "User Telnet to Specified Host", shared secret "xyzzy5461".
    let bytes = from_hex(
        "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb \
         98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d \
         93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8 \
         01 10 05 06 00 00 00 03",
    );
    let p = Packet::decode(&bytes).expect("decode failed");

    assert_eq!(p.code, PacketCode::AccessRequest);
    assert_eq!(p.identifier, 0);
    assert_eq!(
        p.authenticator,
        [
            0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83, 0xd5, 0xcb, 0x98, 0xf4,
            0x22, 0x7a
        ]
    );
    assert_eq!(p.user_name(), Some("nemo"));

    let nas_ip = p
        .attribute(AttributeType::NAS_IP_ADDRESS)
        .unwrap()
        .as_ipv4()
        .unwrap();
    assert_eq!(nas_ip, Ipv4Addr::new(192, 168, 1, 16));
    assert_eq!(
        p.attribute(AttributeType::NAS_PORT)
            .unwrap()
            .as_u32()
            .unwrap(),
        3
    );

    // The hidden User-Password must decrypt to "arctangent" with the secret.
    let pw = p.user_password(b"xyzzy5461").expect("decrypt failed");
    assert_eq!(pw, b"arctangent");
}

#[test]
fn response_authenticator_matches_rfc() {
    // RFC 2865 §7.1 Access-Accept for the request above.
    let request_auth = [
        0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83, 0xd5, 0xcb, 0x98, 0xf4, 0x22,
        0x7a,
    ];
    let accept_bytes = from_hex(
        "02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf \
         9b 55 e0 b2 06 06 00 00 00 01 0f 06 00 00 00 00 \
         0e 06 c0 a8 01 03",
    );

    let mut accept = Packet::new(
        PacketCode::AccessAccept,
        0,
        request_auth,
        vec![
            Attribute::service_type(1),
            Attribute::login_service(0),
            Attribute::login_ip_host(Ipv4Addr::new(192, 168, 1, 3)),
        ],
    );
    accept.set_response_authenticator(&request_auth, b"xyzzy5461");

    assert_eq!(&accept.authenticator[..], &accept_bytes[4..20]);
    assert_eq!(accept.encode(), accept_bytes);
}

#[test]
fn encode_decode_round_trip() {
    let mut p = Packet::access_request(7, Client::random_authenticator(), b"secret", "carol", "pw")
        .unwrap();
    p.add(Attribute::nas_ip_address(Ipv4Addr::new(10, 0, 0, 1)));
    let encoded = p.encode();
    let decoded = Packet::decode(&encoded).unwrap();
    assert_eq!(p, decoded);
}

#[test]
fn password_hiding_round_trip_long() {
    let ra = [0x11u8; 16];
    let long = "this-is-a-password-longer-than-sixteen!";
    let mut p = Packet::new(
        PacketCode::AccessRequest,
        1,
        ra,
        vec![Attribute::user_name("dave")],
    );
    p.hide_user_password(b"shared-secret", long.as_bytes())
        .unwrap();
    let hidden = p
        .attribute(AttributeType::USER_PASSWORD)
        .unwrap()
        .value
        .clone();
    assert_eq!(hidden.len() % 16, 0);
    assert!(hidden.len() >= long.len());

    let recovered = p.user_password(b"shared-secret").unwrap();
    assert_eq!(recovered, long.as_bytes());
}

#[test]
fn password_hiding_independent_oracle() {
    // Independent known-answer vector for the hiding algorithm: secret
    // "xyzzy5461", password "arctangent", request authenticator
    // 6f4440355fb81a4d2a3e7f8f5b1a2683. Hidden value computed with a
    // separate MD5 implementation (not this crate).
    let ra = [
        0x6f, 0x44, 0x40, 0x35, 0x5f, 0xb8, 0x1a, 0x4d, 0x2a, 0x3e, 0x7f, 0x8f, 0x5b, 0x1a, 0x26,
        0x83,
    ];
    let mut p = Packet::new(
        PacketCode::AccessRequest,
        0,
        ra,
        vec![Attribute::user_name("nemo")],
    );
    p.hide_user_password(b"xyzzy5461", b"arctangent").unwrap();
    let hidden = p
        .attribute(AttributeType::USER_PASSWORD)
        .unwrap()
        .value
        .clone();
    assert_eq!(
        hidden,
        from_hex("c5 73 62 5d 58 8f 44 f4 50 18 ea 39 fe 43 ec 02")
    );
}

#[test]
fn client_server_integration() {
    let backend = Arc::new(MemoryBackend::new());
    backend.add_user("alice", "s3cret");
    let server = Server::new(Arc::clone(&backend), "secret").unwrap();

    let mut client = Client::new("secret");
    let request = client.access_request("alice", "s3cret").unwrap();
    let reply = server.process(&request).unwrap().expect("should reply");
    assert_eq!(reply.code, PacketCode::AccessAccept);
    assert!(client.verify_response(&request, &reply));

    // Wrong client secret → verification fails.
    let bad = Client::new("WRONG");
    assert!(!bad.verify_response(&request, &reply));

    // Reject path.
    let bad_req = client.access_request("alice", "nope").unwrap();
    let bad_reply = server.process(&bad_req).unwrap().expect("should reply");
    assert_eq!(bad_reply.code, PacketCode::AccessReject);
    assert!(client.verify_response(&bad_req, &bad_reply));
}

#[test]
fn accounting_round_trip() {
    let backend = Arc::new(MemoryBackend::new());
    let server = Server::new(Arc::clone(&backend), "secret").unwrap();

    let mut client = Client::new("secret");
    let mut attrs = vec![Attribute::acct_session_id("sess-1")];
    attrs.push(Attribute::new(
        AttributeType::ACCT_SESSION_TIME,
        120u32.to_be_bytes().to_vec(),
    ));
    let request = client
        .accounting_request(AcctStatusType::Stop.to_u32(), attrs)
        .unwrap();
    assert!(request.verify_accounting_request_authenticator(b"secret"));

    let reply = server.process(&request).unwrap().expect("should reply");
    assert_eq!(reply.code, PacketCode::AccountingResponse);
    assert!(client.verify_accounting_response(&request, &reply));

    // Tamper with the request authenticator → server silently discards.
    let mut tampered = request.clone();
    tampered.authenticator[0] ^= 0xff;
    assert!(server.process(&tampered).unwrap().is_none());
}

#[test]
fn message_authenticator_verify() {
    let mut client = Client::new("secret");
    let mut request = client.access_request_with(vec![Attribute::user_name("eapuser")]);
    request.add_eap_message(&[0x01, 0x02, 0x00, 0x04]);
    request.set_message_authenticator(b"secret");

    assert!(request.verify_message_authenticator(b"secret"));
    // Flip a payload byte → verification fails.
    let mut bad = request.clone();
    bad.attributes[1].value[0] ^= 0x01;
    assert!(!bad.verify_message_authenticator(b"secret"));
}

#[test]
fn eap_message_split_and_join() {
    let mut p = Packet::new(PacketCode::AccessRequest, 0, [0u8; 16], vec![]);
    let payload: Vec<u8> = (0..600u32).map(|i| (i % 256) as u8).collect();
    p.add_eap_message(&payload);
    let frags: Vec<&Attribute> = p.attributes(AttributeType::EAP_MESSAGE).collect();
    assert!(
        frags.len() >= 2,
        "payload should be split across attributes"
    );
    assert!(frags.iter().all(|a| a.value.len() <= 253));
    assert_eq!(p.eap_message(), payload);
}

// A minimal custom backend exercising the AuthBackend trait directly.
struct FixedBackend;
impl tpt_radius::server::AuthBackend for FixedBackend {
    fn authenticate(&self, req: &AuthRequest<'_>) -> AuthDecision {
        match req.username {
            Some("chal") => AuthDecision::Challenge {
                state: b"nonce".to_vec(),
                reply_message: Some("enter response".into()),
                attributes: vec![],
            },
            Some(_) => AuthDecision::Accept { attributes: vec![] },
            None => AuthDecision::Reject {
                message: Some("who?".into()),
            },
        }
    }
}

#[test]
fn challenge_decision() {
    let backend = Arc::new(FixedBackend);
    let server = Server::new(backend, "secret").unwrap();
    let mut client = Client::new("secret");
    let request = client.access_request("chal", "x").unwrap();
    let reply = server.process(&request).unwrap().unwrap();
    assert_eq!(reply.code, PacketCode::AccessChallenge);
    assert!(reply.attribute(AttributeType::STATE).is_some());
    assert!(client.verify_response(&request, &reply));
}
