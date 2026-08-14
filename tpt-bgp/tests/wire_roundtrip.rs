// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire-format round-trip tests for the BGP message codec.

use tpt_bgp::attributes::Asn;
use tpt_bgp::wire::{
    err_code, msg_type, Capability, CodecOptions, Message, Notification, OpenMessage, Update,
    BGP_MARKER,
};

fn assert_roundtrip(msg: Message) {
    let bytes = msg.to_bytes();
    // Header: marker (16) + length (2) + type (1) = 19.
    assert_eq!(&bytes[..16], &BGP_MARKER);
    let declared = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
    assert_eq!(declared, bytes.len());
    let decoded = Message::from_bytes(&bytes).expect("decode must succeed");
    // Re-encoding the decoded message must reproduce the wire bytes exactly
    // (canonical round-trip; an OPEN transparently gains an ASN4 capability).
    assert_eq!(decoded.to_bytes(), bytes);
}

#[test]
fn open_roundtrip() {
    let open = OpenMessage {
        version: 4,
        my_asn: Asn(65001),
        hold_time: 90,
        bgp_id: [10, 0, 0, 1],
        capabilities: vec![Capability::MultiProtocol { afi: 1, safi: 1 }],
    };
    assert_roundtrip(Message::Open(open.clone()));

    // The decoded OPEN must carry the same info (AS recovered from the ASN4
    // capability by default).
    if let Message::Open(o) = Message::from_bytes(&open.to_bytes()).unwrap() {
        assert_eq!(o.my_asn, Asn(65001));
        assert!(o
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::As4(Asn(65001)))));
        assert!(o
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::MultiProtocol { afi: 1, safi: 1 })));
    }
}

#[test]
fn open_four_octet_as_trans() {
    // A four-octet AS larger than 65535 must be encoded with AS_TRANS (23456)
    // in the two-byte OPEN field and recovered from the ASN4 capability.
    let open = OpenMessage {
        version: 4,
        my_asn: Asn(4200000000),
        hold_time: 30,
        bgp_id: [192, 0, 2, 1],
        capabilities: vec![],
    };
    let bytes = open.to_bytes();
    let decoded = match Message::from_bytes(&bytes).unwrap() {
        Message::Open(o) => o,
        _ => panic!("expected OPEN"),
    };
    assert_eq!(decoded.my_asn, Asn(4200000000));
    // The two-byte field inside the header area must be 23456 (AS_TRANS).
    // The OPEN body begins at offset 19: version(1) + myas(2) ...
    let body = &bytes[19..];
    let two_byte = u16::from_be_bytes([body[1], body[2]]);
    assert_eq!(two_byte, 23456);
}

#[test]
fn update_roundtrip_no_mp() {
    use tpt_bgp::attributes::{Ipv4Prefix, Origin, PathAttribute};
    let update = Update {
        withdrawn_routes: vec![Ipv4Prefix::new([10, 1, 0, 0], 16)],
        path_attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop([192, 168, 0, 1]),
            PathAttribute::LocalPref(200),
        ],
        nlri: vec![Ipv4Prefix::new([172, 16, 0, 0], 12)],
    };
    assert_roundtrip(Message::Update(update));
}

#[test]
fn keepalive_roundtrip() {
    let bytes = Message::Keepalive.to_bytes();
    assert_eq!(bytes.len(), 19);
    assert_eq!(bytes[18], msg_type::KEEPALIVE);
    assert_roundtrip(Message::Keepalive);
}

#[test]
fn notification_roundtrip() {
    let note = Notification::new(err_code::CEASE, 3, vec![1, 2, 3, 4]);
    assert_roundtrip(Message::Notification(note));
}

#[test]
fn truncated_message_rejected() {
    let open = OpenMessage {
        version: 4,
        my_asn: Asn(1),
        hold_time: 0,
        bgp_id: [0, 0, 0, 0],
        capabilities: vec![],
    };
    let mut bytes = open.to_bytes();
    bytes.truncate(bytes.len() - 1);
    assert!(Message::from_bytes(&bytes).is_err());
}

#[test]
fn unknown_message_type_rejected() {
    let mut bytes = vec![0xFF; 19];
    bytes.extend_from_slice(&20u16.to_be_bytes()); // length 20
    bytes.push(99); // unknown type
    bytes.push(0); // padding to satisfy length
    assert!(Message::from_bytes(&bytes).is_err());
}

#[test]
fn as4_off_roundtrip() {
    // With four-octet ASNs disabled, an AS_PATH is encoded/decoded using the
    // two-byte form (high 16 bits dropped).
    use tpt_bgp::attributes::{AsPath, AsPathSegment, AsPathSegmentType, PathAttribute};
    let path = AsPath {
        segments: vec![AsPathSegment {
            segment_type: AsPathSegmentType::Sequence,
            asns: vec![Asn(65001), Asn(65002)],
        }],
    };
    let update = Update {
        withdrawn_routes: vec![],
        path_attributes: vec![PathAttribute::AsPath(path)],
        nlri: vec![],
    };
    let bytes = update.encode(CodecOptions { as4: false });
    let decoded = match Message::decode(&bytes, CodecOptions { as4: false }).unwrap() {
        Message::Update(u) => u,
        _ => panic!(),
    };
    let as_path = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(as_path.asns(), vec![Asn(65001), Asn(65002)]);
}
