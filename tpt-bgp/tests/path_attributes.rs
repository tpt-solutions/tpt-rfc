// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Path-attribute tests: AS_PATH (incl. four-octet ASNs), AGGREGATOR,
//! multiprotocol NLRI (RFC 4760), and the decision-relevant attribute width.

use tpt_bgp::attributes::{
    Aggregator, AsPath, AsPathSegment, AsPathSegmentType, Asn, Ipv6Prefix, MpReachNlri, NextHop,
    PathAttribute, Prefix,
};
use tpt_bgp::wire::{CodecOptions, Message, Update};

fn decode_update(bytes: &[u8], as4: bool) -> Update {
    match Message::decode(bytes, CodecOptions { as4 }).unwrap() {
        Message::Update(u) => u,
        _ => panic!("expected UPDATE"),
    }
}

fn update_with(attrs: Vec<PathAttribute>) -> Update {
    Update {
        withdrawn_routes: vec![],
        path_attributes: attrs,
        nlri: vec![],
    }
}

#[test]
fn as_path_four_octet() {
    let path = AsPath {
        segments: vec![AsPathSegment {
            segment_type: AsPathSegmentType::Sequence,
            asns: vec![Asn(4200000000), Asn(65002), Asn(1)],
        }],
    };
    let update = update_with(vec![PathAttribute::AsPath(path)]);
    let bytes = update.to_bytes();
    let decoded = decode_update(&bytes, true);
    let got = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(got.asns(), vec![Asn(4200000000), Asn(65002), Asn(1)]);
    assert_eq!(got.path_length(), 1);
}

#[test]
fn as_path_set_and_sequence() {
    let path = AsPath {
        segments: vec![
            AsPathSegment {
                segment_type: AsPathSegmentType::Set,
                asns: vec![Asn(10), Asn(20)],
            },
            AsPathSegment {
                segment_type: AsPathSegmentType::Sequence,
                asns: vec![Asn(30)],
            },
        ],
    };
    let update = update_with(vec![PathAttribute::AsPath(path)]);
    let decoded = decode_update(&update.to_bytes(), true);
    let got = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    // AS_SET counts as one for path-length; AS_SEQUENCE as one -> total 2.
    assert_eq!(got.path_length(), 2);
    assert_eq!(got.asns(), vec![Asn(10), Asn(20), Asn(30)]);
    assert_eq!(got.first_asn(), Some(Asn(10)));
}

#[test]
fn aggregator_four_octet() {
    let agg = Aggregator {
        asn: Asn(4200000001),
        addr: [10, 0, 0, 9],
    };
    let update = update_with(vec![PathAttribute::Aggregator(agg)]);
    let decoded = decode_update(&update.to_bytes(), true);
    let got = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::Aggregator(a) => Some(a),
            _ => None,
        })
        .unwrap();
    assert_eq!(got, agg);
}

#[test]
fn mp_reach_ipv6() {
    let mp = MpReachNlri {
        afi: 2,
        safi: 1,
        next_hop: NextHop::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        nlri: vec![Prefix::V6(Ipv6Prefix::new(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ))],
    };
    let update = update_with(vec![PathAttribute::MpReachNlri(mp.clone())]);
    let decoded = decode_update(&update.to_bytes(), true);
    let got = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(m) => Some(m),
            _ => None,
        })
        .unwrap();
    assert_eq!(got, mp);
}

#[test]
fn mp_reach_ipv6_link_local() {
    let mp = MpReachNlri {
        afi: 2,
        safi: 1,
        next_hop: NextHop::Ipv6LinkLocal([1; 16], [2; 16]),
        nlri: vec![],
    };
    let update = update_with(vec![PathAttribute::MpReachNlri(mp.clone())]);
    let decoded = decode_update(&update.to_bytes(), true);
    let got = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(m) => Some(m),
            _ => None,
        })
        .unwrap();
    assert_eq!(got, mp);
}

#[test]
fn mp_unreach_ipv4() {
    use tpt_bgp::attributes::Ipv4Prefix;
    let mp = tpt_bgp::attributes::MpUnreachNlri {
        afi: 1,
        safi: 1,
        withdrawn: vec![Prefix::V4(Ipv4Prefix::new([192, 168, 1, 0], 24))],
    };
    let update = update_with(vec![PathAttribute::MpUnreachNlri(mp.clone())]);
    let decoded = decode_update(&update.to_bytes(), true);
    let got = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::MpUnreachNlri(m) => Some(m),
            _ => None,
        })
        .unwrap();
    assert_eq!(got, mp);
}

#[test]
fn unknown_attribute_preserved() {
    let raw = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let update = update_with(vec![PathAttribute::Unknown {
        type_code: 99,
        transitive: true,
        value: raw.clone(),
    }]);
    let decoded = decode_update(&update.to_bytes(), true);
    let got = decoded
        .path_attributes
        .into_iter()
        .find_map(|a| match a {
            PathAttribute::Unknown {
                type_code, value, ..
            } => Some((type_code, value)),
            _ => None,
        })
        .unwrap();
    assert_eq!(got.0, 99);
    assert_eq!(got.1, raw);
}
