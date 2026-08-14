// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Round-trip tests for LSA header/body encode/decode.

use tpt_ospf::lsa::{Ip4, Lsa, LsaHeader, NetworkLsa, RawLsa, RouterLsa, RouterLink};
use tpt_ospf::wire::OspfVersion;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip4 {
    [a, b, c, d]
}

#[test]
fn router_lsa_round_trip() {
    let mut rl = RouterLsa {
        header: LsaHeader::router(ip(1, 1, 1, 1), 0x02),
        v: false,
        e: true,
        b: false,
        links: vec![
            RouterLink::point_to_point(ip(2, 2, 2, 2), ip(10, 0, 0, 1), 10),
            RouterLink::stub(ip(192, 168, 0, 0), ip(255, 255, 255, 0), 5),
        ],
    };
    rl.header.sequence_number = 0x8000_0001;
    rl.header.checksum = 0x1234;

    let mut buf = Vec::new();
    rl.encode(&mut buf);
    let decoded = RouterLsa::decode(OspfVersion::V2, &buf).unwrap();
    rl.header.length = decoded.header.length;
    assert_eq!(rl, decoded);
    assert_eq!(decoded.links.len(), 2);
    assert_eq!(decoded.links[0].link_type, 1);
    assert_eq!(decoded.links[1].link_type, 3);
    // The encode_with_body helper fills in the length field.
    assert!(decoded.header.length >= 20);
}

#[test]
fn network_lsa_round_trip() {
    let mut nl = NetworkLsa {
        header: LsaHeader::network(ip(10, 1, 1, 1), 0x02),
        network_mask: ip(255, 255, 255, 0),
        attached_routers: vec![ip(1, 1, 1, 1), ip(2, 2, 2, 2), ip(3, 3, 3, 3)],
    };
    nl.header.sequence_number = 0x8000_0002;

    let mut buf = Vec::new();
    nl.encode(&mut buf);
    let decoded = NetworkLsa::decode(OspfVersion::V2, &buf).unwrap();
    nl.header.length = decoded.header.length;
    assert_eq!(nl, decoded);
    assert_eq!(decoded.attached_routers.len(), 3);
}

#[test]
fn lsa_enum_round_trips_router_and_network() {
    let mut rl = RouterLsa {
        header: LsaHeader::router(ip(9, 9, 9, 9), 0x02),
        v: false,
        e: false,
        b: false,
        links: vec![],
    };
    rl.header.sequence_number = 0x8000_0001;

    let mut buf = Vec::new();
    Lsa::Router(rl.clone()).encode(&mut buf);
    match Lsa::decode(OspfVersion::V2, &buf).unwrap() {
        Lsa::Router(d) => {
            rl.header.length = d.header.length;
            assert_eq!(d, rl)
        }
        _ => panic!("expected Router LSA"),
    }

    let mut nl = NetworkLsa {
        header: LsaHeader::network(ip(10, 9, 9, 9), 0x02),
        network_mask: ip(255, 255, 255, 0),
        attached_routers: vec![ip(9, 9, 9, 9)],
    };
    nl.header.sequence_number = 0x8000_0003;
    let mut buf = Vec::new();
    Lsa::Network(nl.clone()).encode(&mut buf);
    match Lsa::decode(OspfVersion::V2, &buf).unwrap() {
        Lsa::Network(d) => {
            nl.header.length = d.header.length;
            assert_eq!(d, nl)
        }
        _ => panic!("expected Network LSA"),
    }
}

#[test]
fn opaque_lsa_is_preserved() {
    // A Summary-LSA (type 3) is preserved opaquely as Lsa::Raw.
    let mut hdr = LsaHeader::new(OspfVersion::V2, ip(1, 1, 1, 1), 0x02, 3);
    hdr.sequence_number = 0x8000_0001;
    hdr.link_state_id = ip(172, 16, 0, 0);
    let mut raw = RawLsa {
        header: hdr,
        body: vec![0xAA, 0xBB, 0xCC, 0xDD],
    };
    let mut buf = Vec::new();
    raw.encode(&mut buf);
    match Lsa::decode(OspfVersion::V2, &buf).unwrap() {
        Lsa::Raw(d) => {
            raw.header.length = d.header.length;
            assert_eq!(d, raw)
        }
        other => panic!("expected Raw LSA, got {:?}", other.header().lsa_type),
    }
}
