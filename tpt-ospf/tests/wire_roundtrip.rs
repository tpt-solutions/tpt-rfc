// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Round-trip and checksum tests for the OSPF packet codec (OSPFv2 + OSPFv3).

use tpt_ospf::lsa::{Ip4, Lsa, LsaHeader, NetworkLsa, RouterLink, RouterLsa};
use tpt_ospf::wire::{
    DbdPacket, HelloPacket, LinkStateRequest, LsAckPacket, LsuPacket, OspfPacket, OspfVersion,
    PacketBody, PacketType,
};

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip4 {
    [a, b, c, d]
}

fn hello_v2() -> OspfPacket {
    OspfPacket {
        version: OspfVersion::V2,
        packet_type: PacketType::Hello,
        router_id: ip(10, 0, 0, 1),
        area_id: ip(0, 0, 0, 0),
        auth_type: 0,
        auth: [0; 8],
        instance_id: 0,
        body: PacketBody::Hello(HelloPacket {
            network_mask: ip(255, 255, 255, 0),
            interface_id: 0,
            hello_interval: 10,
            options: 0x02,
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: ip(10, 0, 0, 1),
            backup_designated_router: ip(10, 0, 0, 2),
            neighbors: vec![ip(10, 0, 0, 2), ip(10, 0, 0, 3)],
        }),
    }
}

fn hello_v3() -> OspfPacket {
    OspfPacket {
        version: OspfVersion::V3,
        packet_type: PacketType::Hello,
        router_id: ip(10, 0, 0, 1),
        area_id: ip(0, 0, 0, 0),
        auth_type: 0,
        auth: [0; 8],
        instance_id: 0,
        body: PacketBody::Hello(HelloPacket {
            network_mask: [0; 4],
            interface_id: 7,
            hello_interval: 10,
            options: 0x12,
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: ip(10, 0, 0, 1),
            backup_designated_router: ip(10, 0, 0, 2),
            neighbors: vec![ip(10, 0, 0, 2)],
        }),
    }
}

fn dbd() -> OspfPacket {
    let mut hdr = LsaHeader::router(ip(10, 0, 0, 2), 0x02);
    hdr.sequence_number = 0x8000_0005;
    OspfPacket {
        version: OspfVersion::V2,
        packet_type: PacketType::Dbd,
        router_id: ip(10, 0, 0, 1),
        area_id: ip(0, 0, 0, 0),
        auth_type: 0,
        auth: [0; 8],
        instance_id: 0,
        body: PacketBody::Dbd(DbdPacket {
            interface_mtu: 1500,
            options: 0x02,
            init: true,
            more: true,
            master: true,
            dd_sequence: 0x8000_0005,
            lsas: vec![hdr],
        }),
    }
}

fn lsr() -> OspfPacket {
    OspfPacket {
        version: OspfVersion::V2,
        packet_type: PacketType::Lsr,
        router_id: ip(10, 0, 0, 1),
        area_id: ip(0, 0, 0, 0),
        auth_type: 0,
        auth: [0; 8],
        instance_id: 0,
        body: PacketBody::Lsr(vec![LinkStateRequest {
            lsa_type: 1,
            link_state_id: ip(10, 0, 0, 2),
            advertising_router: ip(10, 0, 0, 2),
        }]),
    }
}

fn lsu() -> OspfPacket {
    let mut rl = RouterLsa {
        header: LsaHeader::router(ip(10, 0, 0, 1), 0x02),
        v: false,
        e: false,
        b: false,
        links: vec![RouterLink::point_to_point(
            ip(10, 0, 0, 2),
            ip(10, 0, 0, 1),
            10,
        )],
    };
    rl.header.sequence_number = 0x8000_0001;
    let mut nl = NetworkLsa {
        header: LsaHeader::network(ip(10, 1, 1, 1), 0x02),
        network_mask: ip(255, 255, 255, 0),
        attached_routers: vec![ip(10, 0, 0, 1), ip(10, 0, 0, 2)],
    };
    nl.header.sequence_number = 0x8000_0002;
    // The encode path computes the LSA length; set it here so the original
    // matches the decoded copy (which reads the real length off the wire).
    rl.header.length = 34; // header(20) + flags(1) + nlinks(1) + 1 link(12)
    nl.header.length = 32; // header(20) + mask(4) + 2 attached routers(8)
    OspfPacket {
        version: OspfVersion::V2,
        packet_type: PacketType::Lsu,
        router_id: ip(10, 0, 0, 1),
        area_id: ip(0, 0, 0, 0),
        auth_type: 0,
        auth: [0; 8],
        instance_id: 0,
        body: PacketBody::Lsu(LsuPacket {
            lsas: vec![Lsa::Router(rl), Lsa::Network(nl)],
        }),
    }
}

fn lsack() -> OspfPacket {
    let mut hdr = LsaHeader::router(ip(10, 0, 0, 2), 0x02);
    hdr.sequence_number = 0x8000_0005;
    OspfPacket {
        version: OspfVersion::V2,
        packet_type: PacketType::LsAck,
        router_id: ip(10, 0, 0, 1),
        area_id: ip(0, 0, 0, 0),
        auth_type: 0,
        auth: [0; 8],
        instance_id: 0,
        body: PacketBody::LsAck(LsAckPacket { lsas: vec![hdr] }),
    }
}

#[test]
fn hello_v2_round_trip() {
    let pkt = hello_v2();
    let bytes = pkt.to_bytes();
    let decoded = OspfPacket::from_bytes(&bytes).unwrap();
    assert_eq!(pkt, decoded);
}

#[test]
fn hello_v3_round_trip() {
    let pkt = hello_v3();
    let bytes = pkt.to_bytes();
    let decoded = OspfPacket::from_bytes(&bytes).unwrap();
    assert_eq!(pkt, decoded);
}

#[test]
fn dbd_round_trip() {
    let pkt = dbd();
    let bytes = pkt.to_bytes();
    let decoded = OspfPacket::from_bytes(&bytes).unwrap();
    assert_eq!(pkt, decoded);
}

#[test]
fn lsr_round_trip() {
    let pkt = lsr();
    let bytes = pkt.to_bytes();
    let decoded = OspfPacket::from_bytes(&bytes).unwrap();
    assert_eq!(pkt, decoded);
}

#[test]
fn lsu_round_trip() {
    let pkt = lsu();
    let bytes = pkt.to_bytes();
    let decoded = OspfPacket::from_bytes(&bytes).unwrap();
    assert_eq!(pkt, decoded);
}

#[test]
fn lsack_round_trip() {
    let pkt = lsack();
    let bytes = pkt.to_bytes();
    let decoded = OspfPacket::from_bytes(&bytes).unwrap();
    assert_eq!(pkt, decoded);
}

#[test]
fn v2_checksum_is_reproducible() {
    let pkt = dbd();
    let bytes = pkt.to_bytes();
    let stored = u16::from_be_bytes([bytes[12], bytes[13]]);
    // Zero the checksum and authentication fields, then recompute.
    let mut chk = bytes.clone();
    chk[12..14].copy_from_slice(&0u16.to_be_bytes());
    chk[16..24].copy_from_slice(&[0u8; 8]);
    assert_eq!(stored, tpt_ospf::wire::internet_checksum(&chk));
}

#[test]
fn v3_checksum_is_reproducible() {
    let pkt = hello_v3();
    let bytes = pkt.to_bytes();
    let stored = u16::from_be_bytes([bytes[14], bytes[15]]);
    let mut chk = bytes.clone();
    chk[14..16].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(stored, tpt_ospf::wire::internet_checksum(&chk));
}

#[test]
fn re_encode_is_stable() {
    let pkt = lsu();
    let bytes = pkt.to_bytes();
    let decoded = OspfPacket::from_bytes(&bytes).unwrap();
    assert_eq!(bytes, decoded.to_bytes());
}

#[test]
fn truncated_packet_is_rejected() {
    let pkt = hello_v2();
    let mut bytes = pkt.to_bytes();
    bytes.truncate(bytes.len() - 1);
    assert!(OspfPacket::from_bytes(&bytes).is_err());
}

#[test]
fn bad_length_is_rejected() {
    let mut bytes = hello_v2().to_bytes();
    // Corrupt the declared length.
    bytes[2..4].copy_from_slice(&9999u16.to_be_bytes());
    assert!(OspfPacket::from_bytes(&bytes).is_err());
}
