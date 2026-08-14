// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Link-state database flooding / LSA-recency tests (RFC 2328 §13).

use tpt_ospf::database::{compare_lsa, LinkStateDatabase, LsaOrdering, ReceiveAction};
use tpt_ospf::lsa::{Ip4, Lsa, LsaHeader, RouterLsa};
use tpt_ospf::wire::OspfVersion;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip4 {
    [a, b, c, d]
}

fn router_lsa(adv: Ip4, seq: u32) -> Lsa {
    let mut rl = RouterLsa {
        header: LsaHeader::router(adv, 0x02),
        v: false,
        e: false,
        b: false,
        links: vec![],
    };
    rl.header.sequence_number = seq;
    Lsa::Router(rl)
}

#[test]
fn newer_lsa_replaces_older() {
    let mut db = LinkStateDatabase::new();
    assert_eq!(
        db.receive(router_lsa(ip(1, 1, 1, 1), 1)),
        ReceiveAction::InstallAndFlood
    );
    assert_eq!(
        db.receive(router_lsa(ip(1, 1, 1, 1), 2)),
        ReceiveAction::InstallAndFlood
    );
    // The database now holds the newer copy.
    let key = router_lsa(ip(1, 1, 1, 1), 2).key();
    let stored = db.get(&key).unwrap();
    assert_eq!(stored.header().sequence_number, 2);
}

#[test]
fn older_lsa_is_rejected() {
    let mut db = LinkStateDatabase::new();
    db.receive(router_lsa(ip(1, 1, 1, 1), 5));
    assert_eq!(
        db.receive(router_lsa(ip(1, 1, 1, 1), 3)),
        ReceiveAction::Reject
    );
}

#[test]
fn duplicate_lsa_acknowledged_only() {
    let mut db = LinkStateDatabase::new();
    db.receive(router_lsa(ip(1, 1, 1, 1), 4));
    assert_eq!(
        db.receive(router_lsa(ip(1, 1, 1, 1), 4)),
        ReceiveAction::Duplicate
    );
}

#[test]
fn compare_lsa_sequence_ordering() {
    let mut a = LsaHeader::router(ip(1, 1, 1, 1), 0);
    a.sequence_number = 5;
    let mut b = a.clone();
    b.sequence_number = 3;
    assert_eq!(compare_lsa(&a, &b), LsaOrdering::Newer);
    assert_eq!(compare_lsa(&b, &a), LsaOrdering::Older);
    assert_eq!(compare_lsa(&a, &a), LsaOrdering::Equal);
}

#[test]
fn compare_lsa_wraparound() {
    // 0x80000001 (initial) is newer than 0x7FFFFFFF (the top of the range).
    let mut a = LsaHeader::router(ip(1, 1, 1, 1), 0);
    a.sequence_number = 0x8000_0001;
    let mut b = a.clone();
    b.sequence_number = 0x7FFF_FFFF;
    assert_eq!(compare_lsa(&a, &b), LsaOrdering::Newer);
    assert_eq!(compare_lsa(&b, &a), LsaOrdering::Older);
}

#[test]
fn compare_lsa_maxage_wins() {
    let mut a = LsaHeader::router(ip(1, 1, 1, 1), 0);
    a.sequence_number = 5;
    let mut b = a.clone();
    b.age = tpt_ospf::lsa::MAX_AGE;
    assert_eq!(compare_lsa(&b, &a), LsaOrdering::Newer);
}

#[test]
fn v3_header_framing_is_distinct() {
    // The same numeric value 1 means "Router" in v2 but 0x2001 in v3.
    let mut v2 = LsaHeader::router(ip(1, 1, 1, 1), 0);
    v2.sequence_number = 1;
    assert!(v2.is_router());
    assert_eq!(v2.lsa_type, 1);

    let mut v3 = LsaHeader::new(OspfVersion::V3, ip(1, 1, 1, 1), 0, 0x2001);
    v3.sequence_number = 1;
    assert!(v3.is_router());
    assert_eq!(v3.lsa_type, 0x2001);
}
