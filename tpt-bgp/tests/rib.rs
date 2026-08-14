// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RIB and decision-process tests (RFC 4271 §9.1.2.1).

use tpt_bgp::attributes::{
    AsPath, AsPathSegment, AsPathSegmentType, Asn, Ipv4Prefix, Origin, Prefix,
};
use tpt_bgp::rib::{DefaultDecision, Policy, Rib, Route, RouteSource};

fn prefix() -> Prefix {
    Prefix::V4(Ipv4Prefix::new([192, 168, 0, 0], 16))
}

fn src(peer: [u8; 4], ibgp: bool) -> RouteSource {
    RouteSource {
        peer,
        is_ibgp: ibgp,
    }
}

fn route(prefix: Prefix, peer: [u8; 4], ibgp: bool, asns: &[u32]) -> Route {
    let as_path = AsPath {
        segments: vec![AsPathSegment {
            segment_type: AsPathSegmentType::Sequence,
            asns: asns.iter().map(|a| Asn(*a)).collect(),
        }],
    };
    let mut r = Route::new(prefix, src(peer, ibgp));
    r.as_path = as_path;
    r.origin = Some(Origin::Igp);
    r
}

#[test]
fn local_pref_wins() {
    let mut rib = Rib::new(DefaultDecision);
    let p = prefix();
    let mut a = route(p, [1, 1, 1, 1], false, &[100]);
    a.local_pref = Some(100);
    let mut b = route(p, [2, 2, 2, 2], false, &[100]);
    b.local_pref = Some(200);
    rib.insert(a);
    rib.insert(b);
    assert_eq!(rib.best(&p).unwrap().source.peer, [2, 2, 2, 2]);
}

#[test]
fn shorter_as_path_wins() {
    let mut rib = Rib::new(DefaultDecision);
    let p = prefix();
    let mut a = route(p, [1, 1, 1, 1], false, &[100]);
    a.local_pref = Some(100);
    let mut b = route(p, [2, 2, 2, 2], false, &[100, 200]);
    b.local_pref = Some(100);
    rib.insert(a);
    rib.insert(b);
    assert_eq!(rib.best(&p).unwrap().source.peer, [1, 1, 1, 1]);
}

#[test]
fn lower_med_wins_same_neighbour() {
    let mut rib = Rib::new(DefaultDecision);
    let p = prefix();
    let mut a = route(p, [1, 1, 1, 1], false, &[100]);
    a.local_pref = Some(100);
    a.med = Some(50);
    let mut b = route(p, [2, 2, 2, 2], false, &[100]);
    b.local_pref = Some(100);
    b.med = Some(10);
    rib.insert(a);
    rib.insert(b);
    assert_eq!(rib.best(&p).unwrap().source.peer, [2, 2, 2, 2]);
}

#[test]
fn ebgp_preferred_over_ibgp() {
    let mut rib = Rib::new(DefaultDecision);
    let p = prefix();
    let a = route(p, [1, 1, 1, 1], false, &[100]);
    let b = route(p, [2, 2, 2, 2], true, &[100]);
    rib.insert(a);
    rib.insert(b);
    assert_eq!(rib.best(&p).unwrap().source.peer, [1, 1, 1, 1]);
}

#[test]
fn withdraw_recomputes_best() {
    let mut rib = Rib::new(DefaultDecision);
    let p = prefix();
    let mut a = route(p, [1, 1, 1, 1], false, &[100]);
    a.local_pref = Some(200);
    let mut b = route(p, [2, 2, 2, 2], false, &[100]);
    b.local_pref = Some(100);
    rib.insert(a);
    rib.insert(b);
    assert_eq!(rib.best(&p).unwrap().source.peer, [1, 1, 1, 1]);
    // Withdraw the best (peer A); B should become best.
    assert!(rib.withdraw(p, [1, 1, 1, 1]));
    assert_eq!(rib.best(&p).unwrap().source.peer, [2, 2, 2, 2]);
    // Withdraw the remaining one; prefix disappears from Loc-RIB.
    assert!(rib.withdraw(p, [2, 2, 2, 2]));
    assert!(rib.best(&p).is_none());
}

/// A trivial import policy that rejects a specific community and bumps
/// LOCAL_PREF otherwise.
struct DemoPolicy {
    reject_community: u32,
    set_local_pref: u32,
}

impl Policy for DemoPolicy {
    fn apply(&self, route: &mut Route) -> bool {
        if route.communities.contains(&self.reject_community) {
            return false;
        }
        route.local_pref = Some(self.set_local_pref);
        true
    }
}

#[test]
fn policy_import_filtering() {
    let mut rib = Rib::new(DefaultDecision);
    let p = prefix();
    let mut a = route(p, [1, 1, 1, 1], false, &[100]);
    a.communities.push(0xFFFF0001);
    let b = route(p, [2, 2, 2, 2], false, &[100]);

    let policy = DemoPolicy {
        reject_community: 0xFFFF0001,
        set_local_pref: 300,
    };
    // A is rejected by policy; B is accepted and gets LOCAL_PREF set to 300.
    assert!(!rib.insert_with_policy(a, &policy));
    assert!(rib.insert_with_policy(b, &policy));
    assert_eq!(rib.len(), 1);
    assert_eq!(rib.best(&p).unwrap().source.peer, [2, 2, 2, 2]);
    assert_eq!(rib.best(&p).unwrap().local_pref, Some(300));
}
