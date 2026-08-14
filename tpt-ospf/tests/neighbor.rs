// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Neighbor finite-state-machine transition tests.

use tpt_ospf::neighbor::{Neighbor, NeighborEvent, NeighborState, NeighborTable};

fn ip(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
    [a, b, c, d]
}

#[test]
fn full_adjacency_progression() {
    let mut n = Neighbor::new(ip(1, 1, 1, 1));
    assert_eq!(n.state, NeighborState::Down);

    assert_eq!(n.on_event(NeighborEvent::HelloReceived), NeighborState::Init);
    assert_eq!(
        n.on_event(NeighborEvent::TwoWayReceived {
            adjacency_eligible: true
        }),
        NeighborState::ExStart
    );
    assert_eq!(n.on_event(NeighborEvent::NegotiationDone), NeighborState::Exchange);
    assert_eq!(
        n.on_event(NeighborEvent::ExchangeDone {
            ls_requests_pending: true
        }),
        NeighborState::Loading
    );
    assert_eq!(
        n.on_event(NeighborEvent::ExchangeDone {
            ls_requests_pending: false
        }),
        NeighborState::Full
    );
    assert!(n.state.is_adjacent());
}

#[test]
fn non_eligible_neighbor_stops_at_two_way() {
    let mut n = Neighbor::new(ip(2, 2, 2, 2));
    n.on_event(NeighborEvent::HelloReceived);
    let s = n.on_event(NeighborEvent::TwoWayReceived {
        adjacency_eligible: false,
    });
    assert_eq!(s, NeighborState::TwoWay);
}

#[test]
fn one_way_reverts_to_init() {
    let mut n = Neighbor::new(ip(3, 3, 3, 3));
    n.on_event(NeighborEvent::HelloReceived);
    n.on_event(NeighborEvent::TwoWayReceived {
        adjacency_eligible: true,
    });
    assert_eq!(n.state, NeighborState::ExStart);
    let s = n.on_event(NeighborEvent::OneWayReceived);
    assert_eq!(s, NeighborState::Init);
}

#[test]
fn seq_mismatch_restarts_from_loading() {
    let mut n = Neighbor::new(ip(4, 4, 4, 4));
    n.on_event(NeighborEvent::HelloReceived);
    n.on_event(NeighborEvent::TwoWayReceived {
        adjacency_eligible: true,
    });
    n.on_event(NeighborEvent::NegotiationDone);
    n.on_event(NeighborEvent::ExchangeDone {
        ls_requests_pending: true,
    });
    assert_eq!(n.state, NeighborState::Loading);
    // A sequence mismatch during Loading re-starts the exchange at ExStart.
    assert_eq!(
        n.on_event(NeighborEvent::SeqNumberMismatch),
        NeighborState::ExStart
    );
}

#[test]
fn inactivity_drops_neighbor() {
    let mut n = Neighbor::new(ip(5, 5, 5, 5));
    n.on_event(NeighborEvent::HelloReceived);
    assert_eq!(n.state, NeighborState::Init);
    assert_eq!(n.on_event(NeighborEvent::InactivityTimer), NeighborState::Down);
}

#[test]
fn neighbor_table_tracks_multiple_peers() {
    let mut table = NeighborTable::new();
    table.process(ip(1, 1, 1, 1), NeighborEvent::HelloReceived);
    table.process(ip(2, 2, 2, 2), NeighborEvent::HelloReceived);
    assert_eq!(table.len(), 2);
    assert_eq!(
        table.get(&ip(1, 1, 1, 1)).unwrap().state,
        NeighborState::Init
    );
}
