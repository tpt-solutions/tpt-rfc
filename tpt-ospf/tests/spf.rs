// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dijkstra SPF tests over hand-verified topologies.

use tpt_ospf::lsa::{Ip4, NetworkLsa, RouterLink, RouterLsa};
use tpt_ospf::spf::Spf;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip4 {
    [a, b, c, d]
}

#[test]
fn point_to_point_chain() {
    // A -10- B -10- C -10- D, plus a stub on A.
    let mut spf = Spf::new(ip(10, 0, 0, 1));
    spf.add_router_lsa(RouterLsa {
        header: header_for(ip(10, 0, 0, 1)),
        v: false,
        e: false,
        b: false,
        links: vec![
            RouterLink::point_to_point(ip(10, 0, 0, 2), ip(10, 0, 0, 1), 10),
            RouterLink::stub(ip(192, 168, 1, 0), ip(255, 255, 255, 0), 1),
        ],
    });
    spf.add_router_lsa(RouterLsa {
        header: header_for(ip(10, 0, 0, 2)),
        v: false,
        e: false,
        b: false,
        links: vec![
            RouterLink::point_to_point(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 10),
            RouterLink::point_to_point(ip(10, 0, 0, 3), ip(10, 0, 0, 2), 10),
        ],
    });
    spf.add_router_lsa(RouterLsa {
        header: header_for(ip(10, 0, 0, 3)),
        v: false,
        e: false,
        b: false,
        links: vec![
            RouterLink::point_to_point(ip(10, 0, 0, 2), ip(10, 0, 0, 3), 10),
            RouterLink::point_to_point(ip(10, 0, 0, 4), ip(10, 0, 0, 3), 10),
        ],
    });
    spf.add_router_lsa(RouterLsa {
        header: header_for(ip(10, 0, 0, 4)),
        v: false,
        e: false,
        b: false,
        links: vec![RouterLink::point_to_point(
            ip(10, 0, 0, 3),
            ip(10, 0, 0, 4),
            10,
        )],
    });

    let table = spf.calculate().unwrap();

    // Next hops propagate to the first-hop router.
    assert_eq!(table.next_hop(ip(10, 0, 0, 2)), Some(ip(10, 0, 0, 2)));
    assert_eq!(table.next_hop(ip(10, 0, 0, 3)), Some(ip(10, 0, 0, 2)));
    assert_eq!(table.next_hop(ip(10, 0, 0, 4)), Some(ip(10, 0, 0, 2)));

    // Costs accumulate along the chain.
    assert_eq!(table.cost_to(ip(10, 0, 0, 2)), Some(10));
    assert_eq!(table.cost_to(ip(10, 0, 0, 3)), Some(20));
    assert_eq!(table.cost_to(ip(10, 0, 0, 4)), Some(30));

    // The tree is built in increasing-cost order: A, B, C, D.
    assert_eq!(
        table.tree_order(),
        &[
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            ip(10, 0, 0, 3),
            ip(10, 0, 0, 4)
        ]
    );

    // Stub network on A is reachable directly.
    let stub = table
        .stub_routes()
        .iter()
        .find(|s| s.network == ip(192, 168, 1, 0))
        .unwrap();
    assert_eq!(stub.cost, 1);
    assert_eq!(stub.next_hop, ip(10, 0, 0, 1));
}

#[test]
fn broadcast_network() {
    // A (DR) and B on 10.1.1.0/24. A is the DR with interface 10.1.1.1.
    let mut spf = Spf::new(ip(10, 0, 0, 1));
    spf.add_router_lsa(RouterLsa {
        header: header_for(ip(10, 0, 0, 1)),
        v: false,
        e: false,
        b: false,
        links: vec![RouterLink {
            link_type: 2, // transit
            link_id: ip(10, 1, 1, 1),
            link_data: ip(10, 1, 1, 1),
            metric: 5,
        }],
    });
    spf.add_router_lsa(RouterLsa {
        header: header_for(ip(10, 0, 0, 2)),
        v: false,
        e: false,
        b: false,
        links: vec![RouterLink {
            link_type: 2,
            link_id: ip(10, 1, 1, 1),
            link_data: ip(10, 1, 1, 2),
            metric: 5,
        }],
    });
    spf.add_network_lsa(NetworkLsa {
        header: network_header_for(ip(10, 1, 1, 1), ip(10, 0, 0, 1)),
        network_mask: ip(255, 255, 255, 0),
        attached_routers: vec![ip(10, 0, 0, 1), ip(10, 0, 0, 2)],
    });

    let table = spf.calculate().unwrap();
    // B is reached through the broadcast network; the first hop is the DR (A).
    assert_eq!(table.next_hop(ip(10, 0, 0, 2)), Some(ip(10, 0, 0, 1)));
    assert_eq!(table.cost_to(ip(10, 0, 0, 2)), Some(5));
}

fn header_for(adv: Ip4) -> tpt_ospf::lsa::LsaHeader {
    let mut h = tpt_ospf::lsa::LsaHeader::router(adv, 0x02);
    h.sequence_number = 0x8000_0001;
    h
}

fn network_header_for(link_state_id: Ip4, adv: Ip4) -> tpt_ospf::lsa::LsaHeader {
    let mut h = tpt_ospf::lsa::LsaHeader::network(adv, 0x02);
    h.link_state_id = link_state_id;
    h.sequence_number = 0x8000_0001;
    h
}
