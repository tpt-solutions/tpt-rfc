// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example: build a small OSPFv2 area topology and run the SPF calculation,
//! then show the resulting next-hop routing table.

use tpt_ospf::lsa::{Ip4, NetworkLsa, RouterLink, RouterLsa};
use tpt_ospf::spf::Spf;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip4 {
    [a, b, c, d]
}

fn main() {
    // A (10.0.0.1) and B (10.0.0.2) share broadcast segment 10.1.1.0/24
    // (DR = A, interface 10.1.1.1). B also reaches C (10.0.0.3) over a
    // point-to-point link.
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
        links: vec![
            RouterLink {
                link_type: 2,
                link_id: ip(10, 1, 1, 1),
                link_data: ip(10, 1, 1, 2),
                metric: 5,
            },
            RouterLink::point_to_point(ip(10, 0, 0, 3), ip(10, 0, 0, 2), 10),
        ],
    });
    spf.add_router_lsa(RouterLsa {
        header: header_for(ip(10, 0, 0, 3)),
        v: false,
        e: false,
        b: false,
        links: vec![RouterLink::point_to_point(
            ip(10, 0, 0, 2),
            ip(10, 0, 0, 3),
            10,
        )],
    });
    spf.add_network_lsa(NetworkLsa {
        header: network_header_for(ip(10, 1, 1, 1), ip(10, 0, 0, 1)),
        network_mask: ip(255, 255, 255, 0),
        attached_routers: vec![ip(10, 0, 0, 1), ip(10, 0, 0, 2)],
    });

    let table = spf.calculate().expect("SPF from root must succeed");
    println!("Routing table from {}:", fmt(ip(10, 0, 0, 1)));
    for route in table.router_routes() {
        println!(
            "  to {} via {}  cost {}",
            fmt(route.destination),
            fmt(route.next_hop),
            route.cost
        );
    }
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

fn fmt(ip: Ip4) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
