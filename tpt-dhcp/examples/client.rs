// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example DHCP client. Because real DHCP uses broadcast and raw sockets, this
//! example drives the [`tpt_dhcp::client::Client`] FSM against an in-process
//! server to show the full DISCOVER/OFFER/REQUEST/ACK exchange.

use std::net::Ipv4Addr;

use tpt_dhcp::client::Client;
use tpt_dhcp::memory::PoolConfig;
use tpt_dhcp::message::DhcpMessage;
use tpt_dhcp::server::Server;

fn main() {
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(mac);

    // Client broadcasts a DISCOVER.
    let discover = client.start_discover();
    let offer = DhcpMessage::from_bytes(
        &server
            .process_bytes(&discover.to_bytes())
            .expect("decode offer")
            .expect("offer reply"),
    )
    .expect("parse offer");
    println!(
        "OFFER: server {} offers {}",
        offer.server_identifier().unwrap(),
        offer.yiaddr
    );

    // Client accepts and sends a REQUEST.
    let request = client.receive_offer(&offer).expect("request");
    let ack = DhcpMessage::from_bytes(
        &server
            .process_bytes(&request.to_bytes())
            .expect("decode ack")
            .expect("ack reply"),
    )
    .expect("parse ack");
    client.receive_ack(&ack).expect("bind");

    let lease = client.lease().expect("lease");
    println!(
        "BOUND: {} for {}s (renew at {}, rebind at {}), server {}",
        lease.ip, lease.lease_time, lease.renewal_time, lease.rebinding_time, lease.server_id
    );
    assert_eq!(lease.ip, Ipv4Addr::new(192, 168, 1, 10));
}
