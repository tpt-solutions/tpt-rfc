// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example DHCPv6 client. Because real DHCPv6 uses multicast and raw sockets, this
//! example drives the [`tpt_dhcpv6::client::Client`] FSM against an in-process
//! server to show the full SOLICIT/ADVERTISE/REQUEST/REPLY exchange and a
//! stateless INFORMATION-REQUEST.

use tpt_dhcpv6::client::Client;
use tpt_dhcpv6::memory::PoolConfig;
use tpt_dhcpv6::message::Dhcpv6Message;
use tpt_dhcpv6::options::Duid;
use tpt_dhcpv6::server::Server;

fn main() {
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(Duid::from_ethernet_ll(&mac));

    // Client multicasts a SOLICIT.
    let solicit = client.start_solicit();
    let advertise = Dhcpv6Message::from_bytes(
        &server
            .process_bytes(&solicit.to_bytes())
            .expect("decode advertise")
            .expect("advertise reply"),
    )
    .expect("parse advertise");
    println!("ADVERTISE from server DUID {:?}", advertise.server_id());

    // Client accepts and sends a REQUEST.
    let request = client.receive_advertise(&advertise).expect("request");
    let reply = Dhcpv6Message::from_bytes(
        &server
            .process_bytes(&request.to_bytes())
            .expect("decode reply")
            .expect("reply"),
    )
    .expect("parse reply");
    client.receive_reply(&reply).expect("bind");

    let lease = client.lease().expect("lease");
    println!(
        "BOUND: {} for {}s (renew at {}, rebind at {})",
        lease.addresses[0].0, lease.addresses[0].2, lease.t1, lease.t2
    );
    println!("DNS servers: {:?}", lease.dns_servers);

    // Stateless configuration: request only DNS/search options.
    let mut stateless = Client::new(Duid::from_ethernet_ll(&[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
    ]));
    let info = stateless.information_request();
    let info_reply =
        Dhcpv6Message::from_bytes(&server.process_bytes(&info.to_bytes()).unwrap().unwrap())
            .unwrap();
    stateless.receive_reply(&info_reply).unwrap();
    println!(
        "INFORMATION-REQUEST: domain search {:?}",
        stateless.lease().unwrap().domain_search
    );
}
