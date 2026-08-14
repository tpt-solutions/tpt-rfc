// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end and wire-codec conformance tests for `tpt-dhcp`.

use std::net::Ipv4Addr;

use tpt_dhcp::client::{Client, ClientState};
use tpt_dhcp::lease::LeaseStore;
use tpt_dhcp::memory::PoolConfig;
use tpt_dhcp::message::{DhcpMessage, MessageOp};
use tpt_dhcp::options::{DhcpOption, MessageType};
use tpt_dhcp::server::Server;

fn mac(n: u8) -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, 0x00, n]
}

/// Build a minimal client DISCOVER by hand (exercises the message codec
/// directly, not just the client helper).
fn manual_discover(xid: u32, m: [u8; 6]) -> DhcpMessage {
    let mut msg = DhcpMessage::new();
    msg.op = MessageOp::BootRequest;
    msg.set_chaddr(&m);
    msg.xid = xid;
    msg.flags = 0x8000;
    msg.set_option(DhcpOption::MessageType(MessageType::Discover));
    msg.set_option(DhcpOption::ClientIdentifier(vec![1, 2, 3, 4, 5, 6]));
    msg.set_option(DhcpOption::ParameterRequestList(vec![
        tpt_dhcp::options::CODE_SUBNET_MASK,
        tpt_dhcp::options::CODE_ROUTER,
    ]));
    msg
}

#[test]
fn wire_round_trip_discover() {
    let msg = manual_discover(0xDEAD_BEEF, mac(1));
    let bytes = msg.to_bytes();
    let decoded = DhcpMessage::from_bytes(&bytes).expect("decode");

    assert_eq!(decoded.op, MessageOp::BootRequest);
    assert_eq!(decoded.xid, 0xDEAD_BEEF);
    assert_eq!(decoded.flags, 0x8000);
    assert_eq!(decoded.mac(), &mac(1));
    assert_eq!(decoded.message_type(), Some(MessageType::Discover));
    assert_eq!(decoded.client_identifier(), Some(&[1, 2, 3, 4, 5, 6][..]));
    // The option-less request list is preserved through decode.
    assert!(decoded
        .find_option(tpt_dhcp::options::CODE_PARAMETER_REQUEST_LIST)
        .is_some());
}

#[test]
fn magic_cookie_required() {
    let msg = manual_discover(1, mac(2));
    let mut bytes = msg.to_bytes();
    // Corrupt the magic cookie.
    bytes[236] ^= 0xFF;
    assert!(DhcpMessage::from_bytes(&bytes).is_err());
}

#[test]
fn unknown_option_preserved() {
    let mut msg = DhcpMessage::new();
    msg.set_option(DhcpOption::Other(99, vec![1, 2, 3]));
    let decoded = DhcpMessage::from_bytes(&msg.to_bytes()).unwrap();
    match decoded.find_option(99) {
        Some(DhcpOption::Other(c, v)) => {
            assert_eq!(*c, 99);
            assert_eq!(v, &vec![1, 2, 3]);
        }
        other => panic!("expected Other(99, ..), got {:?}", other),
    }
}

/// Drive the full DISCOVER → OFFER → REQUEST → ACK exchange on `server` and
/// assert the client ends up `Bound` with the expected lease.
fn bound_exchange<S: LeaseStore>(server: &mut Server<S>, client: &mut Client) -> Ipv4Addr {
    let discover = client.start_discover();
    let offer_bytes = server.process_bytes(&discover.to_bytes()).unwrap().unwrap();
    let offer = DhcpMessage::from_bytes(&offer_bytes).unwrap();
    assert_eq!(offer.message_type(), Some(MessageType::Offer));
    let request = client.receive_offer(&offer).unwrap();
    let ack_bytes = server.process_bytes(&request.to_bytes()).unwrap().unwrap();
    let ack = DhcpMessage::from_bytes(&ack_bytes).unwrap();
    assert_eq!(ack.message_type(), Some(MessageType::Ack));
    client.receive_ack(&ack).unwrap();
    assert_eq!(client.state(), ClientState::Bound);
    client.lease().unwrap().ip
}

#[test]
fn full_discover_offer_request_ack() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(mac(10));
    let ip = bound_exchange(&mut server, &mut client);
    assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 10));
    // The granted lease carries the pool's default duration.
    assert_eq!(client.lease().unwrap().lease_time, 3600);
    assert_eq!(
        client.lease().unwrap().server_id,
        Ipv4Addr::new(192, 168, 1, 1)
    );
}

#[test]
fn renewal_extends_lease() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(mac(11));
    bound_exchange(&mut server, &mut client);

    let renew = client.start_renew().expect("renew request");
    assert_eq!(client.state(), ClientState::Renewing);
    let ack = server.process_bytes(&renew.to_bytes()).unwrap().unwrap();
    client
        .receive_ack(&DhcpMessage::from_bytes(&ack).unwrap())
        .unwrap();
    assert_eq!(client.state(), ClientState::Bound);
}

#[test]
fn release_frees_address() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(mac(12));
    let ip = bound_exchange(&mut server, &mut client);

    let release = client.release().expect("release");
    assert_eq!(client.state(), ClientState::Init);
    // Server has nothing to reply to a RELEASE.
    let reply = server.process_bytes(&release.to_bytes()).unwrap();
    assert!(reply.is_none());
    assert!(server.store().lease_for(ip).is_none());
}

#[test]
fn decline_marks_address_unusable() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(mac(13));
    let ip = bound_exchange(&mut server, &mut client);

    // Client detects a conflict on its address and sends DECLINE.
    let mut decline = DhcpMessage::new();
    decline.set_chaddr(&mac(13));
    decline.set_option(DhcpOption::MessageType(MessageType::Decline));
    decline.set_option(DhcpOption::RequestedIpAddress(ip));
    let reply = server.process_bytes(&decline.to_bytes()).unwrap();
    assert!(reply.is_none());
    assert!(server.store().lease_for(ip).is_none());

    // A fresh client must not be handed the declined address.
    let mut client2 = Client::new(mac(14));
    let ip2 = bound_exchange(&mut server, &mut client2);
    assert_ne!(ip2, ip);
}

#[test]
fn request_for_other_server_is_ignored() {
    let mut server_a = Server::new(PoolConfig::default());
    let server_b_ip = Ipv4Addr::new(10, 0, 0, 1);
    let cfg_b = PoolConfig {
        server_ip: server_b_ip,
        ..Default::default()
    };
    let mut server_b = Server::new(cfg_b);

    let mut client = Client::new(mac(15));
    let discover = client.start_discover();
    let offer_a = DhcpMessage::from_bytes(
        &server_a
            .process_bytes(&discover.to_bytes())
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let request = client.receive_offer(&offer_a).unwrap();

    // Server B receives a REQUEST whose Server Identifier points at A.
    let reply = server_b.process_bytes(&request.to_bytes()).unwrap();
    assert!(reply.is_none());
}

#[test]
fn inform_gets_config_only() {
    let config = PoolConfig::default();
    let mut server = Server::new(config.clone());

    let mut inform = DhcpMessage::new();
    inform.set_chaddr(&mac(16));
    inform.ciaddr = Ipv4Addr::new(192, 168, 1, 50);
    inform.set_option(DhcpOption::MessageType(MessageType::Inform));
    inform.set_option(DhcpOption::ParameterRequestList(vec![
        tpt_dhcp::options::CODE_SUBNET_MASK,
        tpt_dhcp::options::CODE_DOMAIN_NAME_SERVER,
    ]));

    let ack = DhcpMessage::from_bytes(&server.process_bytes(&inform.to_bytes()).unwrap().unwrap())
        .unwrap();
    assert_eq!(ack.message_type(), Some(MessageType::Ack));
    // INFORM must not assign an address.
    assert_eq!(ack.yiaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(ack.server_identifier(), Some(config.server_ip));
    assert!(ack
        .find_option(tpt_dhcp::options::CODE_SUBNET_MASK)
        .is_some());
}

#[test]
fn init_reboot_ack_or_nak() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(mac(17));
    let ip = bound_exchange(&mut server, &mut client);

    // Client reboots and immediately REQUESTs its old address (INIT-REBOOT):
    // ciaddr set, no Server Identifier, no Requested IP.
    let mut reboot = DhcpMessage::new();
    reboot.set_chaddr(&mac(17));
    reboot.ciaddr = ip;
    reboot.set_option(DhcpOption::MessageType(MessageType::Request));
    reboot.set_option(DhcpOption::ClientIdentifier(mac(17).to_vec()));

    let ack = DhcpMessage::from_bytes(&server.process_bytes(&reboot.to_bytes()).unwrap().unwrap())
        .unwrap();
    assert_eq!(ack.message_type(), Some(MessageType::Ack));
}
