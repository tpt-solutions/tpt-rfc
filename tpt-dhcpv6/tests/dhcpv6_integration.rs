// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end and wire-codec conformance tests for `tpt-dhcpv6`.

use std::net::Ipv6Addr;

use tpt_dhcpv6::client::{Client, ClientState};
use tpt_dhcpv6::lease::LeaseStore;
use tpt_dhcpv6::memory::PoolConfig;
use tpt_dhcpv6::message::Dhcpv6Message;
use tpt_dhcpv6::options::{
    Dhcpv6Option, Duid, IaNa, IaPd, IaPrefix, MessageType, OPTION_DNS_SERVERS,
    OPTION_DOMAIN_SEARCH, STATUS_SUCCESS,
};
use tpt_dhcpv6::server::Server;

fn client_duid() -> Duid {
    Duid::from_ethernet_ll(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
}

fn mac(n: u8) -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, 0x00, n]
}

/// Drive the full SOLICIT → ADVERTISE → REQUEST → REPLY exchange on `server`
/// and assert the client ends up `Bound` with a single address and the
/// advertised configuration.
fn bound_exchange<S: tpt_dhcpv6::lease::LeaseStore>(
    server: &mut Server<S>,
    client: &mut Client,
) -> Ipv6Addr {
    let solicit = client.start_solicit();
    let adv_bytes = server.process_bytes(&solicit.to_bytes()).unwrap().unwrap();
    let adv = Dhcpv6Message::from_bytes(&adv_bytes).unwrap();
    assert_eq!(adv.msg_type, MessageType::Advertise);
    let request = client.receive_advertise(&adv).expect("request");
    let reply_bytes = server.process_bytes(&request.to_bytes()).unwrap().unwrap();
    let reply = Dhcpv6Message::from_bytes(&reply_bytes).unwrap();
    assert_eq!(reply.msg_type, MessageType::Reply);
    client.receive_reply(&reply).expect("bind");
    assert_eq!(client.state(), ClientState::Bound);
    client.lease().unwrap().addresses[0].0
}

#[test]
fn wire_round_trip_solicit() {
    let mut msg = Dhcpv6Message::new(MessageType::Solicit);
    msg.transaction_id = [0x01, 0x02, 0x03];
    msg.set_option(Dhcpv6Option::ClientId(client_duid()));
    msg.set_option(Dhcpv6Option::ElapsedTime(0));
    msg.set_option(Dhcpv6Option::IaNa(IaNa {
        iaid: 1,
        t1: 0,
        t2: 0,
        options: vec![],
    }));
    msg.set_option(Dhcpv6Option::Oro(vec![
        OPTION_DNS_SERVERS,
        OPTION_DOMAIN_SEARCH,
    ]));

    let bytes = msg.to_bytes();
    let decoded = Dhcpv6Message::from_bytes(&bytes).expect("decode");

    assert_eq!(decoded.msg_type, MessageType::Solicit);
    assert_eq!(decoded.transaction_id, [0x01, 0x02, 0x03]);
    assert_eq!(decoded.client_id(), Some(&client_duid()));
    assert_eq!(decoded.ia_nas().len(), 1);
    assert_eq!(decoded.ia_nas()[0].iaid, 1);
    assert_eq!(
        decoded.oro(),
        Some(&[OPTION_DNS_SERVERS, OPTION_DOMAIN_SEARCH][..])
    );
}

#[test]
fn unknown_option_preserved() {
    let mut msg = Dhcpv6Message::new(MessageType::Solicit);
    msg.set_option(Dhcpv6Option::Other(99, vec![1, 2, 3]));
    let decoded = Dhcpv6Message::from_bytes(&msg.to_bytes()).unwrap();
    match decoded.find_option(99) {
        Some(Dhcpv6Option::Other(c, v)) => {
            assert_eq!(*c, 99);
            assert_eq!(v, &vec![1, 2, 3]);
        }
        other => panic!("expected Other(99, ..), got {:?}", other),
    }
}

#[test]
fn full_solicit_advertise_request_reply() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(client_duid());

    let ip = bound_exchange(&mut server, &mut client);
    assert_eq!(ip, Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x10));

    let lease = client.lease().unwrap();
    assert_eq!(lease.dns_servers.len(), 1);
    assert_eq!(
        lease.dns_servers[0],
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x53)
    );
    assert_eq!(lease.domain_search, vec!["example.local".to_string()]);
    assert_eq!(lease.t1, 1800);
    assert_eq!(lease.t2, 2880);
}

#[test]
fn renewal_extends_lease() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(client_duid());
    bound_exchange(&mut server, &mut client);

    let renew = client.start_renew().expect("renew request");
    assert_eq!(client.state(), ClientState::Renewing);
    let reply =
        Dhcpv6Message::from_bytes(&server.process_bytes(&renew.to_bytes()).unwrap().unwrap())
            .unwrap();
    assert_eq!(reply.msg_type, MessageType::Reply);
    client.receive_reply(&reply).expect("renew commit");
    assert_eq!(client.state(), ClientState::Bound);
}

#[test]
fn release_frees_ia() {
    let config = PoolConfig::default();
    let mut server = Server::new(config.clone());
    let mut client = Client::new(client_duid());
    let _ip = bound_exchange(&mut server, &mut client);

    let release = client.release().expect("release");
    assert_eq!(client.state(), ClientState::Releasing);
    let reply =
        Dhcpv6Message::from_bytes(&server.process_bytes(&release.to_bytes()).unwrap().unwrap())
            .unwrap();
    assert_eq!(reply.msg_type, MessageType::Reply);
    client.receive_reply(&reply).expect("release commit");
    assert_eq!(client.state(), ClientState::Init);

    // The IA is gone from the store.
    assert!(server
        .store()
        .lease_for(&client_duid(), 1, tpt_dhcpv6::options::IaKind::Na)
        .is_none());
}

#[test]
fn decline_marks_address_unusable() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(client_duid());
    let ip = bound_exchange(&mut server, &mut client);

    // Client detects a conflict and declines.
    let decline = client.decline().expect("decline");
    assert_eq!(client.state(), ClientState::Declining);
    let reply =
        Dhcpv6Message::from_bytes(&server.process_bytes(&decline.to_bytes()).unwrap().unwrap())
            .unwrap();
    assert_eq!(reply.msg_type, MessageType::Reply);
    client.receive_reply(&reply).expect("decline commit");
    assert_eq!(client.state(), ClientState::Init);

    // A fresh client must not be handed the declined address (gets the next one).
    let mut client2 = Client::new(Duid::from_ethernet_ll(&mac(2)));
    let ip2 = bound_exchange(&mut server, &mut client2);
    assert_ne!(ip2, ip);
}

#[test]
fn information_request_gets_config_only() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(client_duid());

    let info = client.information_request();
    assert_eq!(info.msg_type, MessageType::InformationRequest);
    let reply =
        Dhcpv6Message::from_bytes(&server.process_bytes(&info.to_bytes()).unwrap().unwrap())
            .unwrap();
    assert_eq!(reply.msg_type, MessageType::Reply);
    assert!(reply.server_id().is_some());
    assert!(reply.ia_nas().is_empty());
    assert!(reply.find_option(OPTION_DNS_SERVERS).is_some());

    client.receive_reply(&reply).expect("info commit");
    assert_eq!(client.state(), ClientState::Bound);
    // INFORMATION-REQUEST must not grant any addresses.
    assert!(client.lease().unwrap().addresses.is_empty());
    assert!(!client.lease().unwrap().dns_servers.is_empty());
}

#[test]
fn request_for_other_server_is_ignored() {
    let mut server_a = Server::new(PoolConfig::default());
    let config_b = PoolConfig {
        server_duid: Duid::Ll {
            hardware_type: 1,
            link_layer: vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        },
        ..Default::default()
    };
    let mut server_b = Server::new(config_b);

    let mut client = Client::new(client_duid());
    let solicit = client.start_solicit();
    let adv_a = Dhcpv6Message::from_bytes(
        &server_a
            .process_bytes(&solicit.to_bytes())
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let request = client.receive_advertise(&adv_a).unwrap();

    // Server B receives a REQUEST whose Server Identifier points at A.
    let reply = server_b.process_bytes(&request.to_bytes()).unwrap();
    assert!(reply.is_none());
}

#[test]
fn prefix_delegation_allocates_ia_pd() {
    let config = PoolConfig::default();
    let mut server = Server::new(config.clone());

    let mut msg = Dhcpv6Message::new(MessageType::Solicit);
    msg.transaction_id = [0xAA, 0xBB, 0xCC];
    msg.set_option(Dhcpv6Option::ClientId(client_duid()));
    msg.set_option(Dhcpv6Option::ElapsedTime(0));
    msg.set_option(Dhcpv6Option::IaPd(IaPd {
        iaid: 7,
        t1: 0,
        t2: 0,
        options: vec![],
    }));

    let reply = Dhcpv6Message::from_bytes(&server.process_bytes(&msg.to_bytes()).unwrap().unwrap())
        .unwrap();
    assert_eq!(reply.msg_type, MessageType::Advertise);
    let pds: Vec<&IaPd> = reply.ia_pds();
    assert_eq!(pds.len(), 1);
    let prefixes: Vec<&IaPrefix> = pds[0]
        .options
        .iter()
        .filter_map(|o| match o {
            Dhcpv6Option::IaPrefix(p) => Some(p),
            _ => None,
        })
        .collect();
    assert_eq!(prefixes.len(), 1);
    assert_eq!(prefixes[0].prefix_length, 64);
    // The delegated prefix base must sit inside the configured PD pool.
    assert!(
        u128::from(prefixes[0].prefix) >= u128::from(config.pd_pool_start)
            && u128::from(prefixes[0].prefix) <= u128::from(config.pd_pool_end)
    );

    // Request and confirm the prefix.
    let mut request = Dhcpv6Message::new(MessageType::Request);
    request.transaction_id = [0xAA, 0xBB, 0xCC];
    request.set_option(Dhcpv6Option::ClientId(client_duid()));
    request.set_option(Dhcpv6Option::ServerId(server.config().server_duid.clone()));
    let prefix_opts: Vec<Dhcpv6Option> = pds[0]
        .options
        .iter()
        .filter(|o| matches!(o, Dhcpv6Option::IaPrefix(_)))
        .cloned()
        .collect();
    request.set_option(Dhcpv6Option::IaPd(IaPd {
        iaid: 7,
        t1: 0,
        t2: 0,
        options: prefix_opts,
    }));

    let reply2 =
        Dhcpv6Message::from_bytes(&server.process_bytes(&request.to_bytes()).unwrap().unwrap())
            .unwrap();
    assert_eq!(reply2.msg_type, MessageType::Reply);
    assert_eq!(reply2.ia_pds().len(), 1);
}

#[test]
fn confirm_succeeds_when_on_link() {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    let mut client = Client::new(client_duid());
    bound_exchange(&mut server, &mut client);

    let mut confirm = Dhcpv6Message::new(MessageType::Confirm);
    confirm.transaction_id = [0x11, 0x22, 0x33];
    confirm.set_option(Dhcpv6Option::ClientId(client_duid()));
    confirm.set_option(Dhcpv6Option::IaNa(IaNa {
        iaid: 1,
        t1: 0,
        t2: 0,
        options: vec![],
    }));

    let reply =
        Dhcpv6Message::from_bytes(&server.process_bytes(&confirm.to_bytes()).unwrap().unwrap())
            .unwrap();
    assert_eq!(reply.msg_type, MessageType::Reply);
    let (code, _) = reply.status_code().expect("status code");
    assert_eq!(code, STATUS_SUCCESS);
}
