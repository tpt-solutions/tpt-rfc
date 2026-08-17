// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal authenticated + encrypted SNMPv3 agent example. Registers a USM user
//! (SHA-1 auth + AES-CFB-128 privacy) on the agent, then answers a v3 Get from a
//! manager that performs engine discovery automatically.

use tpt_snmp::agent::Agent;
use tpt_snmp::manager::Manager;
use tpt_snmp::mib::InMemoryMib;
use tpt_snmp::oid::ObjectIdentifier;
use tpt_snmp::usm::{AuthProtocol, PrivProtocol};
use tpt_snmp::value::SnmpValue;

fn main() {
    let engine_id = b"tptengine".to_vec();
    let mut mib = InMemoryMib::new();
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
        SnmpValue::from_str("tpt-snmp v3 agent"),
    );

    let mut agent = Agent::new(mib, engine_id.clone());
    agent.add_user(
        b"user",
        AuthProtocol::Sha1,
        b"authpassword",
        PrivProtocol::Aes,
        b"privpassword",
    );

    let mut mgr = Manager::v3(
        b"user",
        &engine_id,
        AuthProtocol::Sha1,
        b"authpassword",
        PrivProtocol::Aes,
        b"privpassword",
    );

    // Engine discovery (no auth, empty engine).
    let discovery =
        mgr.build_discovery_request(&ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]));
    let discovery_resp = agent.process(&discovery).expect("discovery response");
    mgr.parse_response(&discovery_resp).ok();

    // Authenticated + encrypted Get.
    let oid = ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);
    let request = mgr.build_get(&oid);
    let response = agent.process(&request).expect("agent response");
    let binds = mgr.parse_response(&response).expect("parse response");

    for vb in &binds.0 {
        let oid = vb
            .oid
            .0
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".");
        println!("{} = {:?}", oid, vb.value);
    }
}
