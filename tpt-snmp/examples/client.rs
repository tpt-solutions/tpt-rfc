// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal SNMPv2c manager example: build a GetRequest, feed it to an agent,
//! and print the response bindings. Demonstrates the transport-agnostic
//! `Manager`/`Agent` API over in-memory bytes (swap in a UDP socket in practice).

use tpt_snmp::agent::Agent;
use tpt_snmp::manager::Manager;
use tpt_snmp::mib::InMemoryMib;
use tpt_snmp::oid::ObjectIdentifier;
use tpt_snmp::value::SnmpValue;

fn main() {
    let mut mib = InMemoryMib::new();
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
        SnmpValue::from_str("tpt-snmp agent"),
    );

    let mut agent = Agent::new(mib, b"tptengine".to_vec());
    let mut mgr = Manager::v2c(b"public");

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
