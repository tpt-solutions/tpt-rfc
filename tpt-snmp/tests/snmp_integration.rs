// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for `tpt-snmp`: v1/v2c round trips, v3 USM auth + privacy,
//! engine discovery, and GetBulk. Interop against a real Net-SNMP agent/manager
//! is out of scope in this environment; these tests exercise the full
//! encode → agent → decode → encode → manager → decode pipeline.

use tpt_snmp::agent::Agent;
use tpt_snmp::manager::Manager;
use tpt_snmp::mib::InMemoryMib;
use tpt_snmp::oid::ObjectIdentifier;
use tpt_snmp::pdu::{PduType, TrapV1};
use tpt_snmp::usm::{AuthProtocol, PrivProtocol};
use tpt_snmp::value::{SnmpValue, VarBind};

const ENGINE: &[u8] = b"tptengine01";

fn sample_mib() -> InMemoryMib {
    let mut mib = InMemoryMib::new();
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
        SnmpValue::from_str("tpt-snmp agent"),
    );
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 3, 0]),
        SnmpValue::TimeTicks(12345),
    );
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 4, 0]),
        SnmpValue::OctetString(b"contact@example.com".to_vec()),
    );
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
        SnmpValue::Integer(1),
    );
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2]),
        SnmpValue::Integer(2),
    );
    mib.insert(
        ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3]),
        SnmpValue::Integer(3),
    );
    mib
}

fn sys() -> ObjectIdentifier {
    ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])
}

#[test]
fn v2c_get_set_roundtrip() {
    let mut agent = Agent::new(sample_mib(), ENGINE.to_vec());
    let mut mgr = Manager::v2c(b"public");

    let req = mgr.build_get(&sys());
    let resp = agent.process(&req).expect("response");
    let binds = mgr.parse_response(&resp).unwrap();
    assert_eq!(binds.0[0].value, SnmpValue::from_str("tpt-snmp agent"));

    // Set a new value and read it back.
    let oid = ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 4, 0]);
    let set_req = mgr.build_set(VarBind::new(
        oid.clone(),
        SnmpValue::from_str("new-contact"),
    ));
    let set_resp = agent.process(&set_req).expect("response");
    mgr.parse_response(&set_resp).unwrap();
    let get_req = mgr.build_get(&oid);
    let get_resp = agent.process(&get_req).expect("response");
    let binds = mgr.parse_response(&get_resp).unwrap();
    assert_eq!(binds.0[0].value, SnmpValue::from_str("new-contact"));
}

#[test]
fn v2c_getnext_and_missing() {
    let mut agent = Agent::new(sample_mib(), ENGINE.to_vec());
    let mut mgr = Manager::v2c(b"public");

    let req = mgr.build_get_next(&ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1]));
    let resp = agent.process(&req).expect("response");
    let binds = mgr.parse_response(&resp).unwrap();
    assert_eq!(binds.0[0].oid, sys());

    // A missing OID returns noSuchObject in v2c semantics.
    let missing = ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 99, 0]);
    let req = mgr.build_get(&missing);
    let resp = agent.process(&req).expect("response");
    let binds = mgr.parse_response(&resp).unwrap();
    assert_eq!(binds.0[0].value, SnmpValue::NoSuchObject);
}

#[test]
fn v2c_getbulk() {
    let mut agent = Agent::new(sample_mib(), ENGINE.to_vec());
    let mut mgr = Manager::v2c(b"public");

    // Non-repeating: sysDescr.0 ; repeating: the ifIndex column.
    let non_rep = vec![ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])];
    let rep = vec![ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 1])];
    let req = mgr.build_get_bulk(&rep, &non_rep, 10);
    let resp = agent.process(&req).expect("response");
    let binds = mgr.parse_response(&resp).unwrap();
    // 1 non-repeating + up to 3 repeating instances.
    assert_eq!(binds.0.len(), 4);
    assert_eq!(binds.0[0].oid, sys());
    assert_eq!(binds.0[1].value, SnmpValue::Integer(1));
    assert_eq!(binds.0[3].value, SnmpValue::Integer(3));
}

#[test]
fn v1_trap_roundtrip() {
    use tpt_snmp::pdu::{Message, MessageData, SnmpVersion};
    let trap = TrapV1 {
        enterprise: ObjectIdentifier::new(vec![1, 3, 6, 1, 4, 1, 123]),
        agent_address: [10, 0, 0, 1],
        generic_trap: 6,
        specific_trap: 42,
        time_stamp: 9999,
        varbinds: tpt_snmp::value::VarBindList(vec![VarBind::new(
            ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
            SnmpValue::from_str("trap"),
        )]),
    };
    let msg = Message {
        version: SnmpVersion::V1,
        community: b"public".to_vec(),
        data: MessageData::TrapV1(trap.clone()),
    };
    let bytes = msg.encode();
    let decoded = Message::decode(&bytes).unwrap();
    assert_eq!(decoded.data, MessageData::TrapV1(trap));
}

fn v3_roundtrip(auth: AuthProtocol, priv_proto: PrivProtocol) {
    let mut agent = Agent::new(sample_mib(), ENGINE.to_vec());
    agent.add_user(b"user", auth, b"authpassword", priv_proto, b"privpassword");
    // discovery first: learn engine identity
    let mut mgr = Manager::v3(
        b"user",
        ENGINE,
        auth,
        b"authpassword",
        priv_proto,
        b"privpassword",
    );
    let disc = mgr.build_discovery_request(&sys());
    let disc_resp = agent.process(&disc).expect("discovery response");
    // parse but ignore varbinds; the engine identity is recorded
    let _ = mgr.parse_response(&disc_resp);

    let req = mgr.build_get(&sys());
    let resp = agent.process(&req).expect("response");
    let binds = mgr.parse_response(&resp).unwrap();
    assert_eq!(binds.0[0].value, SnmpValue::from_str("tpt-snmp agent"));
}

#[test]
fn v3_md5_auth() {
    v3_roundtrip(AuthProtocol::Md5, PrivProtocol::None);
}

#[test]
fn v3_sha1_auth() {
    v3_roundtrip(AuthProtocol::Sha1, PrivProtocol::None);
}

#[test]
fn v3_md5_auth_des_priv() {
    v3_roundtrip(AuthProtocol::Md5, PrivProtocol::Des);
}

#[test]
fn v3_sha1_auth_aes_priv() {
    v3_roundtrip(AuthProtocol::Sha1, PrivProtocol::Aes);
}

#[test]
fn v3_auth_failure_rejected() {
    let mut agent = Agent::new(sample_mib(), ENGINE.to_vec());
    agent.add_user(
        b"user",
        AuthProtocol::Sha1,
        b"rightpass",
        PrivProtocol::None,
        b"",
    );
    // Manager uses a different password -> auth parameters will not verify.
    let mut mgr = Manager::v3(
        b"user",
        ENGINE,
        AuthProtocol::Sha1,
        b"wrongpass",
        PrivProtocol::None,
        b"",
    );
    let req = mgr.build_get(&sys());
    let resp = agent.process(&req);
    assert!(resp.is_none(), "agent must drop messages with bad auth");
}

#[test]
fn v3_unknown_user_noauth_discovery() {
    let mut agent = Agent::new(sample_mib(), ENGINE.to_vec());
    let mut mgr = Manager::v3(
        b"ghost",
        ENGINE,
        AuthProtocol::Sha1,
        b"x",
        PrivProtocol::None,
        b"",
    );
    let disc = mgr.build_discovery_request(&sys());
    let resp = agent.process(&disc).expect("reportable discovery reply");
    let _ = mgr.parse_response(&resp);
    assert_eq!(mgr.engine_id(), ENGINE);
}

#[test]
fn pdu_type_tag_mapping() {
    assert_eq!(PduType::GetRequest.tag(), 0xA0);
    assert_eq!(PduType::GetBulkRequest.tag(), 0xA5);
    assert_eq!(PduType::Report.tag(), 0xA8);
    assert!(PduType::from_tag(0xA4).is_err()); // v1 trap is not a standard PDU
}
