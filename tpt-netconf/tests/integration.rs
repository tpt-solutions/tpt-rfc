// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end NETCONF-over-SSH integration test.
//!
//! Exercises the full path: SSH handshake -> `netconf` subsystem request ->
//! `<hello>` capability exchange -> `<get-config>`, `<edit-config>`, another
//! `<get-config>` to observe the edit, and finally `<close-session>`. The client
//! and server run as separate threads over in-process byte pipes, mirroring the
//! transport model used for real sockets.

use std::sync::mpsc;
use std::thread;

use tpt_netconf::client::NetconfSshClient;
use tpt_netconf::message::{DatastoreName, EditDefaultOp, Operation, ReplyResult};
use tpt_netconf::server::{serve_ssh_session, InMemoryDatastore};
use tpt_netconf::xml::Xml;
use tpt_ssh::session::{handshake, EncryptedConn};

#[test]
fn full_netconf_session_over_ssh() {
    let (mut client_conn, mut server_conn) = handshake();

    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();

    let server_thread = thread::spawn(move || {
        let mut store = InMemoryDatastore::new();
        store.seed(
            DatastoreName::Running,
            vec![Xml::new("system").child(Xml::new("hostname").text("router-a"))],
        );
        let mut pump = |this: &mut EncryptedConn| {
            if this.pending_len() > 0 {
                let _ = s2c_tx.send(this.take_pending());
            }
            while let Ok(b) = c2s_rx.try_recv() {
                this.feed_recv(&b);
            }
        };
        serve_ssh_session(&mut server_conn, &mut pump, &mut store, 1234).unwrap();
    });

    let mut pump_c = |this: &mut EncryptedConn| {
        if this.pending_len() > 0 {
            let _ = c2s_tx.send(this.take_pending());
        }
        while let Ok(b) = s2c_rx.try_recv() {
            this.feed_recv(&b);
        }
    };

    let mut nc = NetconfSshClient::connect(&mut client_conn, &mut pump_c).unwrap();

    // get-config running should report the seeded hostname.
    let reply = nc
        .rpc(
            &mut client_conn,
            &mut pump_c,
            Operation::GetConfig {
                source: DatastoreName::Running,
            },
        )
        .unwrap();
    match &reply.result {
        ReplyResult::Data(data) => {
            assert!(data.children.iter().any(|c| c.local_name() == "system"));
            let sys = data.child_named("system").unwrap();
            assert_eq!(sys.child_named("hostname").unwrap().text_content(), "router-a");
        }
        other => panic!("expected data, got {other:?}"),
    }

    // edit-config: add an interface node (merge).
    let cfg = Xml::new("config").child(
        Xml::new("interfaces").child(Xml::new("interface").text("eth0")),
    );
    let edit = nc
        .rpc(
            &mut client_conn,
            &mut pump_c,
            Operation::EditConfig {
                target: DatastoreName::Running,
                default_op: EditDefaultOp::Merge,
                config: cfg,
            },
        )
        .unwrap();
    assert_eq!(edit.result, ReplyResult::Ok);

    // get-config running again should now include the interface.
    let reply = nc
        .rpc(
            &mut client_conn,
            &mut pump_c,
            Operation::GetConfig {
                source: DatastoreName::Running,
            },
        )
        .unwrap();
    match &reply.result {
        ReplyResult::Data(data) => {
            let ifaces = data.child_named("interfaces").expect("interfaces present after edit");
            assert_eq!(ifaces.child_named("interface").unwrap().text_content(), "eth0");
        }
        other => panic!("expected data, got {other:?}"),
    }

    // lock/unlock round trip.
    let locked = nc
        .rpc(
            &mut client_conn,
            &mut pump_c,
            Operation::Lock {
                target: DatastoreName::Running,
            },
        )
        .unwrap();
    assert_eq!(locked.result, ReplyResult::Ok);
    let unlocked = nc
        .rpc(
            &mut client_conn,
            &mut pump_c,
            Operation::Unlock {
                target: DatastoreName::Running,
            },
        )
        .unwrap();
    assert_eq!(unlocked.result, ReplyResult::Ok);

    // close-session ends the session.
    nc.close(&mut client_conn, &mut pump_c).unwrap();

    server_thread.join().unwrap();
}

#[test]
fn error_reply_for_unknown_datastore() {
    let (mut client_conn, mut server_conn) = handshake();
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();

    let server_thread = thread::spawn(move || {
        let mut store = InMemoryDatastore::new();
        let mut pump = |this: &mut EncryptedConn| {
            if this.pending_len() > 0 {
                let _ = s2c_tx.send(this.take_pending());
            }
            while let Ok(b) = c2s_rx.try_recv() {
                this.feed_recv(&b);
            }
        };
        serve_ssh_session(&mut server_conn, &mut pump, &mut store, 7).unwrap();
    });

    let mut pump_c = |this: &mut EncryptedConn| {
        if this.pending_len() > 0 {
            let _ = c2s_tx.send(this.take_pending());
        }
        while let Ok(b) = s2c_rx.try_recv() {
            this.feed_recv(&b);
        }
    };

    let mut nc = NetconfSshClient::connect(&mut client_conn, &mut pump_c).unwrap();
    // startup is not seeded, so a get-config against it returns an error reply.
    let reply = nc
        .rpc(
            &mut client_conn,
            &mut pump_c,
            Operation::GetConfig {
                source: DatastoreName::Startup,
            },
        )
        .unwrap();
    match &reply.result {
        ReplyResult::Error(e) => assert_eq!(e.error_tag, "invalid-value"),
        other => panic!("expected error, got {other:?}"),
    }
    nc.close(&mut client_conn, &mut pump_c).unwrap();
    server_thread.join().unwrap();
}
