// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end integration test for tpt-ssh: full transport handshake, user
//! authentication (RFC 4252), and a session `exec` (RFC 4254), driven in
//! process over a byte pipe.

use std::sync::mpsc;
use std::thread;

use tpt_ssh::auth::{
    encode_request_password, parse_response, server_handle, AuthResult, Authenticator,
    SERVICE_SSH_USERAUTH,
};
use tpt_ssh::connection::{run_client_exec, run_server_session, CommandHandler, CommandOutput};
use tpt_ssh::session::{handshake, EncryptedConn, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST};

const USER: &str = "alice";
const PASS: &str = "hunter2";

struct PasswordAuth;
impl Authenticator for PasswordAuth {
    fn check_password(&self, user: &str, password: &str) -> bool {
        user == USER && password == PASS
    }
}

struct EchoHandler;
impl CommandHandler for EchoHandler {
    fn run(&self, command: &str) -> CommandOutput {
        CommandOutput {
            stdout: format!("ran: {command}\n").into_bytes(),
            exit_status: 0,
        }
    }
}

/// Manual in-process exchange helper using direct delivery between endpoints.
fn step(client: &mut EncryptedConn, server: &mut EncryptedConn) {
    client.exchange_with(server);
    server.exchange_with(client);
}

#[test]
fn handshake_then_password_auth_success_and_failure() {
    let (mut client, mut server) = handshake();

    // Service request / accept.
    client.send(&{
        let mut w = tpt_ssh::wire::Writer::new();
        w.write_byte(SSH_MSG_SERVICE_REQUEST);
        w.write_string(SERVICE_SSH_USERAUTH.as_bytes());
        w.into_inner()
    });
    step(&mut client, &mut server);
    let svc = server.recv().unwrap().unwrap();
    assert_eq!(svc[0], SSH_MSG_SERVICE_REQUEST);
    server.send(&{
        let mut w = tpt_ssh::wire::Writer::new();
        w.write_byte(SSH_MSG_SERVICE_ACCEPT);
        w.write_string(SERVICE_SSH_USERAUTH.as_bytes());
        w.into_inner()
    });
    step(&mut client, &mut server);
    let accept = client.recv().unwrap().unwrap();
    assert_eq!(accept[0], SSH_MSG_SERVICE_ACCEPT);

    // Wrong password -> Failure.
    client.send(&encode_request_password(
        USER,
        SERVICE_SSH_USERAUTH,
        "wrong",
    ));
    step(&mut client, &mut server);
    let resp = server.recv().unwrap().unwrap();
    let reply = server_handle(&resp, b"session-id", &PasswordAuth).unwrap();
    server.send(&reply);
    step(&mut client, &mut server);
    let client_resp = client.recv().unwrap().unwrap();
    assert_eq!(
        parse_response(&client_resp).unwrap(),
        AuthResult::Failure {
            allowed: vec!["password".into(), "publickey".into()],
            partial: false
        }
    );

    // Correct password -> Success.
    client.send(&encode_request_password(USER, SERVICE_SSH_USERAUTH, PASS));
    step(&mut client, &mut server);
    let resp = server.recv().unwrap().unwrap();
    let reply = server_handle(&resp, b"session-id", &PasswordAuth).unwrap();
    server.send(&reply);
    step(&mut client, &mut server);
    let client_resp = client.recv().unwrap().unwrap();
    assert_eq!(parse_response(&client_resp).unwrap(), AuthResult::Success);
}

#[test]
fn handshake_auth_then_exec_over_threads() {
    let (mut client, mut server) = handshake();

    // Authenticate (manual, in-process).
    client.send(&{
        let mut w = tpt_ssh::wire::Writer::new();
        w.write_byte(SSH_MSG_SERVICE_REQUEST);
        w.write_string(SERVICE_SSH_USERAUTH.as_bytes());
        w.into_inner()
    });
    step(&mut client, &mut server);
    let svc = server.recv().unwrap().unwrap();
    assert_eq!(svc[0], SSH_MSG_SERVICE_REQUEST);
    server.send(&{
        let mut w = tpt_ssh::wire::Writer::new();
        w.write_byte(SSH_MSG_SERVICE_ACCEPT);
        w.write_string(SERVICE_SSH_USERAUTH.as_bytes());
        w.into_inner()
    });
    step(&mut client, &mut server);
    let accept = client.recv().unwrap().unwrap();
    assert_eq!(accept[0], SSH_MSG_SERVICE_ACCEPT);

    client.send(&encode_request_password(USER, SERVICE_SSH_USERAUTH, PASS));
    step(&mut client, &mut server);
    let resp = server.recv().unwrap().unwrap();
    let reply = server_handle(&resp, b"session-id", &PasswordAuth).unwrap();
    server.send(&reply);
    step(&mut client, &mut server);
    let client_resp = client.recv().unwrap().unwrap();
    assert_eq!(parse_response(&client_resp).unwrap(), AuthResult::Success);

    // Exec over a separate thread for the server, byte pipes for transport.
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();

    let server_thread = thread::spawn(move || {
        let mut pump = |this: &mut EncryptedConn| {
            if this.pending_len() > 0 {
                let _ = s2c_tx.send(this.take_pending());
            }
            while let Ok(b) = c2s_rx.try_recv() {
                this.feed_recv(&b);
            }
        };
        run_server_session(&mut server, &mut pump, &EchoHandler).unwrap();
    });

    let mut pump_c = |this: &mut EncryptedConn| {
        if this.pending_len() > 0 {
            let _ = c2s_tx.send(this.take_pending());
        }
        while let Ok(b) = s2c_rx.try_recv() {
            this.feed_recv(&b);
        }
    };

    let (stdout, exit) = run_client_exec(&mut client, &mut pump_c, "uname -a").unwrap();
    assert_eq!(exit, 0);
    assert_eq!(stdout, b"ran: uname -a\n");

    server_thread.join().unwrap();
}
