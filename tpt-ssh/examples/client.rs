// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal `tpt-ssh` client example: connect to a server, authenticate with a
//! password, and run one command, printing its captured stdout and exit
//! status. Run `examples/server.rs` first (it listens on 127.0.0.1:2222).
//!
//! ```text
//! cargo run -p tpt-ssh --example client
//! ```

mod common;

use std::net::TcpStream;

use tpt_ssh::auth::{encode_request_password, parse_response, AuthResult, SERVICE_SSH_USERAUTH};
use tpt_ssh::connection::run_client_exec;
use tpt_ssh::session::SSH_MSG_SERVICE_ACCEPT;
use tpt_ssh::session::SSH_MSG_SERVICE_REQUEST;
use tpt_ssh::wire::Writer;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2222".to_string());
    let command = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "echo hello from tpt-ssh".to_string());

    let mut stream = TcpStream::connect(&addr).expect("connect");
    let mut conn = common::client_handshake(&mut stream);

    // Service request / accept.
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_SERVICE_REQUEST);
    w.write_string(SERVICE_SSH_USERAUTH.as_bytes());
    conn.send(&w.into_inner());
    common::pump(&mut conn, &mut stream).unwrap();
    loop {
        common::pump(&mut conn, &mut stream).unwrap();
        if let Some(p) = conn.recv().unwrap() {
            assert_eq!(p[0], SSH_MSG_SERVICE_ACCEPT);
            break;
        }
    }

    // Password authentication.
    conn.send(&encode_request_password(
        "alice",
        SERVICE_SSH_USERAUTH,
        "hunter2",
    ));
    common::pump(&mut conn, &mut stream).unwrap();
    let result = loop {
        common::pump(&mut conn, &mut stream).unwrap();
        if let Some(p) = conn.recv().unwrap() {
            break parse_response(&p).unwrap();
        }
    };
    assert_eq!(result, AuthResult::Success, "authentication failed");

    // Run the command.
    let mut pump = |c: &mut tpt_ssh::session::EncryptedConn| {
        common::pump(c, &mut stream).unwrap();
    };
    let (stdout, exit) = run_client_exec(&mut conn, &mut pump, &command).expect("exec");
    println!("exit status: {exit}");
    print!("{}", String::from_utf8_lossy(&stdout));
}
