// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal `tpt-ssh` server example: listen on 127.0.0.1:2222, accept one
//! connection, authenticate it (password `alice`/`hunter2`), and serve a
//! single `exec` request by running the command via the system shell.
//!
//! ```text
//! cargo run -p tpt-ssh --example server
//! ```

mod common;

use std::net::TcpListener;
use std::process::Command;

use tpt_ssh::connection::{run_server_session, CommandHandler, CommandOutput};

struct ShellHandler;
impl CommandHandler for ShellHandler {
    fn run(&self, command: &str) -> CommandOutput {
        let (shell, flag) = if cfg!(windows) {
            ("cmd", "/c")
        } else {
            ("sh", "-c")
        };
        let output = Command::new(shell)
            .arg(flag)
            .arg(command)
            .output()
            .unwrap_or_else(|e| panic!("failed to run command: {e}"));
        CommandOutput {
            stdout: output.stdout,
            exit_status: output.status.code().unwrap_or(-1) as u32,
        }
    }
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2222".to_string());
    let listener = TcpListener::bind(&addr).expect("bind");
    println!("tpt-ssh demo server listening on {addr}");

    if let Some(stream) = listener.incoming().next() {
        let mut stream = stream.expect("accept");
        println!("accepted connection");
        let mut conn = common::server_handshake(&mut stream);
        let _ = common::server_auth(&mut conn, &mut stream);
        println!("authenticated; serving session");

        let mut pump = |c: &mut tpt_ssh::session::EncryptedConn| {
            common::pump(c, &mut stream).unwrap();
        };
        run_server_session(&mut conn, &mut pump, &ShellHandler).expect("session");
        println!("session closed");
    }
}
