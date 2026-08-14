// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example: run a `tpt-pop3` server with the in-memory backend.
//!
//! ```no_run
//! cargo run --example server
//! ```
//!
//! Then connect with any POP3 client, e.g.:
//! ```text
//! telnet 127.0.0.1 1110
//! USER alice
//! PASS secret
//! STAT
//! LIST
//! RETR 1
//! QUIT
//! ```

use std::sync::Arc;

use tpt_pop3::memory::MemoryBackend;
use tpt_pop3::server::Server;

fn main() -> std::io::Result<()> {
    let backend = MemoryBackend::new();
    backend.add_user(
        "alice",
        "secret",
        vec![
            b"From: bob@example.com\r\nSubject: hello\r\n\r\nHello, world!\r\n".to_vec(),
            b"From: carol@example.com\r\nSubject: second\r\n\r\nAnother message.\r\n".to_vec(),
        ],
    );

    let addr = "127.0.0.1:1110";
    println!("tpt-pop3 listening on {}", addr);
    println!("  USER=alice PASS=secret");
    Server::new(Arc::new(backend)).serve(addr)
}
