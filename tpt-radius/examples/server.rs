// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example RADIUS authentication server.
//!
//! Run with `cargo run -p tpt-radius --example server`, then point a client
//! (e.g. the `client` example or `radtest`) at `127.0.0.1:1812` with the
//! shared secret `secret`. The server answers with an in-memory user store.

use std::sync::Arc;

use tpt_radius::memory::MemoryBackend;
use tpt_radius::server::Server;

fn main() -> std::io::Result<()> {
    let backend = Arc::new(MemoryBackend::new());
    backend.add_user("alice", "s3cret");
    backend.add_user("bob", "hunter2");

    let server = Server::new(backend, "secret").expect("secret must be non-empty");
    println!("tpt-radius server listening on 127.0.0.1:1812");
    server.run("127.0.0.1:1812")
}
