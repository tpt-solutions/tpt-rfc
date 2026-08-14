// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example: run a `tpt-smtp` server with the in-memory backend.
//!
//! ```no_run
//! cargo run --example server
//! ```
//!
//! Then submit mail with any SMTP client, e.g.:
//! ```text
//! swaks --server 127.0.0.1:2525 --from alice@example.com --to bob@example.org
//! ```

use std::sync::Arc;

use tpt_smtp::memory::MemoryBackend;
use tpt_smtp::server::Server;
use tpt_smtp::session::Extensions;

fn main() -> std::io::Result<()> {
    let backend = Arc::new(MemoryBackend::new());
    let backend: Arc<dyn tpt_smtp::backend::MailDelivery> = backend;
    let mut server = Server::with_hostname(backend, "tpt-smtp.example");
    server.set_extensions(Extensions {
        size: true,
        starttls: true,
        auth: true,
        starttls_required: false,
    });

    let addr = "127.0.0.1:2525";
    println!("tpt-smtp listening on {}", addr);
    server.serve(addr)
}
