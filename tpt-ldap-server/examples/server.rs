// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example: run a `tpt-ldap-server` server with the in-memory backend.
//!
//! ```no_run
//! cargo run --example server
//! ```
//!
//! Then query it with any LDAP client, e.g.:
//! ```text
//! ldapsearch -H ldap://127.0.0.1:3389 -x -D cn=admin,dc=example,dc=com \
//!     -w secret -b dc=example,dc=com "(objectClass=*)"
//! ```

use std::sync::Arc;

use tpt_ldap_server::backend::{Attribute, Entry};
use tpt_ldap_server::memory::MemoryBackend;
use tpt_ldap_server::server::Server;

fn main() -> std::io::Result<()> {
    let backend = MemoryBackend::new();
    backend
        .add_entry(Entry::new(
            "dc=example,dc=com",
            vec![
                Attribute::new("objectClass", vec![b"domain".to_vec()]),
                Attribute::new("dc", vec![b"example".to_vec()]),
            ],
        ))
        .unwrap();
    backend
        .add_entry(Entry::new(
            "cn=admin,dc=example,dc=com",
            vec![
                Attribute::new("objectClass", vec![b"person".to_vec()]),
                Attribute::new("cn", vec![b"admin".to_vec()]),
                Attribute::new("userPassword", vec![b"secret".to_vec()]),
            ],
        ))
        .unwrap();
    backend
        .add_entry(Entry::new(
            "cn=alice,dc=example,dc=com",
            vec![
                Attribute::new("objectClass", vec![b"person".to_vec()]),
                Attribute::new("cn", vec![b"alice".to_vec()]),
            ],
        ))
        .unwrap();

    let addr = "127.0.0.1:3389";
    println!("tpt-ldap-server listening on {}", addr);
    println!("  bind DN=cn=admin,dc=example,dc=com password=secret");
    Server::new(Arc::new(backend)).serve(addr)
}
