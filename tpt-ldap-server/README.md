# tpt-ldap-server

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of **LDAP
> — the Lightweight Directory Access Protocol** — RFC 4511.

A from-spec LDAP **server** built to close the licensing gap identified in the
TPT Solutions RFC survey: the only production-grade Rust LDAP servers are
client-only or AGPL-3.0 encumbered, so this crate provides a permissively
licensed alternative within the dual MIT/Apache-2.0 platform. It implements the
RFC 4511 protocol operations behind a pluggable directory backend so callers
can bring their own storage. See `SPEC-NOTES.md` for the section-by-section
conformance status and the test vectors wired into the suite.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Quick start

Run a server with the reference in-memory directory backend:

```rust,no_run
use std::sync::Arc;
use tpt_ldap_server::backend::{Attribute, Entry};
use tpt_ldap_server::memory::MemoryBackend;
use tpt_ldap_server::server::Server;

let backend = MemoryBackend::new();
backend
    .add_entry(Entry::new(
        "dc=example,dc=com",
        vec![Attribute::new("dc", vec![b"example".to_vec()])],
    ))
    .unwrap();

// Listen on a high port (port 389 needs privileges).
Server::new(Arc::new(backend)).serve("127.0.0.1:3389").unwrap();
```

Bring your own storage by implementing
[`tpt_ldap_server::backend::DirectoryBackend`] and handing it to
[`tpt_ldap_server::server::Server`] (or driving
[`tpt_ldap_server::session::Session`] directly over any `Read + Write` for
testing).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
