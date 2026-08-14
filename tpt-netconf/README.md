# tpt-netconf

Clean-room, dual-licensed implementation of a **NETCONF** server — the Network
Configuration Protocol of [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241) —
transported over the SSH `netconf` subsystem as specified in
[RFC 6242](https://www.rfc-editor.org/rfc/rfc6242), with YANG carried as opaque
XML per the scoped baseline (RFC 7950 is referenced but a full YANG compiler is
out of scope for this crate).

This crate is the from-spec toolkit identified as a genuine gap in the TPT
Solutions RFC survey: the existing `rustnetconf`/`netconf-rs`/`yang-rs` crates
cover only the client and/or YANG-parsing side, so this implementation focuses
on the **server** and reuses [`tpt-ssh`](../tpt-ssh) for the SSH transport
rather than reimplementing it. Every crate in the platform is MIT OR Apache-2.0
and written clean-room from the specification.

## Features

- NETCONF message framing (RFC 6242): base `]]>]]>` end-of-message marker and
  chunked `#<len>` framing, with an incremental decoder that transparently
  handles either form.
- A small, dependency-free XML DOM for parsing and serializing NETCONF
  messages.
- The NETCONF message model: `<hello>` capability exchange, `<rpc>` and the
  standard operations (`get`, `get-config`, `edit-config`, `copy-config`,
  `delete-config`, `lock`, `unlock`, `close-session`, `kill-session`,
  `discard-changes`), and `<rpc-reply>` / `<rpc-error>`.
- A pluggable [`Datastore`](https://docs.rs/tpt-netconf) backend trait with a
  reference [`InMemoryDatastore`] for tests and examples.
- A `serve_ssh_session` server loop and a minimal [`NetconfSshClient`] for
  testing and examples, both driven over an [`tpt_ssh`] `netconf` subsystem.

## Example

```rust,no_run
use tpt_netconf::client::NetconfSshClient;
use tpt_netconf::message::{DatastoreName, Operation, ReplyResult};
use tpt_netconf::server::{serve_ssh_session, InMemoryDatastore};
use tpt_netconf::xml::Xml;
use tpt_ssh::session::{handshake, EncryptedConn};
use std::sync::mpsc;
use std::thread;

// Server thread.
let (mut client_conn, mut server_conn) = handshake();
let (c2s_tx, c2s_rx) = mpsc::channel();
let (s2c_tx, s2c_rx) = mpsc::channel();
let srv = thread::spawn(move || {
    let mut store = InMemoryDatastore::new();
    let mut pump = |this: &mut EncryptedConn| {
        if this.pending_len() > 0 { let _ = s2c_tx.send(this.take_pending()); }
        while let Ok(b) = c2s_rx.try_recv() { this.feed_recv(&b); }
    };
    serve_ssh_session(&mut server_conn, &mut pump, &mut store, 1234).unwrap();
});

let mut pump_c = |this: &mut EncryptedConn| {
    if this.pending_len() > 0 { let _ = c2s_tx.send(this.take_pending()); }
    while let Ok(b) = s2c_rx.try_recv() { this.feed_recv(&b); }
};
let mut nc = NetconfSshClient::connect(&mut client_conn, &mut pump_c).unwrap();
let reply = nc.rpc(&mut client_conn, &mut pump_c, Operation::GetConfig {
    source: DatastoreName::Running,
}).unwrap();
assert!(matches!(reply.result, ReplyResult::Data(_)));
nc.close(&mut client_conn, &mut pump_c).unwrap();
srv.join().unwrap();
```

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
