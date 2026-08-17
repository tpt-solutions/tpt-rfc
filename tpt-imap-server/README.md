# tpt-imap-server

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **IMAP4rev2** — RFC 9051.

A from-spec IMAP *server* built to close the licensing gap identified in the
TPT Solutions RFC survey: the only production-grade Rust IMAP server
(Stalwart) is AGPL-3.0, leaving the MIT/Apache crowd with no server option at
all. This crate is protocol-only — it owns the IMAP state machine, parsing, and
response generation, but delegates actual message storage to a pluggable
[`MailboxStore`] trait. A ready-to-use in-memory implementation,
[`InMemoryStore`], ships for tests, examples, and as a template.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented RFC sections (IMAP4rev2
command set, including `IDLE`) and the "spec-complete" checklist.

## Example

```rust
use std::collections::HashSet;
use tpt_imap_server::{Flag, InMemoryStore, Server, SystemFlag};

let store = InMemoryStore::new().with_user("alice", "secret");
store.add_mailbox("alice", "INBOX").ok();
let msg = b"From: a@example.com\r\nSubject: Hi\r\n\r\nHello\r\n".to_vec();
store.add_message("alice", "INBOX", msg, HashSet::new(), 0).ok();
let seen: HashSet<Flag> = [Flag::System(SystemFlag::Seen)].into_iter().collect();
let second = b"From: b@example.com\r\nSubject: Two\r\n\r\nSecond\r\n".to_vec();
store.add_message("alice", "INBOX", second, seen, 0).ok();

// Server::new(store).serve("127.0.0.1:143").unwrap();
let _ = Server::new(store);
```

Run the bundled reference server (an in-memory store pre-seeded with one user
and two messages):

```sh
cargo run -p tpt-imap-server --example server
```

Then connect with any IMAP4rev2 client.

## Implemented scope

- States: Not Authenticated → Authenticated → Selected → Logout.
- Core: `CAPABILITY`, `LOGIN`, `AUTHENTICATE` (PLAIN, LOGIN), `LOGOUT`,
  `NOOP`, `ID`, `NAMESPACE`.
- Mailbox management: `CREATE`, `DELETE`, `RENAME`, `LIST`, `LSUB`,
  `SUBSCRIBE`, `UNSUBSCRIBE`, `STATUS`, `APPEND`.
- Messages: `SELECT`/`EXAMINE`, `FETCH` (+ `UID FETCH`), `STORE`
  (+ `UID STORE`), `COPY` (+ `UID COPY`), `SEARCH` (+ `UID SEARCH`),
  `EXPUNGE`, `UID EXPUNGE`, `CLOSE`, `CHECK`, `IDLE`.

TLS (`STARTTLS`) is intentionally not terminated by this crate; run it behind
your own TLS-terminating transport.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
