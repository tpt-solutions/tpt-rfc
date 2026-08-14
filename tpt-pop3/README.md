# tpt-pop3

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **POP3 — the Post Office Protocol, Version 3** — RFC 1939.

A from-spec POP3 **server** built to close the licensing gap identified in the
TPT Solutions RFC survey (the only production-grade Rust POP3 server, Stalwart,
is AGPL-3.0). It implements the RFC 1939 command set behind a pluggable mailbox
backend so callers can bring their own storage. See `SPEC-NOTES.md` for the
section-by-section conformance status and the test vectors wired into the suite.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Quick start

Run a server with the reference in-memory mailbox backend:

```rust,no_run
use std::sync::Arc;
use tpt_pop3::memory::MemoryBackend;
use tpt_pop3::server::Server;

let backend = MemoryBackend::new();
backend.add_user(
    "alice",
    "secret",
    vec![
        b"From: bob@example.com\r\nSubject: hi\r\n\r\nHello, world!\r\n".to_vec(),
    ],
);

// Listen on a high port (port 110 needs privileges).
Server::new(Arc::new(backend)).serve("127.0.0.1:1110").unwrap();
```

Bring your own storage by implementing [`tpt_pop3::backend::MailboxBackend`]
and handing it to [`tpt_pop3::server::Server`] (or driving
[`tpt_pop3::session::Session`] directly over any `BufRead + Write` for testing).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
