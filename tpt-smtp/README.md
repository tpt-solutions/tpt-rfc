# tpt-smtp

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **SMTP — the Simple Mail Transfer Protocol** (RFC 5321) — plus an
> **Internet Message Format / MIME** (RFC 5322 + MIME) parsing and building
> library.

A from-spec **SMTP client *and* server**, built to close the licensing gap
identified in the TPT Solutions RFC survey: the only confirmed MIT-chain Rust
SMTP crates are thin/fragmented clients (`lettre`, `mail-send`), and there is no
cohesive, dual-licensed server. `tpt-smtp` provides both behind pluggable
backends. The companion message module handles RFC 5322 parsing, address
parsing, MIME (multipart, `base64`, `quoted-printable`), and RFC 2047 encoded
words.

See `SPEC-NOTES.md` for the section-by-section conformance status and the test
vectors wired into the suite.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Features

- SMTP **server** session state machine (RFC 5321 §4.3.2) with `HELO`/`EHLO`,
  `MAIL`/`RCPT`/`DATA`, `RSET`/`NOOP`/`QUIT`, `VRFY`/`EXPN`/`HELP`, dot
  transparency, and an ESMTP extension framework (`SIZE`, `8BITMIME`,
  `STARTTLS`/`AUTH` hooks).
- SMTP **client** (submission) with the same command surface and dot-stuffing.
- Pluggable `MailDelivery` backend; an in-memory reference backend doubles as a
  mailbox store.
- RFC 5322 / MIME parsing and building: headers, addresses, multipart, transfer
  encodings, RFC 2047 encoded words, and a `MessageBuilder`.

Both the client and server are **transport-agnostic** — they run over any
`BufRead + Write` — which makes them fully testable without a network and lets
you supply your own transport (TCP, TLS, in-memory pipe).

## Quick start — server

```rust,no_run
use std::sync::Arc;
use tpt_smtp::memory::MemoryBackend;
use tpt_smtp::server::Server;
use tpt_smtp::session::Extensions;

let backend = Arc::new(MemoryBackend::new());
let mut server = Server::with_hostname(backend, "mail.example");
server.set_extensions(Extensions { size: true, ..Default::default() });
server.serve("127.0.0.1:2525").unwrap();
```

## Quick start — client

```rust,no_run
use std::net::TcpStream;
use std::io::{BufReader, Write};
use tpt_smtp::client::Client;

let stream = TcpStream::connect("127.0.0.1:2525").unwrap();
let mut reader = BufReader::new(stream.try_clone().unwrap());
let mut writer = stream;
let mut client = Client::new(&mut reader, &mut writer).unwrap();
client.ehlo("myhost").unwrap();
let _ = client.send_mail(
    Some("alice@example.com"),
    &["bob@example.org"],
    b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: Hi\r\n\r\nHello\r\n",
);
client.quit().unwrap();
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
