# tpt-radius

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **RADIUS** — RFC 2865 (authentication/authorization) and RFC 2866
> (accounting), with `Message-Authenticator` (RFC 3579) and `EAP-Message`
> passthrough.

A from-spec RADIUS client and server, built to close the licensing gap
identified in the TPT Solutions RFC survey: the only full-featured Rust RADIUS
server option (FreeRADIUS bindings aside) is AGPL-licensed or pulls in C, which
is unusable for a dual MIT/Apache-2.0 consumer. This crate is fully auditable
Rust, depending only on the dual-licensed `md-5` / `hmac` primitives for the
shared-secret cryptography.

See `SPEC-NOTES.md` for the section-by-section conformance status and the test
vectors wired into the suite.

## Features

- Wire encode/decode of RADIUS packets with strict length/attribute validation.
- PAP `User-Password` hiding (RFC 2865 §5.2).
- Response and accounting-request authenticator computation/verification
  (RFC 2865 §3, RFC 2866 §3) bound to the shared secret.
- `Message-Authenticator` HMAC-MD5 (RFC 3579 §3.2), enforced for EAP requests.
- `EAP-Message` (79) passthrough with automatic 253-octet fragmentation.
- `Vendor-Specific` (26) and `Proxy-State` (33) handling.
- A pluggable [`server::AuthBackend`] for the server, and a `Client` with a
  blocking UDP transport.

## Example

```rust
use std::sync::Arc;
use tpt_radius::memory::MemoryBackend;
use tpt_radius::server::Server;
use tpt_radius::Client;

let backend = Arc::new(MemoryBackend::new());
backend.add_user("alice", "s3cret");
let server = Server::new(Arc::clone(&backend), "secret").unwrap();

let mut client = Client::new("secret");
let request = client.access_request("alice", "s3cret").unwrap();
let reply = server.process(&request).unwrap().unwrap();
assert!(client.verify_response(&request, &reply));
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
