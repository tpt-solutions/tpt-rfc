# tpt-ssh

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of the
> **SSH** protocol suite — [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251)
> through [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254).

A from-spec SSH implementation. This crate currently provides the **transport
layer foundation**: the on-the-wire data types, protocol version exchange,
binary packet framing, the `curve25519-sha256` key exchange (RFC 8732), and the
`chacha20-poly1305@openssh.com` authenticated-encryption cipher. Client and
server support, the authentication protocol (RFC 4252), and the connection
protocol (RFC 4254) are the next layers.

Crypto primitives are **reused, not reimplemented**, and are all
dual-licensed: SHA-256 (`sha2`), X25519 (`orion`, MIT), ChaCha20/Poly1305
(`chacha20`/`poly1305`), and Ed25519 host keys (`ed25519-compact`).

## Example

```rust
use tpt_ssh::kex;

// A self-contained client/server key exchange. Both sides end up with
// identical session keys, and an encrypted packet round-trips in both
// directions (see `kex::key_exchange` and `cipher::CipherPair`).
let (client_keys, server_keys) = kex::key_exchange("SSH-2.0-tpt-client", "SSH-2.0-tpt-server");
assert_eq!(client_keys.client_to_server, server_keys.client_to_server);
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.
