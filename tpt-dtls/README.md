# tpt-dtls

Clean-room, dual-licensed implementation of **DTLS 1.3** —
[RFC 9147](https://www.rfc-editor.org/rfc/rfc9147), the Datagram Transport
Layer Security protocol for UDP.

DTLS 1.3 is the datagram cousin of TLS 1.3
([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)). It adds to TLS the
machinery that UDP needs and TLS lacks: explicit epoch/sequence-number
records, handshake fragmentation and reassembly, a stateless cookie
exchange (amplification protection), message-driven retransmission,
anti-replay, and Connection IDs
([RFC 9146](https://www.rfc-editor.org/rfc/rfc9146)). This crate implements
all of that on top of a faithful TLS 1.3 key schedule and AEAD record
protection.

It is part of the TPT Solutions RFC platform: every crate is
**MIT OR Apache-2.0** and written clean-room from the specification (no
copying from other DTLS/TLS implementations). All cryptographic primitives
are dual-licensed (RustCrypto `sha2`/`hkdf`/`hmac`, `orion` for X25519,
`ed25519-compact` for Ed25519, and the RustCrypto `aes-gcm` /
`chacha20poly1305` AEADs) and reused rather than reimplemented.

## Features

- DTLS 1.3 record layer (RFC 9147 §4): 13-byte header with explicit 16-bit
  `epoch` and 48-bit `sequence_number`, AEAD seal/open with the TLS 1.3
  additional-data and nonce rules, and an optional trailing **Connection
  ID** (RFC 9146).
- **Anti-replay** (RFC 9147 §4.4): a per-epoch sliding window integrated
  into the receive path.
- Handshake message codec (RFC 8446 §4): `ClientHello`, `ServerHello`
  (including the HelloRetryRequest), `EncryptedExtensions`, `Certificate`
  (raw-public-key form, RFC 7250), `CertificateVerify`, `Finished`, with the
  DTLS fragmentation/reassembly header and a `Reassembler`.
- **Stateless cookie exchange** (RFC 9147 §4.2.3 / §5.2) implemented as an
  HMAC over the client's stable parameters — no server-side state required
  before the second ClientHello.
- **Retransmission** (RFC 9147 §5.2) with exponential backoff.
- **TLS 1.3 key schedule** (RFC 8446 §7.1) for SHA-256 and SHA-384 suites.
- Cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`.
- A transport-agnostic client/server `Connection` state machine that
  performs the 1-RTT handshake (including the cookie round trip), derives
  handshake and application-traffic keys, and protects application data.
  The reference handshake authenticates peers with **raw public keys**
  (RFC 7250) and verifies Ed25519 `CertificateVerify` signatures directly.
  A pluggable `CertVerifier` trait allows full PKI validation to be layered
  on later (e.g. via `tpt-x509`).

## Example

```rust,no_run
use tpt_dtls::crypto::Ed25519KeyPair;
use tpt_dtls::{ClientConfig, Connection, ServerConfig};

// Two in-memory peers performing the 1-RTT handshake with the cookie
// exchange. `process_datagram` / `take_output` ferry records between them;
// substitute your own UDP socket in production.
let mut client = Connection::new_client(ClientConfig {
    cipher_suites: vec![tpt_dtls::crypto::CipherSuite::TlsAes128GcmSha256],
    groups: vec![tpt_dtls::handshake::group::X25519],
    sig_algs: vec![tpt_dtls::handshake::sigscheme::ED25519],
    identity: Ed25519KeyPair::from_seed(&[1u8; 32]).unwrap(),
    connection_id: None,
    server_verifier: Box::new(tpt_dtls::AcceptAllVerifier),
}).unwrap();
let mut server = Connection::new_server(ServerConfig {
    cipher_suites: vec![tpt_dtls::crypto::CipherSuite::TlsAes128GcmSha256],
    groups: vec![tpt_dtls::handshake::group::X25519],
    sig_algs: vec![tpt_dtls::handshake::sigscheme::ED25519],
    identity: Ed25519KeyPair::from_seed(&[2u8; 32]).unwrap(),
    cookie_secret: [0x07u8; 32],
    client_address: b"mem-client".to_vec(),
    client_verifier: Box::new(tpt_dtls::AcceptAllVerifier),
    connection_id: None,
}).unwrap();

client.start().unwrap();
server.process_datagram(&client.take_output()).unwrap();
client.process_datagram(&server.take_output()).unwrap();
server.process_datagram(&client.take_output()).unwrap();
client.process_datagram(&server.take_output()).unwrap();
server.process_datagram(&client.take_output()).unwrap();

assert!(client.is_connected());
assert!(server.is_connected());
```

A complete end-to-end handshake over an in-memory channel (including a
retransmitted first flight, application-data exchange, and a wrong-cookie
rejection) can be found in `tests/handshake_integration.rs`.

## Scope notes

- 0-RTT early data, post-handshake auth, and session resumption (PSK) are
  intentionally out of scope for this release (documented in
  `SPEC-NOTES.md`).
- The reference handshake uses raw public keys; X.509 certificate path
  validation is delegated to a pluggable verifier (the default test verifier
  trusts the peer's raw key). Full RFC 5280 validation is a separate
  platform crate (`tpt-x509`, Phase 4).
- Interop testing against OpenSSL's DTLS 1.3 is blocked in this environment
  (no OpenSSL toolchain present); conformance is demonstrated by the
  in-crate end-to-end handshake harness.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
