# SPEC-NOTES — RFC 9147 (DTLS 1.3) + RFC 9146 (Connection ID)

Clean-room implementation of **DTLS 1.3**, the Datagram Transport Layer
Security protocol for UDP. DTLS 1.3 is the datagram cousin of TLS 1.3
(RFC 8446); this crate implements the DTLS-specific machinery that TLS
lacks — explicit epoch/sequence-number records, handshake
fragmentation and reassembly, the stateless cookie exchange, message-driven
retransmission, anti-replay, and Connection IDs (RFC 9146) — on top of a
faithful TLS 1.3 key schedule and AEAD record protection.

Conformance is exercised by an end-to-end test harness
(`tests/handshake_integration.rs`) that drives two `Connection` state
machines against each other over an in-memory datagram channel, covering
the stateless-cookie 1-RTT handshake, X25519 key agreement, Ed25519
CertificateVerify, the TLS 1.3 key schedule, retransmission on first-flight
loss, and bidirectional application-data protection. A pluggable certificate
verifier trait allows full PKI validation to be layered on later (e.g. via
`tpt-x509`).

No code was copied from any existing DTLS/TLS implementation; every
structure is built independently from the RFC text, reusing only
dual-licensed *cryptographic primitives* (RustCrypto `sha2`/`hkdf`/`hmac`,
`orion` for X25519, `ed25519-compact` for Ed25519, and the RustCrypto
`aes-gcm`/`chacha20poly1305` AEADs).

## Source documents

- RFC 9147: Datagram Transport Layer Security 1.3 — https://www.rfc-editor.org/rfc/rfc9147
- RFC 8446: TLS 1.3 (key schedule, record protection, handshake messages) — https://www.rfc-editor.org/rfc/rfc8446
- RFC 9146: Connection Identifiers for DTLS 1.2/1.3 — https://www.rfc-editor.org/rfc/rfc9146
- RFC 7250: Using Raw Public Keys in TLS / DTLS — https://www.rfc-editor.org/rfc/rfc7250
- Errata: https://www.rfc-editor.org/errata/rfc9147 (none affecting this crate)

## Implemented sections

- [x] Record layer (RFC 9147 §4): 13-byte header with explicit 16-bit
      `epoch` and 48-bit `sequence_number`, `uint16 length` counting only
      `ciphertext || tag` (not the trailing CID), and the AEAD
      additional_data / nonce construction (§4.3).
- [x] Cleartext handshake records (epoch 0) for ClientHello / ServerHello
      (RFC 9147 §5.1, §5.4).
- [x] Protected records (epoch 1 handshake, epoch 2 application): AEAD seal
      / open using the TLS 1.3 AEAD rules (RFC 8446 §5.2–§5.3), with the
      `inner_content_type` byte appended before sealing and the trailing
      optional Connection ID appended after the AEAD output.
- [x] Epoch / sequence-number handling and the 48-bit sequence-space
      overflow guard.
- [x] Anti-replay window (RFC 9147 §4.4) — a per-epoch sliding window
      (default 64, any multiple of 64) integrated into the receive path;
      replays and out-of-window records are dropped.
- [x] Handshake message types (RFC 8446 §4): `ClientHello`, `ServerHello`
      (including the HelloRetryRequest magic `random`), `EncryptedExtensions`,
      `Certificate` (raw-public-key form, RFC 7250), `CertificateVerify`, and
      `Finished`, with the DTLS fragmentation/reassembly header (§5.4) and a
      `Reassembler`.
- [x] Stateless cookie exchange (RFC 9147 §4.2.3 / §5.2): the server issues
      a HelloRetryRequest carrying an HMAC over the client's stable
      parameters (source address + `ClientHello.random`), keyed by a server
      secret; the client echoes the cookie and the server recomputes and
      compares — no per-client state before the second ClientHello.
- [x] Message-driven retransmission timer with exponential backoff and a
      maximum-retry cap (RFC 9147 §5.2, §4.2.4).
- [x] Connection state machine (transport-agnostic client/server driver):
      the 1-RTT handshake including the cookie round trip, derivation of
      handshake and application-traffic keys, and application-data
      protection. Authenticates peers with raw Ed25519 public keys carried
      in `Certificate` messages, verifying Ed25519 `CertificateVerify`
      signatures directly (no X.509 dependency by default).
- [x] TLS 1.3 (EC)DHE key schedule (RFC 8446 §7.1): HKDF-Extract /
      Expand-Label / Derive-Secret, traffic-key and IV derivation, and
      Finished verify-data, for SHA-256-backed suites.
- [x] Cipher suites: `TLS_AES_128_GCM_SHA256` (0x1301),
      `TLS_AES_256_GCM_SHA384` (0x1302), `TLS_CHACHA20_POLY1305_SHA256`
      (0x1303).
- [x] Connection ID support (RFC 9146 §2): optional CID offered by either
      peer, appended to outgoing records and stripped on receipt.

## Explicitly out of scope

- [ ] 0-RTT early data, post-handshake authentication, and session
      resumption (PSK) — documented as deferred; the record/key-schedule
      design leaves room to add them later.
- [ ] X.509 certificate path validation — delegated to a pluggable
      `CertVerifier`. The default test verifier trusts the peer's raw key;
      full RFC 5280 validation is a separate platform crate (`tpt-x509`,
      Phase 4).
- [ ] DTLS 1.2 interop — this crate targets DTLS 1.3 only.

## Data model / public API

- `record::{RecordHeader, ConnectionId, build_cleartext, build_protected,
  open_protected, split_datagram, CONTENT_*}` — the record layer.
- `replay::ReplayWindow` — per-epoch anti-replay sliding window; `ct_eq` for
  constant-time comparisons.
- `handshake::{HandshakeMessage, HandshakeType, ClientHello, ServerHello,
  EncryptedExtensions, Certificate, CertificateVerify, Finished,
  fragment_message, Reassembler, HRR_RANDOM, ext, group, sigscheme}` — the
  handshake messages, codec, and fragmentation.
- `cookie::CookieMaker` — stateless cookie generation/verification.
- `keyschedule::{KeySchedule, TrafficKeys}` — the TLS 1.3 key schedule.
- `crypto::{CipherSuite, HashAlg, X25519KeyPair, Ed25519KeyPair,
  ed25519_verify}` — reused dual-licensed primitives and AEAD wrappers.
- `retransmit::{RetransmitTimer, RetransmitEvent}` — the retransmission
  timer.
- `connection::{Connection, ClientConfig, ServerConfig, CertVerifier,
  AcceptAllVerifier, ConnectionRole}` — the connection state machine
  (`new_client`, `new_server`, `start`, `process_datagram`, `take_output`,
  `tick`, `send_app_data`, `recv_app_data`, `is_connected`).

## Test vectors

- [x] Record header encode/decode round-trip (`tests/record.rs`).
- [x] Cleartext record split (`tests/record.rs`).
- [x] Protected-record round-trip for AES-GCM and ChaCha20-Poly1305, with
      and without a trailing Connection ID (`tests/record.rs`).
- [x] Tamper detection on a protected record (`tests/record.rs`).
- [x] Handshake message round-trips: ClientHello, ServerHello, HRR
      detection, Certificate, CertificateVerify, Finished
      (`tests/handshake.rs`).
- [x] Handshake fragmentation and reassembly (`tests/handshake.rs`).
- [x] Stateless cookie: verifies for matching parameters, rejects a
      tampered address or random (`tests/cookie.rs`).
- [x] Key schedule: client/server traffic-secret derivation
      (`tests/keyschedule.rs`).
- [x] Anti-replay window: in-order accept, replay rejection, out-of-window
      rejection, large-leap slide (`src/replay.rs`).
- [x] Retransmission timer: backoff and abort (`src/retransmit.rs`).
- [x] End-to-end 1-RTT handshake with the cookie round trip over an
      in-memory channel (`tests/handshake_integration.rs`).
- [x] Handshake survives loss of the first client flight (retransmission)
      (`tests/handshake_integration.rs`).
- [x] Application-data round-trips in both directions
      (`tests/handshake_integration.rs`).
- [x] Wrong-cookie rejection (`tests/handshake_integration.rs`).
- [x] Full handshake with the `TLS_CHACHA20_POLY1305_SHA256` suite
      (`tests/handshake_integration.rs`).

## spec-complete checklist

- [x] DTLS record layer: sequence numbers, epoch handling, AEAD protection, anti-replay
- [x] Connection ID support (RFC 9146)
- [x] Handshake: ClientHello/ServerHello with stateless cookie exchange and retransmission
- [x] TLS 1.3 key schedule (SHA-256 and SHA-384 suites)
- [x] End-to-end handshake + application-data integration harness passing
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against OpenSSL DTLS 1.3 and a real UDP use case
      (e.g. `tpt-coap`) (BLOCKED: no OpenSSL toolchain in this environment —
      verified by the in-crate end-to-end integration harness instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once handshake + record layer pass interop
      testing against OpenSSL
