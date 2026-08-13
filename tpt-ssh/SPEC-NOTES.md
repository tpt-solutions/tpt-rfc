# SPEC-NOTES — RFC 4251-4254 (SSH)

Clean-room, dual-licensed implementation of the SSH protocol suite. Tracking
the RFCs section by section. Conformance is proven with self-contained
key-exchange + encrypted-transport round-trip tests (and, at the end of the
phase, interop against OpenSSH).

## Source documents

- RFC 4251: The Secure Shell (SSH) Protocol Architecture — https://www.rfc-editor.org/rfc/rfc4251
- RFC 4252: The Secure Shell (SSH) Authentication Protocol — https://www.rfc-editor.org/rfc/rfc4252
- RFC 4253: The Secure Shell (SSH) Transport Layer Protocol — https://www.rfc-editor.org/rfc/rfc4253
- RFC 4254: The Secure Shell (SSH Connection Protocol — https://www.rfc-editor.org/rfc/rfc4254
- RFC 8732: SSH Key Exchange Method curve25519-sha256 — https://www.rfc-editor.org/rfc/rfc8732
- OpenSSH `PROTOCOL.chacha20poly1305` (the `chacha20-poly1305@openssh.com` construction, identical to draft-ietf-sshm-chacha20-poly1305)

## Implemented sections (Phase 2, transport foundation)

- [x] RFC 4251 §5: on-the-wire data types (`byte`, `boolean`, `uint32`,
       `uint64`, `string`, `name-list`, `mpint`) — `src/wire.rs`.
- [x] RFC 4253 §4.2: protocol version exchange (identification string
       serialization/parsing, CR LF handling) — `src/version.rs`.
- [x] RFC 4253 §6: binary packet framing (length, padding length, payload,
       padding; block-size padding for `none`/stream ciphers) — `src/transport.rs`.
- [x] RFC 8732: `curve25519-sha256` key exchange — ephemeral X25519 via `orion`,
       exchange-hash `H` over `V_C||V_S||I_C||I_S||K_S||e||f||K` (all as
       SSH strings, `K` included as a string), SHA-256 — `src/kex.rs`.
- [x] RFC 4253 §7.2: key/IV derivation (`HASH(K||H||X||session_id)` then
       `HASH(K||H||prev)` chaining) for the 64-byte `chacha20-poly1305` keys.
- [x] `chacha20-poly1305@openssh.com` AEAD (RFC 8439 ChaCha20 + Poly1305 with
       the OpenSSH length-encryption layout) — `src/cipher.rs`.
- [x] RFC 8032-style Ed25519 host-key sign/verify of `H` (blob + signature in
        SSH wire format) via `ed25519-compact` — `src/host_key.rs`.
- [x] RFC 4253 §7 transport handshake orchestration: version exchange,
        `SSH_MSG_KEXINIT` algorithm negotiation (`kex::negotiate`), the
        `curve25519-sha256` exchange, and the `SSH_MSG_NEWKEYS` switch — wired
        end-to-end in `src/session.rs` (`handshake` / `EncryptedConn`).
- [x] RFC 4252 user authentication: `none`, `password`, and `publickey`
        methods plus `SSH_MSG_USERAUTH_BANNER` (RFC 4252 §5/§7/§8) — `src/auth.rs`.
- [x] RFC 4254 connection protocol: channel open/confirm/failure, data,
        extended-data, EOF, close, window-adjust, and the `exec` / `exit-status`
        requests with window/flow control (RFC 4254 §5/§6) — `src/connection.rs`.
- [x] Minimal client/server examples demonstrating connect → auth → `exec`
        over a real TCP socket (`examples/client.rs`, `examples/server.rs`,
        sharing `examples/common/mod.rs` for the socket handshake + byte bridge).

## Public API (so far)

- `wire::{Writer, Reader, WireError}` — encode/decode SSH data types.
- `version::{Identification, VersionError}` — version string handshake.
- `transport` — cleartext framing `frame_packet`/`unframe_packet` and the
  chacha content framing `frame_content`/`unpack_content`.
- `host_key::HostKey` — generate Ed25519 host key, build SSH public-key blob,
  sign/verify the exchange hash.
- `kex::{key_exchange, SessionKeys}` — perform a full `curve25519-sha256`
  exchange (client + server halves) producing matching session keys.
- `cipher::{ChaCha20Poly1305, CipherPair, SessionKeys}` — encrypt/decrypt
  SSH packets for both traffic directions.

## Test vectors

- [x] RFC 7748 §5.2 X25519 test vectors are covered by `orion` upstream; the
       KEX self-test asserts client and server derive identical `K`, `H`, and
       session keys, and that an encrypted packet round-trips in both
       directions.
- [ ] Interop against OpenSSH client/server (deferred to connection-phase work).

## spec-complete checklist (transport)

- [x] Wire codec implemented per RFC 4251 §5
- [x] Version exchange implemented per RFC 4253 §4.2
- [x] Binary packet framing implemented per RFC 4253 §6
- [x] `curve25519-sha256` KEX implemented per RFC 8732
- [x] `chacha20-poly1305@openssh.com` implemented per OpenSSH construction
- [x] KEX exchange-hash + key derivation matching between peers
- [x] Encrypted packet round-trip in both directions
- [x] `cargo clippy` + `cargo fmt` clean (run after build)
- [x] docs.rs-quality documentation
- [ ] Interop against OpenSSH (BLOCKED: no OpenSSH binary in this environment; full interop gating deferred)
- [x] Authentication protocol (RFC 4252)
- [x] Connection protocol (RFC 4254)
- [x] Client + server examples
- [x] Security review (constant-time MAC/auth comparisons)
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io credentials in this environment)
