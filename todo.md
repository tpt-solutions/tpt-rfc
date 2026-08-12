# TPT Solutions RFC Platform — TODO

Single Cargo workspace (this repo). All crates clean-room, dual-licensed
**MIT OR Apache-2.0**, named `tpt-<topic>`. Build order follows demand-ranked
priority from `spec.txt`. Each crate must reach full spec conformance
(official RFC/IETF test vectors + solid test coverage) before moving to the
next. External security audits are a platform-wide phase at the end, not a
per-crate gate.

Crates: `tpt-cbor` · `tpt-ssh` · `tpt-hotp` · `tpt-x509` · `tpt-ed25519` ·
`tpt-imap-server` · `tpt-doh` · `tpt-http-cache` · `tpt-dhcp`

---

## Phase 0 — Platform setup

- [x] Create Cargo workspace root `Cargo.toml` (members list, shared `[workspace.package]` metadata)
- [x] Reserve `tpt-*` crate names on crates.io (or confirm availability) for all 9 crates
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` template files at repo root
- [x] Write shared `CONTRIBUTING.md` clarifying clean-room requirement (no copying from ciborium/russh/ed25519-dalek/etc. source, spec-only reference)
- [x] Write root `README.md` describing the platform and linking to `spec.txt`
- [x] Set up CI (GitHub Actions): build + test matrix per crate, `cargo fmt`/`clippy` gate, license-header check
- [x] Set up `cargo-deny` or similar for dependency license auditing (ensure no Apache-2.0-only or GPL deps sneak into dual-licensed crates)
- [x] Decide on shared MSRV (minimum supported Rust version) policy for the workspace
- [x] Establish a per-crate template structure (README, CHANGELOG, `SPEC-NOTES.md` tracking which RFC sections are implemented)
- [x] Set up a shared repo location/convention for storing official RFC test vectors per crate

## Phase 1 — `tpt-cbor` (RFC 8949)

- [x] Read RFC 8949 in full; write `SPEC-NOTES.md` outlining major sections (data model, encoding, decoding, tags, deterministic encoding)
- [x] Design public API (serde integration plan, similar ergonomics to ciborium for easy migration)
- [x] Implement core encoder (major types 0-7, indefinite-length items, tags)
- [x] Implement core decoder (including strict vs lenient modes)
- [x] Implement serde `Serializer`/`Deserializer` integration
- [x] Source/author official CBOR test vectors (RFC 8949 Appendix A + any IETF CBOR test suite) and wire into test harness
- [x] Add fuzz target (e.g. `cargo-fuzz`) for decoder robustness against malformed input
- [x] Write docs.rs-quality API documentation
- [x] Add `LICENSE-MIT`/`LICENSE-APACHE` + license header check passes
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-cbor`
- [x] Mark crate "spec-complete" in `SPEC-NOTES.md` once all test vectors pass

## Phase 2 — `tpt-ssh` (RFC 4251-4254)

- [ ] Read RFC 4251 (architecture), 4252 (auth), 4253 (transport), 4254 (connection) in full; write `SPEC-NOTES.md`
- [ ] Design crate architecture: transport layer, auth layer, connection/channel layer, client + server support from day one
- [ ] Implement transport protocol (RFC 4253): packet framing, version exchange, key exchange (curve25519-sha256, ECDH, DH group exchange), cipher/MAC negotiation
- [ ] Implement core ciphers/MACs needed for interop (ChaCha20-Poly1305, AES-GCM/CTR, HMAC-SHA2) via existing RustCrypto primitives (dual-licensed) — do not reimplement crypto primitives themselves
- [ ] Implement host key algorithms (Ed25519, RSA, ECDSA) using dual-licensed primitive crates
- [ ] Implement user authentication (RFC 4252): password, public key, keyboard-interactive
- [ ] Implement connection protocol (RFC 4254): channels, port forwarding, exec/shell requests, window/flow control
- [ ] Build minimal client example (connect, auth, run command)
- [ ] Build minimal server example (accept connection, auth, spawn shell/exec)
- [ ] Source/verify against known SSH interop test vectors and/or interop-test against OpenSSH client and server
- [ ] Security review pass: constant-time comparisons for MAC/auth checks, no secret-dependent branching in hot paths
- [ ] Fuzz the packet/message parser
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-ssh`
- [ ] Mark crate "spec-complete" once transport + auth + connection protocols pass interop tests against OpenSSH

## Phase 3 — `tpt-hotp` (RFC 4226)

- [ ] Read RFC 4226 in full; write `SPEC-NOTES.md`
- [ ] Design API (mirror `totp-rs` ergonomics per spec.txt finding, so users can adopt easily)
- [ ] Implement HOTP algorithm (HMAC-based, dynamic truncation, configurable digit count)
- [ ] Implement counter resynchronization window logic (as commonly implemented by hardware token validators)
- [ ] Source RFC 4226 Appendix D official test vectors, wire into test suite
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-hotp`
- [ ] Mark crate "spec-complete" once all RFC test vectors pass

## Phase 4 — `tpt-x509` (RFC 5280 — chain/path validation)

- [ ] Read RFC 5280 in full (focus: certificate/CRL profile, path validation algorithm §6); write `SPEC-NOTES.md`
- [ ] Decide on parsing dependency: reuse an existing dual-licensed parser (e.g. `x509-parser`/`x509-cert`) for decoding, and build clean-room *validation* logic on top (the actual gap) rather than reimplementing ASN.1 parsing
- [ ] Implement path validation algorithm (RFC 5280 §6.1): trust anchor handling, signature chaining, validity period checks, name constraints, policy constraints
- [ ] Implement basic constraints / key usage / extended key usage enforcement
- [ ] Implement revocation checking: CRL support
- [ ] Implement revocation checking: OCSP support (or explicitly scope out with documented rationale if deferred)
- [ ] Source NIST PKITS test vectors (standard X.509 path-validation conformance suite) and wire into test harness
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-x509`
- [ ] Mark crate "spec-complete" once PKITS test suite passes

## Phase 5 — `tpt-ed25519` (RFC 8032)

- [ ] Read RFC 8032 in full; write `SPEC-NOTES.md`
- [ ] Implement Ed25519 signing and verification (deterministic, per spec)
- [ ] Implement Ed25519ph and Ed25519ctx variants if in scope
- [ ] Source RFC 8032 official test vectors + Wycheproof Ed25519 test vectors, wire into test suite
- [ ] Security review: constant-time scalar multiplication, no secret-dependent branching
- [ ] Benchmark against ed25519-dalek/ed25519-compact to validate this is a credible, competitive alternative (not just a license-clean duplicate)
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-ed25519`
- [ ] Mark crate "spec-complete" once RFC + Wycheproof vectors pass

## Phase 6 — `tpt-imap-server` (RFC 3501)

- [ ] Read RFC 3501 in full; write `SPEC-NOTES.md` covering command set, states (not authenticated/authenticated/selected/logout), response syntax
- [ ] Design server architecture: connection/session state machine, pluggable mailbox storage backend trait (so users can plug in their own storage)
- [ ] Implement core commands: CAPABILITY, LOGIN/AUTHENTICATE, SELECT/EXAMINE, LOGOUT
- [ ] Implement mailbox management commands: CREATE, DELETE, RENAME, LIST, LSUB, STATUS
- [ ] Implement message commands: FETCH, STORE, COPY, SEARCH, EXPUNGE
- [ ] Implement IDLE extension (widely expected by real clients)
- [ ] Provide a reference in-memory mailbox backend for testing/examples
- [ ] Interop-test against real IMAP clients (Thunderbird, mutt, or a Rust IMAP client crate) against the reference backend
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-imap-server`
- [ ] Mark crate "spec-complete" once core command set + IDLE pass interop testing

## Phase 7 — `tpt-doh` (RFC 8484)

- [ ] Read RFC 8484 in full; write `SPEC-NOTES.md`
- [ ] Design API as a focused DoH client (wire format is standard DNS message format — reuse a dual-licensed DNS message crate if suitable, or implement minimal encode/decode needed)
- [ ] Implement GET and POST request modes per RFC 8484
- [ ] Implement HTTP client abstraction (pluggable, so users can bring their own HTTP client — mirrors the `oauth2`/`openidconnect` composability pattern noted in spec.txt)
- [ ] Implement response caching per HTTP cache headers (or explicitly defer to `tpt-http-cache` once that exists, and document the integration point)
- [ ] Test against major public DoH resolvers (Cloudflare, Google, Quad9) for interop
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-doh`
- [ ] Mark crate "spec-complete" once RFC 8484 request/response handling passes interop tests

## Phase 8 — `tpt-http-cache` (RFC 9111)

- [ ] Read RFC 9111 in full; write `SPEC-NOTES.md`
- [ ] Design API modeled on `http-cache-semantics`' proven interface shape (clean-room reimplementation of behavior, not code)
- [ ] Implement freshness lifetime calculation (Cache-Control, Expires, heuristic freshness)
- [ ] Implement validators (ETag, Last-Modified) and conditional request generation
- [ ] Implement Vary header handling
- [ ] Implement request directive handling (no-cache, no-store, only-if-cached, etc.)
- [ ] Port/rewrite the `http-cache-semantics` JS test suite as Rust test vectors (clean-room: reimplement test *cases* from the spec, don't copy code)
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-http-cache`
- [ ] Mark crate "spec-complete" once freshness/validation/vary test suite passes

## Phase 9 — `tpt-dhcp` (RFC 2131)

- [ ] Read RFC 2131 in full; write `SPEC-NOTES.md` covering client/server state machines and message flow (DISCOVER/OFFER/REQUEST/ACK)
- [ ] Design crate architecture: wire codec + client state machine + server state machine + pluggable lease-storage trait for the server
- [ ] Implement wire format encode/decode (or depend on dual-licensed `dhcproto` for this layer, per spec.txt noting it already covers this well — confirm license/maintenance still holds before depending on it)
- [ ] Implement client state machine (INIT → SELECTING → REQUESTING → BOUND → RENEWING/REBINDING)
- [ ] Implement server state machine (lease allocation, offer/ack, lease renewal, release, decline handling)
- [ ] Provide a reference in-memory lease pool backend for the server
- [ ] Interop-test client against a real DHCP server (e.g. dnsmasq/ISC DHCP) and server against a real DHCP client
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-dhcp`
- [ ] Mark crate "spec-complete" once client+server state machines pass interop testing

## Phase 10 — Platform-wide hardening & launch

- [ ] Commission/perform external security audits for the security-sensitive crates (`tpt-ssh`, `tpt-x509`, `tpt-ed25519`, `tpt-hotp`)
- [ ] Address audit findings, cut patch releases as needed
- [ ] Cross-crate integration testing (e.g. `tpt-doh` + `tpt-http-cache` together, `tpt-ssh` using `tpt-ed25519` as a host key algorithm)
- [ ] Add `no_std` support where feasible and desirable (evaluate per crate)
- [ ] Set up a docs/landing site for the TPT Solutions RFC platform listing all 9 crates
- [ ] Write a public announcement / blog post summarizing the gaps closed (referencing the original `spec.txt` survey)
- [ ] Cut `1.0.0` releases once each crate has had real-world usage/feedback post `0.1.0`
- [ ] Set up ongoing maintenance cadence (RUSTSEC monitoring, dependency updates, issue triage rotation)
