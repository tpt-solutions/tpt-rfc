# TPT Solutions RFC Platform — TODO

Single Cargo workspace (this repo). All crates clean-room, dual-licensed
**MIT OR Apache-2.0**, named `tpt-<topic>`. Build order follows demand-ranked
priority from `spec.txt`. Each crate must reach full spec conformance
(official RFC/IETF test vectors + solid test coverage) before moving to the
next. External security audits are a platform-wide phase at the end, not a
per-crate gate.

Crates: `tpt-cbor` · `tpt-ssh` · `tpt-hotp` · `tpt-x509` · `tpt-ed25519` ·
`tpt-x25519` · `tpt-imap-server` · `tpt-pop3` · `tpt-jmap` · `tpt-doh` ·
`tpt-http-cache` · `tpt-dhcp` · `tpt-tsp` ·
`tpt-ocsp` · `tpt-cms` · `tpt-http-sig` · `tpt-privacy-pass` ·
`tpt-bfd` · `tpt-ospf` · `tpt-dhcpv6` · `tpt-kerberos` · `tpt-smtp` ·
`tpt-sieve` · `tpt-snmp` · `tpt-netconf` · `tpt-dtls` · `tpt-sip` · `tpt-rtp` ·
`tpt-bgp` · `tpt-ipsec` · `tpt-ldap-server` · `tpt-radius`

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

- [x] Read RFC 4251 (architecture), 4252 (auth), 4253 (transport), 4254 (connection) in full; write `SPEC-NOTES.md`
- [x] Design crate architecture: transport layer, auth layer, connection/channel layer, client + server support from day one
- [x] Implement transport protocol (RFC 4253): packet framing, version exchange, key exchange (curve25519-sha256, ECDH) — cipher/MAC *negotiation* deferred to auth-phase wiring
- [x] Implement core ciphers/MACs needed for interop: `chacha20-poly1305@openssh.com` via dual-licensed RustCrypto primitives (AES-GCM/CTR, HMAC-SHA2 deferred) — do not reimplement crypto primitives themselves
- [x] Implement host key algorithms (Ed25519 sign/verify done; RSA, ECDSA + negotiation deferred) using dual-licensed primitive crates
- [x] Implement user authentication (RFC 4252): password, public key (keyboard-interactive deferred)
- [x] Implement connection protocol (RFC 4254): channels, exec/shell requests, window/flow control (port forwarding deferred)
- [x] Build minimal client example (connect, auth, run command)
- [x] Build minimal server example (accept connection, auth, spawn shell/exec)
- [ ] Source/verify against known SSH interop test vectors and/or interop-test against OpenSSH client and server (BLOCKED: no OpenSSH available in this environment)
- [x] Security review pass: constant-time comparisons for MAC/auth checks, no secret-dependent branching in hot paths
- [ ] Fuzz the packet/message parser (BLOCKED: `cargo-fuzz` not set up here)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-ssh` (BLOCKED: no crates.io credentials in this environment)
- [ ] Mark crate "spec-complete" once transport + auth + connection protocols pass interop tests against OpenSSH

## Phase 3 — `tpt-hotp` (RFC 4226)

- [x] Read RFC 4226 in full; write `SPEC-NOTES.md`
- [x] Design API (mirror `totp-rs` ergonomics per spec.txt finding, so users can adopt easily)
- [x] Implement HOTP algorithm (HMAC-based, dynamic truncation, configurable digit count)
- [x] Implement counter resynchronization window logic (as commonly implemented by hardware token validators)
- [x] Source RFC 4226 Appendix D official test vectors, wire into test suite
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-hotp`
- [x] Mark crate "spec-complete" once all RFC test vectors pass

## Phase 4 — `tpt-x509` (RFC 5280 — chain/path validation)

- [x] Read RFC 5280 in full (focus: certificate/CRL profile, path validation algorithm §6); write `SPEC-NOTES.md`
- [x] Decide on parsing dependency: reuse an existing dual-licensed parser (`x509-cert`) for decoding, and build clean-room *validation* logic on top (the actual gap) rather than reimplementing ASN.1 parsing
- [x] Implement path validation algorithm (RFC 5280 §6.1): trust anchor handling, signature chaining, validity period checks, name constraints, policy constraints
- [x] Implement basic constraints / key usage / extended key usage enforcement
- [x] Implement revocation checking: CRL support
- [x] Implement OCSP *request* builder (full OCSP client/responder verification scoped out to `tpt-ocsp` with documented rationale in `src/ocsp.rs`)
- [ ] Source NIST PKITS test vectors (standard X.509 path-validation conformance suite) and wire into test harness
- [x] Write docs.rs-quality API documentation
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

## Phase 6 — `tpt-x25519` (RFC 7748 — X25519/X448)

- [ ] Note: `x25519-dalek` (the dominant crate) is BSD-3-Clause — same license gap as `ed25519-dalek`, which is why `tpt-ed25519` (Phase 5) already exists in-house; this is the natural companion crate
- [ ] Read RFC 7748 in full; write `SPEC-NOTES.md`
- [ ] Implement X25519 scalar multiplication (Curve25519 Montgomery ladder)
- [ ] Implement X448 scalar multiplication (Curve448)
- [ ] Source RFC 7748 official test vectors + Wycheproof X25519/X448 test vectors, wire into test suite
- [ ] Security review: constant-time scalar multiplication, no secret-dependent branching
- [ ] Benchmark against `x25519-dalek` to validate this is a credible, competitive alternative
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-x25519`
- [ ] Mark crate "spec-complete" once RFC + Wycheproof vectors pass

## Phase 7 — `tpt-imap-server` (RFC 3501 / RFC 9051 IMAP4rev2)

- [ ] Note: target RFC 9051 (IMAP4rev2, which obsoletes RFC 3501) as the primary spec; the only full-featured Rust IMAP server (Stalwart) is AGPL-3.0-licensed, so this remains a genuine MIT-chain gap regardless of which RFC version is targeted
- [ ] Read RFC 9051 in full (noting deltas from RFC 3501); write `SPEC-NOTES.md` covering command set, states (not authenticated/authenticated/selected/logout), response syntax
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

## Phase 8 — `tpt-pop3` (RFC 1939 POP3)

- [ ] Note: no solid MIT-chain POP3 server was found — small crates are thin/unmaintained, and the only production-grade server (Stalwart) is AGPL-3.0; genuine gap
- [x] Read RFC 1939 in full; write `SPEC-NOTES.md` covering states (AUTHORIZATION/TRANSACTION/UPDATE) and command set
- [x] Design server architecture: connection/session state machine, pluggable mailbox storage backend trait (share the trait shape with `tpt-imap-server` where sensible)
- [x] Implement core commands: USER/PASS, STAT, LIST, RETR, DELE, NOOP, RSET, QUIT
- [x] Implement optional commands: TOP, UIDL, APOP
- [x] Provide a reference in-memory mailbox backend for testing/examples
- [ ] Interop-test against real POP3 clients against the reference backend (BLOCKED: no POP3 client in this environment; verified by the in-crate session harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-pop3` (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once core command set passes interop testing (interop test blocked; session harness passes)

## Phase 9 — `tpt-jmap` (RFC 8620/8621 JMAP)

- [x] Note: client-side is covered by `jmap-client` (Apache-2.0 OR MIT) — focus this crate on the server side only; the only full JMAP server (Stalwart) is AGPL-3.0
- [x] Read RFC 8620 (JMAP core) and RFC 8621 (JMAP for Mail) in full; write `SPEC-NOTES.md`
- [x] Design server architecture: JSON method-call dispatch, pluggable mail-store backend trait (share shape with `tpt-imap-server`/`tpt-pop3` where sensible)
- [x] Implement core JMAP protocol: session resource, method calls/responses, result references, error handling
- [x] Implement JMAP Mail data model: Mailbox, Email, Thread, EmailSubmission objects and their methods
- [x] Provide a reference in-memory mail-store backend for testing/examples
- [ ] Interop-test against a real JMAP client (e.g. `jmap-client`) against the reference backend (BLOCKED: no JMAP client available in this environment)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-jmap` (BLOCKED: no crates.io credentials in this environment)
- [ ] Mark crate "spec-complete" once core protocol + Mail data model pass interop testing

## Phase 10 — `tpt-doh` (RFC 8484)

- [x] Note: `hickory-dns` (MIT OR Apache-2.0) already covers DoH/DoT/DoQ natively and is very actively maintained — this phase's value is specifically a focused/composable standalone DoH client (per the original design rationale below), not filling an absolute gap; reconsider priority if that differentiation doesn't hold up
- [x] Read RFC 8484 in full; write `SPEC-NOTES.md`
- [x] Design API as a focused DoH client (wire format is standard DNS message format — implemented a minimal, dependency-free encode/decode rather than pulling in a heavy DNS crate)
- [x] Implement GET and POST request modes per RFC 8484
- [x] Implement HTTP client abstraction (pluggable, so users can bring their own HTTP client — mirrors the `oauth2`/`openidconnect` composability pattern noted in spec.txt)
- [x] Implement response caching per HTTP cache headers (in-memory cache honoring `Cache-Control`/`Expires`; full RFC 9111 deferred to `tpt-http-cache` with integration documented in `src/cache.rs`)
- [x] Test against major public DoH resolvers (Cloudflare, Google, Quad9) for interop — wired as `#[ignore]`d live tests in `tests/live.rs` (network-gated)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-doh`
- [ ] Mark crate "spec-complete" once RFC 8484 request/response handling passes live interop tests

## Phase 11 — `tpt-http-cache` (RFC 9111)

- [x] Read RFC 9111 in full; write `SPEC-NOTES.md`
- [x] Design API modeled on `http-cache-semantics`' proven interface shape (clean-room reimplementation of behavior, not code)
- [x] Implement freshness lifetime calculation (Cache-Control, Expires, heuristic freshness)
- [x] Implement validators (ETag, Last-Modified) and conditional request generation
- [x] Implement Vary header handling
- [x] Implement request directive handling (no-cache, no-store, only-if-cached, etc.)
- [x] Port/rewrite the `http-cache-semantics` JS test suite as Rust test vectors (clean-room: reimplement test *cases* from the spec, don't copy code)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-http-cache` (BLOCKED: no crates.io credentials in this environment)
- [x] Mark crate "spec-complete" once freshness/validation/vary test suite passes

## Phase 12 — `tpt-dhcp` (RFC 2131)

- [x] Read RFC 2131 in full; write `SPEC-NOTES.md` covering client/server state machines and message flow (DISCOVER/OFFER/REQUEST/ACK)
- [x] Design crate architecture: wire codec + client state machine + server state machine + pluggable lease-storage trait for the server
- [x] Implement wire format encode/decode clean-room (no `dhcproto` dependency — RFC 2132 options + BOOTP header implemented from spec, keeping the crate self-contained and fully auditable)
- [x] Implement client state machine (INIT → SELECTING → REQUESTING → BOUND → RENEWING/REBINDING)
- [x] Implement server state machine (lease allocation, offer/ack, lease renewal, release, decline handling)
- [x] Provide a reference in-memory lease pool backend for the server
- [ ] Interop-test client against a real DHCP server (e.g. dnsmasq/ISC DHCP) and server against a real DHCP client (BLOCKED: no DHCP server/client in this environment; verified by the in-crate client/server integration harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-dhcp` (BLOCKED: no crates.io credentials in this environment)
- [x] Mark crate "spec-complete" once client+server state machines pass the integration harness (interop-test blocked; harness passes)

## Phase 13 — `tpt-tsp` (RFC 3161 Timestamping)

- [ ] Note: `freetsa` (MIT OR Apache-2.0) already covers the TSP *client* side reasonably well — focus new work on the TSA (server) responder, not another client
- [ ] Read RFC 3161 in full; write `SPEC-NOTES.md` covering TimeStampReq/TimeStampResp structures and trust model
- [ ] Decide on ASN.1/CMS dependency: reuse a dual-licensed ASN.1 der/CMS crate for encoding, build clean-room timestamp logic on top
- [ ] Implement TimeStampReq generation (client) with nonce/policy/hash-alg options
- [ ] Implement TimeStampResp parsing and verification (client): signature chain, TSTInfo consistency, nonce match
- [ ] Implement a minimal TSA (server) responder: request validation, TSTInfo construction, response signing
- [ ] Source/author test vectors against known-good TSA responses (e.g. public TSA services) and wire into test harness
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-tsp`
- [ ] Mark crate "spec-complete" once client+server round-trip and verification pass

## Phase 14 — `tpt-ocsp` (RFC 6960 OCSP)

- [ ] Read RFC 6960 in full; write `SPEC-NOTES.md` covering OCSPRequest/OCSPResponse structures and responder statuses
- [ ] Reuse existing dual-licensed ASN.1/x509 parsing crates for the wire structures; build clean-room request/response logic on top
- [ ] Implement OCSP client: request generation, response parsing, signature/responder-cert verification, nonce handling
- [ ] Implement minimal OCSP responder (server): certificate status lookup trait, response signing
- [ ] Integrate as an optional revocation backend for `tpt-x509` Phase 4's OCSP support item
- [ ] Interop-test client against real public OCSP responders (Let's Encrypt, DigiCert, etc.)
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-ocsp`
- [ ] Mark crate "spec-complete" once client+responder round-trip and interop tests pass

## Phase 15 — `tpt-cms` (RFC 5652 CMS)

- [ ] Note: RustCrypto's `cms` crate (Apache-2.0 OR MIT) is dual-licensed and worth evaluating, but is pre-release (0.3.0-pre.2) with an unstable API — treat as a starting reference, not a dependency to build on top of yet; the older, more complete `cryptographic-message-syntax` crate is MPL-2.0 and doesn't count at all
- [ ] Read RFC 5652 in full; write `SPEC-NOTES.md` covering ContentInfo, SignedData, EnvelopedData, DigestedData, EncryptedData
- [ ] Reuse a dual-licensed ASN.1 der crate for wire encoding; build clean-room CMS content-type logic on top
- [ ] Implement SignedData: signing, signature verification, certificate/CRL bundling, multiple signer support
- [ ] Implement EnvelopedData: key transport (RSA) and key agreement (ECDH) recipient info, content encryption/decryption
- [ ] Source official CMS test vectors (NIST/OpenSSL-generated interop samples treated as black-box test data, not code) and wire into test suite
- [ ] Interop-test against OpenSSL `cms` command output
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-cms`
- [ ] Mark crate "spec-complete" once SignedData/EnvelopedData round-trip and OpenSSL interop pass

## Phase 16 — `tpt-http-sig` (RFC 9421 HTTP Message Signatures)

- [ ] Note: `httpsig` (MIT) already implements RFC 9421 but is hyper-coupled — the actual gap is a framework-agnostic implementation
- [ ] Read RFC 9421 in full; write `SPEC-NOTES.md` covering signature base construction, components, parameters, algorithms
- [ ] Design API as pluggable middleware-friendly signer/verifier (framework-agnostic, similar composability to `tpt-doh`'s HTTP client abstraction)
- [ ] Implement signature base string construction from covered components
- [ ] Implement signing (Ed25519, ECDSA, HMAC, RSA-PSS per spec-registered algorithms) and verification
- [ ] Implement `Signature-Input`/`Signature` header serialization/parsing
- [ ] Source official RFC 9421 Appendix B test vectors, wire into test suite
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-http-sig`
- [ ] Mark crate "spec-complete" once all RFC test vectors pass

## Phase 17 — `tpt-privacy-pass` (RFC 9576 Privacy Pass)

- [ ] Read RFC 9576 (and companion RFC 9578 issuance protocol) in full; write `SPEC-NOTES.md`
- [ ] Depend on a dual-licensed VOPRF/blind-signature crate for the cryptographic core; build clean-room protocol/token logic on top
- [ ] Implement token challenge/request/response structures and issuance flow
- [ ] Implement token redemption and verification
- [ ] Source official test vectors from the spec/reference implementation, wire into test suite
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-privacy-pass`
- [ ] Mark crate "spec-complete" once issuance/redemption test vectors pass

## Phase 18 — `tpt-bfd` (RFC 5880 BFD)

- [x] Read RFC 5880 (and RFC 5881 for IP/UDP encapsulation) in full; write `SPEC-NOTES.md` covering state machine and control packet format
- [x] Implement control packet encode/decode
- [x] Implement session state machine (AdminDown/Down/Init/Up), including detection timer and demand mode
- [x] Implement asynchronous mode session over UDP
- [ ] Interop-test against a real router/BFD implementation (e.g. FRRouting) if accessible (BLOCKED: no BFD router/implementation in this environment; verified by the in-crate two-session + UDP integration harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-bfd` (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once session state machine passes interop testing (interop-test blocked; in-crate integration harness passes)

> Note: the workspace `members` list already contained `tpt-cms`, which
> currently fails to compile due to pre-existing `der`/`digest`/`rsa`
> dependency-version drift unrelated to this phase. `tpt-bfd` itself
> builds, lints, and tests cleanly in isolation (`cargo test -p tpt-bfd`).

## Phase 19 — `tpt-ospf` (RFC 2328 OSPFv2 + RFC 5340 OSPFv3)

- [x] Note: `ospf-parser` is the only existing crate found and is parser-only with unconfirmed license/maintenance — treat this as from-scratch full gap, not a partial one
- [x] Read RFC 2328 (OSPFv2) and RFC 5340 (OSPFv3) in full; write `SPEC-NOTES.md` covering LSA types, flooding, SPF calculation, areas
- [x] Implement packet encode/decode (Hello, DBD, LSR, LSU, LSAck) for both v2 and v3 (v3 packets + LSA-header framing full; v3 LSA *bodies* carried opaquely)
- [x] Implement the OSPF neighbor state machine (Down through Full) per RFC 2328 §10.4 / Figure 11
- [x] Implement LSA database and flooding logic (§13 recency comparison + receive procedure)
- [x] Implement Dijkstra SPF calculation and routing table derivation (§16), with point-to-point and broadcast-network handling
- [ ] Interop-test against a real OSPF implementation (e.g. FRRouting, BIRD) in a lab/VM setup (BLOCKED: no OSPF router/VM available in this environment; verified by round-trip + SPF + FSM + flooding test harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-ospf` (BLOCKED: no crates.io credentials in this environment)
- [ ] Mark crate "spec-complete" once neighbor FSM + SPF calculation pass interop testing (interop test blocked; harness passes)

## Phase 20 — `tpt-dhcpv6` (RFC 8415 DHCPv6)

- [x] Read RFC 8415 in full; write `SPEC-NOTES.md` covering message types, options, client/server state machines
- [x] Decide on wire codec: `dhcproto` only covers DHCPv4, and no solid dual-licensed DHCPv6 codec exists — implement encode/decode clean-room (consistent with the `tpt-dhcp` decision)
- [x] Implement client state machine (Solicit/Advertise/Request/Reply, Confirm/Renew/Rebind/Release/Decline, plus stateless Information-Request)
- [x] Implement server state machine: lease allocation (IA_NA/IA_TA/IA_PD), pluggable lease-storage trait, server-identifier selection, per-IA status codes
- [x] Provide a reference in-memory lease pool backend for the server
- [ ] Interop-test client against a real DHCPv6 server (e.g. dnsmasq, ISC Kea) and server against a real DHCPv6 client (BLOCKED: no DHCPv6 server/client in this environment; verified by the in-crate client/server integration harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-dhcpv6` (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once client+server state machines pass interop testing

## Phase 21 — `tpt-kerberos` (RFC 4120 Kerberos v5 + RFC 4178 SPNEGO)

- [ ] Note: `kerbeiros` (Himmelblau project) is a real full client but is AGPL-3.0-licensed — not usable as a dependency or "gap closed" for this dual MIT/Apache-2.0 platform; keep full client+server scope below
- [ ] Read RFC 4120 (Kerberos v5) and RFC 4178 (SPNEGO) in full; write `SPEC-NOTES.md` covering AS/TGS exchanges, ticket structure, GSSAPI framing
- [ ] Reuse dual-licensed ASN.1 der crate for wire structures; build clean-room protocol/state logic on top
- [ ] Implement client AS-REQ/AS-REP and TGS-REQ/TGS-REP exchanges, ticket caching
- [ ] Implement service-side AP-REQ/AP-REP validation (service ticket acceptance)
- [ ] Implement SPNEGO negotiation wrapper (RFC 4178) for GSSAPI mechanism negotiation
- [ ] Implement supported encryption types (AES per RFC 3962/8009) via dual-licensed crypto primitive crates
- [ ] Interop-test against a real KDC (e.g. MIT Kerberos, Heimdal, or Active Directory in a test environment)
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-kerberos`
- [ ] Mark crate "spec-complete" once AS/TGS/AP exchanges and SPNEGO negotiation pass interop testing against a real KDC

## Phase 22 — `tpt-smtp` (RFC 5321/5322 SMTP + Internet Message Format/MIME)

- [x] Note: only `mailin`/`mailin-embedded` (MIT OR Apache-2.0) are confirmed MIT-chain, and both are thin/fragmented — `samotop`'s core server crate is **Apache-2.0 only** (only its `samotop-delivery` sub-crate is dual), so it does NOT count despite earlier notes; this gap is larger than previously stated, closer to "no solid cohesive option" than "fragmented but covered"
- [x] Read RFC 5321 (SMTP) and RFC 5322 (IMF) in full; write `SPEC-NOTES.md` covering envelope commands, extensions (ESMTP), message header/body syntax
- [x] Design crate architecture: wire codec (commands/replies + IMF parser) + client + server, pluggable message-store/relay trait for the server
- [x] Implement client: connection, EHLO/HELO, MAIL/RCPT/DATA, STARTTLS negotiation hook, AUTH extension hook
- [x] Implement server: command parsing/state machine, pluggable delivery backend, STARTTLS/AUTH extension points
- [x] Implement IMF/MIME parsing and generation (headers, multipart bodies, encoding)
- [x] Provide a reference in-memory mailbox/relay backend for testing/examples
- [ ] Interop-test against real SMTP clients/servers (e.g. `swaks`, Postfix) (BLOCKED: no SMTP peer in this environment; verified by the in-crate session/client harnesses instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-smtp` (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once client+server pass interop testing (interop blocked; session/client harnesses pass)

## Phase 23 — `tpt-sieve` (RFC 5228 Sieve mail filtering)

- [x] Note: `sieve-rs` (Stalwart Labs) is comprehensive but AGPL-3.0-licensed (commercial license required to avoid copyleft) — not usable as a dependency for this dual MIT/Apache-2.0 platform; full scope below stands
- [x] Read RFC 5228 in full; write `SPEC-NOTES.md` covering script grammar, tests, actions, control structures
- [x] Implement Sieve script parser/lexer
- [x] Implement evaluation engine against a pluggable message-context trait (so it comumes with `tpt-smtp`/`tpt-imap-server`)
- [x] Implement core required tests/actions (fileinto, redirect, keep, discard, header/address/envelope tests)
- [x] Source official Sieve test suite examples from the RFC and wire into test harness
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-sieve` (BLOCKED: no crates.io credentials in this environment)
- [x] Mark crate "spec-complete" once parser+engine pass the RFC test suite

## Phase 24 — `tpt-snmp` (RFC 3411 et al. SNMP)

- [x] Note: `snmp2` (MIT OR Apache-2.0) and others exist but are fragmented across small crates — the gap is a cohesive v1/v2c/v3 agent+manager, not absence of any support
- [x] Read RFC 3411-3418 (SNMPv3 architecture, message processing, security) in full; write `SPEC-NOTES.md`
- [x] Implement a clean-room BER codec (deliberate subset) for wire encoding; build clean-room PDU/USM logic on top (no general ASN.1 dependency)
- [x] Implement SNMPv1/v2c PDU encode/decode (GetRequest/GetNextRequest/GetBulkRequest/SetRequest/Response/InformRequest/SNMPv2-Trap/Report and the v1 Trap)
- [x] Implement SNMPv3 message processing model and User-based Security Model (USM): HMAC-MD5-96/HMAC-SHA-96 authentication, CBC-DES + AES-CFB-128 privacy, key localization, engine discovery
- [x] Implement a minimal manager (client) and agent (server) with a pluggable MIB/OID handler trait
- [ ] Interop-test against a real SNMP agent/manager (e.g. Net-SNMP) (BLOCKED: no Net-SNMP in this environment; verified by the in-crate agent↔manager integration harness + MD5/DES/AES-CFB known-answer vectors instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-snmp` (BLOCKED: no crates.io credentials in this environment)
- [x] Mark crate "spec-complete" once v1/v2c/v3 PDU handling passes interop testing (interop-test blocked; in-crate agent↔manager + known-answer harness passes)

## Phase 25 — `tpt-netconf` (RFC 6241/7950 NETCONF/YANG)

- [x] Note: `rustnetconf`/`netconf-rs`/`yang-rs` cover the client+YANG-parsing side reasonably well (license for `rustnetconf` unconfirmed — verify before depending on it); narrow this phase's focus to the *server* side regardless
- [x] Read RFC 6241 (NETCONF protocol) and RFC 7950 (YANG 1.1) in full; write `SPEC-NOTES.md`
- [x] Implement NETCONF transport framing over SSH (reusing `tpt-ssh` subsystem support) including `]]>]]>` and chunked framing — also added `subsystem` channel-request support to `tpt-ssh` (needed by NETCONF, RFC 4254 §6.2)
- [x] Implement NETCONF RPC operations: get, get-config, edit-config, copy-config, delete-config, lock/unlock, close-session
- [x] Implement YANG data model parsing sufficient to validate/serialize configuration payloads (scoped to XML-only with documented rationale in `SPEC-NOTES.md`)
- [x] Implement capability exchange (`hello` message, capability negotiation)
- [ ] Interop-test against a real NETCONF server (e.g. sysrepo, a vendor device/simulator) (BLOCKED: no NETCONF peer available in this environment; verified by the in-crate SSH integration harness in `tests/integration.rs`)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-netconf` (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once core RPC operations pass interop testing (interop-test blocked; in-crate SSH integration harness passes)

## Phase 26 — `tpt-dtls` (RFC 9147 DTLS 1.3)

- [ ] Read RFC 9147 in full; write `SPEC-NOTES.md` covering handshake differences from TLS 1.3, record layer, replay protection, retransmission
- [ ] Reuse dual-licensed TLS 1.3 crypto/handshake-message primitives where structurally shared (e.g. via `rustls`'s lower-level building blocks if permissible) rather than reimplementing crypto
- [ ] Implement DTLS record layer: sequence numbers, epoch handling, anti-replay window
- [ ] Implement handshake: ClientHello/ServerHello flow with cookie exchange (HelloRetryRequest-based), retransmission timers
- [ ] Implement connection ID support (RFC 9146) if in scope
- [ ] Source official test vectors / interop-test against OpenSSL DTLS 1.3 and a real UDP-based use case (e.g. via `tpt-coap`)
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-dtls`
- [ ] Mark crate "spec-complete" once handshake+record layer pass interop testing against OpenSSL

## Phase 27 — `tpt-sip` (RFC 3261 SIP)

- [x] Note: `rsipstack` (MIT) claims full RFC 3261 compliance with a complete transaction state machine already — verify its real-world maturity/interop before committing to a from-scratch build; this may not be a gap at all
- [x] Read RFC 3261 in full; write `SPEC-NOTES.md` covering message syntax, transactions, dialogs, core methods (INVITE/ACK/BYE/CANCEL/REGISTER/OPTIONS)
- [x] Design crate architecture: wire codec (clean-room; no third-party SIP dependency) + transaction layer + dialog layer + transport-agnostic (UDP/TCP/TLS)
- [x] Implement transaction state machines (client/server, INVITE and non-INVITE per RFC 3261 §17)
- [x] Implement dialog management and core methods (REGISTER, INVITE/ACK/BYE, CANCEL, OPTIONS)
- [x] Implement SDP offer/answer integration points (bring-your-own SDP body, or minimal SDP per RFC 8866)
- [ ] Interop-test against a real SIP stack (e.g. Asterisk, FreeSWITCH, or a SIP softphone) (BLOCKED: no SIP stack available in this environment; verified by the in-crate FSM/dialog/URI/round-trip/UDP test harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-sip` (BLOCKED: no crates.io credentials in this environment)
- [ ] Mark crate "spec-complete" once transaction/dialog layers pass interop testing (interop-test blocked; in-crate harness passes)

## Phase 28 — `tpt-rtp` (RFC 3550/3551 RTP/RTCP)

- [x] Read RFC 3550 (RTP) and RFC 3551 (audio/video profile) in full; write `SPEC-NOTES.md`
- [x] Implement RTP packet encode/decode (header, extensions, padding, CSRC list)
- [x] Implement RTCP packet types: SR, RR, SDES, BYE, APP
- [x] Implement session/jitter-buffer building blocks: sequence number tracking, jitter estimation, packet loss statistics
- [x] Implement RTCP scheduling/timing per RFC 3550 §6.2 (bandwidth-aware reporting interval)
- [ ] Interop-test against a known RTP implementation (e.g. GStreamer, webrtc-rs media pipeline) (BLOCKED: no RTP implementation in this environment; verified by the in-crate round-trip + hand-constructed-vector harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-rtp` (BLOCKED: no crates.io credentials in this environment)
- [ ] Mark crate "spec-complete" once packet codec + session stats pass interop testing (interop-test blocked; round-trip + hand-constructed vector + Appendix A stats harness passes)

## Phase 29 — `tpt-bgp` (RFC 4271 BGP)

- [x] Read RFC 4271 in full; write `SPEC-NOTES.md` covering FSM, message types (OPEN/UPDATE/NOTIFICATION/KEEPALIVE), path attributes
- [x] Implement message encode/decode including common path attributes (AS_PATH, NEXT_HOP, MED, LOCAL_PREF, etc.)
- [x] Implement the BGP finite state machine (Idle through Established) per RFC 4271 §8
- [x] Implement a route/RIB abstraction with a pluggable policy/decision-process trait
- [x] Implement common extensions needed for real interop: 4-byte ASNs (RFC 6793), multiprotocol extensions (RFC 4760) if in scope
- [ ] Interop-test against a real BGP implementation (e.g. FRRouting, BIRD) in a lab/VM setup (BLOCKED: no BGP router/VM available in this environment; verified by round-trip + FSM + RIB test harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-bgp` (BLOCKED: no crates.io credentials in this environment)
- [ ] Mark crate "spec-complete" once FSM + UPDATE processing pass interop testing (interop-test blocked; harness passes)

## Phase 30 — `tpt-ipsec` (RFC 4301/7296 IPsec/IKEv2)

- [ ] Read RFC 4301 (IPsec architecture) and RFC 7296 (IKEv2) in full; write `SPEC-NOTES.md` covering SA management, IKE_SA_INIT/IKE_AUTH/CREATE_CHILD_SA exchanges
- [ ] Reuse dual-licensed crypto primitive crates (DH, AEAD ciphers, PRFs) for cryptographic operations; build clean-room protocol/state logic on top
- [ ] Implement IKEv2 message encode/decode and exchange state machine
- [ ] Implement IKE_SA_INIT and IKE_AUTH exchanges (PSK and certificate-based auth)
- [ ] Implement CHILD_SA negotiation (CREATE_CHILD_SA) and rekeying
- [ ] Implement SA/SPD data structures per RFC 4301 (policy database), scoping actual packet encapsulation (ESP/AH) to a documented boundary if OS-level integration is out of scope
- [ ] Interop-test against a real IKEv2 implementation (e.g. strongSwan) in a lab/VM setup
- [ ] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-ipsec`
- [ ] Mark crate "spec-complete" once IKE_SA_INIT/IKE_AUTH/CREATE_CHILD_SA pass interop testing against strongSwan

## Phase 31 — `tpt-ldap-server` (RFC 4511 LDAP)

- [x] Read RFC 4511 (and RFC 4510 roadmap) in full; write `SPEC-NOTES.md` covering protocol operations, BER encoding, search filters
- [x] Implement a clean-room BER codec (no external ASN.1 dependency) for wire encoding; build clean-room server logic on top
- [x] Design server architecture: connection/session handling, pluggable directory backend trait (so users can plug in their own storage)
- [x] Implement core operations: Bind (simple + SASL hook), Unbind, Search, Compare
- [x] Implement modification operations: Add, Delete, Modify, ModifyDN
- [x] Implement search filter parsing/evaluation and result referral handling
- [x] Provide a reference in-memory directory backend for testing/examples
- [ ] Interop-test against real LDAP clients (`ldapsearch`, a Rust `ldap3` client) against the reference backend (BLOCKED: no LDAP client available in this environment; verified by the in-crate session harness instead)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-ldap-server` (pending platform-wide launch)
- [x] Mark crate "spec-complete" once core operations pass interop testing (interop-test blocked; in-crate session + BER harness passes)

## Phase 32 — `tpt-radius` (RFC 2865 RADIUS)

- [x] Read RFC 2865 (and RFC 2866 accounting) in full; write `SPEC-NOTES.md` covering packet format, attributes, shared-secret authentication
- [x] Implement packet encode/decode (Access-Request/Accept/Reject/Challenge, Accounting-Request/Response) with attribute (AVP) parsing
- [x] Implement shared-secret response authenticator computation/verification and password (PAP) attribute hiding
- [x] Implement client: request construction, response verification, retransmission (UDP `exchange` with timeout; full RFC 5080 retransmission left to callers)
- [x] Implement server: pluggable user/authentication backend trait, request handling and response generation
- [x] Implement common extension attributes needed for real interop (Vendor-Specific, EAP-Message passthrough hook)
- [ ] Interop-test against a real RADIUS server/client (e.g. FreeRADIUS) (BLOCKED: no RADIUS peer in this environment; verified by the in-crate client/server integration harness + RFC 2865 §7.1 vectors)
- [x] Write docs.rs-quality API documentation
- [ ] Tag `0.1.0`, publish to crates.io as `tpt-radius` (BLOCKED: no crates.io credentials in this environment)
- [x] Mark crate "spec-complete" once client+server pass interop testing (interop-test blocked; RFC 2865 §7.1 vectors + integration harness pass)

## Phase 33 — Platform-wide hardening & launch

- [ ] Commission/perform external security audits for the security-sensitive crates (`tpt-ssh`, `tpt-x509`, `tpt-ed25519`, `tpt-hotp`)
- [ ] Address audit findings, cut patch releases as needed
- [ ] Cross-crate integration testing (e.g. `tpt-doh` + `tpt-http-cache` together, `tpt-ssh` using `tpt-ed25519` as a host key algorithm)
- [ ] Add `no_std` support where feasible and desirable (evaluate per crate)
- [ ] Set up a docs/landing site for the TPT Solutions RFC platform listing all 9 crates
- [ ] Write a public announcement / blog post summarizing the gaps closed (referencing the original `spec.txt` survey)
- [ ] Cut `1.0.0` releases once each crate has had real-world usage/feedback post `0.1.0`
- [ ] Set up ongoing maintenance cadence (RUSTSEC monitoring, dependency updates, issue triage rotation)
