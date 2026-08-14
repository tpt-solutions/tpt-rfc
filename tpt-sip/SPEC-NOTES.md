# SPEC-NOTES — RFC 3261 (SIP)

Clean-room implementation of the Session Initiation Protocol. Conformance
is exercised by an in-crate test harness (`tests/sip.rs`) covering message
round-trips (including RFC 3261 Appendix examples), URI parsing, typed
header parsing, the four transaction state machines (§17), dialog
establishment (§12), and SDP bodies. No third-party SIP codec or protocol
dependency is used, keeping the crate self-contained and fully auditable,
consistent with the platform's clean-room requirement.

## Source documents

- RFC 3261: SIP: Session Initiation Protocol — https://www.rfc-editor.org/rfc/rfc3261
- RFC 8866: SDP: Session Description Protocol — https://www.rfc-editor.org/rfc/rfc8866
- RFC 3264: An Offer/Answer Model with SDP (referenced for SDP integration points)
- Errata: https://www.rfc-editor.org/errata/rfc3261 (none affecting this crate)

## Implemented sections

### Message syntax & framing (§7)
- [x] §7.1 Request-Line (`METHOD Request-URI SIP/2.0`).
- [x] §7.2 Status-Line (`SIP/2.0 CODE REASON`) with canonical reason phrases (§21.3).
- [x] §7.3 Header fields: case-insensitive name matching, `name: value`.
- [x] §7.3.1 Header field folding (CRLF + LWS) on parse.
- [x] §7.4 Body handling bounded by `Content-Length` (§20.14).
- [x] §7.5 Message framing: headers terminated by the empty line.

### SIP URI (§19.1)
- [x] `sip:` / `sips:` scheme, userinfo (`user[:password]@`), host (reg-name / IPv4 / IPv6-in-brackets) and `:port`.
- [x] URI parameters (`transport`, `maddr`, `lr`, `ttl`, `user`, `method`, arbitrary) and header parameters after `?`.
- [x] Percent-encoding/decoding of userinfo.

### Headers (§20)
- [x] §20.1 `Via` (multiple entries, `branch`/`received`/`rport`/`maddr`/`ttl`/`alias` params). Branch magic-cookie `z9hG4bK` generation.
- [x] §20.8 / §20.9 `From` / `To` (`name-addr`, display name, `tag` param).
- [x] §20.10 `CSeq` (sequence number + method).
- [x] §20.7 `Contact` (`name-addr`, `expires`).
- [x] §20.23 `Max-Forwards`, §20.6 `Call-ID`, §20.14 `Content-Length`.

### Transactions (§17)
- [x] §17.1.1 Client INVITE: Calling → Proceeding → Accepted | Completed → Terminated, with Timer A/B/D/M and ACK construction (§17.1.1.3).
- [x] §17.1.2 Client non-INVITE: Trying → Proceeding → Completed → Terminated, with Timer E/F/K.
- [x] §17.2.1 Server INVITE: Proceeding → Completed → Confirmed → Terminated, with Timer G/H/I and ACK handling.
- [x] §17.2.2 Server non-INVITE: Trying → Proceeding → Completed → Terminated, with Timer J.
- [x] Reliable vs unreliable transport behaviour (no retransmission / ACK-wait on reliable transports).
- [x] Retransmission intervals doubling up to T2 (T1 = 500ms, T2 = 4s, T4 = 5s).

### Dialogs (§12)
- [x] §12.1 UAC dialog establishment from provisional/2xx responses (early + confirmed).
- [x] §12.1 UAS dialog establishment from a request.
- [x] §12.2 Route set (Record-Route, reversed for UAC) and remote target (Contact).
- [x] In-dialog CSeq management.

### Methods (§10)
- [x] REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS builders with correct header construction.
- [x] CANCEL shares the original INVITE's CSeq number (§9.1).
- [x] ACK for non-2xx reuses the INVITE branch/Call-ID/CSeq with method `ACK`.

### SDP (RFC 8866)
- [x] Parse/serialise `v=`, `o=`, `s=`, `c=`, `t=`, `a=`, `m=` lines.
- [x] Minimal audio offer helper for `application/sdp` bodies.

### Transport (§18)
- [x] `Transport` trait (datagram send/recv) and a dependency-free UDP driver.

## Explicitly out of scope (this crate)

- [ ] Full proxy cores, registrar logic, and authentication challenges (Digest) — the building blocks (parsing, transactions, dialogs) are present; higher-layer services are left to the application.
- [ ] TLS/SCTP transports beyond the UDP driver (the transport trait allows them to be added).
- [ ] Every SIP extension method/header — the model is generic over headers and methods, so extensions compose without crate changes.

## Data model / public API

- `message::{Message, Header, StartLine, RequestLine, StatusLine}` — the wire model and parse/serialise.
- `uri::{Uri, Scheme, Param}` — SIP URI model and parse/display.
- `headers::{ViaEntry, NameAddr, CSeq}` and `parse_via` / `parse_name_addr` / `parse_cseq` — typed header views.
- `transaction::{Transaction, TxState, TxEvent, TxAction, TxTimers, Role, TransactionKind}` — the state machines.
- `dialog::{Dialog, DialogState}` — dialog tracking.
- `methods::{RequestBuilder, ResponseBuilder, register, invite, ack, bye, cancel, options, named}` — request/response construction.
- `sdp::{Sdp, Media, audio_offer}` — minimal SDP bodies.
- `transport::{Transport, UdpTransport}` — datagram transport.

## Test vectors / harness

- [x] RFC 3261 §A.1 example INVITE + §A.2 response round-trip in `tests/sip.rs`.
- [x] URI parsing (userinfo, IPv6, params, headers) in `tests/sip.rs`.
- [x] Typed header parsing (Via branch, From/To tags, CSeq) in `tests/sip.rs`.
- [x] Transaction FSM transitions: client INVITE success (200 → Accepted → Terminate), client INVITE failure (486 → ACK → Completed → Timer D), client non-INVITE (200 → Completed → Timer K), server INVITE (100 → 486 → ACK → Confirmed → Timer I), server non-INVITE (200 → Completed → Timer J) in `tests/sip.rs`.
- [x] Dialog establishment from response (early + confirmed) and from request in `tests/sip.rs`.
- [x] SDP parse/serialise round-trip in `tests/sip.rs`.
- [x] End-to-end two-UA REGISTER/INVITE exchange over `localhost` UDP in `tests/sip.rs`.

## spec-complete checklist

- [x] Message codec (RFC 3261 §7) — parse + serialise
- [x] SIP URI (§19.1) — parse + render
- [x] Typed core headers (§20)
- [x] Transaction layer (§17) — all four state machines + timers
- [x] Dialog management (§12)
- [x] Core method builders (§10)
- [x] SDP integration points (RFC 8866)
- [x] UDP transport (§18)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against a real SIP stack (e.g. Asterisk, FreeSWITCH, a SIP softphone)
      (BLOCKED: no SIP stack available in this environment — verified by the in-crate
      FSM/dialog/URI/round-trip/UDP test harness instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once transaction/dialog layers pass interop testing
