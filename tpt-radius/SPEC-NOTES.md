# SPEC-NOTES — RFC 2865 (RADIUS) + RFC 2866 (Accounting)

This file tracks the RFC sections implemented in `tpt-radius` and the conformance
test vectors wired into the suite. It is the authoritative "are we done?" record
for the crate.

## Source documents

- RFC 2865: Remote Authentication Dial In User Service (RADIUS) — <https://www.rfc-editor.org/rfc/rfc2865>
- RFC 2866: RADIUS Accounting — <https://www.rfc-editor.org/rfc/rfc2866>
- RFC 3579: RADIUS Support For EAP (Message-Authenticator, EAP-Message) — <https://www.rfc-editor.org/rfc/rfc3579>
- RFC 5080: Common RADIUS Implementation Issues and Suggested Fixes (retransmit/timeout guidance)
- Errata: none known affecting the implemented surface.

## Implemented sections

- [x] RFC 2865 §3 — Packet format (Code, Identifier, Length, Authenticator, Attributes), min/max length.
- [x] RFC 2865 §4 — Packet types: Access-Request/Accept/Reject/Challenge; Accounting-Request/Response (RFC 2866 §2).
- [x] RFC 2865 §5.1 — Attribute format (Type | Length | Value) and the type registry (§5.44).
- [x] RFC 2865 §5.2 — User-Password hiding (PAP) with `MD5(secret | PreviousBlock)` chaining.
- [x] RFC 2865 §3 — Response Authenticator: `MD5(Code|ID|Length|RequestAuth|Attributes|Secret)`.
- [x] RFC 2865 §3 — Request Authenticator handling (random 16 octets for Access-Request).
- [x] RFC 2866 §3 — Accounting-Request Authenticator: `MD5(Code|ID|Length|16 zero|Attributes|Secret)`.
- [x] RFC 2866 §5 — Accounting attributes (Acct-Status-Type, Acct-Session-Id, Acct-Session-Time, etc.) carried opaquely + typed helpers.
- [x] RFC 3579 §3.2 — Message-Authenticator (`HMAC-MD5`), required/verified when EAP-Message present.
- [x] RFC 3579 §3.1 — EAP-Message (79) passthrough, automatically fragmented at the 253-octet limit.
- [x] RFC 2865 §5.26 — Vendor-Specific (26) attribute with `split_vendor_specific` helper.
- [x] Proxy-State (33) preserved unmodified and in order on replies (RFC 2865 §2).
- [x] Client: request construction, reply verification, blocking UDP `exchange`.
- [x] Server: pluggable `AuthBackend` (Accept/Reject/Challenge), `process`/`process_bytes`, UDP `run`.
- [ ] Interop-test against a real RADIUS server/client (e.g. FreeRADIUS) — BLOCKED: no RADIUS peer in this environment; verified by the in-crate client/server integration harness and the RFC 2865 §7.1 vectors instead.

## Data model / public API

- `packet::Packet` — header, attributes, `encode`/`decode`, `user_password`/`hide_user_password`, `response_authenticator`/`accounting_request_authenticator`, `set_message_authenticator`/`verify_message_authenticator`, `add_eap_message`/`eap_message`.
- `attribute::Attribute` / `attribute::AttributeType` — AVP container + RFC 2865 §5.44 registry, typed accessors and constructors.
- `client::Client` — shared-secret client with `access_request`, `accounting_request`, `verify_response`, `verify_accounting_response`, `exchange`.
- `server::{Server, AuthBackend, AuthRequest, AuthDecision}` — server behind a pluggable backend, plus `run` UDP listener.
- `memory::MemoryBackend` — reference in-memory backend.
- `accounting::AcctStatusType` — `Acct-Status-Type` constants.

## Test vectors

- [x] RFC 2865 §7.1 — "User Telnet to Specified Host": full Access-Request decode, User-Password decrypts to `arctangent`, and the Access-Accept response authenticator / wire bytes match exactly (`tests/radius_integration.rs::decode_rfc_2865_access_request`, `::response_authenticator_matches_rfc`).
- [x] Independent known-answer for password hiding (secret `xyzzy5461`, password `arctangent`, request authenticator `6f44…2683`) — `tests/radius_integration.rs::password_hiding_independent_oracle`.
- [x] Client/server round trip (Accept + Reject + Challenge), accounting request/response + authenticator verification, Message-Authenticator verify, EAP fragmentation — `tests/radius_integration.rs`.

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [x] Official / independent test vectors passing (`cargo test -p tpt-radius`)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io credentials in this environment)
- [x] Confirmed conformant via RFC 2865 §7.1 vectors + integration harness (interop-test blocked)
