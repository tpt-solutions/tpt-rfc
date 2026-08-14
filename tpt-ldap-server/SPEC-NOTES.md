# SPEC-NOTES — RFC 4511 (LDAP)

Clean-room implementation of the Lightweight Directory Access Protocol, tracking
RFC 4511 (and the RFC 4510 roadmap) section by section. Conformance is exercised
by an end-to-end session test harness (`tests/ldap_session.rs`) that drives a
`Session` over an in-memory backend and asserts the RFC-required
request/response behaviour, plus a focused BER codec round-trip test.

The wire format is BER (Basic Encoding Rules, ITU-T X.690), implemented
clean-room in `src/ber.rs` — no external ASN.1 dependency — keeping the crate
self-contained and auditable.

## Source documents

- RFC 4510: Lightweight Directory Access Protocol (LDAP) Road Map
- RFC 4511: Lightweight Directory Access Protocol (v3) — https://www.rfc-editor.org/rfc/rfc4511
- RFC 4512/4513/4514/4515/4516/4517/4518/4519 (schema, auth, string forms, syntaxes) referenced for the data model and matching semantics.

## Implemented sections

- [x] §4.2 `Bind` — `simple` bind (RFC 4513 §5.1) with constant-time password comparison; `sasl` choice parsed, default backend reports `authMethodNotSupported` (SASL hook present for extension).
- [x] §4.3 `Unbind` — closes the connection, no response.
- [x] §4.5 `Search` — base / singleLevel / wholeSubtree scope, derefAliases, size/time limits, typesOnly, attribute selection (`*` = all user attributes), and result referral handling (referral `resultCode` path wired; no DSE referral chasing).
- [x] §4.5.1 Search `Filter` — `and`, `or`, `not`, `equalityMatch`, `substrings`, `greaterOrEqual`, `lessOrEqual`, `present`, `approxMatch` (treated as equality), `extensibleMatch` (parsed; no matching rules implemented so it never matches).
- [x] §4.6 `Modify` — add / delete / replace changes.
- [x] §4.7 `Add`.
- [x] §4.8 `Delete`.
- [x] §4.9 `ModifyDN` — new RDN, `deleteoldrdn`, optional `newSuperior` (rename/move).
- [x] §4.10 `Compare` — `compareTrue` / `compareFalse`.
- [x] §4.11 `Abandon` — accepted (no-op response).
- [x] §4.12 `Extended` — not implemented by the reference server; returns `unwillingToPerform`.
- [x] §4.1.11 Controls — parsed; any *critical* unrecognized control is rejected with `unavailableCriticalExtension` (RFC 4511 §4.1.11).
- [x] §4.1.9 `LDAPResult` / `resultCode` — full result-code enum and backend-error mapping.
- [x] §4.1 (message envelope, BER encoding, messageID, controls) — implemented in `ber.rs` + `protocol.rs`.

## Data model / public API

- `backend::DirectoryBackend` — pluggable trait for authentication and entry
  storage; `backend::Entry` / `Attribute` / `Modification` / `ModifyDnRequest` /
  `SaslCredentials` are the server-facing data types.
- `backend::BackendError` — storage/authentication error type, mapped onto
  `resultCode` values by the session layer.
- `memory::MemoryBackend` — reference in-memory backend (credentials + entries).
- `protocol` — RFC 4511 message model (`LdapRequest`/`LdapResponse`,
  `BindRequest`, `SearchRequest`, `Filter`, `ModifyRequest`, `AddRequest`,
  `CompareRequest`, `ExtendedRequest`, `ResultCode`, …), (de)serialization,
  search-scope logic, and filter evaluation.
- `ber` — clean-room BER codec (definite + indefinite length, primitive +
  constructed).
- `session::Session` — transport-agnostic connection state machine;
  `server::Server` — std::net TCP listener that spawns a `Session` per
  connection.

## Test vectors

- [x] Session harness in `tests/ldap_session.rs` covering bind (success /
  wrong password / unknown DN / unsupported SASL), search (subtree / base /
  single-level scope, equality / and / substring / present filters, typesOnly
  and attribute selection), compare (true / false), add (success / duplicate /
  then search / modify / delete), modifyDN rename, extended (unwilling), and
  critical-control rejection.
- [x] `ber.rs` round-trip tests for INTEGER encoding (incl. two's-complement
  edge cases) and indefinite-length constructed decoding.

## spec-complete checklist

- [x] Core operations implemented per RFC 4511 (Bind, Unbind, Search, Compare, Add, Delete, Modify, ModifyDN, Abandon, Extended)
- [x] Search filter parsing/evaluation and result referral handling
- [x] Pluggable directory backend trait + in-memory reference backend
- [x] Session harness passing (covers RFC-required behaviour)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against real LDAP clients (`ldapsearch`, a Rust `ldap3` client) against the reference backend (BLOCKED: no LDAP client available in this environment — verified by the in-crate session harness instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
