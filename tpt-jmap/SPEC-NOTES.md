# SPEC-NOTES — RFC 8620 (JMAP) + RFC 8621 (JMAP Mail)

This file tracks the RFC sections implemented in this crate and the conformance
tests wired into the suite. It is the authoritative "are we done?" record for
the crate.

## Source documents

- RFC 8620: The JSON Meta Application Protocol (JMAP) — https://www.rfc-editor.org/rfc/rfc8620
- RFC 8621: The JSON Meta Application Protocol (JMAP) for Mail — https://www.rfc-editor.org/rfc/rfc8621
- Errata: tracked at https://www.rfc-editor.org/errata/rfc8620 and /rfc8621

## Implemented sections

### RFC 8620 (core)

- [x] §1.2: Terminology & data types (Id, Int, UnsignedInt, Date, UTCDate)
- [x] §2: The JMAP Session resource & capability negotiation
- [x] §3.1: The API model (method calls, state strings)
- [x] §3.2: Making requests (Request object: `using`, `methodCalls`, `createdIds`)
- [x] §3.3: Processing requests (response order, session state)
- [x] §3.4: Result references (`#clientId` / `#clientId/property`)
- [x] §3.5: Method-level errors (standard fields: `type`, `status`, `detail`, `properties`, `reference`)
- [x] §3.6: Standard error types (`unknownMethod`, `invalidArguments`, `invalidResultReference`, `forbidden`, `accountNotFound`, `accountNotSupportedByMethod`, `serverFail`, `serverPartialFail`, `unknown`, `requestTooLarge`, `rateLimit`)
- [x] §3.7: Request-level errors (`notJSON`, `notRequest`, `unknownCapability`)
- [x] §4: The `urn:ietf:params:jmap:core` capability object

### RFC 8621 (Mail)

- [x] §1.2: The `urn:ietf:params:jmap:mail` capability object
- [x] §2: Mailbox/Email/Thread/EmailSubmission object relationships
- [x] §3: `Mailbox` object + `Mailbox/get`, `Mailbox/set`, `Mailbox/query`, `Mailbox/changes`
- [x] §4: `Email` object + `Email/get`, `Email/query` (set partially in reference backend)
- [x] §5: `Thread` object + `Thread/get`
- [x] §7: `EmailSubmission` object + `EmailSubmission/get`, `EmailSubmission/set` (send/cancel), `EmailSubmission/query`, `EmailSubmission/changes`

## Data model / public API

- `Session` — the session resource (RFC 8620 §2), with `core` and `mail` capability objects.
- `Dispatcher` — owns a `MailStore` and turns a `Request` value into a `Response`.
- `Request` / `Response` / `Invocation` — the JSON envelopes (RFC 8620 §3.2/§3.3).
- `MailStore` — pluggable backend trait (get/set/query/changes per object type).
- `MemoryMailStore` — in-memory reference backend.
- Mail objects: `Mailbox`, `Email`, `Thread`, `EmailSubmission`, and their `/get`/`/set`/`/query` argument and result types.

## Test vectors

- `tests/dispatch.rs` — core dispatch, result-reference resolution (RFC 8620 §3.4 example), error handling.
- `tests/mail.rs` — Mailbox get/set/query/changes, Email get/query, Thread get, EmailSubmission set/send, against `MemoryMailStore`.

## spec-complete checklist

- [ ] All in-scope RFC sections implemented
- [ ] Interop testing against a real JMAP client (`jmap-client`) against the reference backend
- [ ] `cargo clippy` + `cargo fmt` clean
- [ ] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io
