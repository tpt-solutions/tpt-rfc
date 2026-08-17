# SPEC-NOTES — RFC 9051 (IMAP4rev2)

Clean-room implementation of Internet Message Access Protocol, Version 4rev2,
tracking the RFC section by section. The primary target is **RFC 9051**, which
obsoletes RFC 3501; deltas from RFC 3501 are noted inline where they matter
(notably IMAP4rev2's mandatory command set and the removal of `\Recent`).
Conformance is exercised by an end-to-end test harness
(`tests/integration.rs`) that drives a running `Server` over the in-memory
backend across a real TCP connection and asserts the RFC-required
command/response behaviour.

## Source documents

- RFC 9051: Internet Message Access Protocol (IMAP) - Version 4rev2 —
  https://www.rfc-editor.org/rfc/rfc9051
- RFC 3501: IMAP4rev1 (obsoleted; retained for delta reference) —
  https://www.rfc-editor.org/rfc/rfc3501
- RFC 7888: Non-synchronizing Literals (the `{N}+` form) —
  https://www.rfc-editor.org/rfc/rfc7888
- Errata: https://www.rfc-editor.org/errata/rfc9051 (none affecting this crate)

## Implemented sections

- [x] §6.1.1 Capability indication: `CAPABILITY` (untagged + tagged), and the
      `CAPABILITY` response emitted after a successful `LOGIN`/`AUTHENTICATE`.
- [x] §6.2.1 Connection establishment / greeting (`* OK ...`).
- [x] §6.2.2 `STARTTLS` hook (returns `NO`, TLS not terminated by this crate —
      gated behind an external transport).
- [x] §6.2.3 `AUTHENTICATE` with `PLAIN` and `LOGIN` SASL mechanisms, including
      the continuation handshake and inline/non-synchronising literals.
- [x] §6.2.3 `LOGIN` (and `LOGOUT`, §6.2.5).
- [x] §6.3.1 `SELECT` / `EXAMINE` (`EXISTS`, `RECENT`, `FLAGS`, `UIDVALIDITY`,
      selected/readonly state).
- [x] §6.3.2 `CREATE`, `DELETE`, `RENAME`.
- [x] §6.3.3 `SUBSCRIBE` / `UNSUBSCRIBE`, `LIST` / `LSUB` (with `%`/`*`
      wildcard matching against reference + pattern).
- [x] §6.3.4 `STATUS` (MESSAGES, UIDNEXT, UIDVALIDITY, UNSEEN, DELETED, RECENT).
- [x] §6.3.5 `APPEND` (with optional `(FLAGS)`, optional date, and message
      literal) and §6.3. `CHECK`.
- [x] §6.4.1 `FETCH` / `UID FETCH` — FLAGS, UID, INTERNALDATE, RFC822.SIZE,
      ENVELOPE, BODYSTRUCTURE, BODY (whole/header/text/HEADER.FIELDS), the
      `ALL`/`FAST`/`FULL` macros, and `.PEEK` (no implicit `\Seen`).
- [x] §6.4.2 `STORE` / `UID STORE` — `FLAGS`/`+FLAGS`/`-FLAGS` and `.SILENT`.
- [x] §6.4.3 `UID` command prefix (FETCH/STORE/COPY/SEARCH/EXPUNGE).
- [x] §6.4.4 `COPY` / `UID COPY`.
- [x] §6.4.5 `SEARCH` / `UID SEARCH` — ALL/SEEN/UNSEEN/ANSWERED/FLAGGED/
      DELETED/DRAFT/NEW/OLD/SMALLER/LARGER/TEXT/SUBJECT/FROM/TO, bare sequence
      sets, `OR`/`NOT`, and `UID` scoping.
- [x] §6.4.6 `CLOSE` (expunge-then-close), `EXPUNGE`, and `UID EXPUNGE`.
- [x] §6.5.1 `IDLE` extension (RFC 2177) with the `+ idling` continuation and
      `DONE` termination.
- [x] §6.3 `NOOP`, and the `ID` command (RFC 2971) returning `NIL`.
- [x] `NAMESPACE` (RFC 2342) returning a single personal namespace with `/`
      delimiter.
- [x] §2.3.1.1 `\Recent` is obsolete in IMAP4rev2 and is not advertised or
      stored. `RECENT` is always reported as 0.

## Data model / public API

- `store::MailboxStore` — pluggable trait owning actual message storage and
  credential checking; object-safe and used behind `Arc<dyn MailboxStore>` so a
  single instance serves every connection.
- `types::*` — `SystemFlag`, `Flag`, `FlagOp`, `ListEntry`, `MailboxStatus`,
  `MessageSnapshot`, `AppendMessage`.
- `memory::InMemoryStore` — reference in-memory backend (test/example/template).
- `session::Session` — transport-agnostic state machine (Not Authenticated →
  Authenticated → Selected → Logout); `Session::run` drives a connection over
  any `BufRead + Write`.
- `server::Server` — `std::net` TCP listener that spawns a `Session` per
  connection (`serve` blocking, `spawn` for tests).

## Test vectors

- [x] RFC 9051 command/response behaviour — end-to-end harness in
      `tests/integration.rs` exercising greeting, CAPABILITY, LOGIN (good +
      bad password), LIST, CREATE, APPEND, STATUS, SELECT, FETCH, STORE,
      SEARCH, UID FETCH, EXPUNGE, AUTHENTICATE PLAIN, IDLE, and LOGOUT over a
      real TCP connection.
- [x] Inline/non-synchronising literal framing (`{N}` / `{N}+`) and quoted/
      literal command parsing — covered by the request reader used throughout
      the harness.

## spec-complete checklist

- [x] Core command set (CAPABILITY, LOGIN/AUTHENTICATE, SELECT/EXAMINE, LOGOUT)
- [x] Mailbox management (CREATE, DELETE, RENAME, LIST, LSUB, STATUS, SUBSCRIBE,
      UNSUBSCRIBE)
- [x] Message commands (FETCH, STORE, COPY, SEARCH, EXPUNGE, UID variants,
      APPEND, CLOSE, CHECK)
- [x] IDLE extension
- [x] Reference in-memory backend
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against a real IMAP client (Thunderbird/mutt/Rust client) —
      BLOCKED: no IMAP client in this environment; verified by the in-crate TCP
      integration harness instead
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
