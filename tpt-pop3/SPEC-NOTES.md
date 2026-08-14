# SPEC-NOTES — RFC 1939 (POP3)

Clean-room implementation of the Post Office Protocol, Version 3, tracking the
RFC section by section. Conformance is exercised by an end-to-end session test
harness (`tests/pop3_session.rs`) that drives a `Session` over an in-memory
backend and asserts the RFC-required command/response behaviour.

## Source documents

- RFC 1939: Post Office Protocol - Version 3 — https://www.rfc-editor.org/rfc/rfc1939
- Errata: https://www.rfc-editor.org/errata/rfc1939 (none affecting this crate)

## Implemented sections

- [x] §6.1 AUTHORIZATION state: `USER`, `PASS`, `APOP`, `QUIT` (+ greeting).
- [x] §6.2 TRANSACTION state: `STAT`, `LIST`, `RETR`, `DELE`, `NOOP`, `RSET`.
- [x] §6.3 UPDATE state: `QUIT` expunges messages marked for deletion.
- [x] §7 Optional commands: `TOP`, `UIDL` (implemented as optional per RFC).
- [x] §8 minimum compliance / response grammar (`+OK` / `-ERR`, CRLF, the
      `.`-terminated multi-line response with byte-stuffing of leading dots).
- [x] §11 message deletion semantics (deletions are session-local until QUIT;
      `RSET` undoes them; deleted messages are not listed/retrieved).

## Data model / public API

- `backend::MailboxBackend` — pluggable trait for credential checking and message
  storage; `backend::MailboxMessage` is the unit of mailbox content
  (`uid`, `octets`, `content`).
- `backend::BackendError` — storage/authentication error type.
- `memory::MemoryBackend` — reference in-memory backend (credentials + messages).
- `session::Session` — transport-agnostic state machine; `Session::run` drives
  a connection over any `BufRead + Write`.
- `server::Server` — std::net TCP listener that spawns a `Session` per
  connection.

## Test vectors

- [x] RFC 1939 §7/§11 examples — session harness in `tests/pop3_session.rs`
      covering authorization, STAT/LIST/RETR/UIDL, deletion + RSET, TOP, and
      UPDATE-state expunge on QUIT.

## spec-complete checklist

- [x] Core command set implemented per RFC
- [x] Optional commands (TOP, UIDL, APOP) implemented
- [x] Session harness passing (covers RFC-required behaviour)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against a real POP3 client (BLOCKED: no POP3 client in this
      environment — verified by session harness instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
