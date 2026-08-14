# SPEC-NOTES — RFC 5321 (SMTP) + RFC 5322 (IMF) + MIME (RFC 2045/2046/2047)

Clean-room implementation of the Simple Mail Transfer Protocol (RFC 5321) as
both a **client** and a **server**, together with an Internet Message Format /
MIME library (RFC 5322 + RFC 2045/2046/2047). Conformance is exercised by
end-to-end session/codec tests (`tests/smtp_session.rs`, `tests/client.rs`) and
message-format tests (`tests/message.rs`), driven over in-memory I/O so they run
without a network peer.

## Source documents

- RFC 5321: Simple Mail Transfer Protocol — https://www.rfc-editor.org/rfc/rfc5321
- RFC 5322: Internet Message Format — https://www.rfc-editor.org/rfc/rfc5322
- RFC 2045/2046: MIME Part 1 (formats) / Part 2 (media types)
- RFC 2047: MIME Part Three (message header extensions / encoded words)
- RFC 2049: MIME conformance (informative)

## Implemented sections

### RFC 5321 (SMTP)
- [x] §2.4 / §4.1.1 command set: `HELO`, `EHLO`, `MAIL`, `RCPT`, `DATA`, `RSET`,
      `NOOP`, `QUIT`, `VRFY`, `EXPN`, `HELP`.
- [x] §4.2 reply codes and multi-line reply wire format (`NNN-` continuation,
      terminal `NNN `).
- [x] §4.3.2 session state machine (greeted → initial → mail → rcpt → data),
      with bad-sequence (`503`) enforcement.
- [x] §4.1.1.3 `MAIL FROM:<path>` / `RCPT TO:<path>` reverse/forward-path
      grammar (angle brackets, null reverse-path `<>`).
- [x] §4.5.2 `DATA` dot-transparency (leading dot escaped/unescaped) and the
      `<CRLF>.<CRLF>` terminator.
- [x] §4.5.3 command-line length limit (reject over-long lines).
- [x] ESMTP extension framework: `EHLO` capability advertisement, `SIZE`
      parameter on `MAIL FROM:` (enforces max message size), `8BITMIME`, and
      `STARTTLS` / `AUTH` extension **hooks** (advertised; the actual TLS/auth
      handshake is the integrator's responsibility — see notes below).
- [x] A pluggable [`backend::MailDelivery`] trait so callers bring their own
      store/relay; [`memory::MemoryBackend`] is a reference implementation.

### RFC 5322 (IMF) + MIME
- [x] §2.2 / §3 header field parsing (name/value, folding/unfolding).
- [x] §3.4 address parsing: `mailbox`, `mailbox-list`, `group: ... ;`, display
      names, angle addresses.
- [x] §3.6 required-header awareness (`From`, `Date` auto-filled by the builder).
- [x] MIME multipart parsing (`multipart/*`) with boundary splitting and
      recursive child parts.
- [x] `Content-Transfer-Encoding` decoding: `7bit`/`8bit`/`binary`, `base64`,
      `quoted-printable`.
- [x] RFC 2047 encoded-word decoding (`B`/`Q`) in header values; `B`-encoding
      for non-ASCII header generation.
- [x] [`message::MessageBuilder`] for generating well-formed, CRLF-terminated
      messages.

## Data model / public API

- `client::Client<R, W>` — RFC 5321 submission client (transport-agnostic).
- `session::Session` — server state machine (transport-agnostic); driven by
  `Session::run` over any `BufRead + Write`.
- `server::Server` — std::net TCP listener running a `Session` per connection.
- `backend::MailDelivery` / `backend::Envelope` — pluggable delivery sink.
- `memory::MemoryBackend` — reference in-memory backend (also a mailbox store).
- `message::{Message, Address, Header, MessageBuilder}` — IMF/MIME parsing and
  building.
- `reply::Reply`, `codec` — low-level reply/command helpers.

## Test vectors

- [x] `tests/smtp_session.rs` — greeting, EHLO/HELO, full MAIL/RCPT/DATA/QUIT
      transaction, RSET, bad-sequence rejections, dot-transparency, null
      reverse-path, SIZE enforcement, recipient allow-list, STARTTLS.
- [x] `tests/client.rs` — full client transaction against canned replies,
      negative greeting/reply handling, dot-stuffing on outbound DATA.
- [x] `tests/message.rs` — header/address parsing, RFC 2047 B/Q decoding,
      multipart/base64/quoted-printable MIME decoding, builder round-trip,
      non-ASCII subject encoding.

## Scope notes / deliberate boundaries

- **STARTTLS** and **AUTH** are wired as extension *hooks* only. This crate is
  transport-agnostic and does not perform the TLS handshake or SASL exchange
  itself; integrators wrap the socket in TLS after the `220` STARTTLS reply and
  supply AUTH credentials via the extension point. This keeps the crate free of
  a hard TLS/Crypto dependency and within the platform's clean-room scope.
- The server does not queue/spool to disk; `MemoryBackend` is the reference
  store. Production deployments implement `MailDelivery` against real storage
  or a relay.

## spec-complete checklist

- [x] Core SMTP command set implemented per RFC 5321
- [x] Server session state machine with sequence enforcement
- [x] SMTP client (submission) implemented
- [x] IMF/MIME parsing + building implemented
- [x] Pluggable delivery backend + in-memory reference backend
- [x] Session / client / message test suites passing
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against a real SMTP client/server (e.g. `swaks`, Postfix)
      (BLOCKED: no SMTP peer in this environment — verified by in-crate
      session/client harnesses instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
