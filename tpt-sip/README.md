# tpt-sip

Clean-room, dual-licensed implementation of the **Session Initiation
Protocol (SIP)** — [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261),
the TPT Solutions RFC platform's answer to the clean-room / MIT-OR-Apache
gap noted in the survey (the only full RFC 3261 crate found, `rsipstack`,
is worth verifying for maturity before trusting; this crate is written
from the spec, not from any existing implementation).

`tpt-sip` covers the layers you need to build SIP user agents and
proxies:

- **Message codec** — parse and serialise SIP requests/responses
  (`Message`, `message` module), including header folding and
  `Content-Length`-bounded bodies.
- **URIs** — `sip:` / `sips:` URI parsing and rendering (`uri`).
- **Headers** — typed `Via`, `From`/`To`, `Contact`, `CSeq` plus generic
  parameter parsing (`headers`).
- **Transaction layer** — the four state machines of RFC 3261 §17
  (client/server × INVITE/non-INVITE) with retransmission and all the
  standard timers (A, B, D/E/F, G/H/I, J/K/M). Transport-agnostic and
  timer-driven (`transaction`).
- **Dialogs** — dialog creation/tracking from §12 (early/confirmed,
  route set, remote target) (`dialog`).
- **Methods** — ergonomic builders for REGISTER, INVITE, ACK, BYE,
  CANCEL, OPTIONS (`methods`).
- **SDP** — a minimal RFC 8866 offer/answer body parser/serialiser for
  `application/sdp` integration points (`sdp`).
- **Transport** — a `Transport` trait plus a dependency-free UDP driver
  (`transport`).

## Example

```rust
use tpt_sip::methods::{invite, named};
use tpt_sip::uri::Uri;
use tpt_sip::message::Message;

let from = named(Uri::parse("sip:alice@example.com").unwrap());
let contact = named(Uri::parse("sip:alice@192.0.2.10:5060").unwrap());
let invite = invite(Uri::parse("sip:bob@example.com").unwrap(), from, contact).build();

let bytes = invite.to_bytes();
let parsed = Message::parse(&bytes).unwrap();
assert_eq!(parsed.method().unwrap().to_string(), "INVITE");
```

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for the section-by-section
conformance status and the test vectors wired into the suite. Interop
testing against a real SIP stack (Asterisk/FreeSWITCH/softphone) is
blocked in this environment; conformance is currently verified by the
in-crate round-trip, transaction-FSM, dialog, and URI test harness
(`tests/sip.rs`).

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
