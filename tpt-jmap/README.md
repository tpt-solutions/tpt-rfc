# tpt-jmap

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **JMAP — JSON Meta Application Protocol** — RFC 8620 (core) and RFC 8621
> (Mail).

A from-spec implementation of the **server side** of JMAP, built to close the
licensing gap identified in the TPT Solutions RFC survey: the only full JMAP
server (Stalwart) is AGPL-3.0, while the client side is already covered by the
Apache-2.0/MIT `jmap-client` crate.

This crate provides:

- the JMAP core method-dispatch engine (RFC 8620 §3): request/response
  envelopes, method invocation, **result-reference** resolution (§3.4), and the
  standard error model (§3.5–3.6);
- the JMAP **session** resource and capability negotiation (RFC 8620 §2);
- the **Mail** data model and methods (RFC 8621): `Mailbox`, `Email`, `Thread`,
  and `EmailSubmission` (`/get`, `/set`, `/query`, `/changes`);
- a pluggable `MailStore` backend trait plus an in-memory reference backend for
  testing and examples.

The transport (HTTP) is intentionally out of scope — the crate exposes a
`Dispatcher` that turns a parsed `Request` into a `Response`, so it can be
wired behind any HTTP server.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Example

```rust
use tpt_jmap::{Session, Dispatcher, MemoryMailStore};

let store = MemoryMailStore::new();
let session = Session::default_for("account1");
let dispatcher = Dispatcher::new(store);

// A JMAP request is a JSON value per RFC 8620 §3.2.
let request: serde_json::Value = serde_json::json!({
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
        ["Mailbox/get", { "accountId": "account1" }, "a1"]
    ]
});

let response = dispatcher.dispatch(request).unwrap();
assert_eq!(response.method_responses[0].name, "Mailbox/get");
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
