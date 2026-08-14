# tpt-doh

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust client for
> **DNS-over-HTTPS** — [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484).

A small, composable DoH client. Unlike `hickory-dns` (which exposes DoH only as
a feature buried inside a large resolver), `tpt-doh` is a focused building block:
it implements the DoH wire contract and leaves the HTTP transport pluggable,
mirroring the bring-your-own-HTTP pattern of `oauth2`/`openidconnect`.

## Features

- `GET` and `POST` request modes (RFC 8484 §4.1 / §4.2).
- Pluggable [`HttpClient`](https://docs.rs/tpt-doh) transport — bring `reqwest`,
  `hyper`, `isahc`, or a test stub.
- Minimal, dependency-free DNS wire codec (build queries, parse responses,
  including name compression).
- Optional in-memory response cache honoring `Cache-Control`/`Expires`.

## Example

```rust,no_run
# #[cfg(feature = "reqwest")]
# {
use tpt_doh::{DohClient, ReqwestClient};

let client = DohClient::new(
    "https://dns.google/dns-query",
    ReqwestClient::new().unwrap(),
);
let answers = client.lookup_a("example.com").unwrap();
println!("{:?}", answers);
# }
```

Without the `reqwest` feature, implement [`HttpClient`](https://docs.rs/tpt-doh)
yourself:

```rust,no_run
use tpt_doh::{DohClient, HttpClient, HttpRequest, HttpResponse, Method};

struct MyTransport;
impl HttpClient for MyTransport {
    fn send(&self, _req: &HttpRequest)
        -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>
    { Ok(HttpResponse { status: 200, headers: vec![], body: vec![] }) }
}

let client = DohClient::new("https://dns.google/dns-query", MyTransport);
let _ = client.with_method(Method::Get);
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.
