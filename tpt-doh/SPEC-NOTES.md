# SPEC-NOTES — RFC 8484 (DNS-over-HTTPS)

Clean-room implementation of the DoH wire contract: the standard DNS message
format carried over HTTPS using the `application/dns-message` media type, in
both `GET` and `POST` modes. The HTTP transport is pluggable (a `reqwest`
backend is provided behind a feature); a minimal, dependency-free DNS codec
builds queries and parses responses.

## Source documents

- RFC 8484: DNS Queries over HTTPS (DoH) — https://www.rfc-editor.org/rfc/rfc8484
- RFC 1035 §4.1: DNS message format / name compression (for the wire codec)
- RFC 4648 §5: base64url (GET `dns` parameter, no padding)

## Implemented sections

- [x] §4.1: `GET` request mode — query in the `dns` query parameter as
      base64url **without padding**; `Accept: application/dns-message`.
- [x] §4.2: `POST` request mode — body is the DNS message;
      `Content-Type: application/dns-message`, `Accept: application/dns-message`.
- [x] §4.2.1: non-2xx HTTP responses surfaced as errors (`Error::HttpStatus`).
- [x] §5.1 / §5.2: `application/dns-message` media type used for request and
      response bodies.
- [x] §5.3 (caching): shared-cache rules; this crate provides an optional
      in-memory cache honoring `Cache-Control: max-age` (relative to `Date`)
      and `Expires`. `no-store`/`no-cache` are not cached. Full RFC 9111
      semantics are deferred to `tpt-http-cache` (Phase 11) — see `src/cache.rs`.
- [x] DNS wire codec: header flags, questions, and resource records (A, AAAA,
      CNAME, NS, PTR, MX, TXT, OPT) with name-compression pointer resolution.

## Public API

- `DohClient::<H>` with `new`, `with_method`, `with_cache`, `query_raw`,
  `query`, `lookup_a`, `lookup_aaaa`.
- `HttpClient` trait (pluggable transport) + `HttpRequest`/`HttpResponse`.
- `Method` (Get/Post); `build_query` helper.
- `dns::Message` codec (`to_bytes`, `from_bytes`, `query`/`a_query`/`aaaa_query`).
- `cache` module: freshness computation usable independently.
- `ReqwestClient` backend (feature `reqwest`).

## Test vectors

- [x] DNS codec round-trip + hand-built compressed response — `src/dns.rs`
      unit tests (RFC 1035 name compression verified against a crafted packet).
- [x] base64url no-padding — RFC 4648 §5 test vectors — `src/base64.rs`.
- [x] Cache freshness (`max-age`, `Expires`, `no-store`) — `src/cache.rs`.
- [x] GET/POST wire shape + caching behavior — `tests/client.rs` (stub transport).
- [ ] Live interop against Cloudflare/Google/Quad9 — `tests/live.rs` (ignored;
      requires network; not run in CI).

## spec-complete checklist

- [x] GET + POST modes per RFC 8484
- [x] Pluggable HTTP client abstraction
- [x] Response caching honoring HTTP cache headers
- [ ] Live interop against major public resolvers (manual, network-gated)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
