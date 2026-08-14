# tpt-http-cache

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **HTTP caching semantics** — RFC 9111.

A from-spec implementation of HTTP response cacheability and freshness, built
to close the licensing gap identified in the TPT Solutions RFC survey
(`http-cache-semantics` is BSD-2-Clause, which fails the dual MIT/Apache-2.0
bar). This crate reimplements the behaviour clean-room from RFC 9111 (and the
RFC 5861 `stale-while-revalidate` / `stale-if-error` extensions), modelled on
the proven interface shape of `http-cache-semantics` but with no source code
copied.

It answers the question *"Can I reuse this stored response to satisfy this new
request?"* taking into account `Cache-Control`, `Expires`, `Age`, `ETag`,
`Last-Modified`, and `Vary`, including the subtle cases (shared vs private
caches, heuristic freshness, conditional revalidation).

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Example

```rust
use std::time::Duration;
use tpt_http_cache::{CachePolicy, Options, RequestInfo, ResponseInfo};
use http::{HeaderMap, Method, StatusCode};

let mut res = HeaderMap::new();
res.insert("cache-control", "public, max-age=3600".parse().unwrap());
res.insert("date", "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap());

let policy = CachePolicy::new(
    RequestInfo::from_headers(Method::GET, HeaderMap::new()),
    ResponseInfo::from_status(StatusCode::OK, res),
);

assert!(policy.is_storable());
assert!(!policy.stale());
assert!(policy
    .satisfies_without_revalidation(&RequestInfo::from_headers(Method::GET, HeaderMap::new())));
```

## Integration with `http` types

The crate is framework-agnostic but integrates naturally with the dual-licensed
[`http`](https://crates.io/crates/http) crate via `From` conversions:

```rust,ignore
let policy = CachePolicy::new((&request).into(), (&response).into());
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
