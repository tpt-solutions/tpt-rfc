# SPEC-NOTES — RFC 9111 (HTTP Caching)

This file tracks RFC 9111 sections implemented in `tpt-http-cache` and the
conformance vectors wired into the suite. It is the authoritative "are we
done?" record for the crate.

## Source documents

- RFC 9111: HTTP Caching — <https://www.rfc-editor.org/rfc/rfc9111>
- RFC 5861: HTTP Cache-Control Extensions for Stale Content
  (`stale-while-revalidate`, `stale-if-error`) —
  <https://www.rfc-editor.org/rfc/rfc5861>
- RFC 9110 §5.6.7: HTTP-date format — <https://www.rfc-editor.org/rfc/rfc9110>

## Implemented sections

- [x] §3 — Storing responses in caches (`is_storable`)
- [x] §4.2.1 — Calculating freshness lifetime (`max_age`)
- [x] §4.2.2 — Heuristic freshness (Last-Modified) + 24h warning
- [x] §4.2.3 — Calculating age (Age header, Date, resident time) (`age`)
- [x] §4.2.4 — Serving stale responses (max-stale, stale-while-revalidate)
- [x] §4.3 — Validation (revalidation request generation & 304 handling)
- [x] §5.2 — Cache-Control request & response directives
- [x] §5.3 — Expires
- [x] §5.4 — Pragma
- [x] §5.5.4 — 113 heuristic-expiration warning
- [x] §8.1 — Vary handling
- [x] RFC 5861 — `stale-while-revalidate` / `stale-if-error`

## Data model / public API

- `CachePolicy` — immutable snapshot of request/response metadata; the central
  type. Construct via `CachePolicy::new` / `CachePolicy::new_with_options`.
- `RequestInfo` / `ResponseInfo` — header bundles (with `From<http::Request>`
  / `From<http::Response>` conversions).
- `Options` — `shared`, `cache_heuristic`, `immutable_min_ttl`,
  `ignore_cargo_cult`, `now` (for deterministic tests).
- `evaluate_request` → `CacheDecision { response, revalidation }` — the
  primary "can I use the cache?" entry point.
- `satisfies_without_revalidation`, `is_storable`, `stale`, `max_age`,
  `age`, `time_to_live`, `use_stale_while_revalidate`.
- `response_headers` — cached response headers adjusted for serving
  (hop-by-hop stripped, Age/Date refreshed).
- `revalidation_headers` — conditional request headers to send upstream.
- `revalidated_policy` — fold a 304/error into an updated `CachePolicy`.
- `to_object` / `from_object` — serialize a cache entry.

## Test vectors

- [x] Ported behavioural cases from the `http-cache-semantics` test suite
  (reimplemented clean-room from documented behaviour, not copied code) —
  `tests/rfc9111.rs`.
- [x] HTTP-date parsing/formatting round-trip — `src/time.rs` unit tests.

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [x] Conformance test vectors passing
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io credentials in this environment)
