# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: RFC 9111 (HTTP Caching) conformance baseline.
  - `CachePolicy` with freshness-lifetime, age, validation, and `Vary` logic.
  - `shared` vs single-user cache semantics.
  - Heuristic freshness, `stale-while-revalidate`, and `stale-if-error`.
  - `evaluate_request`, `revalidation_headers`, and `revalidated_policy`.
  - `to_object` / `from_object` serialization for cache stores.
