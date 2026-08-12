# TPT Solutions RFC Platform

A single Cargo workspace of clean-room, **dual-licensed (MIT OR Apache-2.0)**
Rust implementations of widely-used IETF RFC protocols. The goal is to close
real ecosystem gaps caused by licensing incompatibilities between existing,
popular crates and downstream projects that require permissive or
unambiguously dual-licensed dependencies.

Every crate is built spec-first: we read the authoritative RFC, write a
`SPEC-NOTES.md` tracking which sections are implemented, and prove conformance
with **official RFC/IETF test vectors** plus solid test coverage before it is
marked "spec-complete".

## Crates

| Crate | RFC | Status |
|-------|-----|--------|
| `tpt-cbor` | RFC 8949 (CBOR) | in progress |
| `tpt-ssh` | RFC 4251–4254 | planned |
| `tpt-hotp` | RFC 4226 | planned |
| `tpt-x509` | RFC 5280 | planned |
| `tpt-ed25519` | RFC 8032 | planned |
| `tpt-imap-server` | RFC 3501 | planned |
| `tpt-doh` | RFC 8484 | planned |
| `tpt-http-cache` | RFC 9111 | planned |
| `tpt-dhcp` | RFC 2131 | planned |

See [`spec.txt`](spec.txt) for the original survey of gaps, and
[`todo.md`](todo.md) for the prioritized build plan.

## Clean-room policy

These crates are implemented from specification text only. **We do not copy
source** from existing implementations (e.g. `ciborium`, `russh`,
`ed25519-dalek`, `x509-parser`, `http-cache-semantics`, …). Where a
dual-licensed *parser* or *primitive* crate is reused, it is a dependency, not
copied code. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
