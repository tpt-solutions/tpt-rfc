# SPEC-NOTES — <RFC NUMBER> (<TITLE>)

This file tracks the RFC sections implemented in this crate and the conformance
test vectors wired into the suite. It is the authoritative "are we done?" record
for the crate.

## Source documents

- RFC <NUMBER>: <TITLE> — <URL>
- Errata (if any): <URL or "none known">

## Implemented sections

<!-- Use [x] / [ ] to mark status. -->

- [ ] Section <n>: <name>

## Data model / public API

<!-- Describe the public data types and functions that map to the spec. -->

## Test vectors

- [ ] <Source, e.g. "RFC 8949 Appendix A"> — wired in `tests/<file>.rs`

## spec-complete checklist

- [ ] All in-scope RFC sections implemented
- [ ] Official test vectors passing
- [ ] `cargo clippy` + `cargo fmt` clean
- [ ] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io
