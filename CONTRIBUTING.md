# Contributing to the TPT Solutions RFC Platform

Thank you for your interest in contributing. This document explains the one
hard rule that governs the entire platform: **the clean-room requirement**.

## The clean-room requirement (mandatory)

Every crate in this workspace is a **clean-room implementation** of an IETF
RFC. This is the entire reason the platform exists: to provide
dual-licensed (MIT OR Apache-2.0) alternatives where existing popular crates
are single-licensed or otherwise incompatible with downstream license
requirements.

Concretely, when writing code for this workspace you MUST:

1. **Work from the specification text only.** Read the relevant RFC (and
   referenced errata, and authoritative test vectors). Your implementation
   should be derived from the prose of the standard.

2. **NOT copy source code** from any existing implementation of the same or a
   similar protocol. This includes, but is not limited to: `ciborium`,
   `russh`/`ssh2`, `ed25519-dalek`, `x509-parser`/`x509-cert`,
   `http-cache-semantics`, `dhcproto`, and any others. Reading such projects
   to understand a difficult section of a spec is acceptable for your own
   education, but the code you commit must be your own, written from the spec.

3. **NOT paste test vectors that are themselves copyrighted code.** Official
   RFC/IETF test vectors that are part of the published standard may be
   transcribed. Where a conformance suite exists as a body of code
   (e.g. the `http-cache-semantics` JavaScript test suite), reimplement the
   *test cases* from the documented behavior — do not copy the test code.

4. **Reuse dual-licensed dependency crates freely**, but only as dependencies.
   For example, `tpt-ed25519` may build on a dual-licensed curve crate, and
   `tpt-x509` may decode with `x509-parser` while implementing its own
   validation logic. The line is: depend on it, do not copy it.

## Why this matters

If code is copied from a GPL, LGPL, or Apache-2.0-only (or other
incompatibly-licensed) source, the platform's dual-licensing promise is broken
and the crate must be rewritten. Contributions that violate the clean-room rule
will be rejected and may be reverted.

## Development workflow

- Each crate carries a `SPEC-NOTES.md` that records which RFC sections are
  implemented and which test vectors are wired up.
- Run `cargo fmt`, `cargo clippy --all-targets`, and `cargo test` before
  opening a PR. CI enforces these plus a license-header check and
  dependency-license auditing via `cargo-deny`.
- Add a license header to every new source file (see the template below).

## License header

```rust
// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0
```

## Code of conduct

Be respectful and constructive. Reviews focus on spec conformance, safety, and
correctness — especially constant-time behavior in security-sensitive crates.
