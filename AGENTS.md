# AGENTS.md

Cargo workspace of clean-room, dual-licensed (MIT OR Apache-2.0) Rust
implementations of IETF RFC protocols, one crate per protocol under `tpt-*`.

## Hard rule: clean-room
Every crate is built from RFC text only. Do **NOT** copy source from existing
implementations (ciborium, russh, ed25519-dalek, x509-parser, etc.). Reuse
dual-licensed crates as *dependencies* only. This is the whole reason the repo
exists; violations get reverted. See `CONTRIBUTING.md`.

- Add the license header to every new `.rs` file:
  ```rust
  // Copyright 2026 TPT Solutions
  // SPDX-License-Identifier: MIT OR Apache-2.0
  ```
- Each crate carries a `SPEC-NOTES.md` tracking implemented RFC sections and
  wired test vectors. Update it when you change conformance.

## Commands
- Build/test workspace: `cargo test --workspace` (or `cargo test -p tpt-<name>`).
- Lint before PR: `cargo fmt`, `cargo clippy --all-targets`, `cargo test`.
- Dependency/license audit: `cargo deny check` (config in `deny.toml`;
  rejects copyleft and unknown-registry deps).

## Workspace boundaries (non-obvious)
- `Cargo.toml` `[workspace]` lists most crates, but `tpt-x25519` and
  `tpt-ldap-server` are **excluded** — they declare their own `[workspace]` and
  build/test independently (`cargo test -p tpt-x25519` from root will not work;
  `cd tpt-x25519 && cargo test`).
- `tpt-x509` is force-optimized in dev/test profiles (`[profile.dev.package.tpt-x509]`)
  because its RSA mod-exp is slow otherwise — keep that; don't "fix" it.
- Shared settings live in `[workspace.package]` / `[workspace.dependencies]` /
  `[workspace.lints]`. Crates inherit lints via `[lints] workspace = true`.

## Conventions
- MSRV 1.74, edition 2021. `unsafe_code` and `clippy::all` are `warn` everywhere.
- `serde`/`thiserror` come from `workspace.dependencies`; depend on them as
  `workspace = true`, not with inline versions.
- Crates are mostly `planned`/`in-progress`; use `crate-template/` as the
  skeleton for new crates.

## Test quirks
- `tpt-x509` tests depend on bundled `tests/data/nist-pkits/` (public-domain
  NIST data); don't remove it. Its PKITS harness is slow unless optimized (see above).
- `tpt-x25519` dev-depends on `x25519-dalek` **only** for conformance cross-checks
  in `tests/compare_dalek.rs` — dev-only, never a runtime dependency.
