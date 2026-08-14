# SPEC-NOTES — RFC 5228 (Sieve: An Email Filtering Language)

This file tracks the RFC 5228 sections implemented in `tpt-sieve` and the
conformance test vectors wired into the suite. It is the authoritative
"are we done?" record for the crate.

## Source documents

- RFC 5228: Sieve: An Email Filtering Language — <https://www.rfc-editor.org/rfc/rfc5228>
- Errata: <https://www.rfc-editor.org/errata/rfc5228> (none known affecting the
  base feature set implemented here)

## Implemented sections

- [x] §2.1 Script structure (commands, arguments, blocks)
- [x] §2.2 Whitespace, comments (`#` line, `/* */` block), line endings
- [x] §2.3 Strings: quoted (`"..."`) with escapes, multi-line (`text:`),
      string lists (`[ "a", "b" ]`)
- [x] §2.4.1 `require` capability declaration (and ordering constraint)
- [x] §2.4.2 Tests: `allof`, `anyof`, `exists`, `false`, `header`, `not`,
      `size`, `true`, `address`, `envelope`
- [x] §2.4.2.1 Match types: `:is`, `:contains`, `:matches` (wildcards `*`, `?`)
- [x] §2.4.2.2 `address` test with `:localpart` / `:domain` / `:all`
- [x] §2.4.2.3 Comparators: `i;ascii-casemap`, `i;octet`
- [x] §2.4.2.4 `envelope` test (requires `require "envelope"`)
- [x] §2.4.2.5 `exists` test
- [x] §2.4.2.6 `size` test with `:over` / `:under` and `K`/`M`/`G` quantifiers
- [x] §2.4.3 Actions: `keep`, `fileinto`, `redirect`, `discard`, `stop`
- [x] §2.5.1 Control: `if` / `elsif` / `else`
- [x] §2.10.2 Default (implicit `keep`) and action interaction semantics
      (`stop`, explicit `keep` wins over `discard`)

## Data model / public API

- `parse(&str) -> Result<Script, SieveError>` — lex + parse into `Script`
  (see `ast.rs`).
- `evaluate(&Script, &C) -> Result<ActionSet, SieveError>` — run a script
  against a `C: MessageContext` (see `context.rs`), accumulating an
  `ActionSet`.
- `ActionSet::finalize() -> FinalActions` — resolve to `Keep` / `Discard` /
  `Deliver(DeliverActions)`.
- `InMemoryMessage` — a ready-made `MessageContext` for tests/examples.

## Test vectors

- [x] RFC 5228 §6.1 (`header :contains` → `fileinto`) — `tests/rfc5228.rs`
- [x] RFC 5228 §6.2.2 (`exists`) — `tests/rfc5228.rs`
- [x] RFC 5228 §6.2.3 (`anyof`) — `tests/rfc5228.rs`
- [x] RFC 5228 §6.2.4 (`address :domain`) — `tests/rfc5228.rs`
- [x] RFC 5228 §6.2.5 (`envelope :is`) — `tests/rfc5228.rs`
- [x] RFC 5228 §6.2.6 (`size :over 100K`) — `tests/rfc5228.rs`
- [x] RFC 5228 §6.3 (`if`/`elsif`/`else`) — `tests/rfc5228.rs`
- [x] RFC 5228 §6.2.1.2 (`:matches` wildcard) — `tests/rfc5228.rs`
- [x] §2.4.2.3 comparator `i;octet` case sensitivity — `tests/rfc5228.rs`
- [x] Multi-line `text:` strings and comments round-trip — `tests/rfc5228.rs`
- [x] RFC 5228 §10 large worked example parses and evaluates — `tests/rfc5228.rs`

## Deferred / out of scope (base RFC 5228)

- The relational (`":count"`, `":value"`) and `i;ascii-numeric` comparator
  extension (RFC 5231) — not part of the RFC 5228 base feature set.
- Variables (RFC 5229), body (RFC 5170), date/index, regex, etc. — separate
  extensions; the parser rejects unknown tags/tests rather than silently
  accepting them.

## spec-complete checklist

- [x] All in-scope RFC 5228 base sections implemented
- [x] RFC §6 / §10 test vectors passing
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io
      credentials in this environment)
- [x] Marked "spec-complete" once parser + engine pass the RFC test suite
