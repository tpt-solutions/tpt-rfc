# tpt-sieve

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **Sieve mail filtering (RFC 5228)**.

A from-spec implementation of the Sieve filtering language, built to close the
licensing gap identified in the TPT Solutions RFC survey. `sieve-rs`
(Stalwart Labs) is comprehensive but AGPL-3.0-licensed — not usable as a
dependency for this dual MIT/Apache-2.0 platform — so this crate provides a
clean-room, fully MIT/Apache-licensed alternative.

See `SPEC-NOTES.md` for the section-by-section conformance status and the test
vectors wired into the suite.

## What it does

`tpt-sieve` does two things, and keeps them cleanly separated:

1. **Parsing** (`parse`) — turns Sieve source text into an AST (`Script`)
   following the RFC 5228 grammar: commands, tests, actions, and the
   `if` / `elsif` / `else` control structures, including comments, quoted and
   multi-line (`text:`) strings, and `K`/`M`/`G` size quantifiers.
2. **Evaluation** (`evaluate`) — runs a parsed `Script` against a
   [`MessageContext`](src/context.rs) you supply. The engine never touches a
   message directly; it only asks your context for header values, envelope
   values, and message size. That keeps it composable with mail stores such as
   `tpt-smtp` or `tpt-imap-server`.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Example

```rust
use tpt_sieve::{parse, evaluate, InMemoryMessage};

let script = r#"
    require ["fileinto"];
    if header :contains "Subject" "make money" {
        discard;
    } elsif address :is :domain "From" "example.com" {
        fileinto "INBOX.example";
    } else {
        keep;
    }
"#;

let msg = InMemoryMessage::new(1024)
    .add_header("Subject", "you can make money fast")
    .add_header("From", "Someone <someone@example.com>");

let actions = evaluate(&parse(script).unwrap(), &msg).unwrap();
assert!(matches!(actions.finalize(), tpt_sieve::FinalActions::Discard));
```

## Supported features (RFC 5228 base)

- Tests: `allof`, `anyof`, `not`, `exists`, `true`, `false`, `size`,
  `header`, `address`, `envelope`.
- Actions: `keep`, `discard`, `redirect`, `fileinto`, `stop`.
- Control: `if` / `elsif` / `else`, `require`.
- Match types: `:is`, `:contains`, `:matches` (with `*`/`?` wildcards).
- Comparators: `i;ascii-casemap` (default) and `i;octet`.
- Address parts: `:all` (default), `:localpart`, `:domain`.
- Size quantifiers: `K`, `M`, `G` (e.g. `:over 100K`).
- Capability enforcement for `require "fileinto"` and `require "envelope"`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
