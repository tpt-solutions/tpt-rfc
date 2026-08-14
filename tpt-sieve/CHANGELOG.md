# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: RFC 5228 (Sieve) base conformance baseline.
  - Lexer + recursive-descent parser for the RFC 5228 grammar.
  - Evaluation engine over a pluggable `MessageContext` trait.
  - Tests: `allof`, `anyof`, `not`, `exists`, `true`, `false`, `size`,
    `header`, `address`, `envelope`.
  - Actions: `keep`, `discard`, `redirect`, `fileinto`, `stop`.
  - Control: `if` / `elsif` / `else`, `require`.
  - Match types `:is` / `:contains` / `:matches`, comparators
    `i;ascii-casemap` / `i;octet`, address parts `:all` / `:localpart` /
    `:domain`, and `K`/`M`/`G` size quantifiers.
  - Capability enforcement for `require "fileinto"` and `require "envelope"`.
