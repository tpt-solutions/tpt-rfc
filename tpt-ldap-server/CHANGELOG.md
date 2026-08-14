# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: RFC 4511 LDAP server conformance baseline.
  - Clean-room BER codec (`ber`) with definite + indefinite length support.
  - Message model and (de)serialization for all RFC 4511 operations
    (`protocol`).
  - Core operations: Bind (simple + SASL hook), Unbind, Search, Compare, Add,
    Delete, Modify, ModifyDN, Abandon, Extended.
  - Search filter parsing/evaluation (`and`/`or`/`not`/equality/substrings/
    ordering/present/approx/extensible) and base / single-level / subtree scope.
  - Pluggable `DirectoryBackend` trait with a reference in-memory backend
    (`memory`) using constant-time bind-password comparison.
  - Transport-agnostic session driver plus a std::net TCP `Server`.
