# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: RFC 1939 POP3 server conformance baseline.
  - AUTHORIZATION / TRANSACTION / UPDATE state machine.
  - Core commands: USER, PASS, STAT, LIST, RETR, DELE, NOOP, RSET, QUIT.
  - Optional commands: TOP, UIDL, APOP.
  - Pluggable `MailboxBackend` trait with an in-memory reference backend.
  - Transport-agnostic session driver plus a std::net TCP `Server`.
