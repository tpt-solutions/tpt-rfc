# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial implementation of `tpt-sip`:
  - SIP message codec (request/response parse + serialise, RFC 3261 §7).
  - `sip:` / `sips:` URI parsing/rendering (§19.1).
  - Typed headers: `Via`, `From`/`To`, `Contact`, `CSeq` (§20).
  - Transaction layer: client/server × INVITE/non-INVITE state machines with retransmission and timers (§17).
  - Dialog creation and tracking (§12).
  - Method builders: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS.
  - Minimal SDP offer/answer body support (RFC 8866).
  - `Transport` trait plus a dependency-free UDP transport (§18).
