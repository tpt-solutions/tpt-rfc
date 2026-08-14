# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to semantic versioning.

## [Unreleased]

### Added

- Initial implementation of `tpt-bfd`:
  - BFD control-packet encode/decode (RFC 5880 §4.1).
  - Session state machine with detection timer and demand mode (§6.2, §6.6, §6.8).
  - Poll Sequence support (§6.5).
  - Simple Password and Keyed/Meticulous Keyed SHA1 authentication (§6.7).
  - Synchronous UDP transport for asynchronous mode (RFC 5881).
