# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: SNMP v1/v2c/v3 conformance baseline.
  - Clean-room BER codec (`ber.rs`) and SMI syntaxes (`value.rs`, `oid.rs`).
  - v1/v2c PDUs and community-string messages (`pdu.rs`), plus the v1 trap.
  - SNMPv3 message processing and USM envelope (`v3.rs`, `usm.rs`):
    HMAC-MD5-96 / HMAC-SHA-96 authentication and CBC-DES / AES-CFB-128 privacy,
    with password-to-key and key localization (RFC 3414 §11).
  - Clean-room MD5 and DES primitives (`crypto.rs`), validated against published
    known-answer vectors.
  - Pluggable `MibHandler` (`mib.rs`) with an in-memory reference backend.
  - Transport-agnostic `agent::Agent` and `manager::Manager`.
