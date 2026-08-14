# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to semver once `1.0.0` is cut.

## [0.1.0] - Unreleased

### Added

- Clean-room RADIUS packet encode/decode (RFC 2865 §3).
- PAP `User-Password` hiding and recovery (RFC 2865 §5.2).
- Response and accounting-request authenticator computation/verification
  (RFC 2865 §3, RFC 2866 §3).
- `Message-Authenticator` HMAC-MD5 (RFC 3579 §3.2) with verification.
- `EAP-Message` (79) passthrough with automatic 253-octet fragmentation.
- `Vendor-Specific` (26) and `Proxy-State` (33) handling.
- `Client` with shared-secret reply verification and a blocking UDP transport.
- `Server` behind a pluggable `AuthBackend`, with a `run` UDP listener.
- Reference in-memory `AuthBackend` (`MemoryBackend`).
- RFC 2865 §7.1 conformance vectors and a client/server integration harness.
