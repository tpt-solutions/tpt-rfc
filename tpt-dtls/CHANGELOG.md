# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to semantic versioning.

## [Unreleased]

### Added

- Initial implementation of `tpt-dtls`:
  - DTLS 1.3 record layer (RFC 9147 §4) with explicit epoch/sequence-number
    records and TLS 1.3 AEAD protection.
  - Per-epoch anti-replay sliding window (RFC 9147 §4.4) wired into the
    receive path.
  - Handshake message codec (RFC 8446 §4) with DTLS fragmentation /
    reassembly and a HelloRetryRequest-aware ServerHello.
  - Stateless cookie exchange (RFC 9147 §4.2.3 / §5.2) as an HMAC over the
    client's stable parameters.
  - Message-driven retransmission timer with exponential backoff (RFC 9147 §5.2).
  - TLS 1.3 (EC)DHE key schedule (RFC 8446 §7.1) for SHA-256 and SHA-384 suites.
  - Cipher suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
    `TLS_CHACHA20_POLY1305_SHA256`.
  - Connection ID support (RFC 9146 §2).
  - Transport-agnostic client/server `Connection` state machine performing
    the 1-RTT handshake (including the cookie round trip) and protecting
    application data, authenticating peers with raw Ed25519 public keys
    (RFC 7250) and a pluggable `CertVerifier` trait.
