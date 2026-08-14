# SPEC-NOTES — RFC 3161 (Internet X.509 Public Key Infrastructure Time-Stamp Protocol, TSP)

## Source documents

- RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) — https://www.rfc-editor.org/rfc/rfc3161
- RFC 5652 (CMS): referenced for the `SignedData` wrapper around `TSTInfo`
- RFC 5280 (X.509): certificate structures reused for the signer certificate

## Implemented sections

- [x] §2.1 `MessageImprint` (hashAlgorithm + hashedMessage)
- [x] §2.4.1 `TimeStampReq` (version, messageImprint, reqPolicy, nonce, certReq, extensions)
- [x] §2.4.2 `PKIStatusInfo` / `PKIStatus` / `PKIFreeText` / `PKIFailureInfo`
- [x] §2.4.2 `TimeStampResp` (status + optional `timeStampToken`)
- [x] §2.4.3 `TSTInfo` (version, policy, messageImprint, serialNumber, genTime, accuracy, ordering, nonce, tsa, extensions)
- [x] §2.4.3 accuracy (seconds / millis / micros)
- [x] CMS `ContentInfo` / `SignedData` / `SignerInfo` (RFC 5652) sufficient for TSP
- [x] Signed attributes: `content-type`, `message-digest`, `signing-time`
- [x] Client: build `TimeStampReq`, parse + verify `TimeStampResp`
- [x] TSA responder: request validation, `TSTInfo` construction, `SignedData` signing
- [x] Signature algorithms: RSASSA-PKCS1-v1_5 (SHA-256/384/512), ECDSA (P-256/P-384), Ed25519

## Data model / public API

- `MessageImprint` — hash algorithm + digest of the data to be timestamped.
- `TimeStampReq` / `TimeStampReqBuilder` — request construction + DER (de)serialization.
- `TimeStampResp` — response with `PKIStatusInfo` and optional `TimeStampToken`.
- `TstInfo` — the signed `TSTInfo` structure (RFC 3161 §2.4.3).
- `Signer` — key abstraction over RSA / ECDSA / Ed25519 signing keys.
- `Tsa` — minimal time-stamp authority: issues `TimeStampResp` for a request.
- `verify_timestamp_response` — parse + cryptographically verify a `TimeStampResp`
  (signature over signed attributes, message-digest + content-type consistency,
  `TSTInfo` consistency incl. nonce, and optional trust-anchor cert check).

## Test vectors

- [x] Round-trip DER encode/decode of `TimeStampReq` (deterministic snapshot).
- [x] Full TSA issue -> client verify round-trip using an in-test self-signed TSA
      certificate (P-256), proving client + server interop within the crate.
- [ ] Interop against a public RFC 3161 TSA (e.g. a real responder) — BLOCKED:
      no network egress to public TSA services in this environment; verified by
      the in-crate TSA round-trip instead.

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [x] Round-trip + TSA issue/verify test vectors passing
- [ ] `cargo clippy` + `cargo fmt` clean (run during build)
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io
