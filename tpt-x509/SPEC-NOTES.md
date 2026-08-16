# SPEC-NOTES — RFC 5280 (X.509 / PKIX)

Clean-room implementation of the X.509 certification-path validation engine,
tracking the RFC section by section. Reuses `x509-cert` (MIT/Apache-2.0) purely
for DER decoding; the validation logic and signature verification are built
clean-room on top, closing the gap that `rustls-webpki` (ISC-only) leaves for
permissively-licensed consumers.

## Source documents

- RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate
  Revocation List (CRL) Profile — https://www.rfc-editor.org/rfc/rfc5280

## Implemented sections

- [x] §4.2.1.3 Basic Constraints — CA flag + path-len-constraint enforcement.
- [x] §4.2.1.3 Key Usage — `keyCertSign` required on CA certificates.
- [x] §4.2.1.12 Extended Key Usage — accumulation along the chain and
      end-entity purpose check.
- [x] §4.2.1.10 Name Constraints — permitted/excluded subtree intersection
      (DNS names) across the chain.
- [x] §6.1 Path Validation Algorithm — trust-anchor handling, working-key
      progression, signature verification, validity-period checks, policy
      handling (`anyPolicy` accepted by default).
- [x] §6.3 CRL-based revocation checking (signature-verified CRLs issued by a
      CA in the path or the trust anchor).
- [x] Signature verification: RSA PKCS#1 v1.5 (SHA-256/384/512), ECDSA
      P-256/P-384, Ed25519 — all via dual-licensed RustCrypto primitives.

## Public API

- `cert::Cert` (re-export of `x509_cert::Certificate`), `cert::TrustAnchor`,
  `cert::parse_der` / `cert::parse_pem`.
- `validate::PathValidator` / `validate::ValidationConfig`.
- `crl::parse_der` / `crl::parse_pem` and `crl::check_revocation`.
- `ocsp` — OCSP `TimeStampReq`-style request builder (nonce extension).

## Test vectors

- [x] Integration harness in `tests/path_validation.rs` generates root →
      intermediate → leaf chains in clean room (P-256, ECDSA-with-SHA256) and
      asserts acceptance/rejection for: valid root+leaf, missing-CA-bit,
      expired, EKU mismatch, name-constraint violation/satisfaction, and a
      3-certificate intermediate chain.
- [ ] NIST PKITS (Public Key Interoperability Test Suite) conformance vectors —
      tracked as a follow-up; the current harness covers the core algorithm
      paths but does not yet run the full PKITS corpus.

## spec-complete checklist

- [x] Path validation engine implemented per RFC 5280 §6.1
- [x] Basic/key/extended-key-usage + name-constraint enforcement
- [x] CRL revocation checking
- [x] Signature verification via dual-licensed primitives
- [x] `cargo test` / `cargo clippy` / `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] NIST PKITS corpus wired into the test harness
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
