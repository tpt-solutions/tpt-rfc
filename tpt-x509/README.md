# tpt-x509

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **X.509 certificate path validation** — [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).

A from-spec implementation of the X.509 certification-path validation engine
(RFC 5280 §6.1). It reuses [`x509-cert`](https://crates.io/crates/x509-cert)
**only for DER decoding** and builds a clean-room validation layer on top: the
gap that `rustls-webpki` leaves while keeping a permissive MIT/Apache-2.0
license (rustls-webpki is ISC-only).

Signature verification uses dual-licensed RustCrypto primitives (RSA
PKCS#1 v1.5, ECDSA P-256/P-384, Ed25519) — the cryptographic core is never
reimplemented.

## Features

- Path building + RFC 5280 §6.1 validation (trust anchors, signature chaining,
  validity-period checks, basic-constraints / key-usage / extended-key-usage
  enforcement, name constraints, policy handling).
- CRL-based revocation checking (RFC 5280 §6.3).
- A self-contained, dependency-light OCSP **request** builder (full OCSP
  client/responder verification is tracked separately in `tpt-ocsp`).

## Example

```rust
use tpt_x509::{
    cert::TrustAnchor,
    validate::{PathValidator, ValidationConfig},
};
use x509_cert::Certificate;

// `root` and `leaf` are `x509_cert::Certificate` values (parsed from DER/PEM).
let anchor = TrustAnchor::from_cert(&root).unwrap();
let config = ValidationConfig {
    trust_anchors: vec![anchor],
    // Require the server-auth extended key usage (OID 1.3.6.1.5.5.7.3.1).
    required_eku: Some(const_oid::ObjectIdentifier::new_unwrap(
        "1.3.6.1.5.5.7.3.1",
    )),
    ..Default::default()
};
let validator = PathValidator::new(config);
let path = validator.validate(&leaf).expect("valid chain");
assert_eq!(path.len(), 2);
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.
