# tpt-tsp

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **RFC 3161 Time-Stamp Protocol (TSP)**.

A from-spec implementation of RFC 3161, built to close the licensing gap
identified in the TPT Solutions RFC survey. `freetsa` already covers the TSP
*client* side reasonably well, so this crate focuses on the part that is
missing under a clean dual license: a **TSA (server) responder** plus a
**client** that can both build requests and fully verify responses (signature
over the signed attributes, `message-digest`/`content-type` consistency, and
`TSTInfo` consistency). See `SPEC-NOTES.md` for the section-by-section
conformance status and the test vectors wired into the suite.

## Features

- Build a `TimeStampReq` with hash algorithm, policy, nonce, and `certReq`.
- Parse and DER-encode `TimeStampReq` / `TimeStampResp` / `TSTInfo`.
- Verify a `TimeStampResp` cryptographically: CMS `SignedData` signature over
  the signed attributes, `message-digest` and `content-type` attribute checks,
  and `TSTInfo` consistency (message imprint, nonce, policy).
- Optional trust-anchor certificate verification via `tpt-x509`-style clean-room
  signature checks using dual-licensed RustCrypto primitives.
- A minimal TSA responder that validates a request and signs a `TimeStampToken`.

## Example

```rust,no_run
use tpt_tsp::{TimeStampReqBuilder, Tsa, Signer, verify_timestamp_response, HashAlgorithm};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Client: build a request for the SHA-256 hash of some data.
let data = b"document to be timestamped";
let req = TimeStampReqBuilder::new(HashAlgorithm::Sha256, data)
    .nonce(1234)
    .build()?;

// (In real use the DER request is sent to a TSA over HTTP; here we issue it locally.)
let der = req.to_der()?;
let resp = Tsa::self_signed_demo()?.issue(&der)?;

// Client: verify the response.
let token = verify_timestamp_response(&resp.to_der()?, None)?;
assert_eq!(token.message_imprint().hashed_message(), &sha2::Sha256::digest(data)[..]);
# Ok(())
# }
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
