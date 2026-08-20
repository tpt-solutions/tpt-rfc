# tpt-kerberos

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **Kerberos v5** (RFC 4120) and **SPNEGO** (RFC 4178).

The only full-featured Rust Kerberos client (`kerbeiros`, from the Himmelblau
project) is AGPL-3.0-licensed — unusable as a dependency or "gap closed" for
this dual MIT/Apache-2.0 platform. This crate provides a from-spec, fully
auditable client *and* KDC (key-distribution-centre) implementation, covering
the AS-REQ/AS-REP and TGS-REQ/TGS-REP exchanges, AP-REQ/AP-REP service-ticket
acceptance, and SPNEGO GSSAPI mechanism negotiation — built on the AES
encryption types of RFC 3962 and RFC 8009.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections, known scope
limitations, and the "spec-complete" checklist.

## Example

```rust
use tpt_kerberos::client::Client;
use tpt_kerberos::kdc::MemoryKdc;
use tpt_kerberos::crypto::ENCTYPE_AES256_CTS_HMAC_SHA1_96;

let mut kdc = MemoryKdc::new();
kdc.add_principal("alice", "EXAMPLE.COM", "secret", ENCTYPE_AES256_CTS_HMAC_SHA1_96).unwrap();
kdc.add_service("host/server.example.com", "EXAMPLE.COM", "svcpass", ENCTYPE_AES256_CTS_HMAC_SHA1_96).unwrap();

let mut client = Client::new("alice", "EXAMPLE.COM");
client.authenticate(&kdc, "secret").unwrap();
client.service_ticket(&kdc, "host/server.example.com@EXAMPLE.COM").unwrap();
let ap_req = client.make_ap_req("host/server.example.com@EXAMPLE.COM").unwrap();
assert!(!ap_req.is_empty());
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
