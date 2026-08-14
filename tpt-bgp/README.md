# tpt-bgp

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **BGP-4** — the Border Gateway Protocol, RFC 4271.

A from-spec implementation of BGP-4, built to close the licensing gap identified
in the TPT Solutions RFC survey (no maintained, dual-licensed BGP implementation
exists in the Rust ecosystem). It covers the message codec (OPEN / UPDATE /
NOTIFICATION / KEEPALIVE), path attributes, four-octet ASNs (RFC 6793),
multiprotocol NLRI (RFC 4760), the peer finite-state machine (RFC 4271 §8), and
a pluggable RIB with the RFC 4271 §9.1.2.1 decision process.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Example

```rust
use tpt_bgp::wire::{Message, OpenMessage};
use tpt_bgp::attributes::Asn;

let open = OpenMessage {
    version: 4,
    my_asn: Asn(65001),
    hold_time: 90,
    bgp_id: [10, 0, 0, 1],
    capabilities: vec![],
};
let bytes = Message::Open(open).to_bytes();
assert_eq!(Message::from_bytes(&bytes).unwrap(), Message::Open(open));
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
