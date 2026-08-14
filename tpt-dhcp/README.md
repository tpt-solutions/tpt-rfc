# tpt-dhcp

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of **DHCP** —
> the Dynamic Host Configuration Protocol of **RFC 2131**.

A from-spec implementation of DHCP (client + server) built to close the
licensing gap identified in the TPT Solutions RFC survey. It uses the BOOTP
message format (RFC 1542) and the DHCP options encoding (RFC 2132), both
implemented clean-room. The lease backend is pluggable, with a reference
in-memory store provided for tests and small deployments.

The only other production-grade Rust DHCP server
([dhcproto](https://crates.io/crates/dhcproto), MIT) is a wire-codec library
with no bundled client or server, so a full implementation closes a real gap.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented RFC sections and the
"spec-complete" checklist.

## Example

```rust
use std::net::Ipv4Addr;
use tpt_dhcp::client::Client;
use tpt_dhcp::memory::{MemoryLeaseStore, PoolConfig};
use tpt_dhcp::server::Server;

let config = PoolConfig::default();
let mut server = Server::new(config.clone());
let mut client = Client::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

let discover = client.start_discover();
let offer = server.process_bytes(&discover.to_bytes()).unwrap().unwrap();
let request = client.receive_offer(&offer).unwrap();
let ack = server.process_bytes(&request.to_bytes()).unwrap().unwrap();
client.receive_ack(&ack).unwrap();

assert!(client.lease().is_some());
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
