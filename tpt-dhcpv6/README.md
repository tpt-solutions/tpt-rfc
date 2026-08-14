# tpt-dhcpv6

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of **DHCPv6** —
> the Dynamic Host Configuration Protocol for IPv6 of **RFC 8415**.

A from-spec implementation of DHCPv6 (client + server) built to close the
licensing gap identified in the TPT Solutions RFC survey. It uses the message and
option encoding of RFC 8415 §7 and §21, the DUID formats of §11, and the
Identity Association containers of §21.4–§21.6 and §21.21–§21.22, all
implemented clean-room. The lease backend is pluggable, with a reference
in-memory store provided for tests and small deployments.

The only other production-grade Rust DHCPv6 implementations are client libraries
or are coupled to larger frameworks; this crate fills the gap with a
self-contained, fully auditable, MIT/Apache-2.0 implementation covering both the
client and server state machines.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented RFC sections and the
"spec-complete" checklist.

## Example

```rust
use std::net::Ipv6Addr;
use tpt_dhcpv6::client::Client;
use tpt_dhcpv6::memory::PoolConfig;
use tpt_dhcpv6::options::Duid;
use tpt_dhcpv6::server::Server;

let config = PoolConfig::default();
let mut server = Server::new(config.clone());
let mut client = Client::new(Duid::from_ethernet_ll(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));

let solicit = client.start_solicit();
let advertise = server.process_bytes(&solicit.to_bytes()).unwrap().unwrap();
let request = client
    .receive_advertise(&tpt_dhcpv6::message::Dhcpv6Message::from_bytes(&advertise).unwrap())
    .unwrap();
let reply = server.process_bytes(&request.to_bytes()).unwrap().unwrap();
client.receive_reply(&tpt_dhcpv6::message::Dhcpv6Message::from_bytes(&reply).unwrap()).unwrap();

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
