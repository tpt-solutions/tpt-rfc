# tpt-ospf

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **OSPF** — the Open Shortest Path First interior gateway protocol of
> [RFC 2328](https://www.rfc-editor.org/rfc/rfc2328) (OSPFv2) and
> [RFC 5340](https://www.rfc-editor.org/rfc/rfc5340) (OSPFv3).

A from-spec implementation of the OSPF link-state routing protocol, built to
close the licensing gap identified in the TPT Solutions RFC survey. The only
crate found during the survey (`ospf-parser`) is parser-only with an
unconfirmed license and no protocol logic, so this crate is built from scratch
as a full protocol toolkit: encode/decode, the link-state database, the neighbor
finite-state machine, and the Dijkstra shortest-path calculation.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## What this crate covers

- **Wire codec** (`wire`): the OSPF packet header plus all five packet types —
  Hello, Database Description (DBD), Link State Request (LSR), Link State
  Update (LSU), and Link State Acknowledgement (LSAck) — for both OSPFv2 and
  OSPFv3, with the standard 16-bit Internet checksum.
- **LSA model** (`lsa`): the LSA header and body encode/decode for Router and
  Network LSAs (the LSAs that drive intra-area SPF), plus opaque handling of
  Summary and AS-external LSAs; and the Link State Database with flooding
  logic (`database`).
- **Neighbor FSM** (`neighbor`): the Down → Attempt → Init → 2-Way → ExStart →
  Exchange → Loading → Full state machine.
- **SPF engine** (`spf`): Dijkstra's shortest-path-first calculation over the
  Router/Network LSAs of an area, producing a next-hop routing table.

## Example

```rust
use tpt_ospf::lsa::{Lsa, RouterLsa, RouterLink, RouterLinkType};
use tpt_ospf::spf::Spf;

// Build a tiny two-router stub network and run SPF from router 10.0.0.1.
let mut spf = Spf::new([10, 0, 0, 1]);
spf.add_router_lsa(RouterLsa {
    header: tpt_ospf::lsa::LsaHeader::router([10, 0, 0, 1], 0),
    links: vec![RouterLink {
        link_type: RouterLinkType::PointToPoint,
        link_id: [10, 0, 0, 2],
        link_data: [255, 255, 255, 0],
        metric: 10,
    }],
});
spf.add_router_lsa(RouterLsa {
    header: tpt_ospf::lsa::LsaHeader::router([10, 0, 0, 2], 0),
    links: vec![],
});
let table = spf.calculate();
assert_eq!(table.next_hop([10, 0, 0, 2]), Some([10, 0, 0, 2]));
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
