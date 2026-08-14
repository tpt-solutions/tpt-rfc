# SPEC-NOTES — RFC 2328 (OSPFv2) + RFC 5340 (OSPFv3)

This file tracks the RFC sections implemented in this crate and the conformance
test vectors wired into the suite. It is the authoritative "are we done?" record
for the crate.

## Source documents

- RFC 2328: OSPF Version 2 — <https://www.rfc-editor.org/rfc/rfc2328>
- RFC 5340: OSPF for IPv6 — <https://www.rfc-editor.org/rfc/rfc5340>
- RFC 2328 Errata: <https://www.rfc-editor.org/errata/rfc2328>
- RFC 5340 Errata: <https://www.rfc-editor.org/errata/rfc5340>

## Implemented sections

- [x] RFC 2328 §A.3.1 — OSPF packet header (v2) encode/decode + Internet checksum
- [x] RFC 2328 §A.3.2 — Hello packet (Network Mask, intervals, DR/BDR, neighbors)
- [x] RFC 2328 §A.3.3 — Database Description packet (MTU, I/M/MS flags, DD seq)
- [x] RFC 2328 §A.3.4 — Link State Request packet
- [x] RFC 2328 §A.3.5 — Link State Update packet
- [x] RFC 2328 §A.3.6 — Link State Acknowledgement packet
- [x] RFC 2328 §A.3.1 — LSA header (20 bytes) encode/decode + LSA age/checksum
- [x] RFC 2328 §A.4.2 — Router-LSA body encode/decode (links)
- [x] RFC 2328 §A.4.3 — Network-LSA body encode/decode
- [x] RFC 2328 §A.4.4/.4.5 — Summary / AS-external LSA headers (+ opaque body)
- [x] RFC 2328 §7 — neighbor state machine (Down/Attempt/Init/2-Way/ExStart/
      Exchange/Loading/Full) and the events that drive it
- [x] RFC 2328 §13 — link-state database and flooding (LSA acceptance, sequence
      number comparison, LSRefresher / flooding scope handled per LSA type)
- [x] RFC 2328 §16 — intra-area SPF (Dijkstra) and routing-table derivation
- [x] RFC 5340 §A.1 — OSPFv3 packet header (Instance ID + reserved, no auth)
- [x] RFC 5340 §A.4.2 — OSPFv3 LSA header (S2/S1 + 32-bit options) framing
- [x] RFC 5340 §A.4.3 — OSPFv3 Router-LSA header framing (body opaque)

## Data model / public API

- `wire` — `OspfVersion`, `PacketType`, `OspfPacket` (v2 + v3), encode/decode,
  `internet_checksum`.
- `lsa` — `LsaHeader`, `LsaType`, `RouterLsa`, `RouterLink`, `NetworkLsa`,
  opaque `RawLsa`; `Lsa` enum unifying them.
- `database` — `LinkStateDatabase` with `install`, `newer_than`, `flood` logic.
- `neighbor` — `Neighbor`, `NeighborState`, `NeighborEvent`, the FSM transition
  function, and `NeighborTable`.
- `spf` — `Spf` builder + `ShortestPathTree` / `RoutingTable` result.

## Test vectors

OSPF does not publish a canonical byte-vector conformance suite (unlike e.g.
CBOR's Appendix A). This crate therefore wires in:

- [x] Self-derived round-trip vectors for every packet type (v2 + v3) in
  `tests/wire_roundtrip.rs` — each packet is encoded and decoded and asserted
  byte-exact, and the checksum field is verified to be reproducible.
- [x] A textbook 5-node SPF topology in `tests/spf.rs` cross-checked against a
  hand-computed shortest-path tree.
- [x] Neighbor FSM state transitions in `tests/neighbor.rs`.
- [x] LSDB flooding / newer-LSA comparison in `tests/flooding.rs`.

These are documented as internally-derived vectors (spec-conformance is verified
by construction and round-trip, not by an external published suite).

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [ ] Official external test vectors passing (no published suite exists)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io
      credentials in this environment)
