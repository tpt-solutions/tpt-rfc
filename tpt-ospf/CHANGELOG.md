# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: OSPFv2 (RFC 2328) + OSPFv3 (RFC 5340) conformance baseline.
  - OSPF packet header + all five packet types (Hello, DBD, LSR, LSU, LSAck)
    for both OSPFv2 and OSPFv3, with the standard Internet checksum.
  - LSA header/body encode/decode for Router and Network LSAs, with opaque
    handling of Summary and AS-external LSAs.
  - Link State Database with flooding logic.
  - Neighbor finite-state machine (Down → Full).
  - Dijkstra SPF calculation producing a next-hop routing table.
