# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: BGP-4 (RFC 4271) conformance baseline.
  - BGP common header + all four message types (OPEN, UPDATE, NOTIFICATION,
    KEEPALIVE) with length/marker validation.
  - Path attributes: ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE,
    AGGREGATOR, COMMUNITY, ORIGINATOR_ID, CLUSTER_LIST, plus verbatim handling of
    unknown attributes.
  - Four-octet ASNs (RFC 6793): ASN4 capability, 4-byte AS_PATH/AGGREGATOR,
    `AS_TRANS` OPEN handling.
  - Multiprotocol NLRI (RFC 4760): MP_REACH/MP_UNREACH with IPv4 + IPv6 AFI and
    RFC 2545 link-local next hops.
  - Peer finite-state machine (Idle → Established) per RFC 4271 §8 with
    collision detection.
  - RIB (Adj-RIB-In + Loc-RIB) with the RFC 4271 §9.1.2.1 decision process and a
    pluggable import/export policy trait.
