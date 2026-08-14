# SPEC-NOTES — RFC 4271 (BGP-4)

This file tracks the RFC sections implemented in this crate and the conformance
test vectors wired into the suite. It is the authoritative "are we done?" record
for the crate.

## Source documents

- RFC 4271: A Border Gateway Protocol 4 (BGP-4) — <https://www.rfc-editor.org/rfc/rfc4271>
- RFC 4271 Errata: <https://www.rfc-editor.org/errata/rfc4271>
- RFC 5492: Capabilities Advertisement with BGP-4 — <https://www.rfc-editor.org/rfc/rfc5492>
- RFC 6793: BGP Support for Four-octet AS Number Space — <https://www.rfc-editor.org/rfc/rfc6793>
- RFC 4760: Multiprotocol Extensions for BGP-4 — <https://www.rfc-editor.org/rfc/rfc4760>
- RFC 2545: Use of BGP-4 Multiprotocol Extensions for IPv6 — <https://www.rfc-editor.org/rfc/rfc2545>

## Implemented sections

- [x] RFC 4271 §4.1 — common message header (marker, length, type) + length
      validation
- [x] RFC 4271 §4.2 — OPEN message (version, My AS, Hold Time, BGP Identifier,
      optional parameters) + capability TLV envelope (RFC 5492)
- [x] RFC 4271 §4.3 — UPDATE message: withdrawn routes, path attributes, NLRI
- [x] RFC 4271 §4.3 — path attributes: ORIGIN (1), AS_PATH (2), NEXT_HOP (3),
      MED (4), LOCAL_PREF (5), ATOMIC_AGGREGATE (6), AGGREGATOR (7),
      COMMUNITY (8), ORIGINATOR_ID (9), CLUSTER_LIST (10)
- [x] RFC 4271 §4.3 — AS_PATH encoding/decoding (AS_SET / AS_SEQUENCE
      segments)
- [x] RFC 4271 §4.4 — KEEPALIVE message
- [x] RFC 4271 §4.5 — NOTIFICATION message (codes/subcodes) + error constants
- [x] RFC 4271 §8 — peer finite-state machine (Idle → Connect → Active →
      OpenSent → OpenConfirm → Established) with the principal events and
      collision detection (§6.8) by BGP identifier comparison
- [x] RFC 4271 §9.1.2.1 — route-selection (decision) algorithm (local_pref,
      AS-path length, ORIGIN, MED, eBGP/iBGP, peer id)
- [x] RFC 6793 — four-octet ASNs: ASN4 capability (code 65), 4-byte AS_PATH /
      AGGREGATOR encoding, `AS_TRANS` (23456) handling in the OPEN AS field
- [x] RFC 4760 — multiprotocol extensions: MP_REACH_NLRI (14) /
      MP_UNREACH_NLRI (15) with AFI/SAFI, IPv4 + IPv6 NLRI
- [x] RFC 2545 — IPv6 global + link-local next hop

## Data model / public API

- `wire` — `Message`, `OpenMessage`, `Update`, `Notification`, `Capability`,
  `CodecOptions`, the 19-byte `BGP_MARKER` / `BGP_HEADER_LEN`, and the
  `msg_type` / `err_code` / `open_subcode` / `update_subcode` constants.
- `attributes` — `Asn`, `AsPath` (+ `AsPathSegment`/`AsPathSegmentType`),
  `Origin`, `Aggregator`, `NextHop`, `Prefix` (`Ipv4Prefix`/`Ipv6Prefix`),
  `MpReachNlri`/`MpUnreachNlri`, and the `PathAttribute` enum.
- `fsm` — `FsmState`, `FsmEvent`, `FsmAction`, and the event-driven `Fsm`.
- `rib` — `Route`, `RouteSource`, `Rib`, the `DecisionProcess` trait with the
  `DefaultDecision` reference implementation, and the `Policy` trait.

## Test vectors

BGP publishes no single canonical byte-vector conformance suite comparable to
CBOR's Appendix A. This crate therefore wires in:

- [x] Self-derived round-trip vectors for every message type in
  `tests/wire_roundtrip.rs` — each message is encoded and decoded and asserted
  byte-exact, including the 19-byte header length and marker.
- [x] A four-octet AS_PATH / AGGREGATOR round-trip (RFC 6793) and an
  `AS_TRANS` OPEN exchange in `tests/path_attributes.rs`.
- [x] Multiprotocol MP_REACH_NLRI (IPv6) and MP_UNREACH_NLRI round-trips
  (RFC 4760) in `tests/path_attributes.rs`.
- [x] The peer FSM state transitions (Idle → Established and teardown) in
  `tests/fsm.rs`.
- [x] The decision process ranking (local_pref > AS-path > ORIGIN > MED > eBGP)
  over a small route set in `tests/rib.rs`.

These are documented as internally-derived vectors (spec-conformance is verified
by construction and round-trip, not by an external published suite).

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [ ] Official external test vectors passing (no published suite exists)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io
      credentials in this environment)
