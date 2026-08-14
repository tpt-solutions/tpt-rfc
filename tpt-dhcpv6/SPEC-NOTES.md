# SPEC-NOTES — RFC 8415 (DHCPv6)

Clean-room implementation of the Dynamic Host Configuration Protocol for IPv6,
tracking RFC 8415 section by section. Conformance is exercised by an end-to-end
test harness (`tests/dhcpv6_integration.rs`) that drives the client finite-state
machine against the server finite-state machine over an in-memory channel,
covering the full SOLICIT/ADVERTISE/REQUEST/REPLY exchange plus renewal, release,
decline, confirm, prefix delegation, and stateless information-request paths.

The wire format reuses the DHCPv6 message layout (§7.1) and option encoding (§21.1)
and the DUID formats (§11), all implemented clean-room from the RFC text. No
third-party DHCPv6 wire-codec dependency is used — `dhcproto`'s sibling crates do
not cover DHCPv6, so a from-spec implementation keeps the crate self-contained and
fully auditable, consistent with the platform's clean-room requirement.

## Source documents

- RFC 8415: Dynamic Host Configuration Protocol for IPv6 (DHCPv6) — https://www.rfc-editor.org/rfc/rfc8415
- RFC 3646: DNS Configuration options for DHCPv6 (options 23/24) — https://www.rfc-editor.org/rfc/rfc3646
- RFC 6355: DHCPv6 Leasequery (DUID-UUID form, §11) — https://www.rfc-editor.org/rfc/rfc6355
- Errata: https://www.rfc-editor.org/errata/rfc8415 (none affecting this crate)

## Implemented sections

- [x] §7.1 message format: `msg-type` (1 byte), `transaction-id` (3 bytes), and a
      variable options field, with clean-room encode/decode (`message`).
- [x] §7.3 / §7.4 message types: SOLICIT(1), ADVERTISE(2), REQUEST(3),
      CONFIRM(4), RENEW(5), REBIND(6), REPLY(7), RELEASE(8), DECLINE(9),
      RECONFIGURE(10), INFORMATION-REQUEST(11); relay types (12/13) recognised
      and excluded from client/server FSMs.
- [x] §11 DUID: DUID-LL(3), DUID-LLT(1), DUID-EN(2), DUID-UUID(4) with verbatim
      fallback for unrecognised forms.
- [x] §21.1 option encoding: 2-byte code, 2-byte length, nested options for IA
      containers; unknown options preserved losslessly via `Other`.
- [x] §21.2/§21.3 Client/Server Identifier options (DUID).
- [x] §21.4 IA_NA, §21.5 IA_TA, §21.6 IAADDR, §21.21 IA_PD, §21.22 IAPREFIX.
- [x] §21.7 ORO, §21.8 Preference, §21.9 Elapsed Time, §21.12 Unicast,
      §21.13 Status Code (all standard codes), §21.14 Rapid Commit,
      §21.20 Reconfigure Accept.
- [x] §21.23/§21.24 DNS Recursive Name Server and Domain Search List options,
      including RFC 1035-style domain name encode/decode.
- [x] §18.1 client FSM (SOLICIT→ADVERTISE→REQUEST→REPLY), renewal (§18.2),
      rebinding (§18.3), release (§18.4), decline (§18.5), confirm (§18.6),
      and stateless information-request (§18.7).
- [x] §19 server FSM: ADVERTISE/REPLY generation, address/prefix allocation,
      T1/T2 timers, server-identifier selection, and per-IA status codes.
- [x] §21.4/§21.21 lease store trait with an in-memory backend allocating
      addresses (IA_NA/IA_TA) and prefixes (IA_PD) from configurable pools.

## Data model / public API

- `message::Dhcpv6Message` — the DHCPv6 message with encode/decode and typed
  option accessors.
- `options::{Dhcpv6Option, MessageType, Duid, IaNa, IaTa, IaAddress, IaPd,
  IaPrefix, StatusCode}` — options, message types, and IA structures.
- `lease::{LeaseStore, AcquireRequest, IaLease, IaAddressLease, IaPrefixLease}` —
  the pluggable lease backend trait and the unit of a lease.
- `memory::MemoryLeaseStore` / `memory::PoolConfig` — reference in-memory
  backend for tests/examples.
- `server::Server` — the server FSM; `process` is transport-agnostic and `run`
  provides a UDP listener.
- `client::Client` — the client FSM (INIT → SELECTING → REQUESTING → BOUND →
  RENEWING/REBINDING).

## Test vectors

- [x] Round-trip wire encode/decode in `tests/dhcpv6_integration.rs`: a hand-built
  SOLICIT is encoded and decoded and asserted field-by-field (transaction id,
  DUID, IA_NA, ORO), and unknown options survive a round trip.
- [x] End-to-end client/server exchange in `tests/dhcpv6_integration.rs`:
  SOLICIT→ADVERTISE→REQUEST→REPLY binding (with DNS + domain search), plus RENEW,
  RELEASE, DECLINE, CONFIRM, INFORMATION-REQUEST (stateless), prefix delegation
  (IA_PD), and the server-identifier selection that makes a server ignore
  requests not meant for it.

## Spec-conformance notes

- The server allocates a binding on both ADVERTISE and REQUEST (the store reuses
  an existing active lease for the same `(client, IA)`, so a REQUEST that follows
  an ADVERTISE does not allocate a second resource). This is a simplification of
  RFC 8415 §18.1.2's "no binding until REQUEST" rule, acceptable for an
  in-memory reference store and transparent to the client FSM.
- Rapid Commit (§21.14) is honoured by the server: a SOLICIT carrying the Rapid
  Commit option receives a REPLY directly.

## spec-complete checklist

- [x] Client + server state machines implemented per RFC
- [x] Wire codec implemented and round-trip tested
- [x] Lease backend trait + in-memory reference implementation (IA_NA/IA_TA/IA_PD)
- [x] Integration harness passing (covers RFC-required message flow)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against a real DHCPv6 server (dnsmasq, ISC Kea) and client
      (BLOCKED: no DHCPv6 server/client in this environment — verified by the
      in-crate client/server integration harness instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
