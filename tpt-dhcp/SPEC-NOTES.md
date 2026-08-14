# SPEC-NOTES — RFC 2131 (DHCP)

Clean-room implementation of the Dynamic Host Configuration Protocol, tracking
RFC 2131 section by section. Conformance is exercised by an end-to-end test
harness (`tests/dhcp_integration.rs`) that drives the client finite-state
machine against the server finite-state machine over an in-memory channel,
covering the full DISCOVER/OFFER/REQUEST/ACK exchange plus renewal, release,
and decline handling.

The wire format reuses the BOOTP message layout (RFC 1542) and the DHCP
options encoding (RFC 2132), both implemented clean-room from the RFC text. No
third-party DHCP wire-codec dependency is used — `dhcproto` (MIT) was
considered but a from-spec implementation keeps the crate self-contained and
fully auditable, consistent with the platform's clean-room requirement.

## Source documents

- RFC 2131: Dynamic Host Configuration Protocol — https://www.rfc-editor.org/rfc/rfc2131
- RFC 2132: DHCP Options and BOOTP Vendor Extensions — https://www.rfc-editor.org/rfc/rfc2132
- RFC 1542: Clarifications and Extensions for the Bootstrap Protocol (BOOTP) — https://www.rfc-editor.org/rfc/rfc1542
- Errata: https://www.rfc-editor.org/errata/rfc2131 (none affecting this crate)

## Implemented sections

- [x] §2 message format: BOOTP-derived header (op, htype, hlen, hops, xid,
      secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file) plus
      the DHCP magic cookie (§3).
- [x] §3 DHCP options: magic cookie, the `Pad`/`End` sentinels, and TLV
      encoding for the options used by this crate (RFC 2132 §3, §9).
- [x] §2 / §4.3.1 message types: DISCOVER(1), OFFER(2), REQUEST(3),
      DECLINE(4), ACK(5), NAK(6), RELEASE(7), INFORM(8) via option 53.
- [x] §4.3.1 discovering/selecting: client DISCOVER; server OFFER carrying
      yiaddr, Server Identifier, lease time, and requested parameters.
- [x] §4.3.2 requesting: client REQUEST (SELECTING/INIT-REBOOT/RENEWING/
      REBINDING variants); server selection and ACK/NAK logic, including the
      server-identifier check that makes a server ignore requests not meant for
      it.
- [x] §4.3.3/§4.3.4/§4.3.5: lease renewal (T1), rebinding (T2), and release.
- [x] §4.4.4 DECLINE: client detects address conflict, server marks the IP
      declined (probation).
- [x] §4.2/§4.4 INFORM: server replies with configuration only (yiaddr = 0).
- [x] §3.1 parameter request list (option 55) honoured by the server, plus
      standard options: Subnet Mask(1), Router(3), Domain Name Server(6),
      Host Name(12), Domain Name(15), Broadcast Address(28), Requested IP
      Address(50), Lease Time(51), Server Identifier(54), Message(56),
      Renewal Time(58), Rebinding Time(59), Vendor Class Identifier(60),
      Client Identifier(61).
- [x] §2 broadcast flag (bit 15 of `flags`) handled by the client and echoed
      by the server for reply routing.

## Data model / public API

- `message::DhcpMessage` — the BOOTP/DHCP message with encode/decode and
  typed option accessors.
- `options::{DhcpOption, MessageType, MessageOp}` — options and the message-type
  discriminator.
- `lease::{Lease, LeaseStore, AcquireRequest, LeaseError}` — the pluggable
  lease backend trait and the unit of a lease.
- `memory::MemoryLeaseStore` / `memory::PoolConfig` — reference in-memory
  backend for tests/examples.
- `server::{Server, ServerConfig}` — the server FSM; `process` is
  transport-agnostic and `run` provides a UDP listener.
- `client::Client` — the client FSM (INIT → SELECTING → REQUESTING → BOUND →
  RENEWING/REBINDING).

## Test vectors

- [x] Round-trip wire encode/decode in `tests/dhcp_integration.rs`:
  a hand-built DISCOVER/OFFER/REQUEST/ACK sequence is encoded and decoded and
  asserted field-by-field, including the magic cookie and option TLVs.
- [x] End-to-end client/server exchange in `tests/dhcp_integration.rs`:
  DISCOVER→OFFER→REQUEST→ACK binding, plus RENEWING, RELEASE, DECLINE, NAK
  (wrong server), and INFORM paths.

## spec-complete checklist

- [x] Client + server state machines implemented per RFC
- [x] Wire codec implemented and round-trip tested
- [x] Lease backend trait + in-memory reference implementation
- [x] Integration harness passing (covers RFC-required message flow)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against a real DHCP server (dnsmasq/ISC) and client
      (BLOCKED: no DHCP server/client in this environment — verified by the
      in-crate client/server integration harness instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
