# tpt-snmp

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **SNMP** — v1, v2c and v3 with the User-based Security Model (USM), built
> from RFCs 3411–3418 and RFC 3826.

A from-spec SNMP agent (server) and manager (client), built to close the
licensing gap identified in the TPT Solutions RFC survey: the only cohesive
Rust SNMP support (`snmp2`, `rasn-snmp`, etc.) is fragmented across small
crates, and none offer a single dual-licensed v1/v2c/v3 agent **and** manager
with USM authentication and privacy in one auditable crate. `tpt-snmp` keeps
its wire codec (a small, deliberate subset of BER), SMI syntaxes, and the
PDU/USM logic clean-room inside the crate rather than depending on a
general-purpose ASN.1 library. Cryptographic primitives are reused where
dual-licensed: `hmac`/`sha1` for HMAC-SHA-96, `aes` for AES-CFB-128; MD5 and
DES are implemented clean-room and validated against published test vectors.

See `SPEC-NOTES.md` for the section-by-section conformance status and the test
vectors wired into the suite.

## Features

- v1/v2c/v3 message encode/decode with a small, auditable BER codec.
- Full PDU set: `GetRequest`, `GetNextRequest`, `GetResponse`, `SetRequest`,
  `GetBulkRequest` (non-repeaters / max-repetitions), `InformRequest`,
  `SNMPv2-Trap`, `Report`, and the v1 `Trap`.
- USM authentication: HMAC-MD5-96 and HMAC-SHA-96, with key localization
  against the authoritative engine ID.
- USM privacy: CBC-DES (RFC 3414) and AES-CFB-128 (RFC 3826).
- Engine discovery: an unauthenticated request is answered with a reportable
  `Report` carrying the engine identity.
- A pluggable `MibHandler` for the agent, with an in-memory reference backend,
  and a transport-agnostic manager that performs discovery, authentication, and
  (optionally) privacy automatically.

## Example

```rust
use tpt_snmp::agent::Agent;
use tpt_snmp::manager::Manager;
use tpt_snmp::mib::InMemoryMib;
use tpt_snmp::oid::ObjectIdentifier;
use tpt_snmp::value::SnmpValue;

let mut mib = InMemoryMib::new();
mib.insert(
    ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]),
    SnmpValue::from_str("tpt-snmp agent"),
);
let mut agent = Agent::new(mib, b"tptengine".to_vec());

let mut mgr = Manager::v2c(b"public");
let req = mgr.build_get(&ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]));
let resp = agent.process(&req).expect("response");
let binds = mgr.parse_response(&resp).unwrap();
assert_eq!(binds.0[0].value, SnmpValue::from_str("tpt-snmp agent"));
```

For an authenticated + encrypted v3 exchange, register a USM user on the agent
(`Agent::add_user`) and create the `Manager` with `Manager::v3` using the same
passwords; the manager performs engine discovery, authentication and (optionally)
privacy automatically.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
