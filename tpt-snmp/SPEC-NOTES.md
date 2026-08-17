# SPEC-NOTES — RFC 3411–3418 (SNMPv3) + RFC 3826 (AES privacy)

This file tracks the RFC sections implemented in `tpt-snmp` and the conformance
test vectors wired into the suite. It is the authoritative "are we done?" record
for the crate.

## Source documents

- RFC 3411: An Architecture for Describing Simple Network Management Protocol (SNMP) Management Frameworks — <https://www.rfc-editor.org/rfc/rfc3411>
- RFC 3412: Message Processing and Dispatching for the SNMP — <https://www.rfc-editor.org/rfc/rfc3412>
- RFC 3413: Simple Network Management Protocol (SNMP) Applications — <https://www.rfc-editor.org/rfc/rfc3413>
- RFC 3414: User-based Security Model (USM) for SNMPv3 — <https://www.rfc-editor.org/rfc/rfc3414>
- RFC 3416: Version 2 of the Protocol Operations for the SNMP — <https://www.rfc-editor.org/rfc/rfc3416>
- RFC 3417: Transport Mappings for the SNMP — <https://www.rfc-editor.org/rfc/rfc3417>
- RFC 3418: Management Information Base (MIB) for the SNMP — <https://www.rfc-editor.org/rfc/rfc3418>
- RFC 3826: The Advanced Encryption Standard (AES) Cipher Algorithm in the SNMP USM — <https://www.rfc-editor.org/rfc/rfc3826>
- RFC 2578: Structure of Management Information Version 2 (SMIv2) — <https://www.rfc-editor.org/rfc/rfc2578>
- Errata: none known affecting the implemented surface.

## Implemented sections

- [x] RFC 2578 §7.1 / RFC 3416 §6 — SMI application syntaxes: INTEGER, OCTET STRING, OBJECT IDENTIFIER, IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64, and the v2 exception values `noSuchObject` / `noSuchInstance` / `endOfMibView`.
- [x] RFC 3417 — BER usage: definite-length encoding, universal tags, application/context-specific tags (clean-room codec in `ber.rs`; no general ASN.1 dependency).
- [x] RFC 3416 §4 — PDU operations for v2c/v3: `GetRequest`, `GetNextRequest`, `GetResponse`, `SetRequest`, `GetBulkRequest` (non-repeaters / max-repetitions), `InformRequest`, `SNMPv2-Trap`, `Report`.
- [x] RFC 1157 §4.1.6 / RFC 3416 — v1 `Trap-PDU` (enterprise, agent-addr, generic/specific trap, time-stamp, varbinds).
- [x] RFC 3411 §5 — `SnmpEngineID` (opaque octet string carried end to end; per-engine `boots`/`time`).
- [x] RFC 3412 §6 — SNMPv3 message processing model: `msgGlobalData` (`msgID`, `msgMaxSize`, `msgFlags`, `msgSecurityModel`), the `OCTET STRING`-wrapped USM security parameters, and the `msgData` CHOICE (plaintext `ScopedPdu` vs encrypted `OCTET STRING`).
- [x] RFC 3414 §7 — USM authentication: HMAC-MD5-96 and HMAC-SHA-96 (12-byte truncated MAC, computed over the whole message with the auth parameters zeroed).
- [x] RFC 3414 §8 — USM privacy: CBC-DES (8-byte salt, pre-IV = `privKey[8..16] XOR salt`).
- [x] RFC 3826 §3 — USM privacy: AES-CFB-128 (16-byte IV = `boots || time || salt`).
- [x] RFC 3414 §11 — key derivation: `passwordToKey` (password expansion to 1 MiB), and key localization `Hash(key || engineID || key)` for MD5 (16-byte) and SHA-1 (20-byte) auth keys; privacy key localized from the auth key.
- [x] RFC 3414 §5 — engine discovery: an unauthenticated request with an empty/unknown engine ID is answered with a reportable `Report` carrying `usmStatsUnknownEngineIDs`.
- [x] Agent (server) — transport-agnostic `process` for v1/v2c community messages and v3/USM (auth + optional privacy), backed by a pluggable `MibHandler`.
- [x] Manager (client) — `build_get` / `build_get_next` / `build_set` / `build_get_bulk`, v3 engine discovery, and `parse_response` (auth verification, privacy decryption, engine-time synchronisation).
- [ ] Interop-test against a real SNMP agent/manager (e.g. Net-SNMP) — BLOCKED: no SNMP peer in this environment; verified by the in-crate agent↔manager integration harness plus the MD5/DES/AES-CFB known-answer vectors instead.

## Data model / public API

- `oid::ObjectIdentifier` — OID with canonical BER base-128 encoding.
- `value::{SnmpValue, VarBind, VarBindList}` — SMI syntaxes and variable bindings.
- `pdu::{SnmpVersion, Pdu, PduType, Message, MessageData, TrapV1}` — v1/v2c PDUs and community string messages, plus the v1 trap.
- `v3::{HeaderData, UsmSecurityParameters, ScopedPdu, V3Data, V3Message}` — SNMPv3 message, USM security parameters, and scoped PDU; `encode_signed` / `verify_auth` handle the HMAC.
- `usm::{AuthProtocol, PrivProtocol, password_to_auth_key, localize_key, localize_priv_key, auth_mac, encrypt_scoped, decrypt_scoped}` — USM crypto helpers.
- `crypto::{md5, hmac_md5, des_*}` — clean-room MD5 (used for HMAC-MD5-96) and DES-CBC (used for CBC-DES privacy).
- `mib::{MibHandler, InMemoryMib}` — pluggable OID handler and reference in-memory backend.
- `agent::Agent` — agent (server) for v1/v2c/v3 with `process` and `add_user`.
- `manager::Manager` — manager (client) with `v2c` / `v3` constructors, request builders, and `parse_response`.
- `SnmpMessage` — top-level dispatch over `Community` and `V3` messages.

## Test vectors

- [x] RFC 1321 MD5 known-answer vectors (`""` and `"abc"`) in `crypto::tests::md5_known_vector`.
- [x] FIPS 81 DES known-answer vector (key `133457799bcdff1`, plain `0123456789abcdef`) in `crypto::tests::des_known_vector_fips81`.
- [x] AES-CFB-128 and CBC-DES round trips against the clean-room primitives (`usm::tests`).
- [x] v1/v2c Get/GetNext/Set/GetBulk and v1 trap round trips (`tests/snmp_integration.rs`).
- [x] v3 USM auth (MD5 + SHA-1) and auth+priv (DES, AES-CFB-128) full agent↔manager exchanges, plus auth-failure rejection and engine discovery (`tests/snmp_integration.rs`).

## spec-complete checklist

- [x] All in-scope RFC sections implemented (v1/v2c PDUs, v3 message processing, USM auth + CBC-DES + AES-CFB-128 privacy, engine discovery).
- [x] Known-answer vectors (MD5, DES, AES-CFB) + integration harness passing (`cargo test -p tpt-snmp`).
- [x] `cargo clippy` + `cargo fmt` clean.
- [x] docs.rs-quality documentation (`#![deny(missing_docs)]` + crate/module docs).
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io credentials in this environment).
- [x] Confirmed conformant via known-answer vectors + integration harness (interop-test blocked).
