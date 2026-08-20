# SPEC-NOTES — RFC 4120 (Kerberos v5) + RFC 4178 (SPNEGO)

This file tracks the RFC sections implemented in this crate and the
conformance coverage wired into the test suite. It is the authoritative
"are we done?" record for the crate.

## Source documents

- RFC 4120: The Kerberos Network Authentication Service (V5) — <https://www.rfc-editor.org/rfc/rfc4120>
- RFC 4178: The Simple and Protected GSS-API Negotiation Mechanism (SPNEGO) — <https://www.rfc-editor.org/rfc/rfc4178>
- RFC 3961: Encryption and Checksum Specifications for Kerberos 5 (key-usage
  numbers, `DK`/`DR` key derivation, checksum-key derivation) — <https://www.rfc-editor.org/rfc/rfc3961>
- RFC 3962: AES Encryption for Kerberos 5 (`aes{128,256}-cts-hmac-sha1-96`,
  CBC-CTS) — <https://www.rfc-editor.org/rfc/rfc3962>
- RFC 8009: AES Encryption with HMAC-SHA2 for Kerberos 5
  (`aes{128,256}-cts-hmac-sha{256-128,384-192}`) — <https://www.rfc-editor.org/rfc/rfc8009>
- RFC 8018: PKCS #5 (PBKDF2, used by `string2key`) — <https://www.rfc-editor.org/rfc/rfc8018>

## Implemented sections

- [x] RFC 4120 §5.2 — core ASN.1 primitive types (`KerberosString`,
      `KerberosTime`/`GeneralizedTime`, `Int32`/`UInt32`, `PrincipalName`,
      `HostAddress(es)`, `AuthorizationData`, `Checksum`, `EncryptedData`,
      `EncryptionKey`) hand-rolled over the `der` crate's `Any`/DER primitives
      (`src/asn1.rs`, `src/types.rs`)
- [x] RFC 4120 §5.3 — `Ticket` / `EncTicketPart` (flags, session key,
      client/transited/times/addresses/authorization-data)
- [x] RFC 4120 §5.4 — `KDC-REQ`/`KDC-REP` (AS-REQ/AS-REP, TGS-REQ/TGS-REP),
      `KDC-REQ-BODY`, `EncKDCRepPart` (last-req, nonce, flags, times, srealm/sname)
- [x] RFC 4120 §5.5 — `AP-REQ`/`AP-REP`, `Authenticator`, `EncAPRepPart`
- [x] RFC 4120 §5.2.7 — `PA-DATA`; `PA-ENC-TIMESTAMP` pre-authentication
      (encrypted-timestamp construction/verification) and `PA-TGS-REQ`
      (AP-REQ carried as TGS-REQ pre-auth data)
- [x] RFC 4120 §5.9.1 — `KRB-ERROR` status codes surfaced via [`crate::error::Error`]
      (`PreauthRequired`, `KrbError { code, etext }`, ticket-expiry, etc.)
- [x] RFC 4120 §7.5.1 / RFC 3961 §6 — key-usage numbers (`crate::key_usage`)
- [x] RFC 3961 §5.2/§6 — `DK`/`DR` key derivation and `Kc` checksum-key
      derivation for the RFC 3962 enctypes
- [x] RFC 3962 — `aes128/256-cts-hmac-sha1-96` (etypes 17/18): PBKDF2
      `string2key`, `DK`/`DR` key derivation, CBC-CTS (CS3 variant, NIST SP
      800-38A Addendum), HMAC-SHA1-96 integrity
- [x] RFC 8009 — `aes128-cts-hmac-sha256-128` / `aes256-cts-hmac-sha384-192`
      (etypes 19/20): `KDF-HMAC-SHA2` key derivation with the fixed
      `kerberos-8009-KEY-{ENCRYPT,CKSUM}` labels, usage folded into the HMAC
      input, HMAC-SHA256-128 / HMAC-SHA384-192 integrity
- [x] Client: AS-REQ/AS-REP exchange (with PA-ENC-TIMESTAMP), TGS-REQ/TGS-REP
      exchange, AP-REQ construction, and a credential cache (TGT + per-service
      tickets) (`src/client.rs`)
- [x] Service: AP-REQ acceptance (ticket + authenticator decryption/validation,
      clock-skew check, ticket-expiry check) and AP-REP construction (`src/service.rs`)
- [x] KDC: in-memory AS-REQ/TGS-REQ responder with pluggable principal storage,
      lease-free session-key generation, and enforced pre-authentication
      (`src/kdc.rs`)
- [x] RFC 4178 §4.2 — SPNEGO `NegTokenInit`/`NegTokenResp` plus the GSS-API
      `InitialContextToken` (`[APPLICATION 0]`) framing carrying the SPNEGO OID
      (`src/spnego.rs`)

## Known scope limitations

- **Enctype negotiation.** A real KDC lets an AS-REQ omit or guess the client
  enctype and replies with `KRB-ERR-PREAUTH-REQUIRED` plus `PA-ETYPE-INFO2`
  (etype + salt) so the client can retry with the right key. `MemoryKdc` does
  not implement that round trip; a [`crate::client::Client`] must be told the
  correct enctype up front via `Client::with_enctype` (or rely on the
  `Client::new` default, `aes256-cts-hmac-sha1-96`) to match whatever enctype
  the principal was registered with. The `PA-ETYPE-INFO2` wire type itself
  (`types::pa_etype_info2`) is implemented and available for a caller that wants
  to build the full negotiation on top.
- **Legacy enctypes.** `des3-cbc-sha1`/`arcfour-hmac` are intentionally out of
  scope (RFC 3962/8009's AES enctypes are the modern, still-recommended
  choice; the legacy types add no license-clean-room value).
- **Cross-realm / referrals, PAC, FAST (RFC 6113), and renew/validate flag
  handling on the KDC** are not implemented — this crate targets a single
  realm's AS/TGS/AP exchanges plus SPNEGO framing, the demand-ranked scope
  from `spec.txt`.

## Data model / public API

- `types` — the RFC 4120 §5 wire structures (`Ticket`, `EncTicketPart`,
  `KdcReq`/`KdcRep`, `EncKdcRepPart`, `ApReq`/`ApRep`, `Authenticator`,
  `EncApRepPart`, `PrincipalName`, `EncryptionKey`, `EncryptedData`, `PaData`,
  etc.) with hand-written `encode`/`decode` pairs.
- `asn1` — the low-level DER TLV builders/cursor (`Cursor`, `ensure_tag`,
  `peel_explicit`, `unwrap_sequence`) and Kerberos primitive codecs
  (`KerberosString`, `KerberosTime`, `Int32`/`UInt32`), plus `Principal`
  (`name@realm` parsing/formatting).
- `crypto` — `Enctype`, `string2key`, `encrypt`/`decrypt`/`checksum`, and the
  four AES enctype constants.
- `client` — `Client`, `CachedTicket`.
- `kdc` — `Kdc` trait, `MemoryKdc`, `PrincipalEntry`, ticket-flag constants.
- `service` — `Service`, `ApAccepted`.
- `spnego` — `NegTokenInit`, `NegTokenResp`, `OID_SPNEGO`, `OID_KRB5`.
- `key_usage` — the RFC 4120/3961 key-usage number constants.

## Test coverage

RFC 4120 has no official byte-vector conformance suite (unlike, e.g., CBOR's
Appendix A); this crate instead verifies conformance by:

- [x] RFC 3962 §4 `string2key` against the RFC 6070 PBKDF2-HMAC-SHA1 known-answer
      vectors (`tests/crypto_vectors.rs::pbkdf2_sha1_rfc6070`)
- [x] AES-CTS round-trip across all four enctypes and a range of plaintext
      lengths spanning full/partial final blocks
      (`tests/crypto_vectors.rs::aes_cts_roundtrip_all_enctypes`)
- [x] Encrypt/decrypt/checksum determinism, tamper detection, and wrong-key
      rejection (`tests/crypto_vectors.rs`)
- [x] End-to-end AS-REQ → AS-REP → TGS-REQ → TGS-REP → AP-REQ → AP-REP against
      the in-memory KDC, including a rejected AP-REQ against the wrong service
      key and a rejected TGS-REQ from an unauthenticated client
      (`tests/roundtrip.rs`)
- [x] The same end-to-end flow for `aes128-cts-hmac-sha1-96` (17) and
      `aes256-cts-hmac-sha384-192` (20, RFC 8009), not just the AES256-SHA1
      default (`tests/roundtrip.rs`)
- [x] SPNEGO `NegTokenInit`/`NegTokenResp` round-trips, including carrying a
      real AP-REQ as the inner mechanism token (`tests/roundtrip.rs`)
- [ ] Interop against a real KDC (MIT Kerberos, Heimdal, Active Directory) —
      BLOCKED: no such KDC available in this environment

## spec-complete checklist

- [x] AS-REQ/AS-REP, TGS-REQ/TGS-REP, AP-REQ/AP-REP, and SPNEGO framing pass
      the in-crate round-trip harness for all four supported AES enctypes
- [ ] Interop against a real KDC (BLOCKED: no KDC available in this environment)
- [x] `cargo clippy` + `cargo fmt` clean (missing-`#[doc]` warnings only, same
      baseline as the rest of the workspace)
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io
      credentials in this environment)
