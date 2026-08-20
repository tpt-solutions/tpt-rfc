# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: Kerberos v5 (RFC 4120) + SPNEGO (RFC 4178) conformance baseline.
  - RFC 4120 §5 wire types (`Ticket`/`EncTicketPart`, `KDC-REQ`/`KDC-REP`,
    `AP-REQ`/`AP-REP`, `Authenticator`, `PrincipalName`, `EncryptedData`,
    `EncryptionKey`, `Checksum`, `PA-DATA`) with hand-rolled DER encode/decode.
  - AES encryption types `aes{128,256}-cts-hmac-sha1-96` (RFC 3962, etypes
    17/18) and `aes{128,256}-cts-hmac-sha{256-128,384-192}` (RFC 8009, etypes
    19/20): `string2key` (PBKDF2), `DK`/`DR`/`KDF-HMAC-SHA2` key derivation,
    AES-CTS (CS3 ciphertext stealing), and HMAC integrity checksums.
  - Client: AS-REQ/AS-REP with PA-ENC-TIMESTAMP pre-authentication,
    TGS-REQ/TGS-REP, AP-REQ construction, and a credential cache.
  - Service: AP-REQ acceptance (ticket + authenticator validation, clock-skew
    and expiry checks) and AP-REP construction.
  - `MemoryKdc`: in-memory AS-REQ/TGS-REQ responder for testing/self-contained
    operation, enforcing PA-ENC-TIMESTAMP pre-authentication.
  - SPNEGO `NegTokenInit`/`NegTokenResp` (RFC 4178) plus GSS-API
    `InitialContextToken` framing for negotiating the Kerberos v5 mechanism.
