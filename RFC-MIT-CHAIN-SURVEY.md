# 75 Vital RFCs — MIT-Chain Coverage Survey

Generated 2026-08-13. This is a point-in-time survey of the Rust crate ecosystem
for 75 RFCs considered foundational/vital to the internet, run against this
project's licensing bar: **a crate only counts as "already covering" an RFC if
it is MIT-only or dual-licensed "MIT OR Apache-2.0"** (or an equivalent dual
grant that includes MIT). Apache-only, BSD-only, ISC-only, MPL-2.0, and
copyleft (AGPL/GPL) crates do **not** count, regardless of maturity or adoption
— see `licensing_mit_chain` project memory for the full rationale.

Verdict legend:
- **COVERED** — a genuinely solid, complete, MIT-chain-licensed implementation exists
- **PARTIAL** — some MIT-chain coverage exists but it's incomplete, unstable, low-adoption, or covers only part of the protocol (e.g. client but not server, or parsing but not the full protocol)
- **GAP** — no MIT-chain-licensed solid implementation exists at all
- **N/A** — not a crate-shaped problem (e.g. OS-kernel-level transport protocols)

`*` marks RFCs already tracked as a phase in `todo.md`.

---

## Transport/core

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 791 | IPv4 | `smoltcp` | 0BSD | N/A — kernel-level; smoltcp fails license bar anyway |
| 8200 | IPv6 | `smoltcp` | 0BSD | N/A |
| 9293 | TCP | `smoltcp` | 0BSD | N/A |
| 768 | UDP | OS stack | — | N/A — trivial, kernel-level |
| 792 | ICMP | `smoltcp` | 0BSD | N/A |
| 4443 | ICMPv6 | `smoltcp` | 0BSD | N/A |
| 4861 | IPv6 Neighbor Discovery | `smoltcp` | 0BSD | N/A |

## DNS

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 1035 | DNS | `hickory-dns` | MIT OR Apache-2.0 | **COVERED** — very active, full-featured, widely deployed |
| 8484* | DoH | `hickory-dns` (built-in) | MIT OR Apache-2.0 | **COVERED** |
| 7858 | DoT | `hickory-dns` (TLS feature) | MIT OR Apache-2.0 | **COVERED** |
| 9250 | DoQ | `hickory-dns` (quic feature) | MIT OR Apache-2.0 | **COVERED** |

> Note: `tpt-doh` (Phase 7) predates this finding. `hickory-dns` covers DoH
> natively under the MIT chain — worth deciding whether `tpt-doh`'s value is
> purely "focused/composable client" differentiation (per its existing
> `SPEC-NOTES.md` rationale) rather than filling an absolute gap.

## DHCP

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 2131* | DHCPv4 | `dhcproto` (parser), `edge-dhcp` (embedded client+server) | MIT / MIT OR Apache-2.0 | **PARTIAL** — solid wire-format coverage, no mature general-purpose server |
| 8415* | DHCPv6 | `dhcproto` (parser) | MIT | **PARTIAL** — same as above |

## Routing

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 4271* | BGP | `bgpkit-parser`, `bgp-models` | MIT | **PARTIAL** — solid parsers, no full FSM+RIB speaker |
| 2328 | OSPFv2 | `ospf-parser` | unconfirmed | **GAP** — parser-only at best, license/maturity unconfirmed |
| 5340 | OSPFv3 | `ospf-parser` | unconfirmed | **GAP** — same |
| 5880* | BFD | none | — | **GAP** — no real implementation exists at any license |

## TLS/crypto core

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 8446 | TLS 1.3 | `rustls` | Apache-2.0 OR ISC OR MIT | **COVERED** — dominant stack, includes MIT option |
| 9147* | DTLS 1.3 | `webrtc-dtls` | MIT OR Apache-2.0 | **PARTIAL** — DTLS 1.2 solid, 1.3 support experimental |
| 5280* | X.509 + path validation | `x509-parser` (parsing) + `rustls-webpki` (validation) | `x509-parser`: MIT/Apache-2.0; `rustls-webpki`: **ISC-only** | **PARTIAL** — parsing covered, the dominant path-validation engine fails the bar |
| 6960* | OCSP | `x509-ocsp`, `ocsp-stapler` | MIT OR Apache-2.0 | **PARTIAL** — formats solid, full responder/client ecosystem thin/WIP |
| 5652* | CMS | `cms` (RustCrypto) | Apache-2.0 OR MIT | **PARTIAL** — pre-release (0.3.0-pre.2), incomplete API. (`cryptographic-message-syntax` is MPL-2.0, doesn't count) |
| 8032* | Ed25519 | `ed25519-dalek` | **BSD-3-Clause** | **GAP** — the dominant crate fails the license bar entirely |
| 7748 | X25519/X448 | `x25519-dalek` | **BSD-3-Clause** | **GAP** — same dalek-family license issue. Not currently tracked in `todo.md` — natural companion to `tpt-ed25519` |

## Remote access/tunneling

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 4251-4254* | SSH | `russh` / `thrussh` | **Apache-2.0 only** | **GAP** — the only serious full-protocol implementations both fail the license bar. Strongly validates the in-house `tpt-ssh` build |
| 4301* | IPsec architecture | `ipsec-parser` | MIT/Apache-2.0 | **GAP** — parser only, stale since 2021 |
| 7296* | IKEv2 | `ipsec-parser`, `fynx-proto` (alpha) | mixed/unconfirmed | **GAP** — no mature full implementation at any license |
| 3161* | TSP | `x509-tsp` (formats), `freetsa` (client) | Apache-2.0 OR MIT / MIT OR Apache-2.0 | **PARTIAL** — client side reasonably covered (freetsa); `x509-tsp` stalled since 2023; TSA server remains the gap |

## Web/HTTP

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 9110 | HTTP Semantics | `http`, `httparse` | MIT OR Apache-2.0 | **COVERED** |
| 9112 | HTTP/1.1 | `hyper`, `httparse` | MIT | **COVERED** |
| 9113 | HTTP/2 | `h2` | MIT | **COVERED** |
| 9114 | HTTP/3 | `quinn` + `h3` | MIT OR Apache-2.0 / MIT | **COVERED** |
| 6265 | Cookies | `cookie` | MIT OR Apache-2.0 | **COVERED** |
| 9111* | HTTP Caching | `http-cache` (wrapper); `http-cache-semantics` (core logic) | wrapper: MIT/Apache-2.0; **core: BSD-2-Clause** | **PARTIAL** — the actual caching-semantics core fails the bar, only a wrapper is MIT-chain. Validates in-house `tpt-http-cache` |
| 6455 | WebSocket | `tungstenite` / `tokio-tungstenite` | MIT OR Apache-2.0 | **COVERED** |
| 9421* | HTTP Message Signatures | `httpsig` | MIT | **PARTIAL** — real but niche/low-adoption (~1,300 downloads all-time) |
| 9576/9578* | Privacy Pass | `privacypass` | MIT | **PARTIAL** — real but research-grade, stale ~4 years |
| 3986 | URI | `url`, `iri-string` | MIT OR Apache-2.0 | **COVERED** |
| 6570 | URI Templates | `iri-string` | MIT OR Apache-2.0 | **COVERED** |
| 9457 | Problem Details | `problemdetails`, `problem_details` | MIT | **PARTIAL** — real but thin/low-adoption |
| 6266 | Content-Disposition | `content_disposition` | MIT OR 0BSD | **PARTIAL** — real but narrow-scope, low-adoption |
| 8878 | Brotli | `brotli` (dropbox) | BSD-3-Clause OR MIT | **COVERED** — MIT is one of the dual options |
| 7239 | Forwarded header | `forwarded-header-value` (ISC), `rfc7239` (unconfirmed) | ISC / unconfirmed | **GAP** — no confirmed MIT-chain option (ISC fails the literal bar) |

## Auth/identity

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 6749 | OAuth2 | `oauth2` | MIT OR Apache-2.0 | **COVERED** |
| 7519 | JWT | `jsonwebtoken` | MIT | **COVERED** |
| 7515 | JWS | RustCrypto `jose-jws`, `josekit` | Apache-2.0 OR MIT | **COVERED** |
| 7516 | JWE | RustCrypto JOSE (thin), `josekit` (OpenSSL-dependent) | Apache-2.0 OR MIT | **PARTIAL** — weaker pure-Rust coverage than JWS/JWK |
| 7517 | JWK | RustCrypto `jose-jwk` | Apache-2.0 OR MIT | **COVERED** |
| 6238 | TOTP | `totp-rs` | MIT | **COVERED** |
| 4226* | HOTP | (in-house `tpt-hotp`) | — | N/A — in-house |
| 4120* | Kerberos v5 | `kerbeiros` + entire ecosystem (`kerberos_crypto`, `kerberos_asn1`, `cerbero`, `himmelblau_*`) | **AGPL-3.0 across the board** | **GAP** — systemic, the whole Rust Kerberos ecosystem is AGPL |
| 4178* | SPNEGO | none dedicated | — | **GAP** — no standalone crate exists at all |
| 2865* | RADIUS | `radius-rust` (MIT, abandoned 5+ yrs), `radius-server` (MIT OR Apache-2.0, immature, ~2k downloads) | MIT / MIT OR Apache-2.0 | **PARTIAL/GAP** — MIT-chain options exist but are abandoned or too immature. `abol` (Apache-only) and `radius-tokio` (BSD) confirmed to still not count |
| 4511* | LDAP | `ldap3` (client), `ldap` meta-crate (server "not fully written yet" per its own docs) | MIT OR Apache-2.0 | **PARTIAL** — client covered, server confirmed a genuine gap |

## Email

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 5321* | SMTP | `mailin`/`mailin-embedded`; `samotop` (core is **Apache-2.0 only**, only `samotop-delivery` sub-crate is dual) | mailin: MIT OR Apache-2.0; samotop core: Apache-2.0 only | **PARTIAL/GAP** — `mailin` is the only confirmed MIT-chain option and is fragmented/thin; `samotop`'s core server does NOT count (correction to earlier note — see below) |
| 5322* | IMF/MIME | `mail-parser` (Stalwart) | Apache-2.0 OR MIT | **COVERED** — mature, 2.7M+ downloads |
| 9051 | IMAP4rev2 (server) | Stalwart (full server) | **AGPL-3.0** (Community edition) | **GAP** — only real full server is AGPL. `todo.md`'s existing `tpt-imap-server` phase targets the older RFC 3501; worth updating to reference 9051 as current |
| 1939 | POP3 | small/thin crates; Stalwart (AGPL) | mixed, mostly unconfirmed/thin | **GAP** — not currently tracked in `todo.md` |
| 5228* | Sieve | `sieve-rs` (Stalwart) | **AGPL-3.0** | **GAP** — confirmed, matches existing `todo.md` note |
| 8620/8621 | JMAP | `jmap-client` (client), Stalwart (server, AGPL) | client: Apache-2.0 OR MIT | **PARTIAL** — client covered, server is a gap. Not currently tracked |

## Time

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 5905 | NTPv4 | `ntpd` (ntpd-rs) | Apache-2.0 OR MIT | **COVERED** — full client+server+daemon |
| 8915 | NTS | `ntpd` (same crate) | Apache-2.0 OR MIT | **COVERED** |

## Real-time/media

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 3261* | SIP | `rsipstack` | MIT | **COVERED** |
| 3550/3551* | RTP/RTCP | `rtp`, `rtcp` (webrtc-rs) | MIT/Apache-2.0 | **COVERED** |
| 8445 | ICE | `str0m`, `webrtc-ice` | MIT OR Apache-2.0 | **COVERED** |
| 5389/8489 | STUN | `stun` (webrtc-rs) | MIT/Apache-2.0 | **COVERED** |
| 5766/8656 | TURN | `turn` (webrtc-rs) | MIT/Apache-2.0 | **PARTIAL** — license fine, but behind pion's TURN feature parity per upstream docs |
| 8829 | WebRTC JSEP | `webrtc`, `str0m` | MIT / MIT OR Apache-2.0 | **COVERED** |

## Network management

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 3411* | SNMP | `snmp2`, `snmp_rust_agent` | MIT OR Apache-2.0 | **COVERED** |
| 6241* | NETCONF | `rustnetconf` | MIT | **COVERED** — confirmed license (was previously unconfirmed) |
| 7950* | YANG | `yang2` (binds to C `libyang2`) | MIT (wrapper only) | **PARTIAL** — the Rust binding is MIT, but the underlying C library it wraps isn't; no pure-Rust MIT-chain YANG parser exists |

## Serialization

| RFC | Topic | Best Crate(s) | License | Verdict |
|---|---|---|---|---|
| 8949* | CBOR | (in-house `tpt-cbor`) | — | N/A — in-house |
| 8259 | JSON | `serde_json` | MIT OR Apache-2.0 | **COVERED** |
| 6902 | JSON Patch | `json-patch` | MIT/Apache-2.0 | **COVERED** |
| 7396 | JSON Merge Patch | `json-patch` (same crate) | MIT/Apache-2.0 | **COVERED** |

---

## Summary of actionable findings

**New confirmed gaps not yet in `todo.md`:**
- RFC 7748 (X25519/X448) — `x25519-dalek` is BSD-3-Clause. Natural companion to `tpt-ed25519`.
- RFC 2328/5340 (OSPFv2/v3) — no real implementation at any license.
- RFC 1939 (POP3) — no solid MIT-chain server.
- RFC 8620/8621 (JMAP) — client covered, server-side is AGPL-only (Stalwart).
- RFC 9051 (IMAP4rev2) — supersedes RFC 3501 which `tpt-imap-server` currently targets; still a gap either way (Stalwart's server is AGPL).

**Corrections to existing `todo.md` notes:**
- `tpt-smtp` (Phase 18): the note citing `samotop` as dual-licensed is wrong — `samotop`'s core server crate is **Apache-2.0 only**; only its `samotop-delivery` sub-crate is dual. Only `mailin` confirmed MIT-chain. This makes the SMTP gap larger than previously stated.
- `tpt-cms` (Phase 12): RustCrypto's `cms` crate is confirmed dual-licensed but is **pre-release (0.3.0-pre.2)**, more unstable than previously characterized.
- `tpt-netconf` (Phase 21): `rustnetconf`'s license is now confirmed as MIT (previously flagged as unconfirmed).

**Strong validations of existing in-house builds (no change needed, just confirmation):**
- `tpt-ed25519` — `ed25519-dalek` is BSD-3-Clause, a genuine license gap.
- `tpt-ssh` — both `russh` and `thrussh` are Apache-2.0 only, a genuine license gap.
- `tpt-http-cache` — the actual caching-semantics logic (`http-cache-semantics`) is BSD-2-Clause.
- `tpt-x509` — the dominant path-validation engine (`rustls-webpki`) is ISC-only, reinforcing the decision to build clean-room validation logic.

**Notable non-gaps (confirmed well-served, MIT-chain, no action needed):**
DNS/DoH/DoT/DoQ (`hickory-dns`), TLS 1.3 (`rustls`), the whole HTTP/1.1-2-3 stack, WebSocket, Cookies, URI/URI-Templates, OAuth2, JWT/JWS/JWK, TOTP, NTP/NTS, SIP, RTP/RTCP, ICE/STUN, WebRTC JSEP, SNMP, JSON/JSON Patch/Merge Patch, Brotli.
