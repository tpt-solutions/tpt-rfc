# SPEC-NOTES — RFC 6241 (NETCONF) + RFC 6242 (transport) + RFC 7950 (YANG 1.1)

Clean-room implementation of the **NETCONF server** side of the Network
Configuration Protocol. The transport (RFC 6242) reuses [`tpt-ssh`](../tpt-ssh)
for the SSH `netconf` subsystem rather than reimplementing SSH; the NETCONF
message handling, framing, capability exchange, RPC operations, and datastore
dispatch are implemented from the RFC text with no third-party NETCONF/YANG
dependency, keeping the crate self-contained and fully auditable.

YANG (RFC 7950) is carried as opaque XML in this crate's scoped baseline: the
server models config as an XML tree and does not implement a full YANG schema
compiler or validation engine. This is documented as a scope boundary below.

## Source documents

- RFC 6241: Network Configuration Protocol (NETCONF) — https://www.rfc-editor.org/rfc/rfc6241
- RFC 6242: Using the NETCONF Configuration Protocol over Secure Shell (SSH) — https://www.rfc-editor.org/rfc/rfc6242
- RFC 7950: The YANG 1.1 Data Modeling Language — https://www.rfc-editor.org/rfc/rfc7950

## Implemented sections

- [x] RFC 6242 §3 — NETCONF over the SSH `netconf` subsystem (channel open,
      `subsystem` channel request, hello exchange).
- [x] RFC 6242 §4.1 — base framing: messages terminated by the `]]>]]>`
      end-of-message sequence.
- [x] RFC 6242 §4.2 — chunked framing (`#<len>` chunks, `##` terminator),
      used automatically when a message contains `]]>`.
- [x] RFC 6241 §4.1 — `<rpc message-id="...">` envelope and the requirement
      that every rpc carry a `message-id`.
- [x] RFC 6241 §4.2 — `<rpc-reply>` with `<ok/>`, `<data>...</data>`, and
      `<rpc-error>` (error-type/tag/severity/message/app-tag/path/info).
- [x] RFC 6241 §4.3 — `<rpc-error>` structure and the standard error
      categories.
- [x] RFC 6241 §8.1 — `<hello>` capability exchange (capabilities list,
      server `session-id`). Base 1.0 and 1.1 capabilities advertised.
- [x] RFC 6241 §7.1 — `<get-config>` (running/startup/candidate/url source).
- [x] RFC 6241 §7.3 — `<get>` (returns the running state; subtree filtering
      left to the backend — see scope note).
- [x] RFC 6241 §7.2 — `<edit-config>` with `target` and `default-operation`
      (merge/replace/create/delete). The reference backend applies
      top-level node merge/replace/create/delete by element name.
- [x] RFC 6241 §7.4 — `<copy-config>` (Running/Startup/Candidate, Url source
      supported; Url target not supported by the reference backend).
- [x] RFC 6241 §7.5 — `<delete-config>` (refuses running; refuses url in the
      reference backend, RFC-compliant).
- [x] RFC 6241 §7.6 — `<lock>` / `<unlock>` with a lock-held set keyed by
      datastore.
- [x] RFC 6241 §7.7 — `<close-session>` (clears locks and ends the session).
- [x] RFC 6241 §7.8 / §7.9 — `<kill-session>` / `<discard-changes>` accepted
      at the protocol layer and reported unsupported by the reference backend
      (no session/transaction registry yet).

## Data model / public API

- `framing` — `encode_message`, `FrameDecoder` (incremental, base + chunked).
- `xml` — minimal `Xml` DOM, `parse_root`, `to_string`, with attribute and
  child lookup helpers.
- `message` — `Hello`, `Rpc`, `RpcReply`, `Operation`, `RpcError`,
  `ReplyResult`, `DatastoreName`, `EditDefaultOp`, and the parse/serialize
  functions.
- `server` — `Datastore` trait, `InMemoryDatastore` reference backend,
  `dispatch`, and `serve_ssh_session`.
- `client` — `NetconfSshClient` (connect / rpc / close) over an SSH
  `netconf` subsystem.

## YANG scope boundary

RFC 7950 (YANG 1.1) is referenced for context but **not** fully implemented:
this crate does not parse YANG modules, build a schema tree, or validate
configuration against a YANG model. Configuration is modeled as opaque XML. A
full YANG engine is a natural follow-up but is out of scope for this phase's
narrowed server focus.

## Test vectors

- [x] Framing round-trips (base and chunked, including byte-at-a-time
      incremental decode and multiple messages in one buffer) in
      `src/framing.rs`.
- [x] Message model round-trips (`hello`, `get-config`, `edit-config`,
      `rpc-reply` ok/data/error) in `src/message.rs`.
- [x] Minimal XML DOM round-trips and entity decoding in `src/xml.rs`.
- [x] End-to-end integration: full session (handshake → `netconf` subsystem →
      hello exchange → get-config → edit-config → get-config → lock/unlock →
      close-session) driven over an in-process SSH handshake in
      `tests/integration.rs`.
- [ ] Interop-test against a real NETCONF server/client (e.g. a vendor device,
      sysrepo, or `netconf-console`) — BLOCKED: no NETCONF peer available in
      this environment; verified by the in-crate SSH integration harness
      instead.

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [ ] Official external interop test vectors passing (no published NETCONF
      conformance suite; interop-test against a real peer blocked)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io
      credentials in this environment)
