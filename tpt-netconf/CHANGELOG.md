# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to semantic versioning.

## [Unreleased]

### Added

- Initial implementation of `tpt-netconf`:
  - NETCONF message framing (RFC 6242 §4.1–§4.2): base `]]>]]>` and chunked
    `#<len>` framing, with an incremental decoder handling either form.
  - A small, dependency-free XML DOM for parsing/serializing NETCONF messages.
  - NETCONF message model (RFC 6241 §4): `<hello>` capability exchange,
    `<rpc>` with `get`, `get-config`, `edit-config`, `copy-config`,
    `delete-config`, `lock`, `unlock`, `close-session`, `kill-session`,
    `discard-changes`, and `<rpc-reply>` / `<rpc-error>`.
  - A pluggable `Datastore` backend trait and a reference `InMemoryDatastore`.
  - `serve_ssh_session` over an `tpt-ssh` `netconf` subsystem (RFC 6242 §3),
    plus a minimal `NetconfSshClient` for testing and examples.
  - End-to-end integration test driving a full session over an SSH handshake.
