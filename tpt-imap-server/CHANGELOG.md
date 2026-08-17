# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: RFC 9051 (IMAP4rev2) conformance baseline.
- Server state machine (Not Authenticated → Authenticated → Selected → Logout).
- Core: `CAPABILITY`, `LOGIN`, `AUTHENTICATE` (PLAIN, LOGIN), `LOGOUT`,
  `NOOP`, `ID`, `NAMESPACE`.
- Mailbox management: `CREATE`, `DELETE`, `RENAME`, `LIST`, `LSUB`,
  `SUBSCRIBE`, `UNSUBSCRIBE`, `STATUS`, `APPEND`.
- Messages: `SELECT`/`EXAMINE`, `FETCH`/`STORE`/`COPY`/`SEARCH` (and `UID`
  variants), `EXPUNGE`, `UID EXPUNGE`, `CLOSE`, `CHECK`.
- `IDLE` extension (RFC 2177).
- Pluggable [`MailboxStore`] trait with an in-memory reference backend.
