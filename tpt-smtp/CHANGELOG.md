# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: RFC 5321 SMTP client + server and RFC 5322 / MIME library.
  - Server session state machine (greeted → initial → mail → rcpt → data) with
    bad-sequence enforcement and dot-transparency.
  - ESMTP extension framework: `EHLO` capabilities, `SIZE` on `MAIL FROM:`,
    `8BITMIME`, and `STARTTLS`/`AUTH` extension hooks.
  - Client (submission) with `EHLO`/`HELO`, `MAIL`/`RCPT`/`DATA`, `QUIT`.
  - Pluggable `MailDelivery` trait with an in-memory reference backend.
  - RFC 5322 / MIME parsing: headers, address lists/groups, multipart,
    base64 / quoted-printable decoding, RFC 2047 encoded-word decoding.
  - `MessageBuilder` for generating well-formed CRLF-terminated messages.
  - Transport-agnostic client/server plus a std::net TCP `Server`.
