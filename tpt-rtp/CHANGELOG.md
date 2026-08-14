# Changelog

All notable changes to this crate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this crate adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - TBD

- Initial release: RFC 3550 (RTP/RTCP) and RFC 3551 (audio/video profile)
  conformance baseline.
  - RTP packet encode/decode (header, CSRC list, header extension, padding).
  - RTCP SR/RR/SDES/BYE/APP encode/decode.
  - RFC 3551 static payload-type table.
  - Receiver-side sequence tracking, jitter, and packet-loss statistics
    (RFC 3550 Appendix A).
  - Bandwidth-aware RTCP transmission-interval scheduler (RFC 3550 §6.2/§6.3).
