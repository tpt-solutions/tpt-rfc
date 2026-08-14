# tpt-rtp

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **RTP / RTCP** — RFC [3550](https://www.rfc-editor.org/rfc/rfc3550) and the
> audio/video profile RFC
> [3551](https://www.rfc-editor.org/rfc/rfc3551).

A from-spec implementation of the Real-time Transport Protocol and its control
protocol (RTCP), built to close the licensing gap identified in the TPT
Solutions RFC survey. See [`SPEC-NOTES.md`](SPEC-NOTES.md) for the
section-by-section conformance status and the test vectors wired into the
suite.

## Status

See [`SPEC-NOTES.md`](SPEC-NOTES.md) for implemented sections and the
"spec-complete" checklist.

## Features

- RTP packet encode/decode: fixed header, CSRC list, header extension, and
  padding (RFC 3550 §5).
- RTCP packet types: Sender Report (SR), Receiver Report (RR), Source
  Description (SDES), BYE, and APP (RFC 3550 §6).
- Receiver-side statistics — sequence-number validity/wraparound tracking,
  interarrival jitter, and packet-loss accounting — matching RFC 3550
  Appendix A, suitable for generating Receiver Reports.
- Bandwidth-aware RTCP transmission-interval scheduler (RFC 3550 §6.3.1).
- RFC 3551 static payload-type table.

## Example

```rust
use tpt_rtp::rtp::RtpPacket;

let bytes = [
    0x80, 0x60, 0x00, 0x01, // V2, PT=96, seq=1
    0x00, 0x00, 0x00, 0x02, // timestamp
    0x11, 0x22, 0x33, 0x44, // SSRC
    0xab, 0xcd,             // payload
];

let pkt = RtpPacket::decode(&bytes).unwrap();
assert_eq!(pkt.header.payload_type, 96);
assert_eq!(pkt.header.sequence_number, 1);
assert_eq!(pkt.payload(), &[0xab, 0xcd]);

let mut buf = [0u8; 12];
let n = pkt.encode_to_slice(&mut buf).unwrap();
assert_eq!(&buf[..n], &bytes[..]);
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.
