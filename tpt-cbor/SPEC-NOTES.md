# SPEC-NOTES — RFC 8949 (CBOR)

Clean-room implementation of Concise Binary Object Representation, tracking the
RFC section by section. Conformance is proven with the RFC 8949 Appendix A
examples plus round-trip fuzzing-style tests.

## Source documents

- RFC 8949: Concise Binary Object Representation (CBOR) — https://www.rfc-editor.org/rfc/rfc8949
- Appendix A (examples), Appendix B (compact data item notation), Appendix C
  (implementation notes).

## Implemented sections

- [x] Section 2: Data model (integers, floats, simple, byte/text strings, arrays, maps, tags)
- [x] Section 3.1–3.4: Major types 0–3 (integers, byte strings, text strings)
- [x] Section 3.5: Arrays (definite + indefinite length)
- [x] Section 3.6: Maps (definite + indefinite length)
- [x] Section 3.7: Tagged data items (2, 3 bignum; general tag support)
- [x] Section 3.8: Floating-point numbers and values (half/single/double)
- [x] Section 3.9: Simple values (0–19, 24–255; reserved 20–31 rejected)
- [x] Section 3.2.2 / 3.3.2: Indefinite-length byte/text strings
- [x] Section 3.8.2: Preferred serialization of floats (shortest form)
- [x] Section 4.1 / 4.2: Strict and lenient decoding options
- [x] Section 4.2.1: Basic validity (no duplicate map keys in strict mode, length checks)
- [x] Section 4.2.2: Deterministic encoding (canonical map key ordering, shortest lengths)
- [x] Appendix A: All example encodings

## Data model / public API

- `Value` — in-memory CBOR data item (`Integer(i128)`, `Float(f64)`, `Bool`,
  `Null`, `Undefined`, `Simple(u8)`, `Bytes(Vec<u8>)`, `Text(String)`,
  `Array(Vec<Value>)`, `Map(Vec<(Value, Value)>)` (sorted when canonical),
  `Tag(u64, Box<Value>)`).
- `Encoder` / `encode_to_vec` — serialize `Value` (and any `serde::Serialize`).
- `Decoder` — deserialize with `strict` / `canonical` options.
- `serde::Serializer` / `serde::Deserializer` under the `serde` feature.

## Test vectors

- [x] RFC 8949 Appendix A — `tests/appendix_a.rs` (encode and decode round trips)
- [x] Decoder robustness / strict & canonical mode — `tests/robustness.rs`
- [x] `serde` round-trip — `tests/serde_roundtrip.rs`

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [x] Official Appendix A test vectors passing
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [x] Runnable example (`examples/basic.rs`)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
