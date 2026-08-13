# SPEC-NOTES — RFC 4226 (HOTP)

Clean-room implementation of the HMAC-Based One-Time Password algorithm,
tracking the RFC section by section. Conformance is proven with the RFC 4226
Appendix D test vectors (6- and 8-digit) wired into the suite.

## Source documents

- RFC 4226: HOTP: An HMAC-Based One-Time Password Algorithm — https://www.rfc-editor.org/rfc/rfc4226

## Implemented sections

- [x] Section 5.1–5.3: HOTP algorithm — HMAC-SHA-1 of the 8-byte big-endian
      counter, dynamic truncation (offset = low 4 bits of last byte), 31-bit
      big-endian code, `mod 10^Digit`.
- [x] Section 5.3: configurable digit count (1–10; RFC recommends ≥ 6).
- [x] Section 7.4: look-ahead counter resynchronization (`verify_with_counter`).

## Public API

- `Hotp::new(secret, digits)` / `Hotp::with_secret(secret)` (6 digits).
- `Hotp::generate(counter)` → `String` (zero-padded to `digits`).
- `Hotp::verify(code, counter, window)` and `verify_with_counter(...)`.
- `hotp(secret, counter, digits)` standalone function.
- `constant_time_eq` used for code comparison (no secret-dependent timing).

## Test vectors

- [x] RFC 4226 Appendix D — `tests` module in `src/lib.rs` (counters 0–9, 6- and
      8-digit expectations computed from the RFC algorithm).

## spec-complete checklist

- [x] Algorithm implemented per RFC
- [x] Official Appendix D test vectors passing
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
