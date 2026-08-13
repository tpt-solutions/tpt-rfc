# tpt-hotp

> Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
> **HOTP** — [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226).

A from-spec HMAC-based one-time-password implementation. The API mirrors
[`totp-rs`](https://crates.io/crates/totp-rs) for easy migration; the HMAC-SHA-1
primitive comes from the dual-licensed RustCrypto `hmac`/`sha1` crates.

## Example

```rust
use tpt_hotp::Hotp;

// RFC 4226 Appendix D test secret.
let hotp = Hotp::new(b"12345678901234567890", 6).unwrap();
assert_eq!(hotp.generate(0), "755224");
assert_eq!(hotp.generate(1), "287082");

// Server-side verification with a look-ahead resync window (RFC 4226 §7.4).
let code = hotp.generate(5);
let matched = hotp.verify_with_counter(&code, 3, 2).unwrap(); // -> 5
assert_eq!(matched, 5);
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.
