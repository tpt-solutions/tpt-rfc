// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decoder robustness and strict/canonical mode conformance.

use tpt_cbor::decoder::decode_value;
use tpt_cbor::value::{DecodeOptions, EncodeOptions, Value};

#[test]
fn strict_mode_rejects_indefinite() {
    // Indefinite-length array must be rejected under strict mode.
    let indefinite = [0x9fu8, 0xff];
    let r = decode_value(&indefinite, DecodeOptions::strict());
    assert!(
        r.is_err(),
        "strict mode must reject indefinite-length items"
    );

    // Definite-length array is fine.
    let definite = [0x80u8];
    assert!(decode_value(&definite, DecodeOptions::strict()).is_ok());
}

#[test]
fn canonical_mode_rejects_noncanonical_integer() {
    // Non-shortest integer: the value 0 encoded with an extra length byte.
    let non_shortest = [0x18u8, 0x00];
    let r = decode_value(&non_shortest, DecodeOptions::canonical());
    assert!(
        r.is_err(),
        "canonical mode must reject non-shortest integer"
    );

    // Correct shortest form is accepted.
    let shortest = [0x00u8];
    assert!(decode_value(&shortest, DecodeOptions::canonical()).is_ok());
}

#[test]
fn canonical_mode_rejects_out_of_order_map_keys() {
    // Map with keys out of canonical order: { 2: _, 1: _ }.
    let out_of_order = [0xa2u8, 0x02, 0x00, 0x01, 0x00];
    let r = decode_value(&out_of_order, DecodeOptions::canonical());
    assert!(
        r.is_err(),
        "canonical mode must reject out-of-order map keys"
    );

    // Canonical order { 1: _, 2: _ } is accepted.
    let in_order = [0xa2u8, 0x01, 0x00, 0x02, 0x00];
    assert!(decode_value(&in_order, DecodeOptions::canonical()).is_ok());
}

#[test]
fn decoder_does_not_panic_on_garbage() {
    // A small deterministic PRNG so the test is reproducible without deps.
    let mut seed: u64 = 0x1234_5678_9abc_def0;
    let mut next = || {
        seed = seed
            .wrapping_mul(63_643_549_388_867)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
        seed
    };

    for _ in 0..50_000u32 {
        let len = (next() % 9) as usize; // 0..=8 bytes
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((next() & 0xff) as u8);
        }
        // The decoder must always return a clean `Result`, never panic, for
        // any byte sequence under any decode option.
        for opts in [
            DecodeOptions::default(),
            DecodeOptions::strict(),
            DecodeOptions::canonical(),
        ] {
            let _ = decode_value(&buf, opts);
        }
    }
}

#[test]
fn round_trip_random_values() {
    // A fixed set of representative values must survive encode -> decode.
    let values: Vec<Value> = vec![
        Value::Integer(0),
        Value::Integer(-1),
        Value::Integer(255),
        Value::Integer(256),
        Value::Integer(65_536),
        Value::Integer(-65_537),
        Value::Integer(18_446_744_073_709_551_616),
        Value::Integer(-18_446_744_073_709_551_617),
        Value::Float(0.5),
        Value::Float(-0.5),
        Value::Float(std::f64::consts::PI),
        Value::Bool(true),
        Value::Null,
        Value::Text("héllo, 世界".into()),
        Value::Bytes(vec![0, 255, 128, 1]),
        Value::Array((0..10).map(Value::Integer).collect()),
        Value::Map(vec![
            (Value::Integer(1), Value::text("one")),
            (Value::Integer(2), Value::text("two")),
        ]),
        Value::Tag(0, Box::new(Value::text("2024-01-01T00:00:00Z"))),
    ];

    for v in &values {
        let bytes = tpt_cbor::encoder::to_vec(v, &EncodeOptions::default());
        let back = decode_value(&bytes, DecodeOptions::default()).unwrap();
        assert_eq!(&back, v, "round-trip failed for {v:?}");
    }
}
