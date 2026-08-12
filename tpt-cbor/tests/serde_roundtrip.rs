// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `serde` round-trip conformance: a representative set of Rust types must
//! serialize to CBOR and deserialize back to an equal value.

#![cfg(feature = "serde")]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use tpt_cbor::decoder::decode_value;
use tpt_cbor::encoder::to_vec as encode_value;
use tpt_cbor::serde::{from_slice, to_vec};
use tpt_cbor::value::{DecodeOptions, EncodeOptions, Value};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Point {
    x: i64,
    y: i64,
    label: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum Shape {
    Circle { radius: f64 },
    Rect(i64, i64),
    Unit,
    Tagged(Vec<u8>),
}

#[test]
fn round_trip_primitives() {
    let cases: Vec<Value> = vec![
        Value::Integer(42),
        Value::Integer(-42),
        Value::Integer(1_000_000_000_000),
        Value::Bool(true),
        Value::Bool(false),
        Value::Null,
        Value::Text("hello".into()),
        Value::Bytes(vec![1, 2, 3]),
        Value::Float(3.5),
        Value::Array(vec![Value::Integer(1), Value::Integer(2)]),
        Value::Map(vec![(Value::Text("k".into()), Value::Integer(9))]),
    ];
    for c in &cases {
        let bytes = encode_value(c, &EncodeOptions::default());
        let back = decode_value(&bytes, DecodeOptions::default()).unwrap();
        assert_eq!(&back, c);
    }
}

#[test]
fn round_trip_struct() {
    let p = Point {
        x: 3,
        y: -7,
        label: "origin-ish".into(),
    };
    let bytes = to_vec(&p).unwrap();
    let back: Point = from_slice(&bytes).unwrap();
    assert_eq!(p, back);
}

#[test]
fn round_trip_enum() {
    let shapes = vec![
        Shape::Circle { radius: 2.5 },
        Shape::Rect(4, 9),
        Shape::Unit,
        Shape::Tagged(vec![0xde, 0xad]),
    ];
    for s in shapes {
        let bytes = to_vec(&s).unwrap();
        let back: Shape = from_slice(&bytes).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn round_trip_map_and_option() {
    let mut m = BTreeMap::new();
    m.insert("a".to_string(), 1i64);
    m.insert("b".to_string(), 2i64);
    let bytes = to_vec(&m).unwrap();
    let back: BTreeMap<String, i64> = from_slice(&bytes).unwrap();
    assert_eq!(m, back);

    let opt: Option<i32> = Some(5);
    let bytes = to_vec(&opt).unwrap();
    let back: Option<i32> = from_slice(&bytes).unwrap();
    assert_eq!(opt, back);

    let none: Option<i32> = None;
    let bytes = to_vec(&none).unwrap();
    let back: Option<i32> = from_slice(&bytes).unwrap();
    assert_eq!(none, back);
}

#[test]
fn canonical_map_ordering() {
    // Map keys must be sorted by the canonical ordering on encode.
    let v = Value::Map(vec![
        (Value::Integer(2), Value::Integer(20)),
        (Value::Integer(1), Value::Integer(10)),
        (Value::Integer(100), Value::Integer(1000)),
    ]);
    let canonical = encode_value(&v, &EncodeOptions::canonical());
    // The decoded map should have keys in ascending canonical order.
    let decoded = decode_value(&canonical, DecodeOptions::canonical()).unwrap();
    if let Value::Map(pairs) = decoded {
        let keys: Vec<i128> = pairs.iter().map(|(k, _)| k.as_i128().unwrap()).collect();
        assert_eq!(keys, vec![1, 2, 100]);
    } else {
        panic!("expected map");
    }
    // Determinism: canonical encoding should be byte-stable.
    let again = encode_value(&v, &EncodeOptions::canonical());
    assert_eq!(canonical, again);
}

#[test]
fn value_and_serde_encoders_agree_on_integers() {
    // The data-model encoder and the serde encoder must agree for integers.
    let v = Value::Integer(7);
    let via_value = encode_value(&v, &EncodeOptions::default());
    let via_serde: i64 = 7;
    let via_serde = to_vec(&via_serde).unwrap();
    assert_eq!(via_value, via_serde);
}
