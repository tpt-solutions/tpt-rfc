// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8949 Appendix A conformance vectors.
//!
//! Each case is verified in both directions:
//!   1. encoding the expected [`Value`] must yield the exact Appendix A bytes;
//!   2. decoding the Appendix A bytes must yield the expected [`Value`].

use tpt_cbor::decoder::decode_value;
use tpt_cbor::encoder::to_vec;
use tpt_cbor::value::{DecodeOptions, EncodeOptions, Value};

fn eq_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) => (x.is_nan() && y.is_nan()) || x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq_value(p, q))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|((pk, pv), (qk, qv))| eq_value(pk, qk) && eq_value(pv, qv))
        }
        (Value::Tag(t1, v1), Value::Tag(t2, v2)) => t1 == t2 && eq_value(v1, v2),
        _ => a == b,
    }
}

fn check(name: &str, bytes: &[u8], value: &Value) {
    let encoded = to_vec(value, &EncodeOptions::default());
    assert_eq!(encoded, bytes, "encode mismatch for {name}");
    let decoded = decode_value(bytes, DecodeOptions::default()).unwrap();
    assert!(
        eq_value(&decoded, value),
        "decode mismatch for {name}: got {decoded:?}, expected {value:?}"
    );
}

/// Like [`check`] but only verifies the decode direction. Used for source
/// encodings (e.g. indefinite length) that our canonical encoder re-emits in a
/// different, equivalent form.
fn check_decode(name: &str, bytes: &[u8], value: &Value) {
    let decoded = decode_value(bytes, DecodeOptions::default()).unwrap();
    assert!(
        eq_value(&decoded, value),
        "decode mismatch for {name}: got {decoded:?}, expected {value:?}"
    );
}

#[test]
fn appendix_a_unsigned() {
    check("0", &[0x00], &Value::Integer(0));
    check("1", &[0x01], &Value::Integer(1));
    check("10", &[0x0a], &Value::Integer(10));
    check("23", &[0x17], &Value::Integer(23));
    check("24", &[0x18, 0x18], &Value::Integer(24));
    check("25", &[0x18, 0x19], &Value::Integer(25));
    check("26", &[0x18, 0x1a], &Value::Integer(26));
    check("27", &[0x18, 0x1b], &Value::Integer(27));
    check("100", &[0x18, 0x64], &Value::Integer(100));
    check("1000", &[0x19, 0x03, 0xe8], &Value::Integer(1000));
    check(
        "1000000",
        &[0x1a, 0x00, 0x0f, 0x42, 0x40],
        &Value::Integer(1_000_000),
    );
    check(
        "1000000000000",
        &[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00],
        &Value::Integer(1_000_000_000_000),
    );
    check(
        "u64::MAX",
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &Value::Integer(u64::MAX as i128),
    );
    // 2^64: bignum tag 2.
    check(
        "2^64 (bignum)",
        &[
            0xc2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        &Value::Integer(18_446_744_073_709_551_616),
    );
}

#[test]
fn appendix_a_negative() {
    check("-1", &[0x20], &Value::Integer(-1));
    check("-10", &[0x29], &Value::Integer(-10));
    check("-100", &[0x38, 0x63], &Value::Integer(-100));
    check("-1000", &[0x39, 0x03, 0xe7], &Value::Integer(-1000));
    // -2^64 is representable with major type 1 (the shortest form).
    check(
        "-2^64",
        &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &Value::Integer(-18_446_744_073_709_551_616),
    );
    // -2^64-1 requires a negative bignum (tag 3).
    check(
        "-2^64-1 (negative bignum)",
        &[
            0xc3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        &Value::Integer(-18_446_744_073_709_551_617),
    );
}

#[test]
fn appendix_a_floats() {
    check("0.0", &[0xf9, 0x00, 0x00], &Value::Float(0.0));
    check("−0.0", &[0xf9, 0x80, 0x00], &Value::Float(-0.0));
    check("1.0", &[0xf9, 0x3c, 0x00], &Value::Float(1.0));
    check(
        "1.1",
        &[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a],
        &Value::Float(1.1),
    );
    check("1.5", &[0xf9, 0x3e, 0x00], &Value::Float(1.5));
    check("65504.0", &[0xf9, 0x7b, 0xff], &Value::Float(65504.0));
    check(
        "100000.0",
        &[0xfa, 0x47, 0xc3, 0x50, 0x00],
        &Value::Float(100000.0),
    );
    check(
        "3.4028234663852886e+38",
        &[0xfa, 0x7f, 0x7f, 0xff, 0xff],
        &Value::Float(3.4028234663852886e+38),
    );
    check(
        "1.0e+300",
        &[0xfb, 0x7e, 0x37, 0xe4, 0x3c, 0x88, 0x00, 0x75, 0x9c],
        &Value::Float(1.0e+300),
    );
    check(
        "5.960464477539063e-8",
        &[0xf9, 0x00, 0x01],
        &Value::Float(5.960464477539063e-8),
    );
    check(
        "0.00006103515625",
        &[0xf9, 0x04, 0x00],
        &Value::Float(0.00006103515625),
    );
    check("−4.0", &[0xf9, 0xc4, 0x00], &Value::Float(-4.0));
    check(
        "−4.1",
        &[0xfb, 0xc0, 0x10, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66],
        &Value::Float(-4.1),
    );
    check(
        "Infinity",
        &[0xf9, 0x7c, 0x00],
        &Value::Float(f64::INFINITY),
    );
    check("NaN", &[0xf9, 0x7e, 0x00], &Value::Float(f64::NAN));
    check(
        "−Infinity",
        &[0xf9, 0xfc, 0x00],
        &Value::Float(f64::NEG_INFINITY),
    );
}

#[test]
fn appendix_a_simple() {
    check("false", &[0xf4], &Value::Bool(false));
    check("true", &[0xf5], &Value::Bool(true));
    check("null", &[0xf6], &Value::Null);
    check("undefined", &[0xf7], &Value::Undefined);
    check("simple(16)", &[0xf0], &Value::Simple(16));
    check("simple(255)", &[0xf8, 0xff], &Value::Simple(255));
}

#[test]
fn appendix_a_text() {
    check("\"\"", &[0x60], &Value::Text(String::new()));
    check("\"a\"", &[0x61, 0x61], &Value::text("a"));
    check(
        "\"IETF\"",
        &[0x64, 0x49, 0x45, 0x54, 0x46],
        &Value::text("IETF"),
    );
    check("\"\\u00fc\"", &[0x62, 0xc3, 0xbc], &Value::text("ü"));
    check("\"\\u6c34\"", &[0x63, 0xe6, 0xb0, 0xb4], &Value::text("水"));
    check(
        "\"\\ud800\\udd51\"",
        &[0x64, 0xf0, 0x90, 0x85, 0x91],
        &Value::text("𐅑"),
    );
}

#[test]
fn appendix_a_bytes() {
    check("h''", &[0x40], &Value::Bytes(vec![]));
    check(
        "h'01020304'",
        &[0x44, 0x01, 0x02, 0x03, 0x04],
        &Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]),
    );
}

#[test]
fn appendix_a_arrays() {
    check("[]", &[0x80], &Value::Array(vec![]));
    check(
        "[1,2,3]",
        &[0x83, 0x01, 0x02, 0x03],
        &Value::Array(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]),
    );
    check(
        "[1,[2,3],[4,5]]",
        &[0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05],
        &Value::Array(vec![
            Value::Integer(1),
            Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
            Value::Array(vec![Value::Integer(4), Value::Integer(5)]),
        ]),
    );
}

#[test]
fn appendix_a_maps() {
    check("{}", &[0xa0], &Value::Map(vec![]));
    check(
        "{1:2,3:4}",
        &[0xa2, 0x01, 0x02, 0x03, 0x04],
        &Value::Map(vec![
            (Value::Integer(1), Value::Integer(2)),
            (Value::Integer(3), Value::Integer(4)),
        ]),
    );
    check(
        "[\"a\",{\"b\":\"c\"}]",
        &[0x82, 0x61, 0x61, 0xa1, 0x61, 0x62, 0x61, 0x63],
        &Value::Array(vec![
            Value::text("a"),
            Value::Map(vec![(Value::text("b"), Value::text("c"))]),
        ]),
    );
}

#[test]
fn appendix_a_tags() {
    check(
        "0(\"2013-03-21T20:04:00Z\")",
        &[
            0xc0, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x30, 0x33, 0x2d, 0x32, 0x31, 0x54, 0x32,
            0x30, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x30, 0x5a,
        ],
        &Value::Tag(0, Box::new(Value::text("2013-03-21T20:04:00Z"))),
    );
    check(
        "1(1363896240)",
        &[0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0],
        &Value::Tag(1, Box::new(Value::Integer(1_363_896_240))),
    );
    check(
        "1(1363896240.5)",
        &[0xc1, 0xfb, 0x41, 0xd4, 0x52, 0xd9, 0xec, 0x20, 0x00, 0x00],
        &Value::Tag(1, Box::new(Value::Float(1_363_896_240.5))),
    );
    check(
        "23(h'01020304')",
        &[0xd7, 0x44, 0x01, 0x02, 0x03, 0x04],
        &Value::Tag(23, Box::new(Value::Bytes(vec![1, 2, 3, 4]))),
    );
    check(
        "24(h'6449455446')",
        &[0xd8, 0x18, 0x45, 0x64, 0x49, 0x45, 0x54, 0x46],
        &Value::Tag(
            24,
            Box::new(Value::Bytes(vec![0x64, 0x49, 0x45, 0x54, 0x46])),
        ),
    );
    check(
        "32(\"http://www.example.com\")",
        &[
            0xd8, 0x20, 0x76, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ],
        &Value::Tag(32, Box::new(Value::text("http://www.example.com"))),
    );
}

#[test]
fn appendix_a_indefinite() {
    // The data model uses definite-length arrays/maps, so the encoder emits
    // those; we still verify the RFC's indefinite-length forms decode
    // correctly via `check_decode`.
    check_decode("[_]", &[0x9f, 0xff], &Value::Array(vec![]));
    check_decode(
        "[_ 1,[2,3],[_ 4,5]]",
        &[0x9f, 0x01, 0x82, 0x02, 0x03, 0x9f, 0x04, 0x05, 0xff, 0xff],
        &Value::Array(vec![
            Value::Integer(1),
            Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
            Value::Array(vec![Value::Integer(4), Value::Integer(5)]),
        ]),
    );
    check_decode(
        "{_ \"a\":1, \"b\":[_ 2,3]}",
        &[
            0xbf, 0x61, 0x61, 0x01, 0x61, 0x62, 0x9f, 0x02, 0x03, 0xff, 0xff,
        ],
        &Value::Map(vec![
            (Value::text("a"), Value::Integer(1)),
            (
                Value::text("b"),
                Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
            ),
        ]),
    );
}
