// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Basic `tpt-cbor` usage: encode a value, decode it back, and serialize a
//! Rust struct via the optional `serde` integration.

use tpt_cbor::decoder::decode_value;
use tpt_cbor::encoder::to_vec;
use tpt_cbor::value::{DecodeOptions, EncodeOptions, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Encode/decode a hand-built data item.
    let value = Value::Array(vec![
        Value::Integer(1),
        Value::text("hello"),
        Value::Bool(true),
        Value::Map(vec![(Value::text("k"), Value::Integer(9))]),
    ]);
    let bytes = to_vec(&value, &EncodeOptions::default());
    println!("encoded {} bytes: {:?}", bytes.len(), bytes);
    let back = decode_value(&bytes, DecodeOptions::default())?;
    assert_eq!(value, back);
    println!("round-tripped OK");

    // 2. Serde round-trip (requires the `serde` feature).
    #[cfg(feature = "serde")]
    {
        use serde::{Deserialize, Serialize};
        use tpt_cbor::serde::{from_slice, to_vec as serde_to_vec};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Record {
            id: u64,
            name: String,
            tags: Vec<String>,
        }

        let record = Record {
            id: 42,
            name: "example".into(),
            tags: vec!["a".into(), "b".into()],
        };
        let bytes = serde_to_vec(&record)?;
        let recovered: Record = from_slice(&bytes)?;
        assert_eq!(record, recovered);
        println!("serde round-trip OK: {recovered:?}");
    }
    #[cfg(not(feature = "serde"))]
    {
        println!("serde feature not enabled; skipping serde demo");
    }

    Ok(())
}
