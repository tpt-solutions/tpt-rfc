// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional [`serde`] integration for `tpt-cbor`.
//!
//! Enable with the `serde` feature. The mapping is:
//!
//! | Rust / serde            | CBOR                          |
//! |-------------------------|-------------------------------|
//! | `bool`                  | major 7 `false`/`true`        |
//! | integers                | major 0/1 (bignum if huge)   |
//! | `f32`/`f64`             | major 7 float                 |
//! | `char`/`&str`/`String`  | major 3 text string           |
//! | `&[u8]`/`Vec<u8>`       | major 2 byte string           |
//! | `Option::None`          | `null`                        |
//! | `Option::Some(v)`       | `v`                           |
//! | sequences / tuples      | major 4 array                 |
//! | maps                    | major 5 map                   |
//! | structs                 | major 5 map (field name keys) |
//! | enums (ext. tagged)     | map `{ "Variant": content }`  |
//!
//! Decoding is symmetric. Unknown tags and `Simple` values are rejected.

use crate::decoder::decode_value;
use crate::encoder::to_vec as encode_value_to_vec;
use crate::error::{CborError, Result};
use crate::value::DecodeOptions;
use crate::value::{EncodeOptions, Value};

use serde::de::{self, DeserializeOwned, Visitor};
use serde::ser::{self, Serialize};
use serde::Deserializer as _;

// ---------------------------------------------------------------------------
// Serializer
// ---------------------------------------------------------------------------

/// Serialize a `serde` value into a [`Value`].
pub fn to_value<T: Serialize>(value: &T) -> Result<Value> {
    value.serialize(Serializer)
}

/// Serialize a `serde` value directly to CBOR bytes.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = to_value(value)?;
    Ok(encode_value_to_vec(&v, &EncodeOptions::default()))
}

/// Serialize a `serde` value to canonical CBOR bytes.
pub fn to_vec_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = to_value(value)?;
    Ok(encode_value_to_vec(&v, &EncodeOptions::canonical()))
}

struct Serializer;

fn int_to_value(n: i128) -> Value {
    Value::Integer(n)
}

impl ser::Serializer for Serializer {
    type Ok = Value;
    type Error = CborError;
    type SerializeSeq = SeqSerializer;
    type SerializeTuple = SeqSerializer;
    type SerializeTupleStruct = SeqSerializer;
    type SerializeTupleVariant = TupleVariantSerializer;
    type SerializeMap = MapSerializer;
    type SerializeStruct = MapSerializer;
    type SerializeStructVariant = StructVariantSerializer;

    fn serialize_bool(self, v: bool) -> Result<Value> {
        Ok(Value::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_i16(self, v: i16) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_i32(self, v: i32) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_i64(self, v: i64) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_i128(self, v: i128) -> Result<Value> {
        Ok(int_to_value(v))
    }
    fn serialize_u8(self, v: u8) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_u16(self, v: u16) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_u32(self, v: u32) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_u64(self, v: u64) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_u128(self, v: u128) -> Result<Value> {
        Ok(int_to_value(v as i128))
    }
    fn serialize_f32(self, v: f32) -> Result<Value> {
        Ok(Value::Float(v as f64))
    }
    fn serialize_f64(self, v: f64) -> Result<Value> {
        Ok(Value::Float(v))
    }
    fn serialize_char(self, v: char) -> Result<Value> {
        Ok(Value::Text(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Value> {
        Ok(Value::Text(v.to_string()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Value> {
        Ok(Value::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<Value> {
        Ok(Value::Null)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Value> {
        Ok(Value::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value> {
        Ok(Value::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Value> {
        Ok(Value::Text(variant.to_string()))
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value> {
        Ok(Value::Map(vec![(
            Value::Text(variant.to_string()),
            value.serialize(Serializer)?,
        )]))
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        Ok(SeqSerializer { items: Vec::new() })
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Ok(SeqSerializer { items: Vec::new() })
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        Ok(SeqSerializer { items: Vec::new() })
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        Ok(TupleVariantSerializer {
            variant: variant.to_string(),
            items: Vec::new(),
        })
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Ok(MapSerializer { pairs: Vec::new() })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Ok(MapSerializer { pairs: Vec::new() })
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        Ok(StructVariantSerializer {
            variant: variant.to_string(),
            pairs: Vec::new(),
        })
    }
    fn collect_str<T: ?Sized + std::fmt::Display>(self, value: &T) -> Result<Value> {
        Ok(Value::Text(value.to_string()))
    }
}

struct SeqSerializer {
    items: Vec<Value>,
}
impl ser::SerializeSeq for SeqSerializer {
    type Ok = Value;
    type Error = CborError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        self.items.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Value> {
        Ok(Value::Array(self.items))
    }
}
impl ser::SerializeTuple for SeqSerializer {
    type Ok = Value;
    type Error = CborError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        self.items.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Value> {
        Ok(Value::Array(self.items))
    }
}
impl ser::SerializeTupleStruct for SeqSerializer {
    type Ok = Value;
    type Error = CborError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        self.items.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Value> {
        Ok(Value::Array(self.items))
    }
}

struct TupleVariantSerializer {
    variant: String,
    items: Vec<Value>,
}
impl ser::SerializeTupleVariant for TupleVariantSerializer {
    type Ok = Value;
    type Error = CborError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        self.items.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Value> {
        Ok(Value::Map(vec![(
            Value::Text(self.variant),
            Value::Array(self.items),
        )]))
    }
}

struct MapSerializer {
    pairs: Vec<(Value, Value)>,
}
impl ser::SerializeMap for MapSerializer {
    type Ok = Value;
    type Error = CborError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        self.pairs.push((key.serialize(Serializer)?, Value::Null));
        Ok(())
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        let last = self
            .pairs
            .last_mut()
            .ok_or(CborError::Unsupported("map key"))?;
        last.1 = value.serialize(Serializer)?;
        Ok(())
    }
    fn end(self) -> Result<Value> {
        Ok(Value::Map(self.pairs))
    }
}
impl ser::SerializeStruct for MapSerializer {
    type Ok = Value;
    type Error = CborError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.pairs
            .push((Value::Text(key.to_string()), value.serialize(Serializer)?));
        Ok(())
    }
    fn end(self) -> Result<Value> {
        Ok(Value::Map(self.pairs))
    }
}

struct StructVariantSerializer {
    variant: String,
    pairs: Vec<(Value, Value)>,
}
impl ser::SerializeStructVariant for StructVariantSerializer {
    type Ok = Value;
    type Error = CborError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.pairs
            .push((Value::Text(key.to_string()), value.serialize(Serializer)?));
        Ok(())
    }
    fn end(self) -> Result<Value> {
        Ok(Value::Map(vec![(
            Value::Text(self.variant),
            Value::Map(self.pairs),
        )]))
    }
}

// ---------------------------------------------------------------------------
// Deserializer
// ---------------------------------------------------------------------------

/// Deserialize a `serde` value from CBOR bytes (default decode options).
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let v = decode_value(bytes, DecodeOptions::default())?;
    let d = Deserializer { value: &v };
    T::deserialize(d)
}

/// Deserialize a `serde` value from a [`Value`].
pub fn from_value<T: DeserializeOwned>(value: &Value) -> Result<T> {
    T::deserialize(Deserializer { value })
}

struct Deserializer<'de> {
    value: &'de Value,
}

impl<'de> Deserializer<'de> {
    fn unexpected() -> CborError {
        CborError::Unsupported("unexpected CBOR data item for target type")
    }
}

macro_rules! deserialize_int {
    ($method:ident, $visit:ident, $ty:ty) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
            match self.value {
                Value::Integer(i) => {
                    let v = <$ty>::try_from(*i).map_err(|_| CborError::IntegerOutOfRange)?;
                    visitor.$visit(v)
                }
                _ => Err(Deserializer::unexpected()),
            }
        }
    };
}

impl<'de> de::Deserializer<'de> for Deserializer<'de> {
    type Error = CborError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Integer(i) => visitor.visit_i128(*i),
            Value::Float(f) => visitor.visit_f64(*f),
            Value::Bool(b) => visitor.visit_bool(*b),
            Value::Null | Value::Undefined => visitor.visit_unit(),
            Value::Bytes(b) => visitor.visit_borrowed_bytes(b),
            Value::Text(s) => visitor.visit_borrowed_str(s),
            Value::Array(a) => {
                let mut seq = SeqAccess { iter: a.iter() };
                visitor.visit_seq(&mut seq)
            }
            Value::Map(m) => {
                let mut map = MapAccess {
                    pending: None,
                    iter: m.iter(),
                };
                visitor.visit_map(&mut map)
            }
            Value::Tag(_, _) | Value::Simple(_) => Err(Deserializer::unexpected()),
        }
    }

    deserialize_int!(deserialize_i8, visit_i8, i8);
    deserialize_int!(deserialize_i16, visit_i16, i16);
    deserialize_int!(deserialize_i32, visit_i32, i32);
    deserialize_int!(deserialize_i64, visit_i64, i64);
    deserialize_int!(deserialize_u8, visit_u8, u8);
    deserialize_int!(deserialize_u16, visit_u16, u16);
    deserialize_int!(deserialize_u32, visit_u32, u32);
    deserialize_int!(deserialize_u64, visit_u64, u64);

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Integer(i) => visitor.visit_i128(*i),
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Integer(i) if *i >= 0 => visitor.visit_u128(*i as u128),
            _ => Err(Deserializer::unexpected()),
        }
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Float(f) => visitor.visit_f32(*f as f32),
            Value::Integer(i) => visitor.visit_f32(*i as f32),
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Float(f) => visitor.visit_f64(*f),
            Value::Integer(i) => visitor.visit_f64(*i as f64),
            _ => Err(Deserializer::unexpected()),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Bool(b) => visitor.visit_bool(*b),
            _ => Err(Deserializer::unexpected()),
        }
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Text(s) if s.chars().count() == 1 => {
                visitor.visit_char(s.chars().next().unwrap())
            }
            _ => Err(Deserializer::unexpected()),
        }
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Text(s) => visitor.visit_borrowed_str(s),
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Bytes(b) => visitor.visit_borrowed_bytes(b),
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Null | Value::Undefined => visitor.visit_none(),
            Value::Array(_) | Value::Map(_) => {
                // treat empty container as Some, not None
                visitor.visit_some(self)
            }
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Null | Value::Undefined => visitor.visit_unit(),
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Array(a) => {
                let mut seq = SeqAccess { iter: a.iter() };
                visitor.visit_seq(&mut seq)
            }
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.value {
            Value::Map(m) => {
                let mut map = MapAccess {
                    iter: m.iter(),
                    pending: None,
                };
                visitor.visit_map(&mut map)
            }
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        match self.value {
            // Unit variant encoded as a plain text string.
            Value::Text(_) => visitor.visit_enum(EnumAccess {
                variant: self.value,
                content: None,
            }),
            // Externally-tagged: map with exactly one entry.
            Value::Map(m) if m.len() == 1 => {
                let (k, v) = &m[0];
                if let Value::Text(_) = k {
                    visitor.visit_enum(EnumAccess {
                        variant: k,
                        content: Some(v),
                    })
                } else {
                    Err(Deserializer::unexpected())
                }
            }
            _ => Err(Deserializer::unexpected()),
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_any(visitor)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }
}

struct SeqAccess<'de> {
    iter: std::slice::Iter<'de, Value>,
}
impl<'de> de::SeqAccess<'de> for SeqAccess<'de> {
    type Error = CborError;
    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>> {
        match self.iter.next() {
            Some(v) => seed.deserialize(Deserializer { value: v }).map(Some),
            None => Ok(None),
        }
    }
}

struct MapAccess<'de> {
    iter: std::slice::Iter<'de, (Value, Value)>,
    pending: Option<&'de Value>,
}
impl<'de> de::MapAccess<'de> for MapAccess<'de> {
    type Error = CborError;
    fn next_key_seed<K: de::DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        match self.iter.next() {
            Some((k, v)) => {
                self.pending = Some(v);
                seed.deserialize(Deserializer { value: k }).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        match self.pending.take() {
            Some(v) => seed.deserialize(Deserializer { value: v }),
            None => Err(CborError::UnexpectedEof),
        }
    }
}

struct EnumAccess<'de> {
    variant: &'de Value,
    content: Option<&'de Value>,
}
impl<'de> de::EnumAccess<'de> for EnumAccess<'de> {
    type Error = CborError;
    type Variant = VariantAccess<'de>;
    fn variant_seed<V: de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        let v = seed.deserialize(Deserializer {
            value: self.variant,
        })?;
        Ok((
            v,
            VariantAccess {
                content: self.content,
            },
        ))
    }
}

struct VariantAccess<'de> {
    content: Option<&'de Value>,
}
impl<'de> de::VariantAccess<'de> for VariantAccess<'de> {
    type Error = CborError;
    fn unit_variant(self) -> Result<()> {
        match self.content {
            None | Some(Value::Null) | Some(Value::Undefined) => Ok(()),
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        match self.content {
            Some(v) => seed.deserialize(Deserializer { value: v }),
            None => Err(CborError::UnexpectedEof),
        }
    }
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        match self.content {
            Some(Value::Array(_)) | Some(Value::Map(_)) => Deserializer {
                value: self.content.unwrap(),
            }
            .deserialize_seq(visitor),
            _ => Err(Deserializer::unexpected()),
        }
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        match self.content {
            Some(Value::Map(_)) => Deserializer {
                value: self.content.unwrap(),
            }
            .deserialize_map(visitor),
            _ => Err(Deserializer::unexpected()),
        }
    }
}
