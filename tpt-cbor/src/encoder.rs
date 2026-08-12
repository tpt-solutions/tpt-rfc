// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::Result;
use crate::value::{encode_value_to_vec, EncodeOptions, Value};

/// Encode a [`Value`] into a fresh `Vec<u8>` using the given options.
pub fn to_vec(value: &Value, opts: &EncodeOptions) -> Vec<u8> {
    encode_value_to_vec(value, opts)
}

/// A streaming CBOR encoder that writes to any [`std::io::Write`] sink.
///
/// The encoder buffers the serialized bytes for a single data item and flushes
/// them through the writer, keeping the public API ergonomic for users who want
/// to interleave CBOR with other protocol bytes.
pub struct Encoder<W> {
    writer: W,
    opts: EncodeOptions,
}

impl<W: std::io::Write> Encoder<W> {
    /// Create a new encoder over `writer` with the supplied options.
    pub fn new(writer: W, opts: EncodeOptions) -> Self {
        Encoder { writer, opts }
    }

    /// Encode a single data item, writing its bytes to the underlying sink.
    pub fn encode(&mut self, value: &Value) -> Result<()> {
        let bytes = encode_value_to_vec(value, &self.opts);
        self.writer.write_all(&bytes)?;
        Ok(())
    }
}
