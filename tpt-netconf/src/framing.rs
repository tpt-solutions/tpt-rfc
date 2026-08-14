// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NETCONF message framing (RFC 6242).
//!
//! NETCONF messages are carried over a reliable transport (almost always an
//! SSH `netconf` subsystem, RFC 6242) and delimited by one of two framing
//! mechanisms:
//!
//! - **Base framing** (`]]>]]>`): the message is followed by the literal
//!   end-of-message sequence `]]>]]>`.
//! - **Chunked framing** (`#<len>`): used when a message contains the
//!   character sequence `]]>` (which would otherwise be ambiguous), each chunk
//!   is preceded by a `#<octet-count>` line and the message is terminated by a
//!   `##` line.
//!
//! This module encodes either form and incrementally decodes a byte stream
//! into complete XML messages regardless of which form the peer uses.

use crate::error::{NetconfError, Result};

/// The base end-of-message sequence.
pub const BASE_EOM: &[u8] = b"]]>]]>";
/// The chunked-framing terminator line.
const CHUNK_END: &[u8] = b"##";
/// Maximum octets per chunk when emitting chunked framing.
const CHUNK_SIZE: usize = 4096;

/// Encode a NETCONF message for transmission.
///
/// Uses base framing unless the message contains the sequence `]]>` (which
/// would collide with the end-of-message marker), in which case chunked
/// framing is used.
pub fn encode_message(message: &str) -> Vec<u8> {
    if message.contains("]]>") {
        encode_chunked(message)
    } else {
        let mut out = message.as_bytes().to_vec();
        out.extend_from_slice(BASE_EOM);
        out
    }
}

/// Encode using chunked framing (RFC 6242 §4.2). The message is split on line
/// boundaries so that every emitted chunk ends with a newline.
fn encode_chunked(message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for line in message.split('\n') {
        if buf.is_empty() {
            buf.push_str(line);
        } else {
            buf.push('\n');
            buf.push_str(line);
        }
        if buf.len() >= CHUNK_SIZE {
            if !buf.ends_with('\n') {
                buf.push('\n');
            }
            out.extend_from_slice(format!("#{}\n", buf.len()).as_bytes());
            out.extend_from_slice(buf.as_bytes());
            buf.clear();
        }
    }
    if !buf.is_empty() {
        if !buf.ends_with('\n') {
            buf.push('\n');
        }
        out.extend_from_slice(format!("#{}\n", buf.len()).as_bytes());
        out.extend_from_slice(buf.as_bytes());
    }
    out.extend_from_slice(b"##\n");
    out
}

/// An incremental NETCONF frame decoder.
///
/// Feed received bytes with [`FrameDecoder::push`]; complete XML messages are
/// returned as they become available. The decoder transparently handles both
/// base and chunked framing per message.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    /// Create an empty decoder.
    pub fn new() -> FrameDecoder {
        FrameDecoder { buf: Vec::new() }
    }

    /// Append `data` to the internal buffer and return any complete messages
    /// that are now available.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<String>> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while let Some(msg) = self.try_extract()? {
            out.push(msg);
        }
        Ok(out)
    }

    /// The number of bytes currently buffered awaiting completion.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Try to extract one complete message from the front of the buffer.
    fn try_extract(&mut self) -> Result<Option<String>> {
        let first = self.buf.iter().position(|b| !b.is_ascii_whitespace());
        let start = match first {
            Some(p) => p,
            None => return Ok(None),
        };
        if self.buf[start] == b'#' {
            match self.try_chunked(start)? {
                Some((msg, consumed)) => {
                    self.buf.drain(..consumed);
                    Ok(Some(msg))
                }
                None => Ok(None),
            }
        } else if let Some(eom) = find_subslice(&self.buf, BASE_EOM) {
            let msg = String::from_utf8_lossy(&self.buf[..eom]).trim().to_string();
            self.buf.drain(..eom + BASE_EOM.len());
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    /// Attempt to decode a chunked message starting at byte `start`.
    fn try_chunked(&self, start: usize) -> Result<Option<(String, usize)>> {
        let mut pos = start;
        let mut msg: Vec<u8> = Vec::new();
        loop {
            let nl = match find_byte_from(&self.buf, b'\n', pos) {
                Some(i) => i,
                None => return Ok(None),
            };
            let line = &self.buf[pos..nl];
            if line == CHUNK_END {
                let consumed = nl + 1;
                return Ok(Some((String::from_utf8_lossy(&msg).to_string(), consumed)));
            }
            if line.first() != Some(&b'#') {
                return Err(NetconfError::Framing(format!(
                    "malformed chunk header line: {:?}",
                    String::from_utf8_lossy(line)
                )));
            }
            let digits = &line[1..];
            let len: usize = match std::str::from_utf8(digits)
                .ok()
                .and_then(|s| s.parse().ok())
            {
                Some(n) => n,
                None => {
                    return Err(NetconfError::Framing(format!(
                        "invalid chunk size: {:?}",
                        String::from_utf8_lossy(digits)
                    )))
                }
            };
            let chunk_start = nl + 1;
            let chunk_end = chunk_start + len;
            if self.buf.len() < chunk_end {
                return Ok(None);
            }
            msg.extend_from_slice(&self.buf[chunk_start..chunk_end]);
            pos = chunk_end;
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_byte_from(haystack: &[u8], byte: u8, from: usize) -> Option<usize> {
    haystack[from..]
        .iter()
        .position(|b| *b == byte)
        .map(|i| from + i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_framing_round_trips() {
        let msg = "<rpc message-id=\"1\"><get/></rpc>";
        let framed = encode_message(msg);
        assert!(framed.ends_with(BASE_EOM));
        let mut dec = FrameDecoder::new();
        let msgs = dec.push(&framed).unwrap();
        assert_eq!(msgs, vec![msg.to_string()]);
    }

    #[test]
    fn decoder_handles_partial_base_frames() {
        let framed = encode_message("<hello/>");
        let mut dec = FrameDecoder::new();
        let mut collected = Vec::new();
        for i in 0..framed.len() {
            collected.extend(dec.push(&framed[i..=i]).unwrap());
        }
        assert_eq!(collected, vec!["<hello/>".to_string()]);
    }

    #[test]
    fn chunked_framing_round_trips() {
        let msg =
            "<rpc message-id=\"1\"><edit-config><config><a>]]></a></config></edit-config></rpc>";
        let framed = encode_message(msg);
        assert!(framed.starts_with(b"#"));
        let mut dec = FrameDecoder::new();
        let msgs = dec.push(&framed).unwrap();
        // Chunked framing terminates each chunk with a newline (RFC 6242 §4.2),
        // so compare the parsed XML rather than raw bytes.
        let original = crate::xml::parse_root(msg).unwrap();
        let decoded = crate::xml::parse_root(&msgs[0]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn chunked_handles_partial_bytes() {
        let msg = "<rpc><x>content with ]]> inside</x></rpc>";
        let framed = encode_message(msg);
        let mut dec = FrameDecoder::new();
        let mut collected = Vec::new();
        for i in 0..framed.len() {
            collected.extend(dec.push(&framed[i..=i]).unwrap());
        }
        let original = crate::xml::parse_root(msg).unwrap();
        let decoded = crate::xml::parse_root(&collected[0]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn two_messages_in_one_buffer() {
        let a = encode_message("<rpc/>");
        let b = encode_message("<rpc message-id=\"2\"/>");
        let mut all = Vec::new();
        all.extend_from_slice(&a);
        all.extend_from_slice(&b);
        let mut dec = FrameDecoder::new();
        let msgs = dec.push(&all).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], "<rpc/>");
        assert_eq!(msgs[1], "<rpc message-id=\"2\"/>");
    }
}
