// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH binary packet framing (RFC 4253 §6) and content framing helpers for
//! the `chacha20-poly1305@openssh.com` cipher.
//!
//! The binary packet format is:
//!
//! ```text
//! uint32    packet length (bytes after this field, excluding MAC)
//! byte      padding length
//! byte[n1]  payload; n1 = packet length - padding length - 1
//! byte[n2]  random padding; n2 = padding length
//! byte[m]   MAC (absent for the "none" MAC and for AEAD ciphers)
//! ```

use crate::wire::{Reader, WireError};
use crate::Error;

/// Padding block size used when no block cipher is negotiated.
pub const NONE_BLOCK_SIZE: usize = 8;

/// Errors raised while framing packets.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    /// Wire-level decode error.
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
    /// A decoded `packet length` was self-inconsistent.
    #[error("invalid packet length")]
    InvalidLength,
    /// The padding length was inconsistent with the payload.
    #[error("invalid padding")]
    InvalidPadding,
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// Encode a payload into a cleartext SSH packet using the `none` cipher/MAC
/// (padding aligned to [`NONE_BLOCK_SIZE`], at least 4 bytes of padding).
///
/// The returned buffer is the on-wire form: the 4-byte length prefix followed
/// by `padding_length` byte, payload, and padding.
pub fn frame_packet(payload: &[u8]) -> Vec<u8> {
    // The full transmitted packet (4-byte length prefix + body) must be a
    // multiple of the block size; padding itself must be at least 4 bytes.
    let pre = 4 + 1 + payload.len();
    let mut pad = (NONE_BLOCK_SIZE - (pre % NONE_BLOCK_SIZE)) % NONE_BLOCK_SIZE;
    if pad < 4 {
        pad += NONE_BLOCK_SIZE;
    }
    let packet_len = (pre + pad - 4) as u32;

    let mut out = Vec::with_capacity(pre + pad);
    out.extend_from_slice(&packet_len.to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Decode a cleartext SSH packet produced by [`frame_packet`].
pub fn unframe_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(packet);
    let len = r.read_u32()? as usize;
    if len < 1 + 4 {
        // padding length byte + at least 4 bytes of padding.
        return Err(TransportError::InvalidLength);
    }
    let body = r.take(len)?;
    let pad_len = body[0] as usize;
    if pad_len + 1 > body.len() {
        return Err(TransportError::InvalidPadding);
    }
    Ok(body[1..body.len() - pad_len].to_vec())
}

/// Compute the padding length needed so that `content_len` (the byte count
/// after the 4-byte length prefix) is a multiple of `block_size`, with at
/// least 4 bytes of padding (RFC 4253 §6).
fn padding_for(content_len: usize, block_size: usize) -> usize {
    let mut pad = (block_size - (content_len % block_size)) % block_size;
    if pad < 4 {
        pad += block_size;
    }
    pad
}

/// Frame an SSH message into the *content* consumed by
/// `chacha20-poly1305@openssh.com`: `padding_length` byte + message + padding,
/// where the total content length is a multiple of [`NONE_BLOCK_SIZE`].
pub fn frame_content(message: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(1 + message.len() + NONE_BLOCK_SIZE);
    content.push(0u8); // padding length, filled in below
    content.extend_from_slice(message);
    let pad = padding_for(content.len(), NONE_BLOCK_SIZE);
    content.extend(std::iter::repeat_n(0u8, pad));
    content[0] = pad as u8;
    content
}

/// Reverse [`frame_content`], returning the inner message (everything after
/// the padding-length byte and before the trailing padding).
pub fn unpack_content(content: &[u8]) -> std::result::Result<Vec<u8>, Error> {
    if content.is_empty() {
        return Err(Error::Cipher("empty content".into()));
    }
    let pad_len = content[0] as usize;
    if pad_len + 1 > content.len() {
        return Err(Error::Cipher("bad padding".into()));
    }
    Ok(content[1..content.len() - pad_len].to_vec())
}

/// The role a peer plays in a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiates the connection (sends first).
    Client,
    /// Accepts the connection.
    Server,
}

/// A unidirectional in-process byte pipe (used for tests and in-process
/// transports in lieu of a socket).
#[derive(Debug, Default)]
pub struct Pipe {
    buf: Vec<u8>,
}

impl Pipe {
    /// Create an empty pipe.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append received bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Take and clear all buffered bytes.
    pub fn drain(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Number of buffered bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the pipe is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// A logical message read off a connection: either the initial version
/// exchange line (exactly once) or a binary-packet payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// The protocol identification line (without the trailing CR LF).
    Version(String),
    /// A decoded binary packet payload.
    Packet(Vec<u8>),
}

/// Incremental reader that understands the SSH preamble: a single version
/// line followed by length-prefixed binary packets (RFC 4253 §4.2/§6).
#[derive(Debug, Default)]
struct MsgReader {
    buf: Vec<u8>,
    got_version: bool,
}

impl MsgReader {
    fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Return the next message if enough bytes are buffered.
    fn next(&mut self) -> std::result::Result<Option<Message>, Error> {
        if !self.got_version {
            // The version line ends with a single LF (CR is optional).
            let line_end = match self.buf.iter().position(|&b| b == b'\n') {
                Some(i) => i,
                None => return Ok(None),
            };
            let line = self.buf[..line_end].to_vec();
            // Drop a trailing CR if present.
            let line = if line.last() == Some(&b'\r') {
                &line[..line.len() - 1]
            } else {
                &line[..]
            };
            self.buf.drain(..line_end + 1);
            self.got_version = true;
            return Ok(Some(Message::Version(
                String::from_utf8(line.to_vec())
                    .map_err(|_| Error::Cipher("version not UTF-8".into()))?,
            )));
        }

        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
        let total = 4 + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let packet = self.buf[..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(Message::Packet(unframe_packet(&packet)?)))
    }
}

/// A bidirectional in-process connection. Bytes queued with [`Link::send`]
/// are delivered to the peer's reader via [`Link::deliver`].
#[derive(Debug, Default)]
pub struct Link {
    pending: Vec<u8>,
    reader: MsgReader,
}

impl Link {
    /// Create a pair of links such that `a.outbound` → `b.inbound` and
    /// `b.outbound` → `a.inbound`.
    pub fn pair() -> (Link, Link) {
        (Link::default(), Link::default())
    }

    /// Queue bytes to send to the peer.
    pub fn send(&mut self, data: &[u8]) {
        // outbound is conceptually part of `inbound` of the peer; we model it
        // with a transient pipe owned by the caller and delivered via `deliver`.
        self.pending.extend_from_slice(data);
    }

    /// Deliver all bytes this link has queued into `peer`'s reader.
    pub fn deliver(&mut self, peer: &mut Link) {
        let data = std::mem::take(&mut self.pending);
        peer.reader.feed(&data);
    }

    /// Receive the next logical message (version line, then packets), or
    /// `None` if more bytes are needed.
    pub fn recv_message(&mut self) -> std::result::Result<Option<Message>, Error> {
        self.reader.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleartext_round_trip() {
        for payload in [b"" as &[u8], b"hello", &[0xabu8; 100]] {
            let packet = frame_packet(payload);
            // length prefix + body must be a multiple of block size.
            let len = u32::from_be_bytes(packet[..4].try_into().unwrap()) as usize;
            assert_eq!((4 + len) % NONE_BLOCK_SIZE, 0);
            let decoded = unframe_packet(&packet).unwrap();
            assert_eq!(decoded, payload);
        }
    }

    #[test]
    fn chacha_content_round_trip() {
        let msg = b"\x05service-request";
        let content = frame_content(msg);
        assert_eq!(content.len() % NONE_BLOCK_SIZE, 0);
        assert!(content[0] >= 4);
        assert_eq!(unpack_content(&content).unwrap(), msg);
    }
}
