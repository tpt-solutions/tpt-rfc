// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DTLS 1.3 record layer (RFC 9147 §4).
//!
//! A DTLS record carries an explicit 16-bit `epoch` and 48-bit
//! `sequence_number` (unlike TLS, which hides them in the AEAD nonce). The
//! record header is 13 bytes; after the header comes the fragment, which for
//! protected records is `ciphertext || tag`, optionally followed by a
//! trailing **Connection ID** (RFC 9146). The record `length` field counts
//! only the AEAD output, not the CID.
//!
//! ```text
//! struct {
//!     uint8  type;          // outer content type
//!     uint16 version;       // 0xfefd (legacy, DTLS 1.2-compatible)
//!     uint16 epoch;
//!     uint48 sequence_number;
//!     uint16 length;
//!     uint8  fragment[length];
//!     // optional Connection ID follows fragment (length excluded)
//! } DTLSRecord;
//! ```

use crate::crypto::{aead_open, aead_seal, CipherSuite};
use crate::error::{DtlsError, Result};
use crate::wire::{Reader, Writer};

/// `change_cipher_spec` content type (sent in the clear before encryption).
pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
/// `alert` content type.
pub const CONTENT_ALERT: u8 = 21;
/// `handshake` content type.
pub const CONTENT_HANDSHAKE: u8 = 22;
/// `application_data` content type (also the outer type of all protected
/// records in TLS/DTLS 1.3).
pub const CONTENT_APPLICATION_DATA: u8 = 23;
/// DTLS `ACK` content type (RFC 9147 §7).
pub const CONTENT_ACK: u8 = 26;

/// The legacy record-version field value carried by every DTLS 1.3 record
/// (0xfefd, identical to DTLS 1.2 for wire compatibility).
pub const DTLS_LEGACY_VERSION: u16 = 0xfefd;

/// A DTLS 1.3 Connection ID (RFC 9146), a variable-length opaque tag appended
/// to each record so that a server can identify an association after a client
/// roams to a new address/port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    /// The maximum CID length DTLS 1.3 permits (RFC 9146 §2).
    pub const MAX_LEN: usize = 255;

    /// Build a CID from bytes, validating the length.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Self::MAX_LEN {
            return Err(DtlsError::HandshakeIncomplete("cid too long"));
        }
        Ok(ConnectionId(bytes))
    }

    /// The CID bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The fixed-size DTLS record header (13 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    /// Outer content type.
    pub content_type: u8,
    /// Legacy version (always [`DTLS_LEGACY_VERSION`]).
    pub version: u16,
    /// DTLS epoch (0 = initial/cleartext, 1 = handshake keys, 2 = app keys).
    pub epoch: u16,
    /// 48-bit record sequence number.
    pub sequence: u64,
    /// Length of the fragment/`ciphertext||tag` (excludes any trailing CID).
    pub length: u16,
}

impl RecordHeader {
    const SIZE: usize = 13;

    /// Encode the 13-byte header.
    pub fn encode(&self, w: &mut Writer) {
        w.put_u8(self.content_type)
            .put_u16(self.version)
            .put_u16(self.epoch)
            .put_u48(self.sequence)
            .put_u16(self.length);
    }

    /// Decode a header from the front of `buf`, returning the header and the
    /// remaining bytes (the fragment + optional CID).
    pub fn decode(buf: &[u8]) -> Result<(RecordHeader, &[u8])> {
        if buf.len() < Self::SIZE {
            return Err(DtlsError::RecordLengthMismatch(Self::SIZE, buf.len()));
        }
        let mut r = Reader::new(&buf[..Self::SIZE]);
        let content_type = r.read_u8()?;
        let version = r.read_u16()?;
        let epoch = r.read_u16()?;
        let sequence = r.read_u48()?;
        let length = r.read_u16()?;
        let header = RecordHeader {
            content_type,
            version,
            epoch,
            sequence,
            length: length,
        };
        Ok((header, &buf[Self::SIZE..]))
    }
}

/// Split a received datagram into its header, body (cleartext fragment or
/// AEAD output), and optional trailing Connection ID.
///
/// `recv_cid_len` is the CID length this endpoint expects on incoming records
/// (0 disables CID). The `length` field determines the body size; any bytes
/// beyond it (up to `recv_cid_len`) are treated as the CID.
pub fn split_datagram(
    datagram: &[u8],
    recv_cid_len: usize,
) -> Result<(RecordHeader, Vec<u8>, Option<ConnectionId>)> {
    let (header, rest) = RecordHeader::decode(datagram)?;
    let body_len = header.length as usize;
    if rest.len() < body_len {
        return Err(DtlsError::RecordLengthMismatch(body_len, rest.len()));
    }
    let (body, trailing) = rest.split_at(body_len);
    let cid = if recv_cid_len > 0 && trailing.len() >= recv_cid_len {
        Some(ConnectionId::new(trailing[..recv_cid_len].to_vec())?)
    } else if recv_cid_len > 0 {
        // The whole trailing region is the CID if shorter than expected
        // (allowed during CID negotiation handshakes).
        Some(ConnectionId::new(trailing.to_vec())?)
    } else {
        None
    };
    Ok((header, body.to_vec(), cid))
}

/// Build a cleartext (unprotected) record — used for epoch-0 handshake
/// messages (ClientHello, ServerHello) which are sent before any keys exist.
pub fn build_cleartext(content_type: u8, epoch: u16, sequence: u64, content: &[u8]) -> Vec<u8> {
    let header = RecordHeader {
        content_type,
        version: DTLS_LEGACY_VERSION,
        epoch,
        sequence,
        length: content.len() as u16,
    };
    let mut w = Writer::new();
    header.encode(&mut w);
    w.put_bytes(content);
    w.into_inner()
}

/// Build a protected record: AEAD-seal `content` (the inner payload, not
/// including the trailing inner content-type byte) under `inner_type`, append
/// an optional `cid`, and return the full datagram.
pub fn build_protected(
    suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    epoch: u16,
    sequence: u64,
    outer_type: u8,
    inner_type: u8,
    content: &[u8],
    cid: Option<&ConnectionId>,
) -> Result<Vec<u8>> {
    if sequence > 0xFF_FFFF_FFFF_FFFF {
        return Err(DtlsError::SequenceOverflow(epoch));
    }
    let mut plaintext = content.to_vec();
    plaintext.push(inner_type);

    let nonce = nonce_for(iv, sequence);
    let length = plaintext.len() as u16;
    let aad = build_aad(outer_type, epoch, sequence, length);

    let ct = aead_seal(suite, key, &nonce, &aad, &plaintext)?;

    let header = RecordHeader {
        content_type: outer_type,
        version: DTLS_LEGACY_VERSION,
        epoch,
        sequence,
        length: ct.len() as u16,
    };
    let mut w = Writer::new();
    header.encode(&mut w);
    w.put_bytes(&ct);
    if let Some(cid) = cid {
        w.put_bytes(&cid.0);
    }
    Ok(w.into_inner())
}

/// Open a protected record, returning the inner content type and the
/// decrypted payload (without the trailing inner-type byte).
pub fn open_protected(
    suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    header: &RecordHeader,
    aead_output: &[u8],
    cid: Option<&ConnectionId>,
) -> Result<(u8, Vec<u8>)> {
    let _ = cid; // receiver does not need the CID to open; it is present only
                 // for association lookup, which is the caller's concern.
    let nonce = nonce_for(iv, header.sequence);
    let aad = build_aad(
        header.content_type,
        header.epoch,
        header.sequence,
        aead_output.len() as u16,
    );
    let plaintext = aead_open(suite, key, &nonce, &aad, aead_output)?;
    if plaintext.is_empty() {
        return Err(DtlsError::DecryptFailed);
    }
    let inner_type = plaintext[plaintext.len() - 1];
    let content = plaintext[..plaintext.len() - 1].to_vec();
    Ok((inner_type, content))
}

/// Construct the TLS/DTLS 1.3 AEAD additional_data (RFC 8446 §5.2 /
/// RFC 9147 §4.3):
///
/// ```text
/// additional_data = TLStype || version || epoch || sequence_number || length
/// ```
fn build_aad(outer_type: u8, epoch: u16, sequence: u64, length: u16) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(outer_type)
        .put_u16(DTLS_LEGACY_VERSION)
        .put_u16(epoch)
        .put_u48(sequence)
        .put_u16(length);
    w.into_inner()
}

/// TLS/DTLS 1.3 AEAD nonce = write_IV XOR (64-bit seq zero-padded to 12
/// bytes, left-aligned) (RFC 8446 §5.3 / RFC 9147 §4.3).
fn nonce_for(iv: &[u8], sequence: u64) -> [u8; 12] {
    debug_assert_eq!(iv.len(), 12);
    let seq_be = sequence.to_be_bytes(); // 8 bytes
    let mut nonce = [0u8; 12];
    for i in 0..8 {
        nonce[4 + i] = iv[4 + i] ^ seq_be[i];
    }
    // The top 4 IV bytes are used as-is (sequence only fills the low 8 bytes).
    nonce[0..4].copy_from_slice(&iv[0..4]);
    nonce
}
