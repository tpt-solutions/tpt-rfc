// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `chacha20-poly1305@openssh.com` authenticated encryption (RFC 8439 ChaCha20
//! and Poly1305, with the OpenSSH layout that also encrypts the 4-byte packet
//! length). Construction follows OpenSSH `PROTOCOL.chacha20poly1305` /
//! draft-ietf-sshm-chacha20-poly1305.
//!
//! The 64-byte key material splits into `K_2` (first 32 bytes: payload
//! encryption + one-time Poly1305 key) and `K_1` (last 32 bytes: length-field
//! encryption). The packet sequence number is the ChaCha20 nonce, encoded as
//! a big-endian `uint64` per the SSH wire rules.

use crate::constant_time_eq;
use crate::transport::{frame_content, unpack_content};
use crate::Error;
use chacha20::cipher::generic_array::GenericArray;
use chacha20::cipher::{KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20Legacy as ChaCha20;
use poly1305::universal_hash::{Key, UniversalHash};
use poly1305::Poly1305;

/// Construct a `chacha20-poly1305@openssh.com` ChaCha20 instance. The
/// OpenSSH construction uses the original "djb" ChaCha20 with a 64-bit nonce
/// (the big-endian packet sequence number).
fn new_chacha(key: &[u8; 32], nonce: &[u8; 8]) -> ChaCha20 {
    ChaCha20::new(&GenericArray::from(*key), &GenericArray::from(*nonce))
}

/// Symmetric session keys derived from a key exchange. Each direction is a
/// 64-byte `chacha20-poly1305@openssh.com` key (`K_2 || K_1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Key for traffic flowing client → server.
    pub client_to_server: [u8; 64],
    /// Key for traffic flowing server → client.
    pub server_to_client: [u8; 64],
}

/// `chacha20-poly1305@openssh.com` cipher instance.
#[derive(Debug)]
pub struct ChaCha20Poly1305 {
    /// `K_2`: payload encryption + one-time Poly1305 key (block 0).
    k_main: [u8; 32],
    /// `K_1`: length-field encryption.
    k_header: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Build from a 64-byte key (`K_2 || K_1`).
    pub fn new(key_64: &[u8; 64]) -> Self {
        let mut k_main = [0u8; 32];
        k_main.copy_from_slice(&key_64[0..32]);
        let mut k_header = [0u8; 32];
        k_header.copy_from_slice(&key_64[32..64]);
        Self { k_main, k_header }
    }

    /// The ChaCha20 nonce: the packet sequence number as a big-endian `uint64`.
    fn nonce(seq: u32) -> [u8; 8] {
        (seq as u64).to_be_bytes()
    }

    /// Encrypt already-framed `content` (`padding_length` byte + payload +
    /// padding) into a full wire packet:
    /// `[4 encrypted length][encrypted content][16 MAC]`.
    pub fn encrypt_packet(&self, seq: u32, content: &[u8]) -> Vec<u8> {
        let nonce = Self::nonce(seq);

        // Encrypt the 4-byte length field with K_1 (block counter 0).
        let mut enc_len = (content.len() as u32).to_be_bytes();
        new_chacha(&self.k_header, &nonce).apply_keystream(&mut enc_len);

        // One-time Poly1305 key: first 32 bytes of the K_2 keystream (block 0).
        let mut poly_key = [0u8; 32];
        new_chacha(&self.k_main, &nonce).apply_keystream(&mut poly_key);

        // Encrypt the content with K_2 starting at block 1.
        let mut enc_content = content.to_vec();
        let mut main = new_chacha(&self.k_main, &nonce);
        main.seek(64);
        main.apply_keystream(&mut enc_content);

        // MAC over (ciphertext length || ciphertext content), treated as a
        // single message with one round of Poly1305 padding.
        let key = Key::<Poly1305>::from(poly_key);
        let mut mac = Poly1305::new(&key);
        let mut data = Vec::with_capacity(4 + enc_content.len());
        data.extend_from_slice(&enc_len);
        data.extend_from_slice(&enc_content);
        mac.update_padded(&data);
        let tag = mac.finalize();

        let mut out = Vec::with_capacity(4 + enc_content.len() + 16);
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&enc_content);
        out.extend_from_slice(tag.as_ref());
        out
    }

    /// Return the full 64-byte key (`K_2 || K_1`) for this direction.
    pub fn key_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.k_main);
        out[32..].copy_from_slice(&self.k_header);
        out
    }

    /// Recover the plaintext content length from the 4-byte encrypted length
    /// field, used by the transport reader to size an incoming packet before
    /// the full authenticate-then-decrypt step.
    pub fn peek_content_len(&self, seq: u32, enc_len: [u8; 4]) -> Result<usize, Error> {
        let mut buf = enc_len;
        new_chacha(&self.k_header, &Self::nonce(seq)).apply_keystream(&mut buf);
        Ok(u32::from_be_bytes(buf) as usize)
    }

    /// Decrypt a packet produced by [`encrypt_packet`], returning the inner
    /// `content`. The MAC is verified (in constant time) before decryption.
    pub fn decrypt_packet(&self, seq: u32, packet: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.len() < 4 + 16 {
            return Err(Error::Cipher("packet too short".into()));
        }
        let nonce = Self::nonce(seq);
        let enc_len = &packet[0..4];
        let split = packet.len() - 16;
        let enc_content = &packet[4..split];
        let tag = &packet[split..];

        // Recover the plaintext content length from the encrypted length.
        let mut len_buf = enc_len.to_vec();
        new_chacha(&self.k_header, &nonce).apply_keystream(&mut len_buf);
        let content_len = u32::from_be_bytes(len_buf.try_into().unwrap()) as usize;
        if content_len != enc_content.len() {
            return Err(Error::Cipher("length mismatch".into()));
        }

        // Recompute the Poly1305 tag over the ciphertext.
        let mut poly_key = [0u8; 32];
        new_chacha(&self.k_main, &nonce).apply_keystream(&mut poly_key);
        let key = Key::<Poly1305>::from(poly_key);
        let mut mac = Poly1305::new(&key);
        let mut data = Vec::with_capacity(4 + enc_content.len());
        data.extend_from_slice(enc_len);
        data.extend_from_slice(enc_content);
        mac.update_padded(&data);
        let computed = mac.finalize();
        if !constant_time_eq(computed.as_ref(), tag) {
            return Err(Error::Cipher("MAC verification failed".into()));
        }

        // Decrypt the content.
        let mut content = enc_content.to_vec();
        let mut main = new_chacha(&self.k_main, &nonce);
        main.seek(64);
        main.apply_keystream(&mut content);
        Ok(content)
    }
}

/// A pair of [`ChaCha20Poly1305`] ciphers bound to a [`SessionKeys`], offering
#[derive(Debug)]
pub struct CipherPair {
    /// Cipher for traffic flowing client → server.
    pub client_to_server: ChaCha20Poly1305,
    /// Cipher for traffic flowing server → client.
    pub server_to_client: ChaCha20Poly1305,
}

impl CipherPair {
    /// Build from session keys.
    pub fn from_session(keys: &SessionKeys) -> Self {
        Self {
            client_to_server: ChaCha20Poly1305::new(&keys.client_to_server),
            server_to_client: ChaCha20Poly1305::new(&keys.server_to_client),
        }
    }

    /// Client perspective: encrypt an outgoing message.
    pub fn client_encrypt(&self, seq: u32, message: &[u8]) -> Vec<u8> {
        self.client_to_server
            .encrypt_packet(seq, &frame_content(message))
    }

    /// Client perspective: decrypt an incoming message.
    pub fn client_decrypt(&self, seq: u32, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let content = self.server_to_client.decrypt_packet(seq, packet)?;
        unpack_content(&content)
    }

    /// Server perspective: encrypt an outgoing message.
    pub fn server_encrypt(&self, seq: u32, message: &[u8]) -> Vec<u8> {
        self.server_to_client
            .encrypt_packet(seq, &frame_content(message))
    }

    /// Server perspective: decrypt an incoming message.
    pub fn server_decrypt(&self, seq: u32, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let content = self.client_to_server.decrypt_packet(seq, packet)?;
        unpack_content(&content)
    }
}
