// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted SSH session transport over an in-process (or byte-pipe) link.
//!
//! This module ties together the transport framing, key exchange, and
//! `chacha20-poly1305@openssh.com` cipher implemented in the other modules to
//! provide a single abstraction that performs the SSH handshake (RFC 4253
//! §7) — version exchange, algorithm negotiation, `curve25519-sha256` key
//! exchange, and the `NEWKEYS` switch — and then exchanges authenticated,
//! encrypted binary packets.
//!
//! The [`EncryptedConn`] is symmetric: a pair is created with [`EncryptedConn::pair`]
//! (or via [`handshake`]) and the two endpoints deliver bytes to each other with
//! [`EncryptedConn::deliver`]. Over a real socket this same role is filled by a
//! pair of connected `TcpStream`s; the byte-pipe model here keeps the protocol
//! logic testable and dependency-free.

use crate::cipher::{CipherPair, SessionKeys};
use crate::host_key::HostKey;
use crate::kex::{
    exchange_hash, generate_ephemeral, make_kexinit, session_keys, shared_secret, Negotiated,
    SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY, SSH_MSG_NEWKEYS,
};
use crate::transport::{frame_packet, unpack_content, Link, Message, Role};
use crate::version::Identification;
use crate::wire::{Reader, Writer};
use crate::Error;

/// SSH message code for `SSH_MSG_SERVICE_REQUEST` (RFC 4253 §6).
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// SSH_MSG_SERVICE_ACCEPT.
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;

/// A single encrypted SSH connection endpoint.
///
/// Bytes queued with [`EncryptedConn::send`] are held in `pending` until
/// [`EncryptedConn::deliver`] moves them into the peer's receive buffer.
/// [`EncryptedConn::recv`] returns the next decrypted binary-packet payload, or
/// `None` if more bytes are required.
#[derive(Debug)]
pub struct EncryptedConn {
    role: Role,
    cipher: CipherPair,
    pending: Vec<u8>,
    buf: Vec<u8>,
    client_seq: u32,
    server_seq: u32,
}

impl EncryptedConn {
    /// Create a single endpoint for the given role keyed with `keys`. Use this
    /// when bridging to a real socket: the peer is the remote side, not an
    /// in-process [`EncryptedConn`].
    pub fn new(role: Role, keys: SessionKeys) -> EncryptedConn {
        EncryptedConn {
            role,
            cipher: CipherPair::from_session(&keys),
            pending: Vec::new(),
            buf: Vec::new(),
            client_seq: 0,
            server_seq: 0,
        }
    }

    /// Create a connected pair keyed identically (as produced by a key
    /// exchange): `client` sends on the client→server keys, `server` on the
    /// server→client keys.
    pub fn pair_with_keys(keys: SessionKeys) -> (EncryptedConn, EncryptedConn) {
        let client = EncryptedConn {
            role: Role::Client,
            cipher: CipherPair::from_session(&keys),
            pending: Vec::new(),
            buf: Vec::new(),
            client_seq: 0,
            server_seq: 0,
        };
        let server = EncryptedConn {
            role: Role::Server,
            cipher: CipherPair::from_session(&keys),
            pending: Vec::new(),
            buf: Vec::new(),
            client_seq: 0,
            server_seq: 0,
        };
        (client, server)
    }

    /// The role this endpoint plays.
    pub fn role(&self) -> Role {
        self.role
    }

    fn outgoing_cipher(&self) -> &crate::cipher::ChaCha20Poly1305 {
        match self.role {
            Role::Client => &self.cipher.client_to_server,
            Role::Server => &self.cipher.server_to_client,
        }
    }

    fn incoming_cipher(&self) -> &crate::cipher::ChaCha20Poly1305 {
        match self.role {
            Role::Client => &self.cipher.server_to_client,
            Role::Server => &self.cipher.client_to_server,
        }
    }

    fn outgoing_seq(&self) -> u32 {
        match self.role {
            Role::Client => self.client_seq,
            Role::Server => self.server_seq,
        }
    }

    fn advance_outgoing_seq(&mut self) {
        match self.role {
            Role::Client => self.client_seq += 1,
            Role::Server => self.server_seq += 1,
        }
    }

    fn advance_incoming_seq(&mut self) {
        match self.role {
            Role::Client => self.server_seq += 1,
            Role::Server => self.client_seq += 1,
        }
    }

    /// Encrypt and queue a binary-packet payload for the peer.
    pub fn send(&mut self, payload: &[u8]) {
        let seq = self.outgoing_seq();
        let pkt = self
            .outgoing_cipher()
            .encrypt_packet(seq, &frame_content(payload));
        self.pending.extend_from_slice(&pkt);
        self.advance_outgoing_seq();
    }

    /// Queue raw already-encrypted bytes (used when bridging to a socket).
    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    /// Deliver all queued bytes from `self` into `peer`'s receive buffer.
    pub fn deliver(&mut self, peer: &mut EncryptedConn) {
        let data = std::mem::take(&mut self.pending);
        peer.buf.extend_from_slice(&data);
    }

    /// Number of buffered (not-yet-delivered) outgoing bytes.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Number of bytes buffered for receiving.
    pub fn recv_len(&self) -> usize {
        self.buf.len()
    }

    /// Take and clear all pending outgoing bytes (used when bridging to a raw
    /// byte transport such as a socket).
    pub fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    /// Append received bytes into the incoming buffer (used when bridging to a
    /// raw byte transport such as a socket).
    pub fn feed_recv(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Move pending bytes from `self` into `other`'s receive buffer and vice
    /// versa. Convenient for in-process (`Link`-style) pairing.
    pub fn exchange_with(&mut self, other: &mut EncryptedConn) {
        let a = std::mem::take(&mut self.pending);
        other.buf.extend_from_slice(&a);
        let b = std::mem::take(&mut other.pending);
        self.buf.extend_from_slice(&b);
    }

    /// Return the next decrypted payload if a complete packet is buffered.
    pub fn recv(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let seq = match self.role {
            Role::Client => self.server_seq,
            Role::Server => self.client_seq,
        };
        let enc_len: [u8; 4] = self.buf[..4].try_into().unwrap();
        let content_len = self.incoming_cipher().peek_content_len(seq, enc_len)?;
        let total = 4 + content_len + 16;
        if self.buf.len() < total {
            return Ok(None);
        }
        let packet = self.buf[..total].to_vec();
        self.buf.drain(..total);
        let content = self.incoming_cipher().decrypt_packet(seq, &packet)?;
        self.advance_incoming_seq();
        Ok(Some(unpack_content(&content)?))
    }
}

fn frame_content(message: &[u8]) -> Vec<u8> {
    crate::transport::frame_content(message)
}

/// Run a complete SSH transport handshake between two in-process endpoints and
/// return the resulting encrypted connections, ready to exchange
/// service-request/accept and authenticated messages.
///
/// Both sides use the same identification strings and KEXINIT cookies here
/// (deterministic for testing); a real peer supplies its own.
pub fn handshake() -> (EncryptedConn, EncryptedConn) {
    let (mut c, mut s) = Link::pair();
    let v_c = "SSH-2.0-tpt-ssh-client";
    let v_s = "SSH-2.0-tpt-ssh-server";

    // Version exchange.
    c.send(&Identification::new(v_c).to_wire());
    c.deliver(&mut s);
    s.send(&Identification::new(v_s).to_wire());
    s.deliver(&mut c);
    assert!(matches!(
        c.recv_message().unwrap(),
        Some(Message::Version(_))
    ));
    assert!(matches!(
        s.recv_message().unwrap(),
        Some(Message::Version(_))
    ));

    // KEXINIT exchange.
    let i_c = make_kexinit();
    let i_s = make_kexinit();
    c.send(&frame_packet(&i_c));
    c.deliver(&mut s);
    s.send(&frame_packet(&i_s));
    s.deliver(&mut c);
    let i_c_recv = expect_packet(&mut c);
    let i_s_recv = expect_packet(&mut s);
    let _neg: Negotiated = crate::kex::negotiate(&i_c_recv, &i_s_recv).unwrap();

    // Ephemeral ECDH: client sends SSH_MSG_KEX_ECDH_INIT { e }.
    let eph_c = generate_ephemeral();
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_KEX_ECDH_INIT);
    w.write_string(&eph_c.public);
    c.send(&frame_packet(&w.into_inner()));
    c.deliver(&mut s);

    // Server reads INIT, computes K/H, signs, replies with KEX_ECDH_REPLY.
    let init = expect_packet(&mut s);
    let mut r = Reader::new(&init);
    let _code = r.read_byte().unwrap();
    let e = r.read_string().unwrap().to_vec();

    let host = HostKey::generate();
    let eph_s = generate_ephemeral();
    let k = shared_secret(&eph_s, &e).unwrap();
    let k_s = host.public_key_blob();
    let h = exchange_hash(v_c, v_s, &i_c_recv, &i_s_recv, &k_s, &e, &eph_s.public, &k);
    let sig = host.sign(&h);

    let mut w = Writer::new();
    w.write_byte(SSH_MSG_KEX_ECDH_REPLY);
    w.write_string(&k_s);
    w.write_string(&eph_s.public);
    w.write_string(&sig);
    s.send(&frame_packet(&w.into_inner()));
    s.deliver(&mut c);

    // Client reads REPLY, derives K/H, verifies signature.
    let reply = expect_packet(&mut c);
    let mut r = Reader::new(&reply);
    let _code = r.read_byte().unwrap();
    let k_s_recv = r.read_string().unwrap().to_vec();
    let f = r.read_string().unwrap().to_vec();
    let sig_recv = r.read_string().unwrap().to_vec();
    let k_client = shared_secret(&eph_c, &f).unwrap();
    assert_eq!(k_client, k, "both sides derive identical K");
    let h_client = exchange_hash(v_c, v_s, &i_c_recv, &i_s_recv, &k_s_recv, &e, &f, &k_client);
    assert!(
        HostKey::verify(&k_s_recv, &sig_recv, &h_client).unwrap(),
        "host key signature must verify"
    );

    // NEWKEYS both directions.
    let newkeys = {
        let mut w = Writer::new();
        w.write_byte(SSH_MSG_NEWKEYS);
        w.into_inner()
    };
    c.send(&frame_packet(&newkeys));
    c.deliver(&mut s);
    s.send(&frame_packet(&newkeys));
    s.deliver(&mut c);
    let _ = expect_packet(&mut c); // drain server NEWKEYS
    let _ = expect_packet(&mut s); // drain client NEWKEYS

    let keys = session_keys(&k_client, &h_client);
    EncryptedConn::pair_with_keys(keys)
}

fn expect_packet(link: &mut Link) -> Vec<u8> {
    match link.recv_message().unwrap() {
        Some(Message::Packet(p)) => p,
        other => panic!("expected a binary packet, got {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_handshake_and_round_trip() {
        let (mut c, mut s) = handshake();
        // Client -> Server.
        c.send(b"hello-server");
        c.deliver(&mut s);
        assert_eq!(s.recv().unwrap().unwrap(), b"hello-server");
        // Server -> Client.
        s.send(b"hello-client");
        s.deliver(&mut c);
        assert_eq!(c.recv().unwrap().unwrap(), b"hello-client");
        // Sequence numbers advance independently per direction.
        c.send(b"again");
        c.deliver(&mut s);
        assert_eq!(s.recv().unwrap().unwrap(), b"again");
    }

    #[test]
    fn tampered_encrypted_packet_fails() {
        let (mut c, mut s) = handshake();
        c.send(b"secret");
        c.deliver(&mut s);
        // Corrupt the queued bytes before the server reads them.
        let last = s.recv_len() - 1;
        s.buf[last] ^= 0xff;
        assert!(s.recv().is_err());
    }
}
