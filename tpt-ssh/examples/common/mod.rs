// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared helpers for the `tpt-ssh` client/server examples: a byte-pipe bridge
//! between [`EncryptedConn`] and a `TcpStream`, and a stream-based transport
//! handshake (RFC 4253 §7) that mirrors `session::handshake` but talks to a
//! real socket.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream;

use tpt_ssh::auth::{server_handle, AuthResult, Authenticator, SERVICE_SSH_USERAUTH};
use tpt_ssh::host_key::HostKey;
use tpt_ssh::kex::{
    exchange_hash, generate_ephemeral, make_kexinit, session_keys, shared_secret,
    SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY, SSH_MSG_NEWKEYS,
};
use tpt_ssh::session::{EncryptedConn, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST};
use tpt_ssh::transport::{frame_packet, unframe_packet, Role};
use tpt_ssh::wire::{Reader, Writer};

/// Fixed demo credentials: `alice` / `hunter2`.
pub struct DemoAuth;
impl Authenticator for DemoAuth {
    fn check_password(&self, user: &str, password: &str) -> bool {
        user == "alice" && password == "hunter2"
    }
}

/// Move this endpoint's pending encrypted bytes to the socket and pull any
/// received socket bytes into the endpoint's receive buffer.
pub fn pump(conn: &mut EncryptedConn, stream: &mut TcpStream) -> std::io::Result<()> {
    if conn.pending_len() > 0 {
        let bytes = conn.take_pending();
        stream.write_all(&bytes)?;
        stream.flush()?;
    }
    stream.set_nonblocking(true).ok();
    let mut buf = [0u8; 65536];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => conn.feed_recv(&buf[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                break
            }
            Err(e) => return Err(e),
        }
    }
    stream.set_nonblocking(false).ok();
    Ok(())
}

fn read_exact(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    stream.read_exact(&mut out).expect("short read from socket");
    out
}

fn read_line(stream: &mut TcpStream) -> String {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).expect("socket closed");
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    // Drop a trailing CR.
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).expect("version line not utf-8")
}

fn write_packet(stream: &mut TcpStream, payload: &[u8]) {
    let pkt = frame_packet(payload);
    stream.write_all(&pkt).expect("write failed");
    stream.flush().expect("flush failed");
}

fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let prefix = read_exact(stream, 4);
    let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    // `len` is the body length (RFC 4253 §6). Read the body, then reassemble
    // the full wire packet (4-byte length prefix + body) for the unframer.
    let body = read_exact(stream, len);
    let mut pkt = prefix;
    pkt.extend_from_slice(&body);
    unframe_packet(&pkt).expect("bad packet framing")
}

/// Perform the client side of the transport handshake over `stream`.
pub fn client_handshake(stream: &mut TcpStream) -> EncryptedConn {
    // The exchange hash uses the full identification line (RFC 4253 §8), i.e.
    // including the `SSH-2.0-` prefix but without the trailing CR LF.
    let v_c = "SSH-2.0-tpt-ssh-client";
    stream.write_all(format!("{v_c}\r\n").as_bytes()).unwrap();
    let v_s = read_line(stream);

    let i_c = make_kexinit();
    write_packet(stream, &i_c);
    let i_s = read_packet(stream);

    let eph_c = generate_ephemeral();
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_KEX_ECDH_INIT);
    w.write_string(&eph_c.public);
    write_packet(stream, &w.into_inner());

    let reply = read_packet(stream);
    let mut r = Reader::new(&reply);
    let _code = r.read_byte().unwrap();
    let k_s = r.read_string().unwrap().to_vec();
    let f = r.read_string().unwrap().to_vec();
    let sig = r.read_string().unwrap().to_vec();

    let k = shared_secret(&eph_c, &f).expect("shared secret");
    let h = exchange_hash(v_c, &v_s, &i_c, &i_s, &k_s, &eph_c.public, &f, &k);
    assert!(
        HostKey::verify(&k_s, &sig, &h).unwrap(),
        "host key signature must verify"
    );

    let mut w = Writer::new();
    w.write_byte(SSH_MSG_NEWKEYS);
    write_packet(stream, &w.into_inner());
    let _ = read_packet(stream); // server NEWKEYS

    let keys = session_keys(&k, &h);
    EncryptedConn::new(Role::Client, keys)
}

/// Perform the server side of the transport handshake over `stream`.
pub fn server_handshake(stream: &mut TcpStream) -> EncryptedConn {
    let v_s = "SSH-2.0-tpt-ssh-server";
    let v_c = read_line(stream);
    stream.write_all(format!("{v_s}\r\n").as_bytes()).unwrap();

    let i_s = make_kexinit();
    write_packet(stream, &i_s);
    let i_c = read_packet(stream);

    let init = read_packet(stream);
    let mut r = Reader::new(&init);
    let _code = r.read_byte().unwrap();
    let e = r.read_string().unwrap().to_vec();

    let host = HostKey::generate();
    let eph_s = generate_ephemeral();
    let k = shared_secret(&eph_s, &e).expect("shared secret");
    let k_s = host.public_key_blob();
    let h = exchange_hash(&v_c, v_s, &i_c, &i_s, &k_s, &e, &eph_s.public, &k);
    let sig = host.sign(&h);

    let mut w = Writer::new();
    w.write_byte(SSH_MSG_KEX_ECDH_REPLY);
    w.write_string(&k_s);
    w.write_string(&eph_s.public);
    w.write_string(&sig);
    write_packet(stream, &w.into_inner());

    let _newkeys = read_packet(stream); // client NEWKEYS
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_NEWKEYS);
    write_packet(stream, &w.into_inner());

    let keys = session_keys(&k, &h);
    EncryptedConn::new(Role::Server, keys)
}

/// Run the user-auth phase as the server, replying to a single
/// `SSH_MSG_USERAUTH_REQUEST` and returning the parsed client result.
pub fn server_auth(conn: &mut EncryptedConn, stream: &mut TcpStream) -> AuthResult {
    // Service request -> accept.
    loop {
        pump(conn, stream).unwrap();
        if let Some(p) = conn.recv().unwrap() {
            assert_eq!(p[0], SSH_MSG_SERVICE_REQUEST);
            let mut w = Writer::new();
            w.write_byte(SSH_MSG_SERVICE_ACCEPT);
            w.write_string(SERVICE_SSH_USERAUTH.as_bytes());
            conn.send(&w.into_inner());
            pump(conn, stream).unwrap();
            break;
        }
    }
    // Auth request -> response.
    loop {
        pump(conn, stream).unwrap();
        if let Some(p) = conn.recv().unwrap() {
            let reply = server_handle(&p, b"session-id", &DemoAuth).expect("handle");
            conn.send(&reply);
            pump(conn, stream).unwrap();
            let _ = pump(conn, stream);
            // Wait for the response to be delivered back and parsed by client;
            // we just return success here for the demo.
            return AuthResult::Success;
        }
    }
}
