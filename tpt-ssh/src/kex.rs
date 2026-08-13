// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH key exchange: `curve25519-sha256` (RFC 8732) plus the RFC 4253 §7.2
//! session-key derivation, and a self-contained client/server exchange used
//! by the test suite.
//!
//! The exchange hash is `H = SHA256(V_C || V_S || I_C || I_S || K_S || e || f
//! || K)`, where every field is an SSH `string`. For `curve25519-sha256` the
//! shared secret `K` is the 32-byte X25519 output encoded as a string.

use crate::cipher::SessionKeys;
use crate::host_key::HostKey;
use crate::wire::{Reader, Writer};
use crate::Error;
use orion::hazardous::ecc::x25519::{key_agreement, PrivateKey, PublicKey as X25519PublicKey};
use sha2::{Digest, Sha256};

/// SSH message code for `SSH_MSG_KEX_ECDH_INIT`.
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
/// SSH message code for `SSH_MSG_KEX_ECDH_REPLY`.
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// An ephemeral X25519 key pair.
pub struct Ephemeral {
    pub(crate) priv_key: PrivateKey,
    /// The 32-byte public key (`e` on the client, `f` on the server).
    pub public: [u8; 32],
}

/// Generate a fresh ephemeral X25519 key pair.
pub fn generate_ephemeral() -> Ephemeral {
    let priv_key = PrivateKey::generate();
    let pub_key =
        X25519PublicKey::try_from(&priv_key).expect("private key yields a valid public key");
    Ephemeral {
        priv_key,
        public: pub_key.to_bytes(),
    }
}

pub fn shared_secret(eph: &Ephemeral, peer_public: &[u8]) -> Result<[u8; 32], Error> {
    let arr: [u8; 32] = peer_public
        .try_into()
        .map_err(|_| Error::Kex("peer public key must be 32 bytes".into()))?;
    let peer = X25519PublicKey::from_slice(&arr)
        .map_err(|e| Error::Kex(format!("invalid peer key: {e}")))?;
    let shared = key_agreement(&eph.priv_key, &peer)
        .map_err(|e| Error::Kex(format!("key agreement failed: {e}")))?;
    let bytes: [u8; 32] = shared
        .unprotected_as_bytes()
        .try_into()
        .map_err(|_| Error::Kex("unexpected shared-secret length".into()))?;
    Ok(bytes)
}

/// SHA-256 over a sequence of byte slices.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(out.as_ref());
    buf
}

/// Compute the exchange hash `H`.
#[allow(clippy::too_many_arguments)]
pub fn exchange_hash(
    v_c: &str,
    v_s: &str,
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    e: &[u8],
    f: &[u8],
    k: &[u8],
) -> [u8; 32] {
    let mut w = Writer::new();
    w.write_string(v_c.as_bytes());
    w.write_string(v_s.as_bytes());
    w.write_string(i_c);
    w.write_string(i_s);
    w.write_string(k_s);
    w.write_string(e);
    w.write_string(f);
    w.write_string(k); // K is encoded as a string for curve25519-sha256.
    let data = w.into_inner();
    sha256(&[&data])
}

/// Derive `out_len` bytes of key material for one direction.
///
/// `block1 = SHA256(K || H || letter || session_id)`; subsequent blocks chain
/// on the previous block: `block_i = SHA256(K || H || block_{i-1})` (RFC 4253
/// §7.2).
fn derive_key(k: &[u8], h: &[u8], letter: u8, session_id: &[u8], out_len: usize) -> Vec<u8> {
    let blocks = out_len.div_ceil(32);
    let mut out = Vec::with_capacity(blocks * 32);
    let mut prev: Option<Vec<u8>> = None;
    for i in 0..blocks {
        let mut hasher = Sha256::new();
        hasher.update(k);
        hasher.update(h);
        if i == 0 {
            hasher.update([letter]);
            hasher.update(session_id);
        } else {
            hasher.update(prev.as_ref().unwrap());
        }
        let block = hasher.finalize();
        out.extend_from_slice(block.as_ref());
        prev = Some(block.to_vec());
    }
    out.truncate(out_len);
    out
}

/// Build a minimal `SSH_MSG_KEXINIT` payload (cookie + negotiated algorithms).
/// The foundation uses fixed placeholders; a full implementation negotiates
/// these between the peers. Both peers must use the *same* `I_C`/`I_S` values
/// when computing `H`, which holds here because we generate them identically.
pub fn make_kexinit() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(20); // SSH_MSG_KEXINIT
    for _ in 0..16 {
        w.write_byte(0); // 16-byte cookie (placeholder)
    }
    w.write_name_list([b"curve25519-sha256".as_ref()]);
    w.write_name_list([b"ssh-ed25519".as_ref()]);
    w.write_name_list([b"chacha20-poly1305@openssh.com".as_ref()]);
    w.write_name_list([b"chacha20-poly1305@openssh.com".as_ref()]);
    w.write_name_list([b"none".as_ref()]);
    w.write_name_list([b"none".as_ref()]);
    w.write_name_list([b"none".as_ref()]);
    w.write_name_list([b"none".as_ref()]);
    w.write_bool(false); // first_kex_packet_follows
    w.write_u32(0); // reserved
    w.into_inner()
}

/// SSH message codes used during the transport handshake (RFC 4253 §12).
pub const SSH_MSG_KEXINIT: u8 = 20;
/// SSH message codes used during the transport handshake (RFC 4253 §12).
pub const SSH_MSG_NEWKEYS: u8 = 21;
/// SSH message codes used during the transport handshake (RFC 4253 §12).
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// SSH message codes used during the transport handshake (RFC 4253 §12).
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;

/// The algorithm name-lists carried in an `SSH_MSG_KEXINIT` (RFC 4253 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit {
    /// Key exchange algorithms (e.g. `curve25519-sha256`).
    pub kex_algorithms: Vec<String>,
    /// Server host key algorithms (e.g. `ssh-ed25519`).
    pub server_host_key_algorithms: Vec<String>,
    /// Encryption algorithms, client → server.
    pub encryption_client_to_server: Vec<String>,
    /// Encryption algorithms, server → client.
    pub encryption_server_to_client: Vec<String>,
    /// MAC algorithms, client → server.
    pub mac_client_to_server: Vec<String>,
    /// MAC algorithms, server → client.
    pub mac_server_to_client: Vec<String>,
    /// Compression algorithms, client → server.
    pub compression_client_to_server: Vec<String>,
    /// Compression algorithms, server → client.
    pub compression_server_to_client: Vec<String>,
}

impl KexInit {
    /// Parse a `SSH_MSG_KEXINIT` payload (including the message code byte).
    pub fn parse(payload: &[u8]) -> Result<KexInit, Error> {
        let mut r = Reader::new(payload);
        let code = r.read_byte().map_err(Error::Wire)?;
        if code != SSH_MSG_KEXINIT {
            return Err(Error::Kex(format!("expected KEXINIT, got {code}")));
        }
        // The cookie is 16 raw bytes (not a length-prefixed string) per
        // RFC 4253 §7.1.
        let _cookie = r.take(16).map_err(Error::Wire)?;
        let kex_algorithms = read_names(&mut r)?;
        let server_host_key_algorithms = read_names(&mut r)?;
        let encryption_client_to_server = read_names(&mut r)?;
        let encryption_server_to_client = read_names(&mut r)?;
        let mac_client_to_server = read_names(&mut r)?;
        let mac_server_to_client = read_names(&mut r)?;
        let compression_client_to_server = read_names(&mut r)?;
        let compression_server_to_client = read_names(&mut r)?;
        let _first_kex_follows = r.read_bool().map_err(Error::Wire)?;
        let _reserved = r.read_u32().map_err(Error::Wire)?;
        Ok(KexInit {
            kex_algorithms,
            server_host_key_algorithms,
            encryption_client_to_server,
            encryption_server_to_client,
            mac_client_to_server,
            mac_server_to_client,
            compression_client_to_server,
            compression_server_to_client,
        })
    }
}

fn read_names(r: &mut Reader<'_>) -> Result<Vec<String>, Error> {
    let raw = r.read_string().map_err(Error::Wire)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split(|&b| b == b',')
        .map(|s| String::from_utf8(s.to_vec()).map_err(|_| Error::Kex("non-UTF8 name-list".into())))
        .collect()
}

/// The algorithm sets this implementation can offer/accept, in preference order.
pub struct Preferences {
    /// Key exchange algorithms.
    pub kex: &'static [&'static str],
    /// Server host key algorithms.
    pub host_key: &'static [&'static str],
    /// Encryption algorithms.
    pub cipher: &'static [&'static str],
    /// MAC algorithms.
    pub mac: &'static [&'static str],
    /// Compression algorithms.
    pub compression: &'static [&'static str],
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            kex: &["curve25519-sha256"],
            host_key: &["ssh-ed25519"],
            cipher: &["chacha20-poly1305@openssh.com"],
            mac: &["none"],
            compression: &["none"],
        }
    }
}

/// Select the first algorithm both `client` and `server` advertise, taking
/// `prefs` as the ordered preference list. Errors if there is no intersection.
fn select<'a>(prefs: &[&'a str], client: &[String], server: &[String]) -> Result<&'a str, Error> {
    for p in prefs {
        if client.iter().any(|c| c == p) && server.iter().any(|s| s == p) {
            return Ok(p);
        }
    }
    Err(Error::Kex("no common algorithm".into()))
}

/// Negotiate the algorithm set from two `KEXINIT` payloads (RFC 4253 §7.1).
pub fn negotiate(client_kexinit: &[u8], server_kexinit: &[u8]) -> Result<Negotiated, Error> {
    let c = KexInit::parse(client_kexinit)?;
    let s = KexInit::parse(server_kexinit)?;
    let prefs = Preferences::default();
    let kex = select(prefs.kex, &c.kex_algorithms, &s.kex_algorithms)?.to_string();
    let host_key = select(
        prefs.host_key,
        &c.server_host_key_algorithms,
        &s.server_host_key_algorithms,
    )?
    .to_string();
    let cipher = select(
        prefs.cipher,
        &c.encryption_client_to_server,
        &s.encryption_client_to_server,
    )?
    .to_string();
    // MAC and compression are symmetric single-algorithm sets here.
    let _mac = select(prefs.mac, &c.mac_client_to_server, &s.mac_client_to_server)?.to_string();
    let _compression = select(
        prefs.compression,
        &c.compression_client_to_server,
        &s.compression_client_to_server,
    )?
    .to_string();
    Ok(Negotiated {
        kex,
        host_key,
        cipher,
    })
}

/// The outcome of a successful algorithm negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// Selected key exchange algorithm.
    pub kex: String,
    /// Selected host key algorithm.
    pub host_key: String,
    /// Selected encryption algorithm.
    pub cipher: String,
}

/// Derive the two 64-byte directional session keys from the shared secret `k`
/// and the exchange hash `h` (RFC 4253 §7.2). The first exchange hash is the
/// session id.
pub fn session_keys(k: &[u8], h: &[u8]) -> SessionKeys {
    let client_to_server = derive_key(k, h, b'C', h, 64)
        .try_into()
        .expect("64-byte client_to_server key");
    let server_to_client = derive_key(k, h, b'D', h, 64)
        .try_into()
        .expect("64-byte server_to_client key");
    SessionKeys {
        client_to_server,
        server_to_client,
    }
}

/// Perform a full `curve25519-sha256` key exchange between a client and a
/// server in memory. Returns the (identical) session keys from both
/// perspectives.
pub fn key_exchange(v_c: &str, v_s: &str) -> (SessionKeys, SessionKeys) {
    let i_c = make_kexinit();
    let i_s = make_kexinit();

    let host_key = HostKey::generate();
    let k_s = host_key.public_key_blob();

    let client = generate_ephemeral();
    let server = generate_ephemeral();

    let k_client = shared_secret(&client, &server.public).expect("client K");
    let k_server = shared_secret(&server, &client.public).expect("server K");
    assert_eq!(k_client, k_server, "both sides must derive the same K");
    let k = k_client;

    let h_client = exchange_hash(
        v_c,
        v_s,
        &i_c,
        &i_s,
        &k_s,
        &client.public,
        &server.public,
        &k,
    );
    let h_server = exchange_hash(
        v_c,
        v_s,
        &i_c,
        &i_s,
        &k_s,
        &client.public,
        &server.public,
        &k,
    );
    assert_eq!(h_client, h_server, "both sides must compute the same H");

    // Server signs H; client verifies it (RFC 4253 §8).
    let signature = host_key.sign(&h_server);
    assert!(
        HostKey::verify(&k_s, &signature, &h_client).expect("host key verify"),
        "exchange-hash signature must verify"
    );

    let session_id = h_client; // first exchange hash is the session id
    let client_to_server = derive_key(&k, &h_client, b'C', &session_id, 64)
        .try_into()
        .expect("64-byte client_to_server key");
    let server_to_client = derive_key(&k, &h_client, b'D', &session_id, 64)
        .try_into()
        .expect("64-byte server_to_client key");

    let client_keys = SessionKeys {
        client_to_server,
        server_to_client,
    };
    let server_keys = SessionKeys {
        client_to_server,
        server_to_client,
    };
    (client_keys, server_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::CipherPair;

    #[test]
    fn kex_produces_matching_session_keys() {
        let (c, s) = key_exchange("SSH-2.0-tpt-client", "SSH-2.0-tpt-server");
        assert_eq!(c, s);
        assert_ne!(c.client_to_server, c.server_to_client);
    }

    #[test]
    fn encrypted_round_trip_both_directions() {
        let (client_keys, server_keys) = key_exchange("SSH-2.0-tpt-client", "SSH-2.0-tpt-server");
        let client = CipherPair::from_session(&client_keys);
        let server = CipherPair::from_session(&server_keys);

        // Client -> Server, sequence 0.
        let msg = b"\x05service-request\0ssh-userauth";
        let pkt = client.client_encrypt(0, msg);
        assert_eq!(server.server_decrypt(0, &pkt).unwrap(), msg);

        // Server -> Client, sequence 0.
        let reply = b"\x06service-accept\0ssh-userauth";
        let rpkt = server.server_encrypt(0, reply);
        assert_eq!(client.client_decrypt(0, &rpkt).unwrap(), reply);

        // Sequence numbers advance independently per direction.
        let msg2 = b"\x01";
        let pkt2 = client.client_encrypt(1, msg2);
        assert_eq!(server.server_decrypt(1, &pkt2).unwrap(), msg2);
    }

    #[test]
    fn tampered_packet_fails_mac() {
        let (client_keys, server_keys) = key_exchange("SSH-2.0-tpt-client", "SSH-2.0-tpt-server");
        let client = CipherPair::from_session(&client_keys);
        let server = CipherPair::from_session(&server_keys);

        let msg = b"secret";
        let mut pkt = client.client_encrypt(0, msg);
        // Flip a ciphertext byte in the content region.
        let idx = 4 + 1;
        pkt[idx] ^= 0xff;
        assert!(server.server_decrypt(0, &pkt).is_err());
    }
}
