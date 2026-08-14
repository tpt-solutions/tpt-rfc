// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SNMPv3 User-based Security Model (USM) — authentication and privacy
//! (RFC 3414), plus AES-CFB-128 privacy (RFC 3826).
//!
//! This module implements the cryptographic pieces *on top of* dual-licensed
//! primitives: HMAC-SHA-96 reuses `hmac`/`sha1`, HMAC-MD5-96 and CBC-DES are
//! clean-room (see [`crate::crypto`]), and AES-CFB-128 reuses the `aes`
//! block-cipher primitive.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

use crate::crypto;

/// USM authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthProtocol {
    /// No authentication.
    #[default]
    None,
    /// HMAC-MD5-96 (RFC 3414 §7.2).
    Md5,
    /// HMAC-SHA-96 (RFC 3414 §7.2).
    Sha1,
}

impl AuthProtocol {
    /// Number of bytes in the authentication parameter (always 12 for the
    /// RFC 3414 algorithms; 0 when none).
    pub fn param_len(self) -> usize {
        match self {
            AuthProtocol::None => 0,
            AuthProtocol::Md5 | AuthProtocol::Sha1 => 12,
        }
    }
}

/// USM privacy protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivProtocol {
    /// No privacy.
    #[default]
    None,
    /// CBC-DES (RFC 3414 §8).
    Des,
    /// AES-CFB-128 (RFC 3826).
    Aes,
}

impl PrivProtocol {
    /// Number of bytes in the privacy parameter (salt): 8 for the RFC 3414/3826
    /// protocols.
    pub fn param_len(self) -> usize {
        match self {
            PrivProtocol::None => 0,
            PrivProtocol::Des | PrivProtocol::Aes => 8,
        }
    }
}

/// Repeat `password` until it reaches 1,048,576 bytes (RFC 3414 §11.1,
/// `passwordToKey`).
fn expand_password(password: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(1_048_576);
    while data.len() < 1_048_576 {
        let need = 1_048_576 - data.len();
        let take = password.len().min(need);
        if take == 0 {
            break;
        }
        data.extend_from_slice(&password[..take]);
    }
    data
}

/// Derive a non-localized authentication key from a password (RFC 3414 §11.1).
pub fn password_to_auth_key(proto: AuthProtocol, password: &[u8]) -> Vec<u8> {
    match proto {
        AuthProtocol::None => Vec::new(),
        AuthProtocol::Md5 => crypto::md5(&expand_password(password)).to_vec(),
        AuthProtocol::Sha1 => {
            let mut h = Sha1::new();
            h.update(&expand_password(password));
            h.finalize().to_vec()
        }
    }
}

/// Derive a non-localized privacy key from a password (RFC 3414 §11.1).
pub fn password_to_priv_key(proto: PrivProtocol, _password: &[u8]) -> Vec<u8> {
    // For DES/AES the privacy key is localized from the *authentication* key,
    // so callers should localize `password_to_auth_key` then `localize_priv`.
    match proto {
        PrivProtocol::None => Vec::new(),
        PrivProtocol::Des | PrivProtocol::Aes => Vec::new(),
    }
}

/// Localize `key` against `engine_id`: `Hash(key || engineID || key)`
/// (RFC 3414 §11.2). MD5 keys are 16 bytes, SHA-1 keys are 20 bytes.
pub fn localize_key(key: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut d = key.to_vec();
    d.extend_from_slice(engine_id);
    d.extend_from_slice(key);
    match key.len() {
        16 => crypto::md5(&d).to_vec(),
        20 => {
            let mut h = Sha1::new();
            h.update(&d);
            h.finalize().to_vec()
        }
        _ => d,
    }
}

/// Localize an authentication key into a 16-byte privacy key against
/// `engine_id` (RFC 3414 §11.2 / RFC 3826).
pub fn localize_priv_key(auth_key: &[u8], engine_id: &[u8]) -> [u8; 16] {
    let lk = localize_key(auth_key, engine_id);
    let mut out = [0u8; 16];
    out.copy_from_slice(&lk[..16]);
    out
}

type HmacSha1 = Hmac<Sha1>;

/// Compute the 12-byte HMAC (MD5-96 or SHA-96) over `message` using `key`.
pub fn auth_mac(proto: AuthProtocol, key: &[u8], message: &[u8]) -> [u8; 12] {
    let mut out = [0u8; 12];
    match proto {
        AuthProtocol::Md5 => {
            let full = crypto::hmac_md5(key, message);
            out.copy_from_slice(&full[..12]);
        }
        AuthProtocol::Sha1 => {
            let mut mac =
                <HmacSha1 as hmac::Mac>::new_from_slice(key).expect("key length accepted");
            mac.update(message);
            let full = mac.finalize().into_bytes();
            out.copy_from_slice(&full[..12]);
        }
        AuthProtocol::None => {}
    }
    out
}

/// AES-CFB-128 transform (RFC 3826 §3.1.3). Symmetric for encryption and
/// decryption: `output = input XOR E(register)`, with the register fed by the
/// previous ciphertext block.
/// AES-CFB-128 transform (RFC 3826 §3.1.3). The register is fed by the
/// *transmitted ciphertext* block. `encrypt` selects whether `input` is
/// plaintext (the produced `output` becomes the next register) or ciphertext
/// (the `input` itself becomes the next register).
fn aes_cfb128(input: &[u8], key: &[u8; 16], iv: &[u8; 16], encrypt: bool) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let mut reg = *iv;
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let mut ks = reg;
        cipher.encrypt_block((&mut ks).into());
        let take = (input.len() - i).min(16);
        for j in 0..take {
            out.push(input[i + j] ^ ks[j]);
        }
        if take == 16 {
            if encrypt {
                reg.copy_from_slice(&out[out.len() - 16..]);
            } else {
                reg.copy_from_slice(&input[i..i + 16]);
            }
        } else {
            let mut newreg = [0u8; 16];
            newreg[..16 - take].copy_from_slice(&reg[take..]);
            if encrypt {
                newreg[16 - take..].copy_from_slice(&out[out.len() - take..]);
            } else {
                newreg[16 - take..].copy_from_slice(&input[i..i + take]);
            }
            reg = newreg;
        }
        i += take;
    }
    out
}

/// Encrypt a `ScopedPdu` and produce the privacy parameters (8-byte salt).
pub fn encrypt_scoped(
    plaintext: &[u8],
    priv_key: &[u8; 16],
    protocol: PrivProtocol,
    boots: u32,
    time: u32,
    salt: &[u8; 8],
) -> Vec<u8> {
    match protocol {
        PrivProtocol::None => plaintext.to_vec(),
        PrivProtocol::Des => {
            let mut key = [0u8; 8];
            key.copy_from_slice(&priv_key[0..8]);
            let mut iv = [0u8; 8];
            for i in 0..8 {
                iv[i] = priv_key[8 + i] ^ salt[i];
            }
            crypto::des_cbc_encrypt(plaintext, &key, &iv)
        }
        PrivProtocol::Aes => {
            let mut iv = [0u8; 16];
            iv[0..4].copy_from_slice(&boots.to_be_bytes());
            iv[4..8].copy_from_slice(&time.to_be_bytes());
            iv[8..16].copy_from_slice(salt);
            aes_cfb128(plaintext, priv_key, &iv, true)
        }
    }
}

/// Decrypt a `ScopedPdu` using the supplied privacy parameters.
pub fn decrypt_scoped(
    ciphertext: &[u8],
    priv_key: &[u8; 16],
    protocol: PrivProtocol,
    boots: u32,
    time: u32,
    salt: &[u8; 8],
) -> Result<Vec<u8>, crate::error::SnmpError> {
    match protocol {
        PrivProtocol::None => Ok(ciphertext.to_vec()),
        PrivProtocol::Des => {
            let mut key = [0u8; 8];
            key.copy_from_slice(&priv_key[0..8]);
            let mut iv = [0u8; 8];
            for i in 0..8 {
                iv[i] = priv_key[8 + i] ^ salt[i];
            }
            let pt = crypto::des_cbc_decrypt(ciphertext, &key, &iv);
            if pt.is_empty() && !ciphertext.is_empty() {
                return Err(crate::error::SnmpError::DecryptError);
            }
            Ok(pt)
        }
        PrivProtocol::Aes => {
            let mut iv = [0u8; 16];
            iv[0..4].copy_from_slice(&boots.to_be_bytes());
            iv[4..8].copy_from_slice(&time.to_be_bytes());
            iv[8..16].copy_from_slice(salt);
            Ok(aes_cfb128(ciphertext, priv_key, &iv, false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_cfb128_roundtrip() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let pt = b"the quick brown fox scoped pdu";
        let ct = aes_cfb128(pt, &key, &iv, true);
        assert_ne!(ct, pt.to_vec());
        assert_eq!(aes_cfb128(&ct, &key, &iv, false), pt.to_vec());
    }

    #[test]
    fn des_priv_roundtrip() {
        let priv_key = [0x5u8; 16];
        let salt = [0x9u8; 8];
        let pt = b"scoped pdu plaintext for cbc des";
        let ct = encrypt_scoped(pt, &priv_key, PrivProtocol::Des, 0, 0, &salt);
        let dec = decrypt_scoped(&ct, &priv_key, PrivProtocol::Des, 0, 0, &salt).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn aes_priv_roundtrip() {
        let priv_key = [0x5u8; 16];
        let salt = [0x9u8; 8];
        let pt = b"scoped pdu plaintext for aes cfb";
        let ct = encrypt_scoped(pt, &priv_key, PrivProtocol::Aes, 1, 2, &salt);
        let dec = decrypt_scoped(&ct, &priv_key, PrivProtocol::Aes, 1, 2, &salt).unwrap();
        assert_eq!(dec, pt);
    }
}
