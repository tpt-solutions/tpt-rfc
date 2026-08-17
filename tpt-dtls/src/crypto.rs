// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographic building blocks reused (not reimplemented) by this crate:
//! cipher-suite definitions, AEAD record protection wrappers, X25519 key
//! agreement, and Ed25519 signature helpers. All are dual-licensed
//! (MIT/Apache-2.0 or MIT) primitives.

use crate::error::{DtlsError, Result};
use ed25519_compact::{KeyPair, PublicKey as EdPublicKey, Seed, Signature as EdSignature};
use orion::hazardous::ecc::x25519::{key_agreement, PrivateKey, PublicKey as X25519PublicKey};
use sha2::{Digest, Sha256, Sha384};

/// Hash algorithm backing a cipher suite's transcript and key schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256 (used by `TLS_AES_128_GCM_SHA256` and
    /// `TLS_CHACHA20_POLY1305_SHA256`).
    Sha256,
    /// SHA-384 (used by `TLS_AES_256_GCM_SHA384`).
    Sha384,
}

impl HashAlg {
    /// The digest output length in bytes.
    pub fn output_len(&self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    /// Compute the digest of `data`.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    /// HMAC-`Hash` of `data` under `key`.
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        match self {
            HashAlg::Sha256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key len");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashAlg::Sha384 => {
                let mut m = Hmac::<Sha384>::new_from_slice(key).expect("hmac accepts any key len");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// The DTLS 1.3 cipher suites supported by this crate.
///
/// All three are the standard TLS 1.3 AEAD suites; their key schedule and
/// record-protection rules are identical (RFC 8446 §7), only the hash and
/// AEAD primitive differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// `TLS_AES_128_GCM_SHA256` (0x1301).
    TlsAes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384` (0x1302).
    TlsAes256GcmSha384,
    /// `TLS_CHACHA20_POLY1305_SHA256` (0x1303).
    TlsChacha20Poly1305Sha256,
}

impl CipherSuite {
    /// The IANA cipher-suite code.
    pub fn code(&self) -> u16 {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 0x1301,
            CipherSuite::TlsAes256GcmSha384 => 0x1302,
            CipherSuite::TlsChacha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Parse an IANA cipher-suite code, or `None` if unsupported.
    pub fn from_code(code: u16) -> Option<CipherSuite> {
        match code {
            0x1301 => Some(CipherSuite::TlsAes128GcmSha256),
            0x1302 => Some(CipherSuite::TlsAes256GcmSha384),
            0x1303 => Some(CipherSuite::TlsChacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// The hash algorithm used by this suite's key schedule.
    pub fn hash_alg(&self) -> HashAlg {
        match self {
            CipherSuite::TlsAes128GcmSha256 => HashAlg::Sha256,
            CipherSuite::TlsAes256GcmSha384 => HashAlg::Sha384,
            CipherSuite::TlsChacha20Poly1305Sha256 => HashAlg::Sha256,
        }
    }

    /// Symmetric key length in bytes (AES-128 = 16, others = 32).
    pub fn key_len(&self) -> usize {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 16,
            CipherSuite::TlsAes256GcmSha384 => 32,
            CipherSuite::TlsChacha20Poly1305Sha256 => 32,
        }
    }

    /// The fixed AEAD nonce/IV length (12 bytes for all TLS 1.3 suites).
    pub fn iv_len(&self) -> usize {
        12
    }

    /// The AEAD authentication-tag length (16 bytes).
    pub fn tag_len(&self) -> usize {
        16
    }
}

/// AEAD-seal `plaintext` with `key`, `nonce` (12 bytes), and `aad`,
/// returning `ciphertext || tag`.
pub(crate) fn aead_seal(
    suite: CipherSuite,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use aead::{Aead, KeyInit, Payload};
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match suite {
        CipherSuite::TlsAes128GcmSha256 => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(crypto_err)?;
            let nonce = aead::Nonce::<aes_gcm::Aes128Gcm>::from_slice(nonce);
            c.encrypt(nonce, payload)
                .map_err(|_| DtlsError::DecryptFailed)
        }
        CipherSuite::TlsAes256GcmSha384 => {
            let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(crypto_err)?;
            let nonce = aead::Nonce::<aes_gcm::Aes256Gcm>::from_slice(nonce);
            c.encrypt(nonce, payload)
                .map_err(|_| DtlsError::DecryptFailed)
        }
        CipherSuite::TlsChacha20Poly1305Sha256 => {
            let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).map_err(crypto_err)?;
            let nonce = aead::Nonce::<chacha20poly1305::ChaCha20Poly1305>::from_slice(nonce);
            c.encrypt(nonce, payload)
                .map_err(|_| DtlsError::DecryptFailed)
        }
    }
}

/// AEAD-open `ciphertext_and_tag` with `key`, `nonce`, and `aad`, returning
/// the decrypted plaintext.
pub(crate) fn aead_open(
    suite: CipherSuite,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use aead::{Aead, KeyInit, Payload};
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match suite {
        CipherSuite::TlsAes128GcmSha256 => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(crypto_err)?;
            let nonce = aead::Nonce::<aes_gcm::Aes128Gcm>::from_slice(nonce);
            c.decrypt(nonce, payload)
                .map_err(|_| DtlsError::DecryptFailed)
        }
        CipherSuite::TlsAes256GcmSha384 => {
            let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(crypto_err)?;
            let nonce = aead::Nonce::<aes_gcm::Aes256Gcm>::from_slice(nonce);
            c.decrypt(nonce, payload)
                .map_err(|_| DtlsError::DecryptFailed)
        }
        CipherSuite::TlsChacha20Poly1305Sha256 => {
            let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).map_err(crypto_err)?;
            let nonce = aead::Nonce::<chacha20poly1305::ChaCha20Poly1305>::from_slice(nonce);
            c.decrypt(nonce, payload)
                .map_err(|_| DtlsError::DecryptFailed)
        }
    }
}

fn crypto_err<E: std::fmt::Display>(e: E) -> DtlsError {
    DtlsError::HandshakeIncomplete(e.to_string().leak())
}

/// An X25519 key agreement key pair (RFC 7748).
pub struct X25519KeyPair {
    private: PrivateKey,
    /// The 32-byte public key.
    pub public: [u8; 32],
}

impl X25519KeyPair {
    /// Generate a fresh random key pair.
    pub fn generate() -> Result<Self> {
        let private = PrivateKey::generate();
        let pubkey = X25519PublicKey::try_from(&private).map_err(crypto_err)?;
        Ok(Self {
            private,
            public: pubkey.to_bytes(),
        })
    }

    /// The raw 32-byte public key.
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    /// Perform X25519 Diffie-Hellman with `peer_public`, returning the shared
    /// secret (or an error if the peer key is invalid, e.g. all-zero).
    pub fn agree(&self, peer_public: &[u8]) -> Result<[u8; 32]> {
        let peer = X25519PublicKey::from_slice(peer_public).map_err(crypto_err)?;
        let shared = key_agreement(&self.private, &peer).map_err(crypto_err)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.unprotected_as_bytes());
        Ok(out)
    }
}

/// An Ed25519 signing key for `CertificateVerify` (RFC 8446 §4.4.3), used in
/// the reference raw-public-key handshake.
pub struct Ed25519KeyPair {
    kp: KeyPair,
}

impl Ed25519KeyPair {
    /// Build a key pair from a 32-byte seed/secret.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed = Seed::from_slice(seed)
            .map_err(|e| DtlsError::HandshakeIncomplete(format!("ed25519 seed: {e}").leak()))?;
        let kp = KeyPair::from_seed(seed);
        Ok(Self { kp })
    }

    /// The 32-byte public key.
    pub fn public_bytes(&self) -> &[u8] {
        self.kp.pk.as_slice()
    }

    /// Sign `msg` with pure Ed25519 (no prehash), returning the 64-byte
    /// signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.kp.sk.sign(msg, None);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }
}

/// Verify a pure-Ed25519 `signature` over `msg` against `public_key`.
pub fn ed25519_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    match EdPublicKey::from_slice(public_key) {
        Ok(pk) => match EdSignature::from_slice(signature) {
            Ok(sig) => pk.verify(msg, &sig).is_ok(),
            Err(_) => false,
        },
        Err(_) => false,
    }
}
