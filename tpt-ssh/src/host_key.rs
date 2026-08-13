// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 host-key handling (RFC 8032), used to authenticate the key-exchange
//! hash `H` (RFC 4253 §8). The SSH wire format for Ed25519 keys and
//! signatures is implemented here on top of `ed25519-compact`.

use crate::wire::{Reader, Writer};
use crate::Error;
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

/// An Ed25519 host key used to sign/verify the exchange hash.
pub struct HostKey {
    keypair: KeyPair,
}

impl HostKey {
    /// Generate a fresh host key.
    pub fn generate() -> Self {
        Self {
            keypair: KeyPair::generate(),
        }
    }

    /// Derive a host key from a 32-byte seed (deterministic; useful for tests).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(Seed::from(*seed)),
        }
    }

    /// The SSH public-key blob: `string("ssh-ed25519") || string(pubkey 32)`.
    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_string(b"ssh-ed25519");
        w.write_string(self.keypair.pk.as_ref());
        w.into_inner()
    }

    /// Sign the exchange hash `H`, returning the SSH signature blob:
    /// `string("ssh-ed25519") || string(signature 64)`.
    pub fn sign(&self, h: &[u8]) -> Vec<u8> {
        let sig: Signature = self.keypair.sk.sign(h, None);
        let mut w = Writer::new();
        w.write_string(b"ssh-ed25519");
        w.write_string(sig.as_ref());
        w.into_inner()
    }

    /// Verify an SSH signature blob over `H` using the host key blob.
    pub fn verify(host_key_blob: &[u8], signature_blob: &[u8], h: &[u8]) -> Result<bool, Error> {
        let mut r = Reader::new(host_key_blob);
        let key_type = r.read_string().map_err(Error::Wire)?;
        if key_type != b"ssh-ed25519" {
            return Err(Error::HostKey("unsupported host key type".into()));
        }
        let pk_bytes = r.read_string().map_err(Error::Wire)?;
        let pk = PublicKey::from_slice(pk_bytes).map_err(|e| Error::HostKey(format!("{e}")))?;

        let mut r2 = Reader::new(signature_blob);
        let sig_type = r2.read_string().map_err(Error::Wire)?;
        if sig_type != b"ssh-ed25519" {
            return Err(Error::HostKey("unsupported signature type".into()));
        }
        let sig_bytes = r2.read_string().map_err(Error::Wire)?;
        let sig = Signature::from_slice(sig_bytes).map_err(|e| Error::HostKey(format!("{e}")))?;
        Ok(pk.verify(h, &sig).is_ok())
    }
}
