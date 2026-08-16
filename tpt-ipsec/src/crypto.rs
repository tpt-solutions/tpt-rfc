//! Cryptographic primitives reused from dual-licensed crates and wired into
//! the IKEv2 key schedule (RFC 7296 §2.13–§2.15). The only cryptographic
//! operation implemented here is the MODP Diffie-Hellman group operation,
//! which is a thin `BigUint` modular exponentiation over the RFC-specified
//! primes (reusing `num-bigint`, not reimplementing bignum math).

use crate::error::{Error, Result};
use crate::types::{DhGroup, EncrId, IntegId, PrfId};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Nonce;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

macro_rules! hmac_vec {
    ($hash:ty, $key:expr, $data:expr) => {{
        let mut m = Hmac::<$hash>::new_from_slice($key).expect("HMAC accepts any key length");
        m.update($data);
        m.finalize().into_bytes().to_vec()
    }};
}

fn err<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

// ---------------------------------------------------------------------------
// Pseudo-Random Function (PRF)
// ---------------------------------------------------------------------------

/// A negotiated IKEv2 PRF (always HMAC-based in this implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Prf {
    pub fn from_id(id: PrfId) -> Prf {
        match id {
            PrfId::HmacSha1 => Prf::Sha1,
            PrfId::HmacSha256 => Prf::Sha256,
            PrfId::HmacSha384 => Prf::Sha384,
            PrfId::HmacSha512 => Prf::Sha512,
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Prf::Sha1 => 20,
            Prf::Sha256 => 32,
            Prf::Sha384 => 48,
            Prf::Sha512 => 64,
        }
    }

    /// `prf(K, data)` — a single PRF block.
    pub fn prf(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Prf::Sha1 => hmac_vec!(Sha1, key, data),
            Prf::Sha256 => hmac_vec!(Sha256, key, data),
            Prf::Sha384 => hmac_vec!(Sha384, key, data),
            Prf::Sha512 => hmac_vec!(Sha512, key, data),
        }
    }

    /// `prf+(K, seed)` — the key-expansion function of RFC 7296 §2.13:
    /// `T1 | T2 | ...` with `Ti = prf(K, T{i-1} | seed)`, `T0 = ""`.
    pub fn prf_plus(self, key: &[u8], seed: &[u8], n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut t: Vec<u8> = Vec::new();
        while out.len() < n {
            let mut data = t.clone();
            data.extend_from_slice(seed);
            let blk = self.prf(key, &data);
            out.extend_from_slice(&blk);
            t = blk;
        }
        out.truncate(n);
        out
    }
}

// ---------------------------------------------------------------------------
// Integrity algorithm
// ---------------------------------------------------------------------------

/// A negotiated IKEv2 integrity algorithm (used for the SK ICV / AUTH MAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integ {
    HmacSha1_96,
    HmacSha256_128,
    HmacSha384_192,
    HmacSha512_256,
}

impl Integ {
    pub fn from_id(id: IntegId) -> Integ {
        match id {
            IntegId::HmacSha1_96 => Integ::HmacSha1_96,
            IntegId::HmacSha256_128 => Integ::HmacSha256_128,
            IntegId::HmacSha384_192 => Integ::HmacSha384_192,
            IntegId::HmacSha512_256 => Integ::HmacSha512_256,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Integ::HmacSha1_96 => 20,
            Integ::HmacSha256_128 => 32,
            Integ::HmacSha384_192 => 48,
            Integ::HmacSha512_256 => 64,
        }
    }

    /// Truncated ICV length.
    pub fn icv_len(self) -> usize {
        match self {
            Integ::HmacSha1_96 => 12,
            Integ::HmacSha256_128 => 16,
            Integ::HmacSha384_192 => 24,
            Integ::HmacSha512_256 => 32,
        }
    }

    /// Full MAC (length `key_len`).
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Integ::HmacSha1_96 => hmac_vec!(Sha1, key, data),
            Integ::HmacSha256_128 => hmac_vec!(Sha256, key, data),
            Integ::HmacSha384_192 => hmac_vec!(Sha384, key, data),
            Integ::HmacSha512_256 => hmac_vec!(Sha512, key, data),
        }
    }

    /// Truncated integrity checksum value.
    pub fn icv(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let full = self.mac(key, data);
        full[..self.icv_len()].to_vec()
    }
}

// ---------------------------------------------------------------------------
// Encryption algorithm
// ---------------------------------------------------------------------------

/// A negotiated IKEv2 encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encr {
    AesCbc { key_len: usize },
    AesGcm { key_len: usize },
}

impl Encr {
    pub fn from_id(id: EncrId) -> Encr {
        match id {
            EncrId::AesCbc128 => Encr::AesCbc { key_len: 16 },
            EncrId::AesCbc192 => Encr::AesCbc { key_len: 24 },
            EncrId::AesCbc256 => Encr::AesCbc { key_len: 32 },
            EncrId::AesGcm16_128 => Encr::AesGcm { key_len: 16 },
            EncrId::AesGcm16_192 => Encr::AesGcm { key_len: 24 },
            EncrId::AesGcm16_256 => Encr::AesGcm { key_len: 32 },
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Encr::AesCbc { key_len } | Encr::AesGcm { key_len } => key_len,
        }
    }

    pub fn is_aead(self) -> bool {
        matches!(self, Encr::AesGcm { .. })
    }

    pub fn block_size(self) -> usize {
        16
    }

    /// CBC IV length (one AES block).
    pub fn cbc_iv_len(self) -> usize {
        16
    }

    /// Encrypt using CBC mode with caller-supplied plaintext already padded.
    pub fn cbc_encrypt(self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = aes_block_cipher(self.key_len(), key)?;
        let mut out = Vec::with_capacity(plaintext.len());
        let mut prev = iv.to_vec();
        for chunk in plaintext.chunks(16) {
            let mut block = xor_block(chunk, &prev);
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
            out.extend_from_slice(&block);
            prev = block;
        }
        Ok(out)
    }

    /// Decrypt using CBC mode (no padding removal — caller strips IKE padding).
    pub fn cbc_decrypt(self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = aes_block_cipher(self.key_len(), key)?;
        if ciphertext.len() % 16 != 0 {
            return Err(Error::DecryptFailed);
        }
        let mut out = Vec::with_capacity(ciphertext.len());
        let mut prev = iv.to_vec();
        for chunk in ciphertext.chunks(16) {
            let mut block = chunk.to_vec();
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
            let pt = xor_block(&block, &prev);
            out.extend_from_slice(&pt);
            prev = chunk.to_vec();
        }
        Ok(out)
    }

    /// AEAD encrypt (AES-GCM). `nonce` is 12 bytes (4-byte salt || 8-byte IV).
    /// Returns `(ciphertext, tag)`; `tag` is 16 bytes. `aad` is empty for IKEv2.
    pub fn aead_encrypt(
        self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use aes_gcm::aead::KeyInit;
        match self {
            Encr::AesGcm { key_len: 16 } => {
                let c = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(err)?;
                aead_run(&c, nonce, aad, plaintext)
            }
            Encr::AesGcm { key_len: 24 } => {
                Err(Error::Crypto("AES-GCM-192 is unsupported by the aes-gcm crate".into()))
            }
            Encr::AesGcm { key_len: 32 } => {
                let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(err)?;
                aead_run(&c, nonce, aad, plaintext)
            }
            Encr::AesCbc { .. } => Err(Error::Crypto("algorithm is not AEAD".into())),
        }
    }

    /// AEAD decrypt (AES-GCM). `ciphertext` and `tag` (16 bytes) are supplied
    /// separately; `aad` is empty for IKEv2.
    pub fn aead_decrypt(
        self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        use aes_gcm::aead::KeyInit;
        let mut buf = ciphertext.to_vec();
        buf.extend_from_slice(tag);
        let res = match self {
            Encr::AesGcm { key_len: 16 } => {
                let c = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(err)?;
                c.decrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
            }
            Encr::AesGcm { key_len: 24 } => {
                return Err(Error::Crypto(
                    "AES-GCM-192 is unsupported by the aes-gcm crate".into(),
                ));
            }
            Encr::AesGcm { key_len: 32 } => {
                let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(err)?;
                c.decrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
            }
            Encr::AesCbc { .. } => return Err(Error::Crypto("algorithm is not AEAD".into())),
        };
        res.map_err(|_| Error::DecryptFailed)?;
        Ok(buf)
    }
}

fn aead_run<C: AeadInPlace + KeyInit>(
    c: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = plaintext.to_vec();
    c.encrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
        .map_err(|_| Error::Crypto("gcm encrypt failed".into()))?;
    let tag = buf.split_off(buf.len() - 16);
    Ok((buf, tag))
}

fn aes_block_cipher(key_len: usize, key: &[u8]) -> Result<AesCipher> {
    match key_len {
        16 => Ok(AesCipher::A128(aes::Aes128::new_from_slice(key).map_err(err)?)),
        24 => Ok(AesCipher::A192(aes::Aes192::new_from_slice(key).map_err(err)?)),
        32 => Ok(AesCipher::A256(aes::Aes256::new_from_slice(key).map_err(err)?)),
        _ => Err(Error::Crypto("unsupported AES key length".into())),
    }
}

enum AesCipher {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl AesCipher {
    fn encrypt_block(&self, b: &mut GenericArray<u8, 16>) {
        match self {
            AesCipher::A128(c) => c.encrypt_block(b),
            AesCipher::A192(c) => c.encrypt_block(b),
            AesCipher::A256(c) => c.encrypt_block(b),
        }
    }
    fn decrypt_block(&self, b: &mut GenericArray<u8, 16>) {
        match self {
            AesCipher::A128(c) => c.decrypt_block(b),
            AesCipher::A192(c) => c.decrypt_block(b),
            AesCipher::A256(c) => c.decrypt_block(b),
        }
    }
}

fn xor_block(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// ---------------------------------------------------------------------------
// Diffie-Hellman
// ---------------------------------------------------------------------------

/// A Diffie-Hellman key pair for a negotiated group.
#[derive(Debug, Clone)]
pub struct Dh {
    pub group: DhGroup,
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl Dh {
    /// Generate a fresh key pair for `group`.
    pub fn generate(group: DhGroup) -> Result<Dh> {
        match group {
            DhGroup::Curve25519 => {
                let (private, public) = x25519_generate()?;
                Ok(Dh {
                    group,
                    private,
                    public,
                })
            }
            _ => {
                let private = random_bytes(group.key_len());
                let public = modp_pub(group, &private)?;
                Ok(Dh {
                    group,
                    private,
                    public,
                })
            }
        }
    }

    /// Build a key pair from an explicit private scalar (for deterministic tests).
    pub fn from_private(group: DhGroup, private: &[u8]) -> Result<Dh> {
        let public = match group {
            DhGroup::Curve25519 => x25519_public(private)?,
            _ => modp_pub(group, private)?,
        };
        Ok(Dh {
            group,
            private: private.to_vec(),
            public,
        })
    }

    /// Compute the shared secret with a peer's public value.
    pub fn shared(&self, peer_public: &[u8]) -> Result<Vec<u8>> {
        match self.group {
            DhGroup::Curve25519 => x25519_shared(&self.private, peer_public),
            _ => modp_shared(self.group, &self.private, peer_public),
        }
    }
}

fn modp_prime_hex(group: DhGroup) -> Option<&'static str> {
    Some(match group {
        DhGroup::Modp768 => "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        DhGroup::Modp1024 => "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
        DhGroup::Modp1536 => "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71CFFF4B4E3F73B90",
        // MODP 2048/3072/4096 primes (RFC 3526) are not bundled in this
        // revision; Diffie-Hellman over those groups is deferred.
        _ => return None,
    })
}

fn modp_pub(group: DhGroup, scalar: &[u8]) -> Result<Vec<u8>> {
    let hex = modp_prime_hex(group).ok_or(Error::UnsupportedDhGroup(group.to_u16()))?;
    let p = BigUint::parse_bytes(hex.as_bytes(), 16).ok_or(Error::Crypto("bad prime".into()))?;
    let g = BigUint::from(2u32);
    let a = BigUint::from_bytes_be(scalar);
    let pubv = num_integer::Integer::modpow(&g, &a, &p);
    Ok(pad_be(&pubv.to_bytes_be(), group.key_len()))
}

fn modp_shared(group: DhGroup, scalar: &[u8], peer_pub: &[u8]) -> Result<Vec<u8>> {
    let hex = modp_prime_hex(group).ok_or(Error::UnsupportedDhGroup(group.to_u16()))?;
    let p = BigUint::parse_bytes(hex.as_bytes(), 16).ok_or(Error::Crypto("bad prime".into()))?;
    let a = BigUint::from_bytes_be(scalar);
    let b = BigUint::from_bytes_be(peer_pub);
    let s = num_integer::Integer::modpow(&b, &a, &p);
    let bytes = pad_be(&s.to_bytes_be(), group.key_len());
    if bytes.iter().all(|&x| x == 0) {
        return Err(Error::DhFailed);
    }
    Ok(bytes)
}

fn pad_be(bytes: &[u8], len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        bytes[bytes.len() - len..].to_vec()
    } else {
        let mut v = vec![0u8; len - bytes.len()];
        v.extend_from_slice(bytes);
        v
    }
}

// ---------------------------------------------------------------------------
// Curve25519 via orion
// ---------------------------------------------------------------------------

fn x25519_generate() -> Result<(Vec<u8>, Vec<u8>)> {
    use orion::hazardous::ecc::x25519::{PrivateKey, PublicKey};
    let sk = PrivateKey::generate().map_err(err)?;
    let pk = PublicKey::try_from(&sk).map_err(err)?;
    Ok((sk.unprotected_as_bytes().to_vec(), pk.as_bytes().to_vec()))
}

fn x25519_public(private: &[u8]) -> Result<Vec<u8>> {
    use orion::hazardous::ecc::x25519::{PrivateKey, PublicKey};
    let sk = PrivateKey::from_bytes(private).map_err(err)?;
    let pk = PublicKey::try_from(&sk).map_err(err)?;
    Ok(pk.as_bytes().to_vec())
}

fn x25519_shared(private: &[u8], peer_public: &[u8]) -> Result<Vec<u8>> {
    use orion::hazardous::ecc::x25519::{key_agreement, PrivateKey, PublicKey};
    let sk = PrivateKey::from_bytes(private).map_err(err)?;
    let pk = PublicKey::from_bytes(peer_public).map_err(err)?;
    let sh = key_agreement(&sk, &pk).map_err(err)?;
    Ok(sh.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate `n` cryptographically random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("secure RNG unavailable");
    buf
}
