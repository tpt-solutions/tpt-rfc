// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographic primitives for Kerberos v5 (RFC 3962, RFC 8009, RFC 4120 §8).
//!
//! This module implements the AES-based encryption types (the modern,
//! dual-licensed-friendly replacements for the legacy `des3-cbc-sha1` and
//! `arcfour` types):
//!
//! | etype | name                              | hash | key len |
//! |-------|-----------------------------------|------|---------|
//! | 17    | aes128-cts-hmac-sha1-96           | SHA1 | 16      |
//! | 18    | aes256-cts-hmac-sha1-96           | SHA1 | 32      |
//! | 19    | aes128-cts-hmac-sha256-128        | SHA256 | 16   |
//! | 20    | aes256-cts-hmac-sha384-192        | SHA384 | 32    |
//!
//! All building blocks (AES, HMAC, SHA) are reused from dual-licensed
//! RustCrypto crates; the Kerberos-specific glue (string2key, key derivation,
//! AES-CTS, checksum) is implemented clean-room from the RFC text.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};

use crate::error::{Error, Result};

/// AES block size in bytes.
const BLOCK: usize = 16;

/// A supported Kerberos encryption type descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enctype {
    pub etype: u32,
    /// `keylength` — base key / derived key length in bytes.
    pub keylen: usize,
    /// `hashlen` — the hash output length (n) in bytes.
    pub hashlen: usize,
    /// `cksumlen` — the stored checksum length in bytes.
    pub cksumlen: usize,
}

/// AES enctypes implemented in this crate.
pub const ENCTYPE_AES128_CTS_HMAC_SHA1_96: u32 = 17;
pub const ENCTYPE_AES256_CTS_HMAC_SHA1_96: u32 = 18;
pub const ENCTYPE_AES128_CTS_HMAC_SHA256_128: u32 = 19;
pub const ENCTYPE_AES256_CTS_HMAC_SHA384_192: u32 = 20;

impl Enctype {
    pub fn from_etype(etype: u32) -> Result<Self> {
        match etype {
            ENCTYPE_AES128_CTS_HMAC_SHA1_96 => Ok(Enctype {
                etype,
                keylen: 16,
                hashlen: 20,
                cksumlen: 12,
            }),
            ENCTYPE_AES256_CTS_HMAC_SHA1_96 => Ok(Enctype {
                etype,
                keylen: 32,
                hashlen: 20,
                cksumlen: 12,
            }),
            ENCTYPE_AES128_CTS_HMAC_SHA256_128 => Ok(Enctype {
                etype,
                keylen: 16,
                hashlen: 32,
                cksumlen: 16,
            }),
            ENCTYPE_AES256_CTS_HMAC_SHA384_192 => Ok(Enctype {
                etype,
                keylen: 32,
                hashlen: 48,
                cksumlen: 24,
            }),
            other => Err(Error::UnsupportedEnctype(other)),
        }
    }

    fn is_rfc8009(&self) -> bool {
        self.etype == ENCTYPE_AES128_CTS_HMAC_SHA256_128
            || self.etype == ENCTYPE_AES256_CTS_HMAC_SHA384_192
    }
}

// ---------------------------------------------------------------------------
// HMAC helpers (typed by hash)
// ---------------------------------------------------------------------------

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut buf = [0u8; 20];
    buf.copy_from_slice(&out);
    buf
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut buf = [0u8; 48];
    buf.copy_from_slice(&out);
    buf
}

/// Compute the HMAC for the enctype over `data` and return `cksumlen` bytes.
fn hmac_for(enct: &Enctype, key: &[u8], data: &[u8]) -> Vec<u8> {
    let full = match enct.etype {
        ENCTYPE_AES128_CTS_HMAC_SHA1_96 | ENCTYPE_AES256_CTS_HMAC_SHA1_96 => {
            hmac_sha1(key, data).to_vec()
        }
        ENCTYPE_AES128_CTS_HMAC_SHA256_128 => hmac_sha256(key, data).to_vec(),
        ENCTYPE_AES256_CTS_HMAC_SHA384_192 => hmac_sha384(key, data).to_vec(),
        _ => unreachable!(),
    };
    full[..enct.cksumlen].to_vec()
}

// ---------------------------------------------------------------------------
// string2key (RFC 3962 §4, PBKDF2 with the enctype hash as PRF)
// ---------------------------------------------------------------------------

/// Derive a raw protocol key from a password, salt, and iteration count.
///
/// Mirrors RFC 3962 §4: `tkey = PBKDF2-HMAC(password, salt, iterations, keylen)`,
/// then `random-to-key` (identity for AES).
pub fn string2key(
    etype: u32,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>> {
    let enct = Enctype::from_etype(etype)?;
    let k = enct.keylen;
    let key = pbkdf2(etype, password, salt, iterations, k);
    Ok(key)
}

/// Default iteration count for AES string2key (RFC 3962 §4 recommends 4096).
pub const DEFAULT_STRING2KEY_ITER: u32 = 4096;

/// PBKDF2 (RFC 8018) with HMAC-<H> as the PRF, producing `dklen` bytes.
fn pbkdf2(etype: u32, password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    match etype {
        ENCTYPE_AES128_CTS_HMAC_SHA1_96 | ENCTYPE_AES256_CTS_HMAC_SHA1_96 => {
            pbkdf2_with_hmac::<Hmac<Sha1>>(20, password, salt, iterations, dklen)
        }
        ENCTYPE_AES128_CTS_HMAC_SHA256_128 => {
            pbkdf2_with_hmac::<Hmac<Sha256>>(32, password, salt, iterations, dklen)
        }
        ENCTYPE_AES256_CTS_HMAC_SHA384_192 => {
            pbkdf2_with_hmac::<Hmac<Sha384>>(48, password, salt, iterations, dklen)
        }
        _ => Vec::new(),
    }
}

fn pbkdf2_with_hmac<M: Mac + KeyInit>(hlen: usize, password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    let mut out = vec![0u8; dklen];
    let blocks = (dklen + hlen - 1) / hlen;
    for i in 1..=blocks as u32 {
        let mut msg = salt.to_vec();
        msg.extend_from_slice(&i.to_be_bytes());
        let mut u = hmac_bytes::<M>(password, &msg);
        let mut t = u.clone();
        for _ in 1..iterations {
            u = hmac_bytes::<M>(password, &u);
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        let start = ((i as usize) - 1) * hlen;
        let end = ((i as usize) * hlen).min(dklen);
        out[start..end].copy_from_slice(&t[..end - start]);
    }
    out
}

fn hmac_bytes<M: Mac + KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <M as KeyInit>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Key derivation: DK / DR (RFC 3962 §6) and RFC 8009 KDF
// ---------------------------------------------------------------------------

/// `DR(key, constant, k)` — the "dense" random-to-key key-derivation step.
fn dr(enct: &Enctype, key: &[u8], constant: &[u8], k: usize) -> Vec<u8> {
    let mut blocks: Vec<u8> = Vec::with_capacity(k);
    // K_0 = HMAC(key, constant)
    let mut prev = match enct.etype {
        ENCTYPE_AES128_CTS_HMAC_SHA1_96 | ENCTYPE_AES256_CTS_HMAC_SHA1_96 => {
            hmac_sha1(key, constant).to_vec()
        }
        ENCTYPE_AES128_CTS_HMAC_SHA256_128 => hmac_sha256(key, constant).to_vec(),
        ENCTYPE_AES256_CTS_HMAC_SHA384_192 => hmac_sha384(key, constant).to_vec(),
        _ => unreachable!(),
    };
    blocks.extend_from_slice(&prev);
    while blocks.len() < k {
        prev = match enct.etype {
            ENCTYPE_AES128_CTS_HMAC_SHA1_96 | ENCTYPE_AES256_CTS_HMAC_SHA1_96 => {
                hmac_sha1(key, &prev).to_vec()
            }
            ENCTYPE_AES128_CTS_HMAC_SHA256_128 => hmac_sha256(key, &prev).to_vec(),
            ENCTYPE_AES256_CTS_HMAC_SHA384_192 => hmac_sha384(key, &prev).to_vec(),
            _ => unreachable!(),
        };
        blocks.extend_from_slice(&prev);
    }
    blocks[..k].to_vec()
}

/// `DK(base-key, constant)` — derive a key of `keylen` bytes (RFC 3962 §6).
/// For AES, `random-to-key` is the identity, so `DK = DR(key, constant, keylen)`.
fn dk(enct: &Enctype, base_key: &[u8], constant: &[u8]) -> Vec<u8> {
    dr(enct, base_key, constant, enct.keylen)
}

/// RFC 8009 KDF: `KDF-HMAC-SHA2(K, label, k)`.
///
/// `label` is the ASCII well-known constant; the PRF input is
/// `label || 0x00000001 || 0x00` (the 4-byte counter `1` then a 1-byte length-0
/// context), per RFC 8009 §3.
fn kdf_8009(enct: &Enctype, key: &[u8], label: &[u8], k: usize) -> Vec<u8> {
    let mut constant = label.to_vec();
    constant.extend_from_slice(&1u32.to_be_bytes());
    constant.push(0x00);
    dr(enct, key, &constant, k)
}

/// Derive the per-usage encryption and integrity keys for an enctype.
///
/// For RFC 3962 enctypes, `Ke = DK(K, usage||0xAA)`, `Ki = DK(K, usage||0x55)`.
/// For RFC 8009 enctypes, the keys are fixed per (K, enctype) and derived from
/// the well-known labels; the *usage* is instead folded into the HMAC input.
struct DerivedKeys {
    enc: Vec<u8>,
    integ: Vec<u8>,
    /// Whether the key usage must be included in the HMAC input (RFC 8009).
    usage_in_hmac: bool,
}

fn derive_keys(enct: &Enctype, base_key: &[u8], usage: u32) -> DerivedKeys {
    if enct.is_rfc8009() {
        let enc = kdf_8009(enct, base_key, b"kerberos-8009-KEY-ENCRYPT", enct.keylen);
        let integ = kdf_8009(enct, base_key, b"kerberos-8009-KEY-CKSUM", enct.keylen);
        DerivedKeys {
            enc,
            integ,
            usage_in_hmac: true,
        }
    } else {
        let mut c_enc = usage.to_be_bytes().to_vec();
        c_enc.push(0xAA);
        let mut c_int = usage.to_be_bytes().to_vec();
        c_int.push(0x55);
        let enc = dk(enct, base_key, &c_enc);
        let integ = dk(enct, base_key, &c_int);
        DerivedKeys {
            enc,
            integ,
            usage_in_hmac: false,
        }
    }
}

// ---------------------------------------------------------------------------
// AES-CTS (CBC ciphertext stealing) — RFC 3962 §5.3
// ---------------------------------------------------------------------------

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn aes_ecb_encrypt(enct: &Enctype, key: &[u8], block: &[u8]) -> [u8; BLOCK] {
    let b: [u8; BLOCK] = block.try_into().expect("block len");
    match enct.etype {
        ENCTYPE_AES128_CTS_HMAC_SHA1_96 | ENCTYPE_AES128_CTS_HMAC_SHA256_128 => {
            let cipher = Aes128::new(GenericArray::from_slice(key));
            let mut b = b;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));
            b
        }
        _ => {
            let cipher = Aes256::new(GenericArray::from_slice(key));
            let mut b = b;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));
            b
        }
    }
}

fn aes_ecb_decrypt(enct: &Enctype, key: &[u8], block: &[u8]) -> [u8; BLOCK] {
    let b: [u8; BLOCK] = block.try_into().expect("block len");
    match enct.etype {
        ENCTYPE_AES128_CTS_HMAC_SHA1_96 | ENCTYPE_AES128_CTS_HMAC_SHA256_128 => {
            let cipher = Aes128::new(GenericArray::from_slice(key));
            let mut b = b;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut b));
            b
        }
        _ => {
            let cipher = Aes256::new(GenericArray::from_slice(key));
            let mut b = b;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut b));
            b
        }
    }
}

/// Encrypt `pt` with AES-CTS (zero IV), returning ciphertext of equal length.
fn aes_cts_encrypt(enct: &Enctype, key: &[u8], pt: &[u8]) -> Vec<u8> {
    let l = pt.len();
    if l == 0 {
        return Vec::new();
    }
    if l <= BLOCK {
        let mut block = [0u8; BLOCK];
        block[..l].copy_from_slice(pt);
        let iv = [0u8; BLOCK];
        let x = xor_bytes(&block, &iv);
        let xb: [u8; BLOCK] = x.try_into().expect("block len");
        return aes_ecb_encrypt(enct, key, &xb).to_vec();
    }
    let n = (l + BLOCK - 1) / BLOCK; // number of blocks (last may be partial)
    let mut cbc = vec![0u8; n * BLOCK];
    let iv = [0u8; BLOCK];
    let mut prev = iv;
    for i in 0..(n - 1) {
        let mut p = [0u8; BLOCK];
        p.copy_from_slice(&pt[i * BLOCK..i * BLOCK + BLOCK]);
        let x = xor_bytes(&p, &prev);
        let c = aes_ecb_encrypt(enct, key, &x);
        cbc[i * BLOCK..i * BLOCK + BLOCK].copy_from_slice(&c);
        prev = c;
    }
    // prev = C_{n-1} (X in the spec)
    let lastlen = l - (n - 1) * BLOCK;
    // X_padded = X[0..B-lastlen] || P_n
    let mut xpadded = prev[..BLOCK - lastlen].to_vec();
    xpadded.extend_from_slice(&pt[(n - 1) * BLOCK..l]);
    let mut xblk = [0u8; BLOCK];
    xblk.copy_from_slice(&xpadded);
    let cn = aes_ecb_encrypt(enct, key, &xblk);
    // Output: C_1..C_{n-2}, C_n (full), X[0..lastlen]
    let mut out = Vec::with_capacity(l);
    out.extend_from_slice(&cbc[..(n - 1) * BLOCK]); // C_1..C_{n-2}
    out.extend_from_slice(&cn); // C_n (full block)
    out.extend_from_slice(&prev[..lastlen]); // X[0..lastlen]
    out
}

/// Decrypt AES-CTS ciphertext `ct` (length == plaintext length), zero IV.
fn aes_cts_decrypt(enct: &Enctype, key: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let l = ct.len();
    if l == 0 {
        return Ok(Vec::new());
    }
    if l <= BLOCK {
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(ct);
        let iv = [0u8; BLOCK];
        let p = aes_ecb_decrypt(enct, key, &block);
        return Ok(xor_bytes(&p, &iv)[..l].to_vec());
    }
    let n = (l + BLOCK - 1) / BLOCK;
    let lastlen = l - (n - 1) * BLOCK;
    // Recover X_full = D(C_n), whose head is X[0..B-lastlen] and tail is P_n.
    let mut cn_block = [0u8; BLOCK];
    cn_block.copy_from_slice(&ct[(n - 2) * BLOCK..(n - 1) * BLOCK]);
    let xfull = aes_ecb_decrypt(enct, key, &cn_block);
    // Reconstruct full X = X_full[0..B-lastlen] || (ct tail)
    let mut x = xfull[..BLOCK - lastlen].to_vec();
    x.extend_from_slice(&ct[(n - 1) * BLOCK..l]);
    // P_n = X_full[B-lastlen .. B]
    let p_n = xfull[BLOCK - lastlen..BLOCK].to_vec();
    // P_{n-1} = D(X) ^ C_{n-2}
    let mut xblk = [0u8; BLOCK];
    xblk.copy_from_slice(&x);
    let dx = aes_ecb_decrypt(enct, key, &xblk);
    let c_n2 = if n == 2 {
        [0u8; BLOCK]
    } else {
        let mut c = [0u8; BLOCK];
        c.copy_from_slice(&ct[..BLOCK]);
        c
    };
    let p_nm1 = xor_bytes(&dx, &c_n2);
    // CBC-decrypt C_1..C_{n-2} (all full blocks preceding C_n in `ct`)
    let mut pt = Vec::with_capacity(l);
    let mut prev = [0u8; BLOCK];
    for i in 0..(n - 2) {
        let mut c = [0u8; BLOCK];
        c.copy_from_slice(&ct[i * BLOCK..i * BLOCK + BLOCK]);
        let p = aes_ecb_decrypt(enct, key, &c);
        let ptext = xor_bytes(&p, &prev);
        pt.extend_from_slice(&ptext);
        prev = c;
    }
    // P_{n-1}
    pt.extend_from_slice(&p_nm1);
    // P_n (length lastlen)
    pt.extend_from_slice(&p_n);
    Ok(pt)
}

// ---------------------------------------------------------------------------
// High-level encrypt / decrypt / checksum (RFC 3962 §7, RFC 8009 §6)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with a base key and key-usage, appending the checksum.
///
/// Returns the `cipher` field of an `EncryptedData` (confounder || data), with
/// the MAC appended.
pub fn encrypt(enct: &Enctype, base_key: &[u8], usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let dk = derive_keys(enct, base_key, usage);
    // Confounder (one AES block) || data, zero-padded to block multiple.
    let mut buf = vec![0u8; BLOCK];
    getrandom(&mut buf)?;
    buf.extend_from_slice(plaintext);
    while buf.len() % BLOCK != 0 {
        buf.push(0);
    }
    let c = aes_cts_encrypt(enct, &dk.enc, &buf);
    // HMAC input: 0x0000 (kvno, unused) || [usage] || C  (usage only for RFC 8009)
    let mut hmac_input = vec![0x00, 0x00];
    if dk.usage_in_hmac {
        hmac_input.extend_from_slice(&usage.to_be_bytes());
    }
    hmac_input.extend_from_slice(&c);
    let h = hmac_for(enct, &dk.integ, &hmac_input);
    let mut out = c;
    out.extend_from_slice(&h);
    Ok(out)
}

/// Decrypt and verify an `EncryptedData.cipher` produced by [`encrypt`].
pub fn decrypt(enct: &Enctype, base_key: &[u8], usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
    if cipher.len() < enct.cksumlen + 1 {
        return Err(Error::DecryptFailed);
    }
    let split = cipher.len() - enct.cksumlen;
    let c = &cipher[..split];
    let expected = &cipher[split..];
    let dk = derive_keys(enct, base_key, usage);
    let mut hmac_input = vec![0x00, 0x00];
    if dk.usage_in_hmac {
        hmac_input.extend_from_slice(&usage.to_be_bytes());
    }
    hmac_input.extend_from_slice(c);
    let actual = hmac_for(enct, &dk.integ, &hmac_input);
    if !constant_time_eq(&actual, expected) {
        return Err(Error::ChecksumMismatch);
    }
    let pt = aes_cts_decrypt(enct, &dk.enc, c)?;
    // Strip the confounder (first block) and trailing zero padding.
    if pt.len() < BLOCK {
        return Err(Error::DecryptFailed);
    }
    let data = &pt[BLOCK..];
    let end = data.iter().rposition(|b| *b != 0).map(|i| i + 1).unwrap_or(0);
    Ok(data[..end].to_vec())
}

/// Compute a standalone checksum (used for `Checksum`/`GSSAPI-MIC`).
///
/// The RFC 3962/8009 checksum is `HMAC(Kc, 0x0000 [|| usage] || data)` where
/// `Kc` is derived from the key with the special usage `0x8003` (per RFC
/// 3961 §5.2.1.1 / the "checksum key" usage). We follow the same derivation as
/// [`encrypt`] but with the dedicated checksum-usage so that the resulting value
/// matches the standard `Kc` (usage `0x8003 << 0` with the 0x55 constant).
pub fn checksum(enct: &Enctype, base_key: &[u8], key_usage: u32, data: &[u8]) -> Result<Vec<u8>> {
    // The checksum key uses the "Kc" derivation: DK(K, 0x8003 || 0x55).
    let mut c = 0x8003u32.to_be_bytes().to_vec();
    c.push(0x55);
    let kc = if enct.is_rfc8009() {
        // RFC 8009 reuses the same fixed check-sum key label.
        kdf_8009(enct, base_key, b"kerberos-8009-KEY-CKSUM", enct.keylen)
    } else {
        dk(enct, base_key, &c)
    };
    let mut hmac_input = vec![0x00, 0x00];
    if enct.is_rfc8009() {
        hmac_input.extend_from_slice(&key_usage.to_be_bytes());
    }
    hmac_input.extend_from_slice(data);
    Ok(hmac_for(enct, &kc, &hmac_input))
}

fn getrandom(buf: &mut [u8]) -> Result<()> {
    ::getrandom::getrandom(buf).map_err(Error::from)
}

/// Constant-time equality for checksum / MIC verification.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
