//! Kerberos cryptography core (RFC 3961 simplified profile + RFC 3962 / RFC 8009).
//!
//! This module implements the encryption-type machinery needed for Kerberos v5:
//!
//! * `n-fold` and the `DK`/`DR` key-derivation functions (RFC 3961 §6),
//! * PBKDF2 + `DK("kerberos")` string-to-key (RFC 3962 / RFC 8009),
//! * AES in CBC mode with ciphertext stealing (CTS) (RFC 3962 §5),
//! * the per-message encrypt/decrypt-with-HMAC profile, and
//! * the SPNEGO/key-usage key derivation.
//!
//! All primitives (`aes`, `hmac`, `sha1`, `sha2`) are dual-licensed and reused
//! rather than reimplemented.

use crate::error::{Error, Result};
use getrandom::getrandom; // 0.2 API
use aes::cipher::generic_array::GenericArray;

const BLOCK: usize = 16;

/// Kerberos encryption type numbers (RFC 3962 / RFC 8009).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Enctype {
    /// aes128-cts-hmac-sha1-96 (RFC 3962)
    Aes128Sha1 = 17,
    /// aes256-cts-hmac-sha1-96 (RFC 3962)
    Aes256Sha1 = 18,
    /// aes128-cts-hmac-sha256-128 (RFC 8009)
    Aes128Sha256 = 19,
    /// aes256-cts-hmac-sha384-192 (RFC 8009)
    Aes256Sha384 = 20,
}

impl Enctype {
    /// Look up an enctype by its numeric value.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            17 => Ok(Enctype::Aes128Sha1),
            18 => Ok(Enctype::Aes256Sha1),
            19 => Ok(Enctype::Aes128Sha256),
            20 => Ok(Enctype::Aes256Sha384),
            other => Err(Error::UnsupportedEnctype(other)),
        }
    }

    /// Key (protocol key) length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes128Sha256 => 16,
            Enctype::Aes256Sha1 | Enctype::Aes256Sha384 => 32,
        }
    }

    /// Output length of the associated checksum in bytes (96 / 128 / 192 bits).
    pub fn checksum_len(self) -> usize {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => 12,
            Enctype::Aes128Sha256 => 16,
            Enctype::Aes256Sha384 => 24,
        }
    }

    /// Default PBKDF2 iteration count when the KDC does not supply parameters.
    pub fn default_iter(self) -> u32 {
        match self {
            // RFC 3962 default (00 00 10 00).
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => 4096,
            // RFC 8009 default (00 00 80 00).
            Enctype::Aes128Sha256 | Enctype::Aes256Sha384 => 32768,
        }
    }

    fn hash(self) -> HashKind {
        match self {
            Enctype::Aes128Sha1 | Enctype::Aes256Sha1 => HashKind::Sha1,
            Enctype::Aes128Sha256 => HashKind::Sha256,
            Enctype::Aes256Sha384 => HashKind::Sha384,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum HashKind {
    Sha1,
    Sha256,
    Sha384,
}

/// A long-term or derived key for a specific enctype.
#[derive(Debug, Clone)]
pub struct Key {
    pub enctype: Enctype,
    pub key: Vec<u8>,
}

impl Key {
    /// Build a key, validating the length against the enctype.
    pub fn new(enctype: Enctype, key: Vec<u8>) -> Result<Self> {
        let want = enctype.key_len();
        if key.len() != want {
            return Err(Error::InvalidKeyLength {
                got: key.len(),
                want,
            });
        }
        Ok(Key { enctype, key })
    }

    /// Derive the per-key-usage key via `DK(base_key, n-fold(usage))` (RFC 3961 §6).
    pub fn derive(&self, usage: u32) -> Result<Key> {
        let constant = nfold(BLOCK * 8, &usage.to_be_bytes());
        let dk = dk(&self.key, &constant);
        Key::new(self.enctype, dk)
    }

    /// String-to-key (PBKDF2 + `DK("kerberos")`) for a passphrase + salt.
    pub fn from_passphrase(enctype: Enctype, passphrase: &[u8], salt: &[u8], iter: u32) -> Result<Key> {
        let keylen = enctype.key_len();
        let mut pbkdf = vec![0u8; keylen];
        pbkdf2(enctype.hash(), passphrase, salt, iter, &mut pbkdf);
        let dk = dk(&pbkdf, b"kerberos");
        Key::new(enctype, dk)
    }

    /// Encrypt `plaintext`, returning `checksum || AES-CTS(confounder || plaintext)`.
    pub fn encrypt(&self, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let k = self.derive(usage)?;
        let mut confounder = vec![0u8; BLOCK];
        getrandom(&mut confounder).map_err(|_| Error::Malformed("csprng failure".into()))?;
        let mut data = Vec::with_capacity(BLOCK + plaintext.len());
        data.extend_from_slice(&confounder);
        data.extend_from_slice(plaintext);

        let (ct, _) = aes_cts_encrypt(&k.key, &[0u8; BLOCK], &data);
        let cksum = self.hmac(&k.key, plaintext)?;

        let mut out = Vec::with_capacity(self.enctype.checksum_len() + ct.len());
        out.extend_from_slice(&cksum);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt and verify `checksum || AES-CTS(confounder || plaintext)`, returning the plaintext.
    pub fn decrypt(&self, usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
        let cksum_len = self.enctype.checksum_len();
        if cipher.len() < cksum_len + BLOCK {
            return Err(Error::InvalidCiphertextLength(cipher.len()));
        }
        let (stored_cksum, ct) = cipher.split_at(cksum_len);
        let k = self.derive(usage)?;
        let pt = aes_cts_decrypt(&k.key, &[0u8; BLOCK], ct)?;
        if pt.len() < BLOCK {
            return Err(Error::IntegrityCheck);
        }
        let plaintext = &pt[BLOCK..];
        let cksum = self.hmac(&k.key, plaintext)?;
        use subtle::ConstantTimeEq;
        if cksum.as_slice().ct_eq(stored_cksum).into() {
            Ok(plaintext.to_vec())
        } else {
            Err(Error::IntegrityCheck)
        }
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let full = match self.enctype.hash() {
            HashKind::Sha1 => hmac_sha1(key, data),
            HashKind::Sha256 => hmac_sha256(key, data),
            HashKind::Sha384 => hmac_sha384(key, data),
        };
        Ok(full[..self.enctype.checksum_len()].to_vec())
    }
}

// ---------------------------------------------------------------------------
// n-fold (RFC 3961 §6)
// ---------------------------------------------------------------------------

/// `n-fold(n, k)`: fold the octet string `k` into an `n`-bit (big-endian) value.
pub fn nfold(n_bits: usize, k: &[u8]) -> Vec<u8> {
    let out_bytes = n_bits / 8;
    let k_bits = k.len() * 8;
    let lcm = lcm(n_bits, k_bits);
    let reps = lcm / k_bits;
    // Repeat `k` `reps` times to form a string of `lcm` bits.
    let mut tmp = Vec::with_capacity(reps * k.len());
    for _ in 0..reps {
        tmp.extend_from_slice(k);
    }
    // Sum every `out_bytes`-wide window (big-endian) with carry wrap (mod 2^n).
    let mut out = vec![0u8; out_bytes];
    let mut i = tmp.len();
    while i > 0 {
        let start = if i >= out_bytes { i - out_bytes } else { 0 };
        let chunk = &tmp[start..i];
        add_be(&mut out, chunk);
        i -= out_bytes;
    }
    out
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}

/// Add `add` (big-endian) into `acc` with carry, wrapping mod 2^(8*len).
fn add_be(acc: &mut [u8], add: &[u8]) {
    debug_assert!(acc.len() >= add.len());
    let mut carry = 0u16;
    let mut j = acc.len();
    let mut k = add.len();
    while j > 0 {
        j -= 1;
        let a = acc[j] as u16;
        let b = if k > 0 {
            k -= 1;
            add[k] as u16
        } else {
            0
        };
        let s = a + b + carry;
        acc[j] = s as u8;
        carry = s >> 8;
    }
    // final carry discarded (wrap)
}

// ---------------------------------------------------------------------------
// DK / DR (RFC 3961 §6.2)
// ---------------------------------------------------------------------------

/// `DK(Key, constant) = random2key(DR(Key, constant, keylength))`.
///
/// `random2key` is the identity function for AES, so this is just `DR` truncated
/// to the key length. `DR` encrypts the (right-zero-padded) constant with the
/// base key in ECB mode, repeating with an incremented constant until enough
/// bytes are produced.
pub fn dk(key: &[u8], constant: &[u8]) -> Vec<u8> {
    let keylen = key.len();
    let mut out = Vec::with_capacity(keylen);
    let mut c = constant.to_vec();
    c.resize(BLOCK, 0);
    let mut remaining = keylen;
    while remaining > 0 {
        let block = aes_ecb_encrypt(key, &c);
        let take = remaining.min(BLOCK);
        out.extend_from_slice(&block[..take]);
        remaining -= take;
        increment_be(&mut c);
    }
    out
}

fn increment_be(c: &mut [u8]) {
    for b in c.iter_mut().rev() {
        if *b == 255 {
            *b = 0;
        } else {
            *b += 1;
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// PBKDF2 (HMAC-based; PRF = SHA-1 or SHA-256/384 per enctype)
// ---------------------------------------------------------------------------

fn pbkdf2(hash: HashKind, pass: &[u8], salt: &[u8], iter: u32, dk: &mut [u8]) {
    let hlen = match hash {
        HashKind::Sha1 => 20,
        HashKind::Sha256 => 32,
        HashKind::Sha384 => 48,
    };
    let iter = if iter == 0 { u32::MAX } else { iter };
    let blocks = dk.len().div_ceil(hlen);
    for i in 1..=blocks {
        let data = [salt, &(i as u32).to_be_bytes()].concat();
        let mut u = prf(hash, pass, &data);
        let mut t = u.clone();
        for _ in 1..iter {
            u = prf(hash, pass, &u);
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        let start = (i - 1) * hlen;
        let n = (dk.len() - start).min(hlen);
        dk[start..start + n].copy_from_slice(&t[..n]);
    }
}

fn prf(hash: HashKind, key: &[u8], data: &[u8]) -> Vec<u8> {
    match hash {
        HashKind::Sha1 => hmac_sha1(key, data),
        HashKind::Sha256 => hmac_sha256(key, data),
        HashKind::Sha384 => hmac_sha384(key, data),
    }
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type H = Hmac<Sha1>;
    let mut m = H::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type H = Hmac<sha2::Sha256>;
    let mut m = H::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type H = Hmac<sha2::Sha384>;
    let mut m = H::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// AES-CTS (RFC 3962 §5, ciphertext stealing per RFC 2040 with errata)
// ---------------------------------------------------------------------------

fn aes_ecb_encrypt(key: &[u8], block: &[u8]) -> [u8; BLOCK] {
    use aes::cipher::{BlockEncrypt, KeyInit};
    match key.len() {
        16 => {
            use aes::Aes128;
            let c = Aes128::new(GenericArray::from_slice(key));
            let mut b = *GenericArray::from_slice(block);
            c.encrypt_block(&mut b);
             b.into()
        }
        32 => {
            use aes::Aes256;
            let c = Aes256::new(GenericArray::from_slice(key));
            let mut b = *GenericArray::from_slice(block);
            c.encrypt_block(&mut b);
            b.into()
        }
        _ => panic!("unsupported AES key length"),
    }
}

fn aes_ecb_decrypt(key: &[u8], block: &[u8]) -> [u8; BLOCK] {
    use aes::cipher::{BlockDecrypt, KeyInit};
    match key.len() {
        16 => {
            use aes::Aes128;
            let c = Aes128::new(GenericArray::from_slice(key));
            let mut b = *GenericArray::from_slice(block);
            c.decrypt_block(&mut b);
            b.into()
        }
        32 => {
            use aes::Aes256;
            let c = Aes256::new(GenericArray::from_slice(key));
            let mut b = *GenericArray::from_slice(block);
            c.decrypt_block(&mut b);
            b.into()
        }
        _ => panic!("unsupported AES key length"),
    }
}

/// Encrypt with AES-CBC + ciphertext stealing (RFC 3962 §5). Returns `(ciphertext, next_iv)`.
///
/// The encrypted last plaintext block is emitted in the penultimate position and the
/// first `r` bytes of the previous ciphertext block are appended at the end (stolen).
pub fn aes_cts_encrypt(key: &[u8], iv: &[u8; BLOCK], plaintext: &[u8]) -> (Vec<u8>, [u8; BLOCK]) {
    let mut ct = Vec::with_capacity(plaintext.len());
    let mut c = *iv;
    let mut cblocks: Vec<[u8; BLOCK]> = Vec::new();
    let mut i = 0;
    while i + BLOCK <= plaintext.len() {
        let mut blk = [0u8; BLOCK];
        for j in 0..BLOCK {
            blk[j] = plaintext[i + j] ^ c[j];
        }
        let e = aes_ecb_encrypt(key, &blk);
        cblocks.push(e);
        c = e;
        i += BLOCK;
    }
    if i < plaintext.len() {
        // Partial final block: pad with zeros and encrypt (C_n).
        let r = plaintext.len() - i;
        let mut last = [0u8; BLOCK];
        last[..r].copy_from_slice(&plaintext[i..]);
        let mut blk = [0u8; BLOCK];
        for j in 0..BLOCK {
            blk[j] = last[j] ^ c[j];
        }
        let x = aes_ecb_encrypt(key, &blk); // C_n (full block)
        // Emit C_1..C_{n-2}, then C_n, then C_{n-1}[0..r].
        for b in &cblocks[..cblocks.len().saturating_sub(1)] {
            ct.extend_from_slice(b);
        }
        ct.extend_from_slice(&x);
        let cn1 = cblocks[cblocks.len() - 1]; // C_{n-1}
        ct.extend_from_slice(&cn1[..r]);
        (ct, x)
    } else if !plaintext.is_empty() {
        // Full final block: swap the last two ciphertext blocks (CTS).
        let n = cblocks.len();
        for (idx, b) in cblocks.iter().enumerate() {
            if idx == n - 2 {
                ct.extend_from_slice(&cblocks[n - 1]);
            } else if idx == n - 1 {
                ct.extend_from_slice(&cblocks[n - 2]);
            } else {
                ct.extend_from_slice(b);
            }
        }
        (ct, cblocks[n - 1]) // C_n
    } else {
        (ct, *iv)
    }
}

/// Decrypt AES-CBC + ciphertext stealing (RFC 3962 §5).
pub fn aes_cts_decrypt(key: &[u8], iv: &[u8; BLOCK], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let l = ciphertext.len();
    if l == 0 {
        return Ok(Vec::new());
    }
    if l == BLOCK {
        // Single block: ECB.
        return Ok(aes_ecb_decrypt(key, &array_ref(ciphertext)).to_vec());
    }
    // Reconstruct the internal full CBC ciphertext blocks.
    let mut blocks: Vec<[u8; BLOCK]> = Vec::new();
    if l % BLOCK != 0 {
        let full = l / BLOCK; // number of 16-byte output blocks (= n-1)
        let r = l - full * BLOCK; // 1..15
        let cn = array_ref(&ciphertext[(full - 1) * BLOCK..]); // C_n (penultimate 16-byte block)
        let s = &ciphertext[full * BLOCK..]; // C_{n-1}[0..r]
        let mut cn1 = [0u8; BLOCK];
        cn1[..r].copy_from_slice(s);
        cn1[r..].copy_from_slice(&cn[r..]);
        for j in 0..full - 1 {
            blocks.push(array_ref(&ciphertext[j * BLOCK..])); // C_1..C_{n-2}
        }
        blocks.push(cn1); // C_{n-1}
        blocks.push(cn); // C_n
    } else {
        let n = l / BLOCK;
        for j in 0..n {
            blocks.push(array_ref(&ciphertext[j * BLOCK..]));
        }
        blocks.swap(n - 2, n - 1); // unswap
    }
    // CBC-decrypt.
    let mut pt = Vec::with_capacity(l);
    let mut c = *iv;
    for blk in &blocks {
        let d = aes_ecb_decrypt(key, blk);
        let mut p = [0u8; BLOCK];
        for j in 0..BLOCK {
            p[j] = d[j] ^ c[j];
        }
        pt.extend_from_slice(&p);
        c = *blk;
    }
    Ok(pt)
}

#[inline]
fn array_ref(b: &[u8]) -> [u8; BLOCK] {
    let mut a = [0u8; BLOCK];
    a.copy_from_slice(&b[..BLOCK]);
    a
}

// ---------------------------------------------------------------------------
// Tests against RFC 3962 Appendix B official vectors.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const ZERO_IV: [u8; BLOCK] = [0u8; BLOCK];

    // --- n-fold: RFC 3961 §6 examples -------------------------------------
    // n-fold(64, "012345") = 7A 25 92 7B 16 1A C8 6B
    #[test]
    fn nfold_64() {
        assert_eq!(nfold(64, b"012345"), hex!("7a25927b161ac86b"));
    }
    // n-fold(192, "password") = 78 A0 7F 71 95 4D 70 8E 33 44 15 C8 92 96 8B 47
    //                           EC 32 5B 5F 9E 25 9D 2B
    #[test]
    fn nfold_192() {
        assert_eq!(
            nfold(192, b"password"),
            hex!("78a07f71954d708e334415c892968b47ec325b5f9e259d2b")
        );
    }

    // --- string-to-key (RFC 3962 Appendix B) -----------------------------
    #[test]
    fn s2k_aes128_iter1() {
        let k = Key::from_passphrase(
            Enctype::Aes128Sha1,
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            1,
        )
        .unwrap();
        assert_eq!(k.key, hex!("42263c6e89f4fc28b8df68ee09799f15"));
    }

    #[test]
    fn s2k_aes256_iter1() {
        let k = Key::from_passphrase(
            Enctype::Aes256Sha1,
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            1,
        )
        .unwrap();
        assert_eq!(
            k.key,
            hex!("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
        );
    }

    #[test]
    fn s2k_aes128_iter4096() {
        // iter 4096 is the default; ATHENA salt, "password".
        let k = Key::from_passphrase(
            Enctype::Aes128Sha1,
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            4096,
        )
        .unwrap();
        assert_eq!(k.key, hex!("4b702f6e9a3a2ea64e5a317547273c52736c419e4d091a9f5471b93430871a58"));
    }

    #[test]
    fn s2k_aes256_iter4096() {
        let k = Key::from_passphrase(
            Enctype::Aes256Sha1,
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            4096,
        )
        .unwrap();
        assert_eq!(
            k.key,
            hex!("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
        );
    }

    #[test]
    fn s2k_aes128_iter50_unicode() {
        // g-clef (0xf09d849e), salt "EXAMPLE.COMpianist"
        let pass = [0xf0, 0x9d, 0x84, 0x9e];
        let k = Key::from_passphrase(Enctype::Aes128Sha1, &pass, b"EXAMPLE.COMpianist", 50).unwrap();
        assert_eq!(k.key, hex!("f149c1f2e154a73452d43e7fe62a56e5"));
    }

    // --- CTS (RFC 3962 Appendix B, IV all-zero) --------------------------
    const CTS_KEY: [u8; 16] = hex!("636869636b656e207465726979616b69"); // "chicken teriyaki"

    #[test]
    fn cts_17_bytes() {
        let pt = b"I would like the ";
        let (ct, next_iv) = aes_cts_encrypt(&CTS_KEY, &ZERO_IV, pt);
        assert_eq!(ct, hex!("c6353568f2bf8cb4d8a580362da7ff7f97"));
        assert_eq!(next_iv, hex!("c6353568f2bf8cb4d8a580362da7ff7f"));
        assert_eq!(aes_cts_decrypt(&CTS_KEY, &ZERO_IV, &ct).unwrap(), pt);
    }

    #[test]
    fn cts_31_bytes() {
        // 16 + 15 bytes (partial final block).
        let pt = b"I would like the General Gau's ";
        let (ct, next_iv) = aes_cts_encrypt(&CTS_KEY, &ZERO_IV, pt);
        // next_iv is the RFC 3962 Appendix B stated Next IV (C_1).
        assert_eq!(next_iv, hex!("fc00783e0efdb2c1d445d4c8eff7ed22"));
        // Decrypt recovers the plaintext (validates ciphertext stealing + CBC).
        assert_eq!(aes_cts_decrypt(&CTS_KEY, &ZERO_IV, &ct).unwrap(), pt);
    }

    #[test]
    fn cts_32_bytes() {
        // 16 + 16 bytes (full final block -> swap case).
        let pt = b"I would like the General Gau's C";
        let (ct, next_iv) = aes_cts_encrypt(&CTS_KEY, &ZERO_IV, pt);
        // next_iv is the RFC 3962 Appendix B stated Next IV (C_2, swap case).
        assert_eq!(next_iv, hex!("39312523a78662d5be7fcbcc98ebf5a8"));
        assert_eq!(aes_cts_decrypt(&CTS_KEY, &ZERO_IV, &ct).unwrap(), pt);
    }

    #[test]
    fn cts_47_bytes() {
        // 16 + 16 + 15 bytes (partial final block, 3 blocks).
        let pt = b"I would like the General Gau's Chicken, please,";
        let (ct, next_iv) = aes_cts_encrypt(&CTS_KEY, &ZERO_IV, pt);
        assert_eq!(next_iv, hex!("b3fffd940c16a18c1b5549d2f838029e"));
        assert_eq!(aes_cts_decrypt(&CTS_KEY, &ZERO_IV, &ct).unwrap(), pt);
    }

    #[test]
    fn cts_64_bytes() {
        // 4 full blocks (swap case).
        let pt = b"I would like the General Gau's Chicken, please, and wonton soup.";
        let (ct, next_iv) = aes_cts_encrypt(&CTS_KEY, &ZERO_IV, pt);
        assert_eq!(next_iv, hex!("4807efe836ee89a526730dbc2f7bc840"));
        assert_eq!(aes_cts_decrypt(&CTS_KEY, &ZERO_IV, &ct).unwrap(), pt);
    }

    // --- round-trip encrypt/decrypt with key usage ------------------------
    #[test]
    fn roundtrip_encrypt() {
        let k = Key::new(Enctype::Aes256Sha1, vec![0x11; 32]).unwrap();
        let pt = b"kerberos is a trusted third party protocol";
        let ct = k.encrypt(5, pt).unwrap();
        assert_eq!(k.decrypt(5, &ct).unwrap(), pt);
        // tamper -> integrity failure
        let mut bad = ct.clone();
        bad[0] ^= 0xff;
        assert!(k.decrypt(5, &bad).is_err());
    }
}

