//! Cryptographic primitives for CMS: hashing, content encryption (AES-CBC),
//! AES key wrap (RFC 3394), ECDH key derivation (RFC 5753), and signing /
//! verification key handling built on dual-licensed RustCrypto primitives.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha2_010::{Sha256 as Sha256_010, Sha384 as Sha384_010, Sha512 as Sha512_010};

use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire;

// ===========================================================================
// Digest algorithms
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn oid(&self) -> ObjectIdentifier {
        oids::oid(match self {
            HashAlgorithm::Sha256 => oids::SHA256,
            HashAlgorithm::Sha384 => oids::SHA384,
            HashAlgorithm::Sha512 => oids::SHA512,
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        let s = oid.to_string();
        match s.as_str() {
            oids::SHA256 => Ok(HashAlgorithm::Sha256),
            oids::SHA384 => Ok(HashAlgorithm::Sha384),
            oids::SHA512 => Ok(HashAlgorithm::Sha512),
            _ => Err(CmsError::UnsupportedHash(s)),
        }
    }

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

// ===========================================================================
// Content-encryption algorithms (AES-CBC, RFC 3565)
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentEncryption {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

impl ContentEncryption {
    pub fn oid(&self) -> ObjectIdentifier {
        oids::oid(match self {
            ContentEncryption::Aes128Cbc => oids::AES128_CBC,
            ContentEncryption::Aes192Cbc => oids::AES192_CBC,
            ContentEncryption::Aes256Cbc => oids::AES256_CBC,
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        let s = oid.to_string();
        match s.as_str() {
            oids::AES128_CBC => Ok(ContentEncryption::Aes128Cbc),
            oids::AES192_CBC => Ok(ContentEncryption::Aes192Cbc),
            oids::AES256_CBC => Ok(ContentEncryption::Aes256Cbc),
            _ => Err(CmsError::UnsupportedContentEncryption(s)),
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            ContentEncryption::Aes128Cbc => 16,
            ContentEncryption::Aes192Cbc => 24,
            ContentEncryption::Aes256Cbc => 32,
        }
    }

    pub fn iv_size(&self) -> usize {
        16
    }

    pub fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
        use block_padding::Pkcs7;
        use cbc::{Decryptor, Encryptor};
        match self {
            ContentEncryption::Aes128Cbc => {
                let enc = Encryptor::<aes::Aes128>::new(key.into(), iv.into());
                Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
            }
            ContentEncryption::Aes192Cbc => {
                let enc = Encryptor::<aes::Aes192>::new(key.into(), iv.into());
                Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
            }
            ContentEncryption::Aes256Cbc => {
                let enc = Encryptor::<aes::Aes256>::new(key.into(), iv.into());
                Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
            }
        }
    }

    pub fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
        use block_padding::Pkcs7;
        use cbc::{Decryptor, Encryptor};
        let pt = match self {
            ContentEncryption::Aes128Cbc => {
                let dec = Decryptor::<aes::Aes128>::new(key.into(), iv.into());
                dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            }
            ContentEncryption::Aes192Cbc => {
                let dec = Decryptor::<aes::Aes192>::new(key.into(), iv.into());
                dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            }
            ContentEncryption::Aes256Cbc => {
                let dec = Decryptor::<aes::Aes256>::new(key.into(), iv.into());
                dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            }
        };
        pt.map_err(|e| CmsError::Crypto(format!("AES-CBC decrypt failed: {e}")))
    }
}

// ===========================================================================
// Key-wrap algorithms (AES Key Wrap, RFC 3394) and the wrap primitive
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyWrap {
    Aes128Wrap,
    Aes192Wrap,
    Aes256Wrap,
}

impl KeyWrap {
    pub fn oid(&self) -> ObjectIdentifier {
        oids::oid(match self {
            KeyWrap::Aes128Wrap => oids::AES128_WRAP,
            KeyWrap::Aes192Wrap => oids::AES192_WRAP,
            KeyWrap::Aes256Wrap => oids::AES256_WRAP,
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        let s = oid.to_string();
        match s.as_str() {
            oids::AES128_WRAP => Ok(KeyWrap::Aes128Wrap),
            oids::AES192_WRAP => Ok(KeyWrap::Aes192Wrap),
            oids::AES256_WRAP => Ok(KeyWrap::Aes256Wrap),
            _ => Err(CmsError::UnsupportedKeyWrap(s)),
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            KeyWrap::Aes128Wrap => 16,
            KeyWrap::Aes192Wrap => 24,
            KeyWrap::Aes256Wrap => 32,
        }
    }

    /// AlgorithmIdentifier DER (no parameters) for this key-wrap algorithm.
    pub fn algorithm_id(&self) -> Vec<u8> {
        wire::algorithm_identifier(&self.oid(), None)
    }
}

/// RFC 3394 AES key wrap. `kek` length selects AES-128/192/256.
pub(crate) fn aes_key_wrap(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() % 8 != 0 || plaintext.is_empty() {
        return Err(CmsError::Crypto(
            "key wrap input must be a multiple of 8 bytes".into(),
        ));
    }
    let n = plaintext.len() / 8;
    let mut r: Vec<[u8; 8]> = Vec::with_capacity(n);
    let mut a = [0xA6u8; 8];
    a[1] = 0xA6;
    a[2] = 0xA6;
    a[3] = 0xA6;
    a[4] = 0xA6;
    a[5] = 0xA6;
    a[6] = 0xA6;
    a[7] = 0xA6;
    for i in 0..n {
        let mut block = [0u8; 8];
        block.copy_from_slice(&plaintext[i * 8..i * 8 + 8]);
        r.push(block);
    }
    for j in 0..6u64 {
        for i in 0..n {
            let mut in_block = [0u8; 16];
            in_block[..8].copy_from_slice(&a);
            in_block[8..].copy_from_slice(&r[i]);
            let out = aes_block(kek, &in_block)?;
            let t = (n as u64) * j + (i as u64) + 1;
            let t_bytes = t.to_be_bytes();
            let mut new_a = [0u8; 8];
            new_a.copy_from_slice(&out[..8]);
            for (k, b) in t_bytes.iter().enumerate() {
                new_a[k] ^= b;
            }
            a = new_a;
            let mut new_r = [0u8; 8];
            new_r.copy_from_slice(&out[8..]);
            r[i] = new_r;
        }
    }
    let mut out = Vec::with_capacity(8 + n * 8);
    out.extend_from_slice(&a);
    for block in &r {
        out.extend_from_slice(block);
    }
    Ok(out)
}

/// RFC 3394 AES key unwrap.
pub(crate) fn aes_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 16 || wrapped.len() % 8 != 0 {
        return Err(CmsError::Crypto("invalid key wrap length".into()));
    }
    let n = wrapped.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut r: Vec<[u8; 8]> = Vec::with_capacity(n);
    for i in 0..n {
        let mut block = [0u8; 8];
        block.copy_from_slice(&wrapped[8 + i * 8..8 + i * 8 + 8]);
        r.push(block);
    }
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64) + 1;
            let t_bytes = t.to_be_bytes();
            let mut a_xor = [0u8; 8];
            for (k, b) in t_bytes.iter().enumerate() {
                a_xor[k] = a[k] ^ b;
            }
            let mut in_block = [0u8; 16];
            in_block[..8].copy_from_slice(&a_xor);
            in_block[8..].copy_from_slice(&r[i]);
            let out = aes_block_decrypt(kek, &in_block)?;
            a.copy_from_slice(&out[..8]);
            let mut new_r = [0u8; 8];
            new_r.copy_from_slice(&out[8..]);
            r[i] = new_r;
        }
    }
    let expected = [0xA6u8, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    if a != expected {
        return Err(CmsError::KeyUnwrap);
    }
    let mut out = Vec::with_capacity(n * 8);
    for block in &r {
        out.extend_from_slice(block);
    }
    Ok(out)
}

fn aes_block(kek: &[u8], block: &[u8; 16]) -> Result<[u8; 16]> {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    let mut buf = GenericArray::clone_from_slice(block);
    match kek.len() {
        16 => aes::Aes128::new(GenericArray::from_slice(kek)).encrypt_block(&mut buf),
        24 => aes::Aes192::new(GenericArray::from_slice(kek)).encrypt_block(&mut buf),
        32 => aes::Aes256::new(GenericArray::from_slice(kek)).encrypt_block(&mut buf),
        _ => return Err(CmsError::Crypto("invalid KEK length".into())),
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(&buf);
    Ok(out)
}

fn aes_block_decrypt(kek: &[u8], block: &[u8; 16]) -> Result<[u8; 16]> {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    let mut buf = GenericArray::clone_from_slice(block);
    match kek.len() {
        16 => aes::Aes128::new(GenericArray::from_slice(kek)).decrypt_block(&mut buf),
        24 => aes::Aes192::new(GenericArray::from_slice(kek)).decrypt_block(&mut buf),
        32 => aes::Aes256::new(GenericArray::from_slice(kek)).decrypt_block(&mut buf),
        _ => return Err(CmsError::Crypto("invalid KEK length".into())),
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(&buf);
    Ok(out)
}

// ===========================================================================
// ECDH key derivation (RFC 5753 CMS DH KDF)
// ===========================================================================

/// CMS single-step KDF (NIST SP 800-56A / RFC 5753) used to derive the
/// key-encryption key (KEK) from the ECDH shared secret `zz`.
pub(crate) fn cms_ecdh_kdf(
    hash: HashAlgorithm,
    zz: &[u8],
    key_wrap_alg_der: &[u8],
    ukm: &[u8],
    key_bits: u32,
) -> Result<Vec<u8>> {
    // ECC-CMS-SharedInfo ::= SEQUENCE {
    //   keyInfo      AlgorithmIdentifier,
    //   entityUInfo  [0] EXPLICIT OCTET STRING OPTIONAL,
    //   suppPubInfo  [2] EXPLICIT OCTET STRING }   -- contains KeyLength INTEGER
    let key_len_int = wire::integer_u64(key_bits as u64);
    let supp_pub_info = wire::ctx(2, &wire::octet_string(&key_len_int));
    let entity_u = if ukm.is_empty() {
        Vec::new()
    } else {
        wire::ctx(0, &wire::octet_string(ukm))
    };
    let other_info = wire::sequence(&[key_wrap_alg_der.to_vec(), entity_u, supp_pub_info]);

    let key_bytes = (key_bits / 8) as usize;
    let mut out = Vec::with_capacity(key_bytes);
    let mut counter: u32 = 1;
    while out.len() < key_bytes {
        let digest = match hash {
            HashAlgorithm::Sha256 => {
                let mut h = Sha256::new();
                h.update(zz);
                h.update(counter.to_be_bytes());
                h.update(&other_info);
                h.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut h = Sha384::new();
                h.update(zz);
                h.update(counter.to_be_bytes());
                h.update(&other_info);
                h.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut h = Sha512::new();
                h.update(zz);
                h.update(counter.to_be_bytes());
                h.update(&other_info);
                h.finalize().to_vec()
            }
        };
        out.extend_from_slice(&digest);
        counter += 1;
    }
    out.truncate(key_bytes);
    Ok(out)
}

// ===========================================================================
// Signing / verification key abstractions
// ===========================================================================

use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p384::ecdsa::signature::hazmat::{PrehashSigner as _, PrehashVerifier as _};
use rsa::RsaPublicKey as RsaPub;
use rsa::pkcs1v15::{Pkcs1v15Encrypt, Pkcs1v15Sign};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

/// A private signing key usable for SignedData.
#[derive(Clone)]
pub enum SigningKey {
    EcdsaP256(P256SigningKey),
    EcdsaP384(P384SigningKey),
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_compact::SecretKey),
}

/// A public key extracted from a certificate's `SubjectPublicKeyInfo`.
pub(crate) enum PublicKey {
    Rsa(RsaPublicKey),
    EcdsaP256(P256VerifyingKey),
    EcdsaP384(P384VerifyingKey),
    Ed25519(ed25519_compact::PublicKey),
}

impl SigningKey {
    /// Sign `digest` (the hash of the SignedAttributes SET, or the message for
    /// Ed25519) returning the signature algorithm OID and the raw signature.
    pub fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
        match self {
            SigningKey::EcdsaP256(key) => {
                if hash != HashAlgorithm::Sha256 {
                    return Err(CmsError::Crypto(
                        "ECDSA P-256 must be used with SHA-256".into(),
                    ));
                }
                let sig: P256Signature = key
                    .sign_prehash(digest)
                    .map_err(|e| CmsError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA256), sig.to_vec()))
            }
            SigningKey::EcdsaP384(key) => {
                if hash != HashAlgorithm::Sha384 {
                    return Err(CmsError::Crypto(
                        "ECDSA P-384 must be used with SHA-384".into(),
                    ));
                }
                let sig: P384Signature = key
                    .sign_prehash(digest)
                    .map_err(|e| CmsError::Crypto(e.to_string()))?;
                Ok((oids::oid(oids::ECDSA_SHA384), sig.to_vec()))
            }
            SigningKey::Rsa(key) => {
                let padding = match hash {
                    HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256_010>(),
                    HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384_010>(),
                    HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512_010>(),
                };
                let sig = key
                    .sign(padding, digest)
                    .map_err(|e| CmsError::Crypto(e.to_string()))?;
                let oid = match hash {
                    HashAlgorithm::Sha256 => oids::SHA256_RSA,
                    HashAlgorithm::Sha384 => oids::SHA384_RSA,
                    HashAlgorithm::Sha512 => oids::SHA512_RSA,
                };
                Ok((oids::oid(oid), sig))
            }
            SigningKey::Ed25519(key) => {
                let sig = key.sign(digest, None);
                Ok((oids::oid(oids::ED25519), sig.to_vec()))
            }
        }
    }

    /// Demo P-256 key from a fixed seed (tests/examples only).
    pub fn demo_p256(seed: [u8; 32]) -> SigningKey {
        SigningKey::EcdsaP256(P256SigningKey::from_bytes((&seed).into()).unwrap())
    }

    /// Demo P-384 key from a fixed seed (tests/examples only).
    pub fn demo_p384(seed: [u8; 48]) -> SigningKey {
        SigningKey::EcdsaP384(P384SigningKey::from_bytes((&seed).into()).unwrap())
    }

    /// Demo RSA-2048 key (tests/examples only).
    pub fn demo_rsa(rng: &mut impl rand_core::CryptoRngCore) -> SigningKey {
        SigningKey::Rsa(RsaPrivateKey::new(rng, 2048).unwrap())
    }

    /// Demo Ed25519 key from a fixed seed (tests/examples only).
    pub fn demo_ed25519(seed: [u8; 32]) -> SigningKey {
        SigningKey::Ed25519(ed25519_compact::SecretKey::from_slice(&seed).unwrap())
    }
}

/// Extract the public key from an `x509_cert` SubjectPublicKeyInfo.
pub(crate) fn public_key_from_spki(
    spki: &spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString>,
) -> Result<PublicKey> {
    let alg = spki.algorithm.oid.to_string();
    let params_der = spki.algorithm.parameters.as_ref().map(|p| p.value().to_vec());
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CmsError::Crypto("missing subject public key".into()))?;
    match alg.as_str() {
        oids::RSA_ENCRYPTION => {
            let spki_der = spki
                .to_der()
                .map_err(|e| CmsError::Crypto(format!("spki der: {e}")))?;
            let pubkey = RsaPub::from_public_key_der(&spki_der)
                .map_err(|e| CmsError::Crypto(format!("RSA pubkey: {e}")))?;
            Ok(PublicKey::Rsa(pubkey))
        }
        oids::EC_PUBLIC_KEY => {
            let curve =
                params_der.ok_or_else(|| CmsError::Crypto("EC key missing curve OID".into()))?;
            let full = wire::tlv(0x06, &curve);
            let curve_oid: ObjectIdentifier = ObjectIdentifier::from_der(&full)
                .map_err(|e| CmsError::Crypto(format!("EC curve OID: {e}")))?;
            match curve_oid.to_string().as_str() {
                oids::P256 => {
                    let pk = p256::PublicKey::from_sec1_bytes(key_bytes)
                        .map_err(|e| CmsError::Crypto(format!("P-256 pubkey: {e}")))?;
                    Ok(PublicKey::EcdsaP256(pk.into()))
                }
                oids::P384 => {
                    let pk = p384::PublicKey::from_sec1_bytes(key_bytes)
                        .map_err(|e| CmsError::Crypto(format!("P-384 pubkey: {e}")))?;
                    Ok(PublicKey::EcdsaP384(pk.into()))
                }
                other => Err(CmsError::UnsupportedCurve(other.into())),
            }
        }
        oids::ED25519 => {
            let pk = ed25519_compact::PublicKey::from_slice(key_bytes)
                .map_err(|e| CmsError::Crypto(format!("Ed25519 pubkey: {e}")))?;
            Ok(PublicKey::Ed25519(pk))
        }
        other => Err(CmsError::UnsupportedKey(other.to_string())),
    }
}

/// Map a CMS signature-algorithm OID to its digest (None for pure EdDSA).
pub(crate) fn sig_alg_hash(alg_oid: &ObjectIdentifier) -> Result<HashAlgorithm> {
    let s = alg_oid.to_string();
    match s.as_str() {
        oids::SHA256_RSA | oids::ECDSA_SHA256 => Ok(HashAlgorithm::Sha256),
        oids::SHA384_RSA | oids::ECDSA_SHA384 => Ok(HashAlgorithm::Sha384),
        oids::SHA512_RSA | oids::ECDSA_SHA512 => Ok(HashAlgorithm::Sha512),
        oids::ED25519 => Err(CmsError::Crypto("Ed25519 has no prehash".into())),
        _ => Err(CmsError::UnsupportedSignature(s)),
    }
}

/// Verify a signature over `message` (the hash bytes for RSA/ECDSA, or the raw
/// message for Ed25519) using `pubkey` and the signature algorithm `alg_oid`.
pub(crate) fn verify_signature(
    alg_oid: &ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
    pubkey: &PublicKey,
) -> Result<()> {
    let s = alg_oid.to_string();
    match s.as_str() {
        oids::SHA256_RSA | oids::SHA384_RSA | oids::SHA512_RSA => {
            let hash = sig_alg_hash(alg_oid)?;
            let padding = match hash {
                HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256_010>(),
                HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384_010>(),
                HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512_010>(),
            };
            if let PublicKey::Rsa(pk) = pubkey {
                pk.verify(padding, message, signature)
                    .map_err(|e| CmsError::Signature(e.to_string()))?;
                Ok(())
            } else {
                Err(CmsError::Signature("algorithm/public key mismatch".into()))
            }
        }
        oids::ECDSA_SHA256 => {
            if let PublicKey::EcdsaP256(pk) = pubkey {
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| CmsError::Signature(e.to_string()))?;
                pk.verify_prehash(message, &sig)
                    .map_err(|e| CmsError::Signature(e.to_string()))?;
                Ok(())
            } else {
                Err(CmsError::Signature("algorithm/public key mismatch".into()))
            }
        }
        oids::ECDSA_SHA384 => {
            if let PublicKey::EcdsaP384(pk) = pubkey {
                let sig = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| CmsError::Signature(e.to_string()))?;
                pk.verify_prehash(message, &sig)
                    .map_err(|e| CmsError::Signature(e.to_string()))?;
                Ok(())
            } else {
                Err(CmsError::Signature("algorithm/public key mismatch".into()))
            }
        }
        oids::ED25519 => {
            if let PublicKey::Ed25519(pk) = pubkey {
                let sig = ed25519_compact::Signature::from_slice(signature)
                    .map_err(|e| CmsError::Signature(format!("{e}")))?;
                pk.verify(message, &sig)
                    .map_err(|e| CmsError::Signature(format!("{e}")))?;
                Ok(())
            } else {
                Err(CmsError::Signature("algorithm/public key mismatch".into()))
            }
        }
        _ => Err(CmsError::UnsupportedSignature(s)),
    }
}
