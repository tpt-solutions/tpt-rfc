// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clean-room cryptographic primitives needed by SNMP USM.
//!
//! - [`md5`] — used to build HMAC-MD5-96 authentication (RFC 3414 §7).
//! - [`des`] — DES block cipher used for CBC-DES privacy (RFC 3414 §8).
//!
//! AES-CFB-128 privacy (RFC 3826) reuses the dual-licensed `aes` block-cipher
//! crate; only DES is implemented here because `des` is not a dependency of
//! this workspace. HMAC-SHA-96 reuses the dual-licensed `hmac`/`sha1` crates.

// --------------------------------------------------------------------------
// MD5
// --------------------------------------------------------------------------

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Compute the MD5 digest of `msg`, returning the 16-byte result.
pub fn md5(msg: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    // Pad: 0x80 then zeros to 56 mod 64, then 64-bit length little endian.
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0x00);
    }
    data.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in data.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(MD5_K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(MD5_S[i]));
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// HMAC-MD5 truncated/padded to the requested number of bytes (SNMP uses 12).
pub fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        md5(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let inner_digest = md5(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_digest);
    md5(&outer)
}

// --------------------------------------------------------------------------
// DES
// --------------------------------------------------------------------------

// Permuted Choice 1 (64-bit key -> 56-bit C0||D0).
const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

// Permuted Choice 2 (56-bit C||D -> 48-bit subkey).
const DES_PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const DES_ROTATIONS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const DES_IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const DES_FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34,
    2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const DES_E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13,
    30, 6, 22, 11, 4, 25,
];

const DES_S: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1,
        7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14,
        12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8,
        7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12,
        1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13,
        8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Permute `input` (whose significant bits occupy the low `width` bits) using
/// `table` (1-indexed positions from the MSB of that `width`-bit field).
fn permute(input: u64, width: u32, table: &[u8]) -> u64 {
    let field = input << (64 - width);
    let mut out = 0u64;
    for (i, &t) in table.iter().enumerate() {
        let bit = (field >> (64 - t as u32)) & 1;
        if bit == 1 {
            out |= 1u64 << (63 - i as u32);
        }
    }
    out
}

fn rotl28(x: u64, n: u32) -> u64 {
    let m = 0x0fff_ffff_ffff_ffff;
    ((x << n) | (x >> (28 - n))) & m
}

/// Expand a 56-bit (C||D) key schedule into 16 48-bit round subkeys.
fn des_key_schedule(key: &[u8; 8]) -> [u64; 16] {
    let k = u64::from_be_bytes(*key);
    let pc1 = permute(k, 64, &DES_PC1);
    let mut c = (pc1 >> 28) & 0x0fff_ffff_ffff_ffff;
    let mut d = pc1 & 0x0fff_ffff_ffff_ffff;
    let mut subkeys = [0u64; 16];
    for (round, &shift) in DES_ROTATIONS.iter().enumerate() {
        c = rotl28(c, shift);
        d = rotl28(d, shift);
        let cd = (c << 28) | d;
        subkeys[round] = permute(cd, 56, &DES_PC2);
    }
    subkeys
}

fn des_feistel(block: &[u8; 8], subkeys: &[u64; 16]) -> [u8; 8] {
    let ip = permute(u64::from_be_bytes(*block), 64, &DES_IP);
    let mut l = (ip >> 32) & 0xffff_ffff;
    let mut r = ip & 0xffff_ffff;

    for &sk in subkeys {
        let er = permute(r, 32, &DES_E);
        let e48 = er >> 16; // 48-bit value in low 48 bits
        let mut sbox_out: u32 = 0;
        for j in 0..8 {
            let chunk = (e48 >> (42 - 6 * j)) & 0x3f;
            let row = ((chunk >> 5) & 1) * 2 + (chunk & 1);
            let col = (chunk >> 1) & 0xf;
            let s = DES_S[j][(row * 16 + col) as usize] as u32;
            sbox_out |= s << (28 - 4 * j);
        }
        let f = permute(sbox_out as u64, 32, &DES_P) & 0xffff_ffff;
        let new_r = l ^ f;
        l = r;
        r = new_r;
    }

    let preoutput = (r << 32) | l;
    let fp = permute(preoutput, 64, &DES_FP);
    fp.to_be_bytes()
}

/// Encrypt a single 8-byte DES block.
pub fn des_encrypt_block(block: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    des_feistel(block, &des_key_schedule(key))
}

/// Decrypt a single 8-byte DES block.
pub fn des_decrypt_block(block: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    let mut subkeys = des_key_schedule(key);
    subkeys.reverse();
    des_feistel(block, &subkeys)
}

/// DES in CBC mode (RFC 3414 §8.1.1.1). Plaintext is zero-padded to a multiple
/// of 8 bytes; the trailing padding is harmless to the BER decoder that reads
/// the inner `ScopedPdu` SEQUENCE.
pub fn des_cbc_encrypt(plaintext: &[u8], key: &[u8; 8], iv: &[u8; 8]) -> Vec<u8> {
    let mut padded = plaintext.to_vec();
    while padded.len() % 8 != 0 {
        padded.push(0x00);
    }
    let mut out = Vec::with_capacity(padded.len());
    let mut prev = *iv;
    for chunk in padded.chunks_exact(8) {
        let mut x = [0u8; 8];
        for i in 0..8 {
            x[i] = chunk[i] ^ prev[i];
        }
        let c = des_encrypt_block(&x, key);
        out.extend_from_slice(&c);
        prev = c;
    }
    out
}

/// DES in CBC mode decryption (RFC 3414 §8.1.1.1).
pub fn des_cbc_decrypt(ciphertext: &[u8], key: &[u8; 8], iv: &[u8; 8]) -> Vec<u8> {
    if ciphertext.len() % 8 != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;
    for chunk in ciphertext.chunks_exact(8) {
        let c: [u8; 8] = chunk.try_into().unwrap();
        let p = des_decrypt_block(&c, key);
        let mut block = [0u8; 8];
        for i in 0..8 {
            block[i] = p[i] ^ prev[i];
        }
        out.extend_from_slice(&block);
        prev = c;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known_vector() {
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
        assert_eq!(
            md5(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }

    #[test]
    fn des_known_vector_fips81() {
        // FIPS 81 test vector: key, plaintext, ciphertext.
        let key = [
            0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1,
        ];
        let plain = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let cipher = des_encrypt_block(&plain, &key);
        assert_eq!(
            cipher,
            [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05]
        );
        assert_eq!(des_decrypt_block(&cipher, &key), plain);
    }

    #[test]
    fn des_cbc_roundtrip() {
        let key = [0x00u8; 8];
        let iv = [0xffu8; 8];
        let pt = b"hello scoped pdu world";
        let ct = des_cbc_encrypt(pt, &key, &iv);
        assert_eq!(des_cbc_decrypt(&ct, &key, &iv), pt);
    }
}
