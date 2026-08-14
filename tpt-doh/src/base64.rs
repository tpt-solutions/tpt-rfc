// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Base64url (RFC 4648 §5) encoding without padding, as required by DoH GET.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `input` to base64url **without** trailing `=` padding.
pub fn encode_nopad(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = match chunk.len() {
            1 => [chunk[0], 0, 0, 0],
            2 => [chunk[0], chunk[1], 0, 0],
            _ => [chunk[0], chunk[1], chunk[2], 0],
        };
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decode base64url, tolerating either padded or unpadded input.
pub fn decode_nopad(input: &str) -> Result<Vec<u8>, String> {
    let mut buf = String::with_capacity(input.len() + 4);
    buf.push_str(input);
    while buf.len() % 4 != 0 {
        buf.push('=');
    }
    base64_decode_standard(&buf)
}

/// Value of a base64/base64url character, or an error if invalid.
fn b64_val(c: u8) -> std::result::Result<u32, String> {
    match c {
        b'A'..=b'Z' => Ok((c - b'A') as u32),
        b'a'..=b'z' => Ok((c - b'a') as u32 + 26),
        b'0'..=b'9' => Ok((c - b'0') as u32 + 52),
        b'+' | b'-' => Ok(62),
        b'/' | b'_' => Ok(63),
        _ => Err(format!("invalid base64 character: {}", c as char)),
    }
}

/// Decode a base64 / base64url string that is `=` padded to a 4-char boundary.
fn base64_decode_standard(input: &str) -> std::result::Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        // A padding character at the start of a group means we're done; ignore
        // any trailing all-padding groups (tolerate over-padded input).
        if bytes[i] == b'=' {
            break;
        }
        let mut vals = [0u32; 4];
        let mut pad = 0usize;
        for j in 0..4 {
            if i + j < bytes.len() && bytes[i + j] != b'=' {
                vals[j] = b64_val(bytes[i + j])?;
            } else {
                vals[j] = 0;
                pad += 1;
            }
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_no_padding() {
        assert_eq!(encode_nopad(b""), "");
        assert_eq!(encode_nopad(b"f"), "Zg");
        assert_eq!(encode_nopad(b"fo"), "Zm8");
        assert_eq!(encode_nopad(b"foo"), "Zm9v");
        assert_eq!(encode_nopad(b"foob"), "Zm9vYg");
        assert_eq!(encode_nopad(b"fooba"), "Zm9vYmE");
        assert_eq!(encode_nopad(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn roundtrip() {
        let cases: &[&[u8]] = &[b"", b"x", b"abc", b"hello world", &[0u8, 1, 2, 3, 255, 254]];
        for s in cases {
            let enc = encode_nopad(s);
            let dec = decode_nopad(&enc).unwrap();
            assert_eq!(dec, *s);
        }
    }

    #[test]
    fn decode_tolerates_padding() {
        assert_eq!(decode_nopad("Zm9vYmFy==").unwrap(), b"foobar");
    }
}
