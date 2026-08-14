// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Constant-time helpers shared by the field arithmetic and public API.
//!
//! None of these routines branch on secret data; they only ever use
//! bitwise masking so the timing profile does not depend on the values
//! being compared or selected.

/// Constant-time equality of two equal-length byte slices.
///
/// Returns `true` iff `a` and `b` are byte-for-byte identical. The running
/// time is independent of the contents (it does depend on the length, which
/// is not secret here).
pub(crate) fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Overwrite `buf` with zeros.
///
/// Used by the secret-key types on drop so that key material does not linger
/// in memory. `volatile` writes prevent the optimizer from eliminating the
/// store.
// Volatile writes are required here so the optimizer cannot eliminate the
// store; this is the one place we use `unsafe`.
#[allow(unsafe_code)]
pub(crate) fn zeroize(buf: &mut [u8]) {
    // SAFETY: we write only within the bounds of `buf`.
    #[allow(clippy::volatile_ref_deref)]
    unsafe {
        let ptr = buf.as_mut_ptr();
        for i in 0..buf.len() {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq_bytes(b"hello", b"hello"));
        assert!(!ct_eq_bytes(b"hello", b"world"));
        assert!(!ct_eq_bytes(b"hello", b"hell"));
    }
}
