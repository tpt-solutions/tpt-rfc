//! Clean-room, dual-licensed Cryptographic Message Syntax (CMS, RFC 5652).
//!
//! `tpt-cms` implements the CMS content types needed by RFC 5652:
//!
//! * [`build_signed_data`]/[`verify_signed_data`] — `SignedData` (signing,
//!   signature verification, certificate/CRL bundling, multiple signers).
//! * [`build_enveloped_data`]/[`open_enveloped_data`] — `EnvelopedData` with RSA
//!   key transport and ECDH key agreement recipients.
//! * [`build_digested_data`]/[`verify_digested_data`] and
//!   [`build_encrypted_data`]/[`decrypt_encrypted_data`] — `DigestedData` and
//!   `EncryptedData`.
//!
//! All wire encoding is built clean-room on top of the dual-licensed RustCrypto
//! `der`/`spki`/`x509-cert` primitives; no code is copied from existing CMS
//! implementations.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod signed_data;
pub mod enveloped_data;
pub mod other;

pub use error::{CmsError, Result};
pub use signed_data::{build_signed_data, verify_signed_data, CmsSigner, VerifiedSignedData};
pub use enveloped_data::{
    build_enveloped_data, open_enveloped_data, RecipientPrivateKey, RecipientSpec,
};
pub use other::{
    build_digested_data, build_encrypted_data, decrypt_encrypted_data, verify_digested_data,
};

pub use crypto::{ContentEncryption, HashAlgorithm, KeyWrap, SigningKey};

mod crypto;
mod cert;
mod wire;
