//! # `tpt-privacy-pass`
//!
//! Clean-room, dual-licensed (MIT OR Apache-2.0) implementation of
//! **Privacy Pass** ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576))
//! — a privacy-preserving authorization architecture built on
//! **OPRF / VOPRF / POPRF** ([RFC 9497](https://www.rfc-editor.org/rfc/rfc9497)).
//!
//! The crate implements, from the specifications only (no code copied from
//! `voprf`/`curve25519-dalek`/etc.):
//!
//! * the OPRF/VOPRF/POPRF three-message core over the NIST P-256 and P-384
//!   prime-order groups (with the DLEQ proof system and deterministic key
//!   generation), and
//! * the Privacy Pass token **issuance** (`TokenRequest` → `TokenResponse`)
//!   and **redemption** (`Token`) protocol of
//!   [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578), for the
//!   privately-verifiable (VOPRF) token type `0x0001` (P-384, with the
//!   official IETF test vectors) and P-256 / public-metadata (POPRF)
//!   variants built on the same structure.
//!
//! ## Why these curves?
//!
//! Privacy Pass token types `0x0001` (P-384 VOPRF) and `0x0002` (Blind RSA)
//! are the only IANA-registered types in RFC 9578. The companion
//! ristretto255 token types in RFC 9576 rely on `curve25519-dalek`, which is
//! **BSD-3-Clause** and therefore fails this platform's dual MIT/Apache-2.0
//! requirement. P-256 and P-384 — via RustCrypto's `p256`/`p384`, both
//! MIT/Apache-2.0 — cover the same construction cleanly, which is why this
//! crate targets them.
//!
//! ## Crate layout
//!
//! * [`suite`] — the [`Suite`] trait and the [`NistP256`](p256::NistP256) /
//!   [`NistP384`](p384::NistP384) backends plus serialization helpers.
//! * [`oprf`] — `Blind` / `BlindEvaluate` / `Finalize` / `Evaluate`,
//!   the DLEQ `GenerateProof` / `VerifyProof`, and `DeriveKeyPair`.
//! * [`token`] — the RFC 9578 issuance/redemption protocol.
//!
//! ## Example: issue and redeem a P-384 VOPRF token
//!
//! ```no_run
//! use tpt_privacy_pass::oprf::{derive_key_pair, random_scalar};
//! use tpt_privacy_pass::token::{
//!     challenge_digest, create_token_request, finalize_token, issuer_respond,
//!     issuer_key_id, verify_token, TOKEN_TYPE_P384_VOPRF,
//! };
//! use p384::NistP384;
//! use tpt_privacy_pass::suite::Suite;
//!
//! // Issuer generates a key (RFC 9578 §5.5).
//! let (sk, pk) = derive_key_pair::<NistP384>(b"seed...", b"PrivacyPass", 0x01);
//! let kid = issuer_key_id::<NistP384>(&pk);
//!
//! // Client issues a token for a challenge.
//! let challenge = b"issuer.example\x00origin.example";
//! let nonce = [0x42u8; 32];
//! let blind = random_scalar::<NistP384>();
//! let (req, state) = create_token_request::<NistP384>(
//!     TOKEN_TYPE_P384_VOPRF, challenge, &nonce, &kid, &blind).unwrap();
//!
//! // Issuer responds.
//! let resp = issuer_respond::<NistP384>(&sk, &pk, &req).unwrap();
//!
//! // Client finalizes into a token.
//! let token = finalize_token::<NistP384>(&state, &resp, &pk).unwrap();
//!
//! // Origin redeems / verifies the token.
//! verify_token::<NistP384>(&sk, &token).unwrap();
//! # let _ = challenge_digest(challenge);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod oprf;
pub mod suite;
pub mod token;

pub use error::{OprfError, TokenError};
pub use suite::{NistP256, NistP384, Suite};
