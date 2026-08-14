//! Privacy Pass token issuance & redemption (RFC 9578).
//!
//! This module builds the two-message issuance protocol — `TokenRequest`
//! → `TokenResponse` — and the resulting `Token` on top of the VOPRF
//! ([`oprf::blind_evaluate_voprf`] / [`oprf::finalize_voprf`]) and POPRF
//! ([`oprf::blind_evaluate_poprf`] / [`oprf::finalize_poprf`]) cores. It
//! implements the privately-verifiable (VOPRF) token type, matching
//! RFC 9578 §5 exactly for `0x0001` (VOPRF(P-384, SHA-384), with official
//! test vectors), and a P-256 VOPRF token type plus public-metadata
//! (POPRF) variants built clean-room on the same structure.

use crate::error::{OprfError, TokenError};
use crate::oprf::*;
use crate::suite::*;
use sha2::{Digest, Sha256};

type ScalarE<C> = Scalar<C>;
type PointE<C> = Point<C>;

/// Token type `0x0001`: VOPRF(P-384, SHA-384), privately verifiable
/// (RFC 9578 §5 / §8.2.1 — the only token type with official IETF test
/// vectors).
pub const TOKEN_TYPE_P384_VOPRF: u16 = 0x0001;
/// Token type `0x0009`: VOPRF(P-256, SHA-256), privately verifiable.
/// Clean-room local assignment — P-256 VOPRF is *not* an IANA-registered
/// Privacy Pass token type in RFC 9578 (only `0x0001` P-384 and `0x0002`
/// Blind RSA are), but the OPRF/VOPRF(P-256) core is fully RFC 9497
/// conformant and tested.
pub const TOKEN_TYPE_P256_VOPRF: u16 = 0x0009;
/// Token type `0x0003`: VOPRF(P-384, SHA-384) **with Public Metadata**,
/// privately verifiable (the Privacy Pass public-metadata extension; the
/// metadata is bound as the POPRF `info`).
pub const TOKEN_TYPE_P384_POPRF_META: u16 = 0x0003;
/// Token type `0x000A`: VOPRF(P-256, SHA-256) **with Public Metadata**,
/// privately verifiable. Clean-room local assignment.
pub const TOKEN_TYPE_P256_POPRF_META: u16 = 0x000A;

/// `SHA-256(challenge)` — the `challenge_digest` used in `token_input`.
pub fn challenge_digest(challenge: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(challenge);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// `SHA-256(SerializeElement(pkI))` — the issuer key identifier
/// (`token_key_id` in RFC 9578 §5.5).
pub fn issuer_key_id<C: Suite>(pk: &PointE<C>) -> [u8; 32] {
    let bytes = serialize_element::<C>(pk);
    let mut h = Sha256::new();
    h.update(&bytes);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Build the `token_input` byte string: `token_type (2 bytes) || nonce (32)
/// || challenge_digest (32) || token_key_id (32)` (RFC 9578 §5.1).
pub fn token_input(
    token_type: u16,
    nonce: &[u8; 32],
    challenge_digest: &[u8; 32],
    token_key_id: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(98);
    v.extend_from_slice(&token_type.to_be_bytes());
    v.extend_from_slice(nonce);
    v.extend_from_slice(challenge_digest);
    v.extend_from_slice(token_key_id);
    v
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

/// `TokenRequest` (RFC 9578 §5.1): `token_type (2) || truncated_key_id (1)
/// || blinded_msg (Ne)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRequest {
    /// Token type (e.g. [`TOKEN_TYPE_P384_VOPRF`]).
    pub token_type: u16,
    /// Least-significant byte of the issuer key id (truncated for privacy).
    pub truncated_key_id: u8,
    /// Serialized blinded group element (`Ne` bytes).
    pub blinded_msg: Vec<u8>,
}

impl TokenRequest {
    /// Serialize to the on-the-wire byte format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(3 + self.blinded_msg.len());
        v.extend_from_slice(&self.token_type.to_be_bytes());
        v.push(self.truncated_key_id);
        v.extend_from_slice(&self.blinded_msg);
        v
    }

    /// Parse from the on-the-wire byte format.
    pub fn from_bytes<C: Suite>(b: &[u8]) -> Result<Self, TokenError> {
        if b.len() < 3 + C::NE {
            return Err(TokenError::Malformed);
        }
        let token_type = u16::from_be_bytes([b[0], b[1]]);
        let truncated_key_id = b[2];
        let blinded_msg = b[3..].to_vec();
        Ok(TokenRequest {
            token_type,
            truncated_key_id,
            blinded_msg,
        })
    }
}

/// `TokenResponse` (RFC 9578 §5.2): `evaluate_msg (Ne) || evaluate_proof
/// (2·Ns)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenResponse {
    /// Serialized evaluated group element (`Ne` bytes).
    pub evaluate_msg: Vec<u8>,
    /// Serialized DLEQ proof (`2·Ns` bytes).
    pub evaluate_proof: Vec<u8>,
}

impl TokenResponse {
    /// Serialize to the on-the-wire byte format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.evaluate_msg.len() + self.evaluate_proof.len());
        v.extend_from_slice(&self.evaluate_msg);
        v.extend_from_slice(&self.evaluate_proof);
        v
    }

    /// Parse from the on-the-wire byte format.
    pub fn from_bytes<C: Suite>(b: &[u8]) -> Result<Self, TokenError> {
        if b.len() != C::NE + 2 * C::NS {
            return Err(TokenError::Malformed);
        }
        let evaluate_msg = b[..C::NE].to_vec();
        let evaluate_proof = b[C::NE..].to_vec();
        Ok(TokenResponse {
            evaluate_msg,
            evaluate_proof,
        })
    }
}

/// A redemption `Token` (RFC 9578 §5.3): `token_type (2) || nonce (32) ||
/// challenge_digest (32) || token_key_id (32) || authenticator (Nk)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// Token type.
    pub token_type: u16,
    /// Client nonce (`nonce`, 32 bytes).
    pub nonce: [u8; 32],
    /// `SHA-256(challenge)` (`challenge_digest`, 32 bytes).
    pub challenge_digest: [u8; 32],
    /// `SHA-256(SerializeElement(pkI))` (`token_key_id`, 32 bytes).
    pub token_key_id: [u8; 32],
    /// Token authenticator (`Nk` = `Nh` bytes).
    pub authenticator: Vec<u8>,
}

impl Token {
    /// Serialize to the on-the-wire byte format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(98 + self.authenticator.len());
        v.extend_from_slice(&self.token_type.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.challenge_digest);
        v.extend_from_slice(&self.token_key_id);
        v.extend_from_slice(&self.authenticator);
        v
    }

    /// Parse from the on-the-wire byte format.
    pub fn from_bytes<C: Suite>(b: &[u8]) -> Result<Self, TokenError> {
        if b.len() != 98 + C::NH {
            return Err(TokenError::Malformed);
        }
        let token_type = u16::from_be_bytes([b[0], b[1]]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&b[2..34]);
        let mut challenge_digest = [0u8; 32];
        challenge_digest.copy_from_slice(&b[34..66]);
        let mut token_key_id = [0u8; 32];
        token_key_id.copy_from_slice(&b[66..98]);
        let authenticator = b[98..].to_vec();
        Ok(Token {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
            authenticator,
        })
    }
}

// ---------------------------------------------------------------------------
// VOPRF (privately verifiable) issuance & redemption
// ---------------------------------------------------------------------------

/// Client-side state retained between issuance request and finalization.
#[derive(Clone)]
pub struct VoprfState<C: Suite> {
    /// Token type.
    pub token_type: u16,
    /// Client nonce.
    pub nonce: [u8; 32],
    /// `SHA-256(challenge)`.
    pub challenge_digest: [u8; 32],
    /// Issuer key id.
    pub token_key_id: [u8; 32],
    /// Blinding scalar (secret).
    pub blind: ScalarE<C>,
    /// Blinded element (echoed in finalization).
    pub blinded_element: PointE<C>,
}

/// Build a `TokenRequest` for a VOPRF token type (RFC 9578 §5.1).
pub fn create_token_request<C: Suite>(
    token_type: u16,
    challenge: &[u8],
    nonce: &[u8; 32],
    token_key_id: &[u8; 32],
    blind: &ScalarE<C>,
) -> Result<(TokenRequest, VoprfState<C>), TokenError> {
    let cd = challenge_digest(challenge);
    let ti = token_input(token_type, nonce, &cd, token_key_id);
    let blinded_element = blind::<C>(&ti, blind, 0x01);
    let req = TokenRequest {
        token_type,
        truncated_key_id: token_key_id[31],
        blinded_msg: serialize_element::<C>(&blinded_element),
    };
    let state = VoprfState {
        token_type,
        nonce: *nonce,
        challenge_digest: cd,
        token_key_id: *token_key_id,
        blind: *blind,
        blinded_element,
    };
    Ok((req, state))
}

/// Issuer-side response to a `TokenRequest` (RFC 9578 §5.2).
pub fn issuer_respond<C: Suite>(
    sk: &ScalarE<C>,
    pk: &PointE<C>,
    req: &TokenRequest,
) -> Result<TokenResponse, TokenError> {
    let blinded = deserialize_element::<C>(&req.blinded_msg).map_err(TokenError::Oprf)?;
    let (evaluated, proof) = blind_evaluate_voprf::<C>(sk, pk, &blinded);
    Ok(TokenResponse {
        evaluate_msg: serialize_element::<C>(&evaluated),
        evaluate_proof: serialize_proof::<C>(&proof),
    })
}

/// Client-side finalization of a `TokenResponse` into a `Token`
/// (RFC 9578 §5.3).
pub fn finalize_token<C: Suite>(
    state: &VoprfState<C>,
    resp: &TokenResponse,
    pk: &PointE<C>,
) -> Result<Token, TokenError> {
    let evaluated = deserialize_element::<C>(&resp.evaluate_msg).map_err(TokenError::Oprf)?;
    let proof = deserialize_proof::<C>(&resp.evaluate_proof).map_err(TokenError::Oprf)?;
    let ti = token_input(
        state.token_type,
        &state.nonce,
        &state.challenge_digest,
        &state.token_key_id,
    );
    let authenticator = finalize_voprf::<C>(
        &ti,
        &state.blind,
        &evaluated,
        &state.blinded_element,
        pk,
        &proof,
    )
    .map_err(TokenError::Oprf)?;
    Ok(Token {
        token_type: state.token_type,
        nonce: state.nonce,
        challenge_digest: state.challenge_digest,
        token_key_id: state.token_key_id,
        authenticator: authenticator.to_vec(),
    })
}

/// Verify a redeemed `Token` against the issuer private key (RFC 9578 §5.4).
pub fn verify_token<C: Suite>(sk: &ScalarE<C>, token: &Token) -> Result<(), TokenError> {
    if token.authenticator.len() != C::NH {
        return Err(TokenError::Malformed);
    }
    let ti = token_input(
        token.token_type,
        &token.nonce,
        &token.challenge_digest,
        &token.token_key_id,
    );
    let expected = evaluate::<C>(sk, &ti, 0x01);
    if expected.to_vec() == token.authenticator {
        Ok(())
    } else {
        Err(TokenError::Verification)
    }
}

// ---------------------------------------------------------------------------
// POPRF (public-metadata) issuance & redemption
// ---------------------------------------------------------------------------

/// Client-side state retained between issuance request and finalization for
/// a public-metadata (POPRF) token.
#[derive(Clone)]
pub struct PoprfState<C: Suite> {
    /// Token type.
    pub token_type: u16,
    /// Client nonce.
    pub nonce: [u8; 32],
    /// `SHA-256(challenge)`.
    pub challenge_digest: [u8; 32],
    /// Issuer key id.
    pub token_key_id: [u8; 32],
    /// Public metadata bound as the POPRF `info`.
    pub metadata: Vec<u8>,
    /// Blinding scalar (secret).
    pub blind: ScalarE<C>,
    /// Blinded element.
    pub blinded_element: PointE<C>,
    /// Tweaked public key (secret, derived client-side).
    pub tweaked_key: PointE<C>,
}

/// Build a `TokenRequest` for a public-metadata (POPRF) token type. The
/// `metadata` is bound via the POPRF `info` (RFC 9497 §3.3.3).
pub fn create_token_request_poprf<C: Suite>(
    token_type: u16,
    challenge: &[u8],
    nonce: &[u8; 32],
    token_key_id: &[u8; 32],
    pk: &PointE<C>,
    blind: &ScalarE<C>,
    metadata: &[u8],
) -> Result<(TokenRequest, PoprfState<C>), TokenError> {
    let cd = challenge_digest(challenge);
    let ti = token_input(token_type, nonce, &cd, token_key_id);
    let (blinded_element, tweaked_key) = blind_poprf::<C>(&ti, metadata, pk, blind);
    let req = TokenRequest {
        token_type,
        truncated_key_id: token_key_id[31],
        blinded_msg: serialize_element::<C>(&blinded_element),
    };
    let state = PoprfState {
        token_type,
        nonce: *nonce,
        challenge_digest: cd,
        token_key_id: *token_key_id,
        metadata: metadata.to_vec(),
        blind: *blind,
        blinded_element,
        tweaked_key,
    };
    Ok((req, state))
}

/// Issuer-side response to a public-metadata `TokenRequest`.
pub fn issuer_respond_poprf<C: Suite>(
    sk: &ScalarE<C>,
    req: &TokenRequest,
    metadata: &[u8],
) -> Result<TokenResponse, TokenError> {
    let blinded = deserialize_element::<C>(&req.blinded_msg).map_err(TokenError::Oprf)?;
    let (evaluated, proof) = blind_evaluate_poprf::<C>(sk, &blinded, metadata);
    Ok(TokenResponse {
        evaluate_msg: serialize_element::<C>(&evaluated),
        evaluate_proof: serialize_proof::<C>(&proof),
    })
}

/// Client-side finalization of a public-metadata `TokenResponse`.
pub fn finalize_token_poprf<C: Suite>(
    state: &PoprfState<C>,
    resp: &TokenResponse,
) -> Result<Token, TokenError> {
    let evaluated = deserialize_element::<C>(&resp.evaluate_msg).map_err(TokenError::Oprf)?;
    let proof = deserialize_proof::<C>(&resp.evaluate_proof).map_err(TokenError::Oprf)?;
    let ti = token_input(
        state.token_type,
        &state.nonce,
        &state.challenge_digest,
        &state.token_key_id,
    );
    let authenticator = finalize_poprf::<C>(
        &ti,
        &state.blind,
        &evaluated,
        &state.blinded_element,
        &proof,
        &state.metadata,
        &state.tweaked_key,
    )
    .map_err(TokenError::Oprf)?;
    Ok(Token {
        token_type: state.token_type,
        nonce: state.nonce,
        challenge_digest: state.challenge_digest,
        token_key_id: state.token_key_id,
        authenticator: authenticator.to_vec(),
    })
}

/// Verify a redeemed public-metadata `Token` (the metadata must be supplied
/// to recompute the POPRF).
pub fn verify_token_poprf<C: Suite>(
    sk: &ScalarE<C>,
    token: &Token,
    metadata: &[u8],
) -> Result<(), TokenError> {
    if token.authenticator.len() != C::NH {
        return Err(TokenError::Malformed);
    }
    let ti = token_input(
        token.token_type,
        &token.nonce,
        &token.challenge_digest,
        &token.token_key_id,
    );
    let expected = evaluate_poprf::<C>(sk, &ti, metadata);
    if expected.to_vec() == token.authenticator {
        Ok(())
    } else {
        Err(TokenError::Verification)
    }
}
