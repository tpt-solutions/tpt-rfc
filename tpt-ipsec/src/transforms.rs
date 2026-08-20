//! IKEv2 SA proposal / transform model and negotiation (RFC 7296 §3.3).

use crate::error::{Error, Result};
use crate::types::{DhGroup, EncrId, IntegId, PrfId, ProtocolId, TransformType};

/// A single transform within a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub transform_type: TransformType,
    pub transform_id: u16,
    /// AES key length in bytes (for `TransformType::Encr` only).
    pub key_len: Option<usize>,
}

impl Transform {
    pub fn new(transform_type: TransformType, transform_id: u16) -> Transform {
        Transform {
            transform_type,
            transform_id,
            key_len: None,
        }
    }
    pub fn with_key(mut self, key_len_bytes: usize) -> Transform {
        self.key_len = Some(key_len_bytes);
        self
    }

    pub fn encr(&self) -> Option<EncrId> {
        if self.transform_type == TransformType::Encr {
            EncrId::from_u16(self.transform_id)
        } else {
            None
        }
    }
    pub fn prf(&self) -> Option<PrfId> {
        if self.transform_type == TransformType::Prf {
            PrfId::from_u16(self.transform_id)
        } else {
            None
        }
    }
    pub fn integ(&self) -> Option<IntegId> {
        if self.transform_type == TransformType::Integ {
            IntegId::from_u16(self.transform_id)
        } else {
            None
        }
    }
    pub fn dh(&self) -> Option<DhGroup> {
        if self.transform_type == TransformType::Dh {
            DhGroup::from_u16(self.transform_id)
        } else {
            None
        }
    }
}

/// A single proposal (one protocol).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub proposal_num: u8,
    pub protocol: ProtocolId,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    pub fn new(protocol: ProtocolId, transforms: Vec<Transform>) -> Proposal {
        Proposal {
            proposal_num: 1,
            protocol,
            spi: Vec::new(),
            transforms,
        }
    }

    fn find(&self, t: TransformType) -> Option<&Transform> {
        self.transforms.iter().find(|x| x.transform_type == t)
    }

    /// True if this proposal is acceptable given a policy proposal of the same
    /// protocol (every required transform type has a matching id, and AES key
    /// lengths agree).
    fn compatible(&self, policy: &Proposal) -> bool {
        for t in [TransformType::Encr, TransformType::Prf, TransformType::Integ, TransformType::Dh] {
            let a = self.find(t);
            let b = policy.find(t);
            match (a, b) {
                (Some(x), Some(y)) => {
                    if x.transform_id != y.transform_id {
                        return false;
                    }
                    if t == TransformType::Encr && x.key_len != y.key_len {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

/// An SA payload: a list of proposals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaPayload {
    pub proposals: Vec<Proposal>,
}

impl SaPayload {
    /// Select a single proposal from `self` (the initiator's offer) that is
    /// compatible with `policy` (the responder's accepted transforms).
    pub fn select(&self, policy: &SaPayload) -> Result<SaPayload> {
        for prop in &self.proposals {
            for pp in &policy.proposals {
                if pp.protocol == prop.protocol && prop.compatible(pp) {
                    return Ok(chosen_proposal(prop, pp));
                }
            }
        }
        Err(Error::NoProposalChosen)
    }

    /// Convenience: the single IKE proposal's transforms.
    pub fn ike_transforms(&self) -> Option<&[Transform]> {
        self.proposals
            .iter()
            .find(|p| p.protocol == ProtocolId::Ike)
            .map(|p| p.transforms.as_slice())
    }
}

fn chosen_proposal(offer: &Proposal, _policy: &Proposal) -> SaPayload {
    let mut transforms = Vec::new();
    for t in [
        TransformType::Encr,
        TransformType::Prf,
        TransformType::Integ,
        TransformType::Dh,
        TransformType::Esn,
    ] {
        if let Some(x) = offer.find(t) {
            transforms.push(x.clone());
        }
    }
    SaPayload {
        proposals: vec![Proposal {
            proposal_num: 1,
            protocol: offer.protocol,
            spi: Vec::new(),
            transforms,
        }],
    }
}

/// Build the default IKE SA proposal used by this implementation:
/// AES-CBC-128, PRF=HMAC-SHA256, HMAC-SHA256-128, Curve25519, ESN=NONE.
pub fn default_ike_proposal() -> Proposal {
    Proposal::new(
        ProtocolId::Ike,
        vec![
            Transform::new(TransformType::Encr, EncrId::AesCbc128.to_u16()).with_key(16),
            Transform::new(TransformType::Prf, PrfId::HmacSha256.to_u16()),
            Transform::new(TransformType::Integ, IntegId::HmacSha256_128.to_u16()),
            Transform::new(TransformType::Dh, DhGroup::Curve25519.to_u16()),
            Transform::new(TransformType::Esn, 0),
        ],
    )
}

/// Build a default CHILD SA proposal for ESP: AES-CBC-128, HMAC-SHA256-128,
/// ESN=NONE.
pub fn default_esp_proposal(spi: &[u8]) -> Proposal {
    Proposal {
        proposal_num: 1,
        protocol: ProtocolId::Esp,
        spi: spi.to_vec(),
        transforms: vec![
            Transform::new(TransformType::Encr, EncrId::AesCbc128.to_u16()).with_key(16),
            Transform::new(TransformType::Integ, IntegId::HmacSha256_128.to_u16()),
            Transform::new(TransformType::Esn, 0),
        ],
    }
}

/// Build the default IKE SA proposal with an explicit 8-byte IKE SPI (used for
/// IKE SA rekeying, where the new SA has a freshly chosen initiator SPI).
pub fn ike_proposal_with_spi(spi: &[u8]) -> Proposal {
    let mut p = default_ike_proposal();
    p.spi = spi.to_vec();
    p
}

/// Build a default CHILD SA (ESP) proposal with an explicit 4-byte SPI (used
/// for CHILD SA rekeying).
pub fn esp_proposal_with_spi(spi: &[u8]) -> Proposal {
    default_esp_proposal(spi)
}

/// The number of keying-material bytes (`KEYMAT`) required by a CHILD SA
/// proposal: the encryption key length plus the integrity key length (in
/// bytes). AEAD CHILD SAs would add a 4-byte salt (not used by the default
/// ESP proposal).
pub fn child_keymat_len(prop: &Proposal) -> usize {
    let encr = prop
        .find(TransformType::Encr)
        .and_then(|t| EncrId::from_u16(t.transform_id).map(|e| e.key_len()))
        .unwrap_or(0);
    let integ = prop
        .find(TransformType::Integ)
        .map(|t| {
            IntegId::from_u16(t.transform_id)
                .map(|i| i.key_len())
                .unwrap_or(0)
        })
        .unwrap_or(0);
    encr + integ
}
