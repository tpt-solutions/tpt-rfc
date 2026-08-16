//! # tpt-ipsec
//!
//! Clean-room, dual-licensed (MIT OR Apache-2.0) Rust implementation of
//! **IKEv2 / IPsec** — RFC 7296 (IKEv2) for the control plane, with the SA/
//! SPD data model from RFC 4301 (IPsec architecture).
//!
//! The focus of this crate is the IKEv2 protocol: the IKE_SA_INIT and
//! IKE_AUTH exchanges, CHILD SA negotiation via CREATE_CHILD_SA, IKE SA
//! rekeying, PSK and Ed25519 ("Digital Signature", RFC 7420) authentication,
//! and the AES-CBC + HMAC and AES-GCM SK payload envelopes. Actual ESP/AH
//! packet encapsulation is scoped out (documented boundary); the negotiated
//! keying material and the RFC 4301 SA/SPD model are provided for
//! integration with an OS or userspace data plane.
//!
//! See `SPEC-NOTES.md` for the section-by-section conformance status and the
//! test vectors wired into the suite.

#![allow(clippy::upper_case_acronyms)]

pub mod crypto;
pub mod error;
pub mod message;
pub mod spd;
pub mod state;
pub mod transforms;
pub mod types;

pub use error::{Error, Result};
pub use message::{
    AuthPayload, CertPayload, EncryptedPayload, Header, IdPayload, KePayload, Message, NoncePayload,
    NotifyPayload, Payload, TsPayload, TrafficSelector,
};
pub use state::{
    AuthConfig, IkeInitiator, IkeResponder, IkeSa, IkeSaKeys, SaParams, child_keymat, derive_keys,
};
pub use transforms::{Proposal, SaPayload, Transform};
pub use types::TransformType;
pub use types::{
    AuthMethod, CertEncoding, DhGroup, EncrId, ExchangeType, IdType, IntegId, PayloadType,
    PrfId, ProtocolId,
};

/// The IKE version implemented (2.0).
pub const IKE_VERSION: u8 = types::IKE_VERSION;
