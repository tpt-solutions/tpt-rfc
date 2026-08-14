// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-bgp
//!
//! A clean-room, dual-licensed implementation of **BGP-4** — the Border Gateway
//! Protocol — covering [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271).
//! This crate is the from-spec toolkit identified as a complete gap in the TPT
//! Solutions RFC survey (no maintained, dual-licensed BGP implementation
//! exists in the Rust ecosystem). It provides:
//!
//! - [`wire`] — the 19-byte common header and all four message types (OPEN,
//!   UPDATE, NOTIFICATION, KEEPALIVE), optional capabilities (RFC 5492), the
//!   four-octet ASN capability (RFC 6793), and multiprotocol NLRI
//!   (RFC 4760).
//! - [`attributes`] — path attributes (ORIGIN, AS_PATH, NEXT_HOP, MED,
//!   LOCAL_PREF, AGGREGATOR, COMMUNITY, …), the AS_PATH representation with
//!   both two- and four-octet ASNs, and IPv4/IPv6 NLRI.
//! - [`fsm`] — the peer finite-state machine (Idle → Established) per
//!   RFC 4271 §8, transport-agnostic and driven by events.
//! - [`rib`] — an Adj-RIB-In + Loc-RIB with a pluggable decision process
//!   implementing RFC 4271 §9.1.2.1 and a pluggable import/export policy.
//!
//! ## Example
//!
//! ```
//! use tpt_bgp::wire::{Message, OpenMessage, CodecOptions};
//! use tpt_bgp::attributes::Asn;
//!
//! let open = OpenMessage {
//!     version: 4,
//!     my_asn: Asn(65001),
//!     hold_time: 90,
//!     bgp_id: [10, 0, 0, 1],
//!     capabilities: vec![],
//! };
//! let bytes = Message::Open(open).encode(CodecOptions { as4: true });
//! match Message::from_bytes(&bytes).unwrap() {
//!     Message::Open(o) => assert_eq!(o.my_asn, Asn(65001)),
//!     _ => panic!("expected OPEN"),
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod attributes;
pub mod error;
pub mod fsm;
pub mod rib;
pub mod wire;

pub use attributes::{
    Aggregator, AsPath, AsPathSegment, AsPathSegmentType, Asn, Ipv4Prefix, Ipv6Prefix, MpReachNlri,
    MpUnreachNlri, NextHop, Origin, PathAttribute, Prefix,
};
pub use error::{BgpError, DecodeError, Result};
pub use fsm::{Fsm, FsmAction, FsmEvent, FsmState};
pub use rib::{DecisionProcess, DefaultDecision, Policy, Rib, Route, RouteSource};
pub use wire::{
    Capability, CodecOptions, Message, Notification, OpenMessage, Update, BGP_HEADER_LEN,
    BGP_MARKER,
};
