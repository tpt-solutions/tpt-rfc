// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-ospf
//!
//! A clean-room, dual-licensed implementation of **OSPF** — the Open Shortest
//! Path First interior gateway protocol — covering [RFC 2328](https://www.rfc-editor.org/rfc/rfc2328)
//! (OSPFv2) and [RFC 5340](https://www.rfc-editor.org/rfc/rfc5340) (OSPFv3).
//!
//! This crate is the from-spec toolkit identified as a complete gap in the TPT
//! Solutions RFC survey (the only existing crate, `ospf-parser`, is
//! parser-only with an unconfirmed license and no protocol logic). It provides:
//!
//! - [`wire`] — the OSPF packet header plus all five packet types (Hello, DBD,
//!   LSR, LSU, LSAck) for both OSPFv2 and OSPFv3, with the standard Internet
//!   checksum.
//! - [`lsa`] — the LSA header and body encode/decode for Router and Network
//!   LSAs (the LSAs that drive intra-area SPF), plus an opaque carrier for the
//!   remaining LSA types.
//! - [`database`] — the link-state database with the §13 flooding acceptance
//!   logic.
//! - [`neighbor`] — the neighbor finite-state machine (Down → Full).
//! - [`spf`] — Dijkstra's shortest-path-first calculation producing a
//!   next-hop routing table.
//!
//! ## Example
//!
//! ```
//! use tpt_ospf::lsa::{LsaHeader, RouterLsa, RouterLink};
//! use tpt_ospf::spf::Spf;
//!
//! let mut spf = Spf::new([10, 0, 0, 1]);
//! spf.add_router_lsa(RouterLsa {
//!     header: LsaHeader::router([10, 0, 0, 1], 0),
//!     v: false, e: false, b: false,
//!     links: vec![RouterLink::point_to_point([10, 0, 0, 2], [10, 0, 0, 1], 10)],
//! });
//! spf.add_router_lsa(RouterLsa {
//!     header: LsaHeader::router([10, 0, 0, 2], 0),
//!     v: false, e: false, b: false,
//!     links: vec![],
//! });
//! let table = spf.calculate().unwrap();
//! assert_eq!(table.next_hop([10, 0, 0, 2]), Some([10, 0, 0, 2]));
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod database;
pub mod error;
pub mod lsa;
pub mod neighbor;
pub mod spf;
pub mod wire;

pub use error::{DecodeError, OspfError, Result};
pub use lsa::{Ip4, Lsa, LsaHeader, RouterLink, RouterLsa};
pub use neighbor::{NeighborState, NeighborTable};
pub use spf::{Route, RoutingTable, Spf, StubRoute};
pub use wire::{
    DbdPacket, HelloPacket, LinkStateRequest, LsAckPacket, LsuPacket, OspfPacket, OspfVersion,
    PacketBody, PacketType,
};
