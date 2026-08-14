//! # tpt-rtp
//!
//! A clean-room, dual-licensed implementation of the Real-time Transport
//! Protocol ([RTP](https://www.rfc-editor.org/rfc/rfc3550)) and its control
//! protocol ([RTCP](https://www.rfc-editor.org/rfc/rfc3550)), together with the
//! audio/video profile ([RFC 3551](https://www.rfc-editor.org/rfc/rfc3551)).
//!
//! The crate is a focused protocol library: it encodes and decodes RTP/RTCP
//! packets, tracks receiver-side statistics, and computes the RTCP
//! transmission interval. It deliberately does **not** own sockets, media
//! pipelines, or timing — callers feed it bytes and clock readings.
//!
//! ## Modules
//!
//! - [`rtp`] — RTP packet encode/decode (RFC 3550 §5).
//! - [`rtcp`] — RTCP SR/RR/SDES/BYE/APP encode/decode (RFC 3550 §6).
//! - [`profile`] — RFC 3551 static payload-type table.
//! - [`session`] — per-SSRC receiver statistics: sequence tracking, jitter,
//!   packet loss, and `ReceptionReport` generation (RFC 3550 Appendix A).
//! - [`scheduler`] — bandwidth-aware RTCP transmission-interval computation
//!   (RFC 3550 §6.3.1).
//!
//! ## Example
//!
//! ```
//! use tpt_rtp::rtp::RtpPacket;
//! let pkt = RtpPacket::decode(&[0x80, 0x60, 0x00, 0x01,
//!                              0x00, 0x00, 0x00, 0x02,
//!                              0x11, 0x22, 0x33, 0x44]).unwrap();
//! assert_eq!(pkt.header.payload_type, 96);
//! ```
#![warn(missing_docs)]

pub mod error;
pub mod profile;
pub mod rtcp;
pub mod rtp;
pub mod scheduler;
pub mod session;

pub use error::RtpError;
pub use profile::{PayloadTypeInfo, StaticPayload};
pub use rtcp::{
    App, Bye, ReceptionReport, RtcpPacket, RtcpType, Sdes, SdesItem, SdesItemType,
    SdesChunk, SenderReport,
};
pub use rtp::{RtpHeader, RtpPacket};
pub use scheduler::RtcpScheduler;
pub use session::{ReceiverStats, SessionStatistics};
