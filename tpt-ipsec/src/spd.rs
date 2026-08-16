//! RFC 4301 IPsec Security Policy Database (SPD) and Security Association
//! Database (SAD) data model.
//!
//! This module models the policy/SA data structures described in RFC 4301
//! §4.4 (SPD) and §4.3 (SAD). It does **not** perform packet processing or
//! ESP/AH encapsulation; it exists so that an IKEv2 implementation can
//! record negotiated SAs and express the policy that governs them, ready for
//! hand-off to a data plane.

use crate::types::ProtocolId;

/// IPsec protocol carried by an SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSecProtocol {
    Ah,
    Esp,
}

impl IpSecProtocol {
    pub fn from_protocol_id(p: ProtocolId) -> Option<IpSecProtocol> {
        match p {
            ProtocolId::Ah => Some(IpSecProtocol::Ah),
            ProtocolId::Esp => Some(IpSecProtocol::Esp),
            _ => None,
        }
    }
    pub fn protocol_id(self) -> ProtocolId {
        match self {
            IpSecProtocol::Ah => ProtocolId::Ah,
            IpSecProtocol::Esp => ProtocolId::Esp,
        }
    }
}

/// SA mode (RFC 4301 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaMode {
    Transport,
    Tunnel,
}

/// Action applied to traffic matched by an SPD entry (RFC 4301 §4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdAction {
    /// Bypass IPsec; process as cleartext.
    Bypass,
    /// Discard the traffic.
    Discard,
    /// Apply IPsec using the referenced SA (or negotiate one).
    Protect,
}

/// A traffic selector used by the SPD/SAD (IPv4/IPv6 address + port range).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdSelector {
    pub protocol: Option<IpSecProtocol>,
    pub src_addr: std::net::IpAddr,
    pub src_prefix: u8,
    pub dst_addr: std::net::IpAddr,
    pub dst_prefix: u8,
    pub src_port_range: (u16, u16),
    pub dst_port_range: (u16, u16),
}

/// An SPD entry: a selector plus the action and (for Protect) the SA bundle
/// parameters to apply.
#[derive(Debug, Clone)]
pub struct SpdEntry {
    pub selector: SpdSelector,
    pub action: SpdAction,
    /// For `Protect`: the IPsec protocol and mode to apply.
    pub ipsec: Option<(IpSecProtocol, SaMode)>,
    /// For `Protect`: an optional name of an SA or SA bundle to use.
    pub sa_name: Option<String>,
}

/// A Security Association entry in the SAD (RFC 4301 §4.3).
#[derive(Debug, Clone)]
pub struct SadEntry {
    pub spi: u32,
    pub protocol: IpSecProtocol,
    pub mode: SaMode,
    /// Sequence number counter for outbound traffic.
    pub seq: u32,
    /// Anti-replay window size (0 disables anti-replay).
    pub replay_window: u32,
    /// Encryption key (for ESP/AH transforms that need one).
    pub encr_key: Vec<u8>,
    /// Integrity key (for ESP/AH transforms that need one).
    pub integ_key: Vec<u8>,
    /// Lifetime (soft) in seconds, if bounded.
    pub lifetime_seconds: Option<u64>,
}

impl SadEntry {
    /// Build a SAD entry from IKEv2-derived CHILD SA keying material.
    /// `keymat` is the KEYMAT from [`crate::state::child_keymat`]; `encr_len`
    /// and `integ_len` are the key lengths in bytes.
    pub fn from_keymat(
        spi: u32,
        protocol: IpSecProtocol,
        mode: SaMode,
        keymat: &[u8],
        encr_len: usize,
        integ_len: usize,
    ) -> SadEntry {
        let mut o = 0;
        let encr_key = if encr_len > 0 {
            let k = keymat[o..o + encr_len].to_vec();
            o += encr_len;
            k
        } else {
            Vec::new()
        };
        let integ_key = if integ_len > 0 {
            let k = keymat[o..o + integ_len].to_vec();
            o += integ_len;
            k
        } else {
            Vec::new()
        };
        SadEntry {
            spi,
            protocol,
            mode,
            seq: 1,
            replay_window: 64,
            encr_key,
            integ_key,
            lifetime_seconds: None,
        }
    }
}
