//! BFD control packet wire format (RFC 5880 §4.1).
//!
//! This module implements clean-room encode/decode of the mandatory BFD
//! control-packet section plus the optional authentication section. No
//! third-party BFD codec dependency is used.

use crate::error::BfdError;

/// Protocol version implemented by this crate.
pub const BFD_VERSION: u8 = 1;

/// Minimum length of a BFD control packet without an authentication
/// section (RFC 5880 §6.8.6).
pub const MIN_LEN_NO_AUTH: usize = 24;

/// Minimum length of a BFD control packet carrying an authentication
/// section (RFC 5880 §6.8.6).
pub const MIN_LEN_AUTH: usize = 26;

/// Diagnostic codes carried in the `Diag` field (RFC 5880 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Diagnostic {
    /// 0 — No Diagnostic.
    None = 0,
    /// 1 — Control Detection Time Expired.
    ControlDetectionTimeExpired = 1,
    /// 2 — Echo Function Failed.
    EchoFunctionFailed = 2,
    /// 3 — Neighbor Signaled Session Down.
    NeighborSignaledSessionDown = 3,
    /// 4 — Forwarding Plane Reset.
    ForwardingPlaneReset = 4,
    /// 5 — Path Down.
    PathDown = 5,
    /// 6 — Concatenated Path Down.
    ConcatenatedPathDown = 6,
    /// 7 — Administratively Down.
    AdministrativelyDown = 7,
    /// 8 — Reverse Concatenated Path Down.
    ReverseConcatenatedPathDown = 8,
}

impl Diagnostic {
    /// Map a raw `Diag` octet to a [`Diagnostic`], rejecting reserved
    /// values (9-31).
    pub fn from_u8(v: u8) -> Result<Diagnostic, BfdError> {
        Ok(match v {
            0 => Diagnostic::None,
            1 => Diagnostic::ControlDetectionTimeExpired,
            2 => Diagnostic::EchoFunctionFailed,
            3 => Diagnostic::NeighborSignaledSessionDown,
            4 => Diagnostic::ForwardingPlaneReset,
            5 => Diagnostic::PathDown,
            6 => Diagnostic::ConcatenatedPathDown,
            7 => Diagnostic::AdministrativelyDown,
            8 => Diagnostic::ReverseConcatenatedPathDown,
            other => return Err(BfdError::ReservedDiagnostic(other)),
        })
    }

    /// The numeric code for this diagnostic.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// BFD session states carried in the `Sta` field (RFC 5880 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// 0 — AdminDown.
    AdminDown = 0,
    /// 1 — Down.
    Down = 1,
    /// Up (state 3) is only reachable after Init.
    Init = 2,
    /// 3 — Up.
    Up = 3,
}

impl SessionState {
    /// Map a raw `Sta` octet to a [`SessionState`], rejecting invalid
    /// values (4-255).
    pub fn from_u8(v: u8) -> Result<SessionState, BfdError> {
        Ok(match v {
            0 => SessionState::AdminDown,
            1 => SessionState::Down,
            2 => SessionState::Init,
            3 => SessionState::Up,
            other => return Err(BfdError::InvalidState(other)),
        })
    }

    /// The numeric code for this state.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Authentication types (RFC 5880 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    /// 0 — Reserved.
    Reserved = 0,
    /// 1 — Simple Password.
    SimplePassword = 1,
    /// 2 — Keyed MD5.
    KeyedMd5 = 2,
    /// 3 — Meticulous Keyed MD5.
    MeticulousKeyedMd5 = 3,
    /// 4 — Keyed SHA1.
    KeyedSha1 = 4,
    /// 5 — Meticulous Keyed SHA1.
    MeticulousKeyedSha1 = 5,
}

impl AuthType {
    /// Map a raw `Auth Type` octet; unknown values collapse to
    /// [`AuthType::Reserved`].
    pub fn from_u8(v: u8) -> AuthType {
        match v {
            1 => AuthType::SimplePassword,
            2 => AuthType::KeyedMd5,
            3 => AuthType::MeticulousKeyedMd5,
            4 => AuthType::KeyedSha1,
            5 => AuthType::MeticulousKeyedSha1,
            _ => AuthType::Reserved,
        }
    }

    /// Whether this auth type carries a keyed digest (SHA1 family).
    pub fn is_keyed(self) -> bool {
        matches!(
            self,
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1
        )
    }

    /// Length of the digest carried by this auth type (0 for simple
    /// password / reserved).
    pub fn digest_len(self) -> usize {
        match self {
            AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => 16,
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => 20,
            _ => 0,
        }
    }
}

/// An authentication section as carried on the wire (RFC 5880 §4.2-4.4).
///
/// For `SimplePassword`, `data` holds the password bytes. For the keyed
/// types, `data` holds the received/sent digest and `sequence_number`
/// carries the anti-replay sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSection {
    /// Authentication type in use.
    pub auth_type: AuthType,
    /// Authentication key ID.
    pub key_id: u8,
    /// Sequence number (keyed authentication only).
    pub sequence_number: u32,
    /// Password bytes (simple) or digest bytes (keyed).
    pub data: Vec<u8>,
}

/// A decoded BFD control packet (RFC 5880 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    /// Protocol version (must be 1).
    pub version: u8,
    /// Diagnostic code.
    pub diagnostic: Diagnostic,
    /// Current session state of the sender.
    pub state: SessionState,
    /// Poll (P) bit.
    pub poll: bool,
    /// Final (F) bit.
    pub final_bit: bool,
    /// Control Plane Independent (C) bit.
    pub control_plane_independent: bool,
    /// Authentication Present (A) bit.
    pub auth_present: bool,
    /// Demand (D) bit.
    pub demand: bool,
    /// Multipoint (M) bit — must always be zero.
    pub multipoint: bool,
    /// Detection time multiplier.
    pub detect_mult: u8,
    /// My Discriminator.
    pub my_discriminator: u32,
    /// Your Discriminator.
    pub your_discriminator: u32,
    /// Desired Min TX Interval (microseconds).
    pub desired_min_tx_interval: u32,
    /// Required Min RX Interval (microseconds).
    pub required_min_rx_interval: u32,
    /// Required Min Echo RX Interval (microseconds).
    pub required_min_echo_rx_interval: u32,
    /// Optional authentication section.
    pub auth: Option<AuthSection>,
}

impl ControlPacket {
    /// Encode the packet to its on-wire byte representation.
    ///
    /// For keyed authentication, `auth.data` is taken as the digest
    /// bytes verbatim (typically zero-filled by the caller, which then
    /// patches the computed digest into the returned buffer — see
    /// [`crate::session::Session::encode_packet`]). For simple password,
    /// `auth.data` holds the password bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; MIN_LEN_NO_AUTH];
        buf[0] = (self.version & 0x07) << 5 | (self.diagnostic.as_u8() & 0x1f);
        buf[1] = (self.state.as_u8() & 0x03) << 6
            | ((self.poll as u8) << 5)
            | ((self.final_bit as u8) << 4)
            | ((self.control_plane_independent as u8) << 3)
            | ((self.auth_present as u8) << 2)
            | ((self.demand as u8) << 1)
            | (self.multipoint as u8);
        buf[2] = self.detect_mult;
        // buf[3] (Length) is filled in last.
        buf[4..8].copy_from_slice(&self.my_discriminator.to_be_bytes());
        buf[8..12].copy_from_slice(&self.your_discriminator.to_be_bytes());
        buf[12..16].copy_from_slice(&self.desired_min_tx_interval.to_be_bytes());
        buf[16..20].copy_from_slice(&self.required_min_rx_interval.to_be_bytes());
        buf[20..24].copy_from_slice(&self.required_min_echo_rx_interval.to_be_bytes());

        if let Some(auth) = &self.auth {
            let mut ab: Vec<u8> = vec![auth.auth_type as u8, 0, auth.key_id, 0];
            match auth.auth_type {
                AuthType::SimplePassword => {
                    let pw = &auth.data;
                    ab[1] = (pw.len() + 3) as u8; // Auth Len = password + 3
                    ab.extend_from_slice(pw);
                }
                AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => {
                    ab[1] = 24;
                    ab.extend_from_slice(&auth.sequence_number.to_be_bytes());
                    let mut d = [0u8; 16];
                    let n = auth.data.len().min(16);
                    d[..n].copy_from_slice(&auth.data[..n]);
                    ab.extend_from_slice(&d);
                }
                AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
                    ab[1] = 28;
                    ab.extend_from_slice(&auth.sequence_number.to_be_bytes());
                    let mut d = [0u8; 20];
                    let n = auth.data.len().min(20);
                    d[..n].copy_from_slice(&auth.data[..n]);
                    ab.extend_from_slice(&d);
                }
                AuthType::Reserved => {}
            }
            buf.extend_from_slice(&ab);
        }

        buf[3] = buf.len() as u8;
        buf
    }

    /// Decode a BFD control packet from its on-wire bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<ControlPacket, BfdError> {
        if buf.len() < MIN_LEN_NO_AUTH {
            return Err(BfdError::PacketTooShort(buf.len()));
        }
        let version = buf[0] >> 5;
        let diagnostic = Diagnostic::from_u8(buf[0] & 0x1f)?;
        let state = SessionState::from_u8((buf[1] >> 6) & 0x03)?;
        let poll = (buf[1] >> 5) & 0x01 == 1;
        let final_bit = (buf[1] >> 4) & 0x01 == 1;
        let control_plane_independent = (buf[1] >> 3) & 0x01 == 1;
        let auth_present = (buf[1] >> 2) & 0x01 == 1;
        let demand = (buf[1] >> 1) & 0x01 == 1;
        let multipoint = buf[1] & 0x01 == 1;
        let detect_mult = buf[2];
        let length = buf[3] as usize;

        if length < MIN_LEN_NO_AUTH || (auth_present && length < MIN_LEN_AUTH) {
            return Err(BfdError::LengthMismatch(length, buf.len()));
        }
        if length > buf.len() {
            return Err(BfdError::LengthMismatch(length, buf.len()));
        }

        let my_discriminator = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let your_discriminator = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let desired_min_tx_interval =
            u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let required_min_rx_interval =
            u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let required_min_echo_rx_interval =
            u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);

        let auth = if auth_present {
            Some(parse_auth_section(&buf[MIN_LEN_NO_AUTH..length])?)
        } else {
            None
        };

        Ok(ControlPacket {
            version,
            diagnostic,
            state,
            poll,
            final_bit,
            control_plane_independent,
            auth_present,
            demand,
            multipoint,
            detect_mult,
            my_discriminator,
            your_discriminator,
            desired_min_tx_interval,
            required_min_rx_interval,
            required_min_echo_rx_interval,
            auth,
        })
    }
}

fn parse_auth_section(slice: &[u8]) -> Result<AuthSection, BfdError> {
    if slice.len() < 3 {
        return Err(BfdError::PacketTooShort(slice.len()));
    }
    let auth_type = AuthType::from_u8(slice[0]);
    let auth_len = slice[1] as usize;
    let key_id = slice[2];
    match auth_type {
        AuthType::Reserved => Err(BfdError::UnsupportedAuth(slice[0])),
        AuthType::SimplePassword => {
            if slice.len() < auth_len || auth_len < 4 {
                return Err(BfdError::LengthMismatch(auth_len, slice.len()));
            }
            let data = slice[3..auth_len].to_vec();
            Ok(AuthSection {
                auth_type,
                key_id,
                sequence_number: 0,
                data,
            })
        }
        AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => {
            if slice.len() < 24 {
                return Err(BfdError::LengthMismatch(24, slice.len()));
            }
            let sequence_number = u32::from_be_bytes(slice[4..8].try_into().unwrap());
            let data = slice[8..24].to_vec();
            Ok(AuthSection {
                auth_type,
                key_id,
                sequence_number,
                data,
            })
        }
        AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
            if slice.len() < 28 {
                return Err(BfdError::LengthMismatch(28, slice.len()));
            }
            let sequence_number = u32::from_be_bytes(slice[4..8].try_into().unwrap());
            let data = slice[8..28].to_vec();
            Ok(AuthSection {
                auth_type,
                key_id,
                sequence_number,
                data,
            })
        }
    }
}
