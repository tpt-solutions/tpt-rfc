//! BFD session state machine and timers (RFC 5880 §6).
//!
//! A [`Session`] models one endpoint's view of a single BFD session. It
//! is transport-agnostic: callers feed it decoded/encoded packets
//! ([`Session::process_bytes`] / [`Session::next_periodic_packet`] /
//! [`Session::encode_packet`]) and are responsible for putting those
//! bytes on the wire. [`crate::transport::UdpTransport`] provides a
//! ready-made UDP (asynchronous-mode) driver.

use std::time::{Duration, Instant};

use crate::error::BfdError;
use crate::packet::{AuthSection, AuthType, ControlPacket, Diagnostic, SessionState, BFD_VERSION};

/// Role a system takes in session initialization (RFC 5880 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Active systems transmit BFD packets regardless of having received
    /// any, and may thus bootstrap a session unilaterally.
    Active,
    /// Passive systems wait for the first packet before transmitting.
    Passive,
}

/// Authentication configuration for a session.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Authentication type to use. Only `SimplePassword`,
    /// `KeyedSha1`, and `MeticulousKeyedSha1` are implemented.
    pub auth_type: AuthType,
    /// Authentication key ID carried in each packet.
    pub key_id: u8,
    /// Shared secret: the password (simple) or the keyed hash key.
    pub key: Vec<u8>,
}

/// Configuration used to construct a [`Session`].
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Local discriminator. Must be unique and nonzero on this system.
    pub local_discriminator: u32,
    /// Desired Min TX Interval, in microseconds, when the session is Up.
    pub desired_min_tx_interval: u32,
    /// Required Min RX Interval, in microseconds.
    pub required_min_rx_interval: u32,
    /// Detection time multiplier.
    pub detect_mult: u8,
    /// Whether this system wishes to use Demand mode.
    pub demand_mode: bool,
    /// Whether this BFD implementation is independent of the control
    /// plane (sets the C bit).
    pub control_plane_independent: bool,
    /// Initialization role.
    pub role: Role,
    /// Optional authentication.
    pub auth: Option<AuthConfig>,
}

impl SessionConfig {
    /// Validate the configuration, returning an error for unsupported
    /// authentication types.
    pub fn validate(&self) -> Result<(), BfdError> {
        if let Some(auth) = &self.auth {
            match auth.auth_type {
                AuthType::SimplePassword | AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
                    Ok(())
                }
                other => Err(BfdError::UnsupportedAuth(other as u8)),
            }
        } else {
            Ok(())
        }
    }
}

/// Outcome of feeding a received packet into a [`Session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketResult {
    /// The packet failed validation and was discarded (no state change).
    Discarded,
    /// The packet was accepted. `respond` is `Some` when the received
    /// packet had the Poll (P) bit set and an immediate Final (F)
    /// response must be transmitted.
    Accepted {
        /// An immediate response packet to transmit (Final bit set).
        respond: Option<ControlPacket>,
    },
}

/// State of one BFD session endpoint (RFC 5880 §6.8.1).
pub struct Session {
    // --- Local state variables ---
    session_state: SessionState,
    local_diag: Diagnostic,
    local_discr: u32,
    desired_min_tx: u32,
    required_min_rx: u32,
    detect_mult: u8,
    demand_mode: bool,
    cpi: bool,
    role: Role,
    auth: Option<AuthConfig>,

    // --- Remote state variables (as learned from received packets) ---
    remote_discr: u32,
    remote_state: SessionState,
    remote_demand: bool,
    remote_min_rx: u32,
    remote_desired_min_tx: u32,
    remote_detect_mult: u8,

    // --- Runtime ---
    last_rx: Option<Instant>,
    poll_sequence: bool,
    poll_start: Option<Instant>,
    xmit_auth_seq: u32,
    rcv_auth_seq: u32,
    auth_seq_known: bool,
}

impl Session {
    /// Construct a new session from `config`. The session always begins
    /// in the `Down` state.
    pub fn new(config: SessionConfig) -> Result<Session, BfdError> {
        config.validate()?;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0);
        Ok(Session {
            session_state: SessionState::Down,
            local_diag: Diagnostic::None,
            local_discr: config.local_discriminator,
            desired_min_tx: config.desired_min_tx_interval,
            required_min_rx: config.required_min_rx_interval,
            detect_mult: config.detect_mult,
            demand_mode: config.demand_mode,
            cpi: config.control_plane_independent,
            role: config.role,
            auth: config.auth,
            remote_discr: 0,
            remote_state: SessionState::Down,
            remote_demand: false,
            remote_min_rx: 1,
            remote_desired_min_tx: 0,
            remote_detect_mult: 0,
            last_rx: None,
            poll_sequence: false,
            poll_start: None,
            xmit_auth_seq: seed,
            rcv_auth_seq: 0,
            auth_seq_known: false,
        })
    }

    /// The current local session state.
    pub fn state(&self) -> SessionState {
        self.session_state
    }

    /// Whether the session is currently `Up`.
    pub fn is_up(&self) -> bool {
        self.session_state == SessionState::Up
    }

    /// The most recent local diagnostic code.
    pub fn local_diag(&self) -> Diagnostic {
        self.local_diag
    }

    /// The remote discriminator learned from the peer, if any.
    pub fn remote_discriminator(&self) -> u32 {
        self.remote_discr
    }

    /// The remote session state last reported by the peer.
    pub fn remote_state(&self) -> SessionState {
        self.remote_state
    }

    /// Whether Demand mode is currently active on the remote system
    /// (remote D bit set, both ends `Up`).
    pub fn remote_demand_active(&self) -> bool {
        self.remote_demand
            && self.session_state == SessionState::Up
            && self.remote_state == SessionState::Up
    }

    /// Whether the local system would set the Demand (D) bit on its next
    /// transmitted packet (local demand mode requested and both ends
    /// `Up`).
    pub fn demand_bit(&self) -> bool {
        self.demand_mode
            && self.session_state == SessionState::Up
            && self.remote_state == SessionState::Up
    }

    /// Set the session administratively down, signaling
    /// [`Diagnostic::AdministrativelyDown`].
    pub fn admin_down(&mut self) {
        self.session_state = SessionState::AdminDown;
        self.local_diag = Diagnostic::AdministrativelyDown;
    }

    /// Take the session out of `AdminDown`, returning it to `Down`.
    pub fn admin_up(&mut self) {
        if self.session_state == SessionState::AdminDown {
            self.session_state = SessionState::Down;
            self.local_diag = Diagnostic::None;
        }
    }

    /// Begin a Poll Sequence (RFC 5880 §6.5). The next transmitted
    /// packets will carry the Poll (P) bit until a Final (F) is
    /// received.
    pub fn start_poll(&mut self) {
        self.poll_sequence = true;
        self.poll_start = Some(Instant::now());
    }

    /// Encode a packet to its on-wire byte representation, computing the
    /// keyed authentication digest when authentication is configured.
    pub fn encode_packet(&self, pkt: &ControlPacket) -> Vec<u8> {
        let cfg = match &self.auth {
            None => return pkt.to_bytes(),
            Some(c) => c,
        };
        match cfg.auth_type {
            AuthType::SimplePassword => pkt.to_bytes(),
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
                let digest_len = cfg.auth_type.digest_len();
                let mut buf = pkt.to_bytes();
                let off = 24 + 8;
                // Digest field is replaced by the (padded) key while the
                // hash is computed (RFC 5880 §6.7.4).
                let mut key_padded = vec![0u8; digest_len];
                let n = cfg.key.len().min(digest_len);
                key_padded[..n].copy_from_slice(&cfg.key[..n]);
                buf[off..off + digest_len].copy_from_slice(&key_padded);
                let digest = sha1_hash(&buf);
                buf[off..off + digest_len].copy_from_slice(&digest);
                buf
            }
            _ => pkt.to_bytes(),
        }
    }

    /// Decode and process a received BFD packet from raw bytes,
    /// performing authentication and discriminator validation, then
    /// driving the state machine. Returns `Ok(Some(packet))` when an
    /// immediate Final (F) response must be transmitted, or `Ok(None)`
    /// when the packet was accepted without response or was discarded.
    pub fn process_bytes(&mut self, buf: &[u8]) -> Result<Option<ControlPacket>, BfdError> {
        let pkt = match ControlPacket::from_bytes(buf) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let auth_in_use = self.auth.is_some();
        if pkt.auth_present != auth_in_use {
            return Ok(None);
        }
        if pkt.auth_present && !self.verify_auth(&pkt, buf)? {
            return Ok(None);
        }
        match self.process_packet(&pkt)? {
            PacketResult::Discarded => Ok(None),
            PacketResult::Accepted { respond } => Ok(respond),
        }
    }

    /// Process an already-decoded control packet against the reception
    /// rules and state machine (RFC 5880 §6.8.6). Authentication must
    /// already have been validated by the caller (see
    /// [`Session::process_bytes`]).
    pub fn process_packet(&mut self, pkt: &ControlPacket) -> Result<PacketResult, BfdError> {
        if pkt.version != BFD_VERSION {
            return Ok(PacketResult::Discarded);
        }
        if pkt.detect_mult == 0 {
            return Ok(PacketResult::Discarded);
        }
        if pkt.multipoint {
            return Ok(PacketResult::Discarded);
        }
        if pkt.my_discriminator == 0 {
            return Ok(PacketResult::Discarded);
        }
        if pkt.your_discriminator != 0 && pkt.your_discriminator != self.local_discr {
            return Ok(PacketResult::Discarded);
        }
        if pkt.your_discriminator == 0
            && pkt.state != SessionState::Down
            && pkt.state != SessionState::AdminDown
        {
            return Ok(PacketResult::Discarded);
        }

        // Learn remote parameters (RFC 5880 §6.8.6).
        self.remote_discr = pkt.my_discriminator;
        self.remote_state = pkt.state;
        self.remote_demand = pkt.demand;
        self.remote_min_rx = pkt.required_min_rx_interval;
        self.remote_desired_min_tx = pkt.desired_min_tx_interval;
        self.remote_detect_mult = pkt.detect_mult;

        let mut respond = None;
        if pkt.final_bit && self.poll_sequence {
            self.poll_sequence = false;
            self.poll_start = None;
        }

        if self.session_state == SessionState::AdminDown {
            // Packet is discarded (no state change) once AdminDown.
            self.last_rx = Some(Instant::now());
            return Ok(PacketResult::Accepted { respond: None });
        }

        if pkt.state == SessionState::AdminDown {
            if self.session_state != SessionState::Down {
                self.local_diag = Diagnostic::NeighborSignaledSessionDown;
                self.session_state = SessionState::Down;
            }
        } else if self.session_state == SessionState::Down {
            // RFC 5880 §6.8.6 (the normative procedure; note the §6.2
            // diagram has a known erratum — Down+Down must advance to
            // Init, which is what real implementations follow).
            if pkt.state == SessionState::Down {
                self.session_state = SessionState::Init;
            } else if pkt.state == SessionState::Init {
                self.session_state = SessionState::Up;
            }
        } else if self.session_state == SessionState::Init {
            if pkt.state == SessionState::Init || pkt.state == SessionState::Up {
                self.session_state = SessionState::Up;
            }
        } else {
            // session_state == Up
            if pkt.state == SessionState::Down {
                self.local_diag = Diagnostic::NeighborSignaledSessionDown;
                self.session_state = SessionState::Down;
            }
        }

        if pkt.poll {
            respond = Some(self.build_packet(false, true));
        }

        self.last_rx = Some(Instant::now());
        Ok(PacketResult::Accepted { respond })
    }

    /// Build the next periodic packet to transmit, if one is permitted.
    /// Returns `None` when periodic transmission must be suppressed
    /// (e.g. passive-with-unknown-peer, remote requested no packets, or
    /// remote Demand mode active and no poll in progress).
    pub fn next_periodic_packet(&mut self) -> Option<ControlPacket> {
        if !self.should_send_periodic() {
            return None;
        }
        Some(self.build_packet(self.poll_sequence, false))
    }

    /// The negotiated transmit interval (RFC 5880 §6.8.7): the greater
    /// of our desired min TX and the remote's required min RX.
    pub fn transmit_interval(&self) -> Duration {
        let tx = self.effective_desired_min_tx().max(self.remote_min_rx);
        Duration::from_micros(tx as u64)
    }

    /// The calculated detection time for this session (RFC 5880 §6.8.4).
    pub fn detection_time(&self) -> Duration {
        let (interval, mult) = if self.remote_demand_active() {
            (
                self.effective_desired_min_tx().max(self.remote_min_rx),
                self.detect_mult,
            )
        } else {
            (
                self.required_min_rx.max(self.remote_desired_min_tx),
                self.remote_detect_mult,
            )
        };
        Duration::from_micros(interval as u64 * mult as u64)
    }

    /// Check the detection timer. Returns `true` if the session was
    /// declared down as a result (RFC 5880 §6.8.4).
    pub fn check_timeout(&mut self) -> bool {
        if self.remote_demand_active() {
            if self.poll_sequence {
                if let Some(start) = self.poll_start {
                    if start.elapsed() >= self.detection_time() {
                        self.declare_down(Diagnostic::ControlDetectionTimeExpired);
                        self.poll_sequence = false;
                        self.poll_start = None;
                        return true;
                    }
                }
            }
            return false;
        }
        if self.session_state == SessionState::Init || self.session_state == SessionState::Up {
            if let Some(t) = self.last_rx {
                if t.elapsed() >= self.detection_time() {
                    self.declare_down(Diagnostic::ControlDetectionTimeExpired);
                    return true;
                }
            }
        }
        false
    }

    // --- internal helpers ---

    fn declare_down(&mut self, diag: Diagnostic) {
        self.session_state = SessionState::Down;
        self.local_diag = diag;
        self.remote_discr = 0;
    }

    fn effective_desired_min_tx(&self) -> u32 {
        if self.session_state == SessionState::Up {
            self.desired_min_tx
        } else {
            // RFC 5880 §6.8.3: when not Up, the effective interval MUST
            // be at least one second.
            self.desired_min_tx.max(1_000_000)
        }
    }

    /// Whether a periodic packet is currently permitted (used by the
    /// UDP transport to gate transmission).
    pub fn should_send_periodic(&self) -> bool {
        if self.role == Role::Passive && self.remote_discr == 0 {
            return false;
        }
        if self.remote_min_rx == 0 {
            return false;
        }
        if self.remote_demand_active() && !self.poll_sequence {
            return false;
        }
        true
    }

    fn build_packet(&mut self, poll: bool, final_bit: bool) -> ControlPacket {
        let d_bit = self.demand_mode
            && self.session_state == SessionState::Up
            && self.remote_state == SessionState::Up;
        let auth = self.auth.as_ref().map(|cfg| {
            let seq = if cfg.auth_type.is_keyed() {
                self.xmit_auth_seq = self.xmit_auth_seq.wrapping_add(1);
                self.xmit_auth_seq
            } else {
                0
            };
            let data = if cfg.auth_type == AuthType::SimplePassword {
                cfg.key.clone()
            } else {
                Vec::new()
            };
            AuthSection {
                auth_type: cfg.auth_type,
                key_id: cfg.key_id,
                sequence_number: seq,
                data,
            }
        });
        ControlPacket {
            version: BFD_VERSION,
            diagnostic: self.local_diag,
            state: self.session_state,
            poll,
            final_bit,
            control_plane_independent: self.cpi,
            auth_present: auth.is_some(),
            demand: d_bit,
            multipoint: false,
            detect_mult: self.detect_mult,
            my_discriminator: self.local_discr,
            your_discriminator: self.remote_discr,
            desired_min_tx_interval: self.effective_desired_min_tx(),
            required_min_rx_interval: self.required_min_rx,
            required_min_echo_rx_interval: 0,
            auth,
        }
    }

    fn verify_auth(&mut self, pkt: &ControlPacket, raw: &[u8]) -> Result<bool, BfdError> {
        let cfg = self.auth.as_ref().unwrap();
        let section = pkt.auth.as_ref().unwrap();
        if section.auth_type != cfg.auth_type {
            return Ok(false);
        }
        match section.auth_type {
            AuthType::SimplePassword => Ok(section.data == cfg.key),
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
                let digest_len = cfg.auth_type.digest_len();
                let off = 24 + 8;
                if raw.len() < off + digest_len {
                    return Ok(false);
                }
                let mut buf = raw.to_vec();
                let mut key_padded = vec![0u8; digest_len];
                let n = cfg.key.len().min(digest_len);
                key_padded[..n].copy_from_slice(&cfg.key[..n]);
                buf[off..off + digest_len].copy_from_slice(&key_padded);
                let digest = sha1_hash(&buf);
                if digest[..] != section.data[..digest_len.min(section.data.len())] {
                    return Ok(false);
                }
                let seq = section.sequence_number;
                if self.auth_seq_known {
                    if cfg.auth_type == AuthType::MeticulousKeyedSha1 {
                        if seq != self.rcv_auth_seq.wrapping_add(1) {
                            return Err(BfdError::AuthSeqReplay);
                        }
                    } else if seq < self.rcv_auth_seq {
                        return Err(BfdError::AuthSeqReplay);
                    }
                }
                self.rcv_auth_seq = seq;
                self.auth_seq_known = true;
                Ok(true)
            }
            _ => Err(BfdError::UnsupportedAuth(section.auth_type as u8)),
        }
    }
}

fn sha1_hash(buf: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(buf);
    let out = h.finalize();
    let mut d = [0u8; 20];
    d.copy_from_slice(&out);
    d
}
