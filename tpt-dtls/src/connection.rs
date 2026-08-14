// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DTLS 1.3 connection state machine: a transport-agnostic client/server
//! driver that performs the 1-RTT handshake (including the stateless-cookie
//! round trip), derives handshake and application-traffic keys, and protects
//! application data. The reference handshake authenticates peers with
//! **raw public keys** (RFC 7250) carried in `Certificate` messages, verifying
//! Ed25519 `CertificateVerify` signatures directly — keeping the crate
//! self-contained (no X.509 dependency). A pluggable [`CertVerifier`] allows
//! full PKI validation to be layered on later.

use std::time::Duration;

use crate::crypto::{CipherSuite, Ed25519KeyPair, HashAlg, X25519KeyPair};
use crate::error::{DtlsError, Result};
use crate::handshake::{
    self, Certificate, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
    HandshakeBody, HandshakeMessage, HandshakeType, KeyShareEntry, ServerHello, HRR_RANDOM,
};
use crate::keyschedule::{KeySchedule, TrafficKeys};
use crate::record::{
    build_cleartext, build_protected, open_protected, ConnectionId, CONTENT_APPLICATION_DATA,
    CONTENT_HANDSHAKE,
};
use crate::retransmit::{RetransmitEvent, RetransmitTimer};

/// Ed25519 `CertificateVerify` context string for the server.
pub const SERVER_CV_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
/// Ed25519 `CertificateVerify` context string for the client.
pub const CLIENT_CV_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";

/// Verifies a peer's raw public key presented in a `Certificate` message.
///
/// The default [`AcceptAllVerifier`] trusts any key (sufficient for the
/// in-crate interop harness). Production deployments should supply a verifier
/// that checks the key against configured trust material, or delegate to a
/// full PKI path validator (e.g. `tpt-x509`, Phase 4).
pub trait CertVerifier: Send {
    /// Return `true` if `raw_public_key` (the Ed25519 public key bytes from
    /// the peer's `Certificate` message) is acceptable.
    fn verify(&self, raw_public_key: &[u8]) -> bool;
}

/// A verifier that accepts any raw public key. Intended for tests and
/// closed-environment deployments only.
#[derive(Debug, Default, Clone)]
pub struct AcceptAllVerifier;

impl CertVerifier for AcceptAllVerifier {
    fn verify(&self, _raw_public_key: &[u8]) -> bool {
        true
    }
}

/// Configuration for a DTLS client [`Connection`].
pub struct ClientConfig {
    /// Cipher suites offered, in preference order.
    pub cipher_suites: Vec<CipherSuite>,
    /// Named groups offered (must include `x25519`).
    pub groups: Vec<u16>,
    /// Signature schemes offered (must include `ed25519`).
    pub sig_algs: Vec<u16>,
    /// This endpoint's Ed25519 identity (raw public key signed in
    /// `CertificateVerify`).
    pub identity: Ed25519KeyPair,
    /// Optional Connection ID this client offers (RFC 9146).
    pub connection_id: Option<ConnectionId>,
    /// Verifier for the server's raw public key.
    pub server_verifier: Box<dyn CertVerifier>,
}

/// Configuration for a DTLS server [`Connection`].
pub struct ServerConfig {
    /// Cipher suites supported, in preference order.
    pub cipher_suites: Vec<CipherSuite>,
    /// Named groups supported.
    pub groups: Vec<u16>,
    /// Signature schemes supported.
    pub sig_algs: Vec<u16>,
    /// This endpoint's Ed25519 identity.
    pub identity: Ed25519KeyPair,
    /// Optional Connection ID this server offers (RFC 9146).
    pub connection_id: Option<ConnectionId>,
    /// Secret used to generate/verify stateless cookies.
    pub cookie_secret: [u8; 32],
    /// The client's source-address label used in the cookie HMAC (e.g. its
    /// IP:port). Empty for the in-memory test harness.
    pub client_address: Vec<u8>,
    /// Verifier for the client's raw public key.
    pub client_verifier: Box<dyn CertVerifier>,
}

/// The role of a [`Connection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// Acts as the DTLS client (initiates the handshake).
    Client,
    /// Acts as the DTLS server (responds, issues the cookie).
    Server,
}

/// Connection state-machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    ClientStart,
    ClientWaitServerHello,
    ClientWaitServerFlight,
    ClientConnected,
    ServerStart,
    ServerWaitClientHello,
    ServerWaitClientHelloCookie,
    ServerWaitClientFlight,
    ServerConnected,
}

/// A DTLS 1.3 connection (client or server).
pub struct Connection {
    role: ConnectionRole,
    suite: CipherSuite,
    hash: HashAlg,
    ks: KeySchedule,

    /// Accumulated handshake-message bytes (the TLS transcript).
    transcript: Vec<u8>,

    /// Next send sequence number per epoch (indices 0,1,2).
    send_seq: [u64; 3],
    /// Outgoing handshake `message_seq` counter (per sender).
    msg_seq_counter: u16,
    /// Length of the Connection ID expected on incoming records (0 = none).
    recv_cid_len: usize,
    /// Our Connection ID appended to outgoing records (if offered).
    send_cid: Option<ConnectionId>,

    client_hs: Option<TrafficKeys>,
    server_hs: Option<TrafficKeys>,
    client_app: Option<TrafficKeys>,
    server_app: Option<TrafficKeys>,
    handshake_secret: Option<Vec<u8>>,
    dhe: Option<[u8; 32]>,

    client_random: [u8; 32],
    server_random: [u8; 32],
    client_ks: Option<X25519KeyPair>,
    server_ks: Option<X25519KeyPair>,
    peer_raw_pubkey: Option<Vec<u8>>,
    pending_cookie: Option<Vec<u8>>,

    identity: Ed25519KeyPair,
    verifier: Box<dyn CertVerifier>,

    /// Pending outbound datagrams (one or more records each).
    out: Vec<Vec<u8>>,
    state: State,
    retransmit: RetransmitTimer,
    /// The current handshake flight to retransmit, if any.
    pending_flight: Option<Vec<Vec<u8>>>,

    /// Server-side cookie material.
    cookie_maker: Option<crate::cookie::CookieMaker>,
    server_cookie_secret: Option<[u8; 32]>,
    client_address: Vec<u8>,

    /// Decrypted application-data records awaiting `recv_app_data`.
    app_inbox: Vec<Vec<u8>>,
    connected: bool,
}

impl Connection {
    /// Create a client connection from `config`.
    pub fn new_client(config: ClientConfig) -> Result<Self> {
        let suite = *config
            .cipher_suites
            .first()
            .ok_or(DtlsError::HandshakeIncomplete("no cipher suites"))?;
        let mut c = Self::blank(ConnectionRole::Client, suite);
        c.identity = config.identity;
        c.verifier = config.server_verifier;
        c.send_cid = config.connection_id;
        if c.send_cid.is_some() {
            c.recv_cid_len = c.send_cid.as_ref().map(|c| c.0.len()).unwrap_or(0);
        }
        c.client_ks = Some(X25519KeyPair::generate()?);
        c.client_random = Self::random_32();
        Ok(c)
    }

    /// Create a server connection from `config`.
    pub fn new_server(config: ServerConfig) -> Result<Self> {
        let suite = *config
            .cipher_suites
            .first()
            .ok_or(DtlsError::HandshakeIncomplete("no cipher suites"))?;
        let mut c = Self::blank(ConnectionRole::Server, suite);
        c.identity = config.identity;
        c.verifier = config.client_verifier;
        c.send_cid = config.connection_id;
        if c.send_cid.is_some() {
            c.recv_cid_len = c.send_cid.as_ref().map(|c| c.0.len()).unwrap_or(0);
        }
        c.cookie_maker = Some(crate::cookie::CookieMaker::new(config.cookie_secret));
        c.server_cookie_secret = Some(config.cookie_secret);
        c.client_address = config.client_address;
        c.server_ks = Some(X25519KeyPair::generate()?);
        c.server_random = Self::random_32();
        c.state = State::ServerStart;
        Ok(c)
    }

    fn blank(role: ConnectionRole, suite: CipherSuite) -> Self {
        let hash = suite.hash_alg();
        Self {
            role,
            suite,
            hash,
            ks: KeySchedule::new(hash),
            transcript: Vec::new(),
            send_seq: [0; 3],
            msg_seq_counter: 0,
            recv_cid_len: 0,
            send_cid: None,
            client_hs: None,
            server_hs: None,
            client_app: None,
            server_app: None,
            handshake_secret: None,
            dhe: None,
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            client_ks: None,
            server_ks: None,
            peer_raw_pubkey: None,
            pending_cookie: None,
            identity: Ed25519KeyPair::from_seed(&[0u8; 32]).unwrap(),
            verifier: Box::new(AcceptAllVerifier),
            out: Vec::new(),
            state: if role == ConnectionRole::Client {
                State::ClientStart
            } else {
                State::ServerStart
            },
            retransmit: RetransmitTimer::new(
                Duration::from_millis(100),
                Duration::from_secs(60),
                10,
            ),
            pending_flight: None,
            cookie_maker: None,
            server_cookie_secret: None,
            client_address: Vec::new(),
            app_inbox: Vec::new(),
            connected: false,
        }
    }

    /// The negotiated cipher suite.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    /// Whether the handshake has completed.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    fn tx_hash(&self) -> Vec<u8> {
        self.hash.digest(&self.transcript)
    }

    // -------------------------------------------------------------------
    // Output / retransmission plumbing
    // -------------------------------------------------------------------

    /// Begin the client handshake: sends the first (cookie-less) ClientHello.
    pub fn start(&mut self) -> Result<()> {
        if self.role != ConnectionRole::Client {
            return Err(DtlsError::WrongRole("start is client-only"));
        }
        self.state = State::ClientWaitServerHello;
        let ch = self.build_client_hello(false)?;
        self.send_handshake(HandshakeBody::ClientHello(ch))?;
        self.arm_flight();
        Ok(())
    }

    /// Drain queued outbound datagrams (one or more records each), returning
    /// the concatenated bytes to place on the wire. Retransmittable handshake
    /// flights are retained internally for [`tick`].
    ///
    /// [`tick`]: Connection::tick
    pub fn take_output(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for d in self.out.drain(..) {
            out.extend_from_slice(&d);
        }
        out
    }

    /// Advance the retransmission timer by `dt`, retransmitting the current
    /// flight on timeout. Returns the timer event.
    pub fn tick(&mut self, dt: Duration) -> RetransmitEvent {
        let ev = self.retransmit.tick(dt);
        if ev == RetransmitEvent::Retransmit {
            if let Some(flight) = &self.pending_flight {
                for d in flight {
                    self.out.push(d.clone());
                }
            }
        }
        ev
    }

    /// Queue a handshake message: append to the transcript, encrypt with the
    /// appropriate epoch key, and enqueue the datagram.
    fn send_handshake(&mut self, body: HandshakeBody) -> Result<()> {
        let msg_seq = self.next_send_msg_seq();
        let msg = HandshakeMessage::new(body, msg_seq);
        let bytes = msg.encode();
        self.msg_seq_counter += 1;
        let epoch = if self.connected { 2 } else { self.handshake_epoch() };
        let datagram = self.encrypt(epoch, CONTENT_HANDSHAKE, &bytes)?;
        self.transcript.extend_from_slice(&bytes);
        self.out.push(datagram);
        Ok(())
    }

    /// The epoch used for outgoing handshake records (0 before keys exist,
    /// 1 once handshake keys are established).
    fn handshake_epoch(&self) -> u16 {
        if self.client_hs.is_some() || self.server_hs.is_some() {
            1
        } else {
            0
        }
    }

    fn next_send_msg_seq(&self) -> u16 {
        self.msg_seq_counter
    }

    fn arm_flight(&mut self) {
        self.pending_flight = Some(self.out.clone());
        self.retransmit.arm();
    }

    fn clear_flight(&mut self) {
        self.pending_flight = None;
        self.retransmit.disarm();
    }

    // -------------------------------------------------------------------
    // Record encryption / decryption
    // -------------------------------------------------------------------

    /// Encrypt `content` as a record of `inner_type` at `epoch`, using the
    /// appropriate traffic keys for this role/direction.
    fn encrypt(&mut self, epoch: u16, inner_type: u8, content: &[u8]) -> Result<Vec<u8>> {
        if epoch == 0 {
            // Cleartext handshake record (ClientHello / ServerHello).
            let seq = self.send_seq[0];
            if seq > 0xFF_FFFF_FFFF_FFFF {
                return Err(DtlsError::SequenceOverflow(0));
            }
            self.send_seq[0] += 1;
            return Ok(build_cleartext(CONTENT_HANDSHAKE, 0, seq, content));
        }
        let keys = self.outgoing_keys(epoch)?;
        let (key, iv) = (keys.key.clone(), keys.iv.clone());
        let seq = self.send_seq[epoch as usize];
        if seq > 0xFF_FFFF_FFFF_FFFF {
            return Err(DtlsError::SequenceOverflow(epoch));
        }
        self.send_seq[epoch as usize] += 1;
        let outer = CONTENT_APPLICATION_DATA;
        build_protected(
            self.suite,
            &key,
            &iv,
            epoch,
            seq,
            outer,
            inner_type,
            content,
            self.send_cid.as_ref(),
        )
    }

    /// The traffic keys used to *send* at `epoch` for this role.
    fn outgoing_keys(&self, epoch: u16) -> Result<&TrafficKeys> {
        match (self.role, epoch) {
            (ConnectionRole::Client, 1) => self
                .client_hs
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("client hs keys missing")),
            (ConnectionRole::Client, 2) => self
                .client_app
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("client app keys missing")),
            (ConnectionRole::Server, 1) => self
                .server_hs
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("server hs keys missing")),
            (ConnectionRole::Server, 2) => self
                .server_app
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("server app keys missing")),
            _ => Err(DtlsError::HandshakeIncomplete("no keys for epoch")),
        }
    }

    /// The traffic keys used to *receive* at `epoch` for this role.
    fn incoming_keys(&self, epoch: u16) -> Result<&TrafficKeys> {
        match (self.role, epoch) {
            (ConnectionRole::Client, 1) => self
                .server_hs
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("server hs keys missing")),
            (ConnectionRole::Client, 2) => self
                .server_app
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("server app keys missing")),
            (ConnectionRole::Server, 1) => self
                .client_hs
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("client hs keys missing")),
            (ConnectionRole::Server, 2) => self
                .client_app
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("client app keys missing")),
            _ => Err(DtlsError::HandshakeIncomplete("no keys for epoch")),
        }
    }

    fn random_32() -> [u8; 32] {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("system randomness");
        buf
    }

    // -------------------------------------------------------------------
    // Inbound processing
    // -------------------------------------------------------------------

    /// Process one received datagram (which may contain several records).
    /// Parses each record, decrypts protected records, and dispatches
    /// handshake or application-data content to the state machine.
    pub fn process_datagram(&mut self, datagram: &[u8]) -> Result<()> {
        let mut pos = 0;
        while pos < datagram.len() {
            let (header, rest) = match crate::record::RecordHeader::decode(&datagram[pos..]) {
                Ok(x) => x,
                Err(e) => return Err(e),
            };
            let body_len = header.length as usize;
            if rest.len() < body_len {
                return Err(DtlsError::RecordLengthMismatch(body_len, rest.len()));
            }
            let (body, trailing) = rest.split_at(body_len);
            // Determine trailing CID length from the configured receive CID.
            let (cid, advance) = if self.recv_cid_len > 0 && trailing.len() >= self.recv_cid_len {
                (
                    Some(ConnectionId::new(trailing[..self.recv_cid_len].to_vec())?),
                    body_len + self.recv_cid_len,
                )
            } else if self.recv_cid_len > 0 {
                (
                    Some(ConnectionId::new(trailing.to_vec())?),
                    body_len + trailing.len(),
                )
            } else {
                (None, body_len)
            };
            pos += 13 + advance;

            if header.epoch == 0 && header.content_type == CONTENT_HANDSHAKE {
                // Cleartext handshake record (ClientHello / ServerHello).
                self.handle_handshake_bytes(body)?;
            } else if header.epoch >= 1 {
                let keys = self.incoming_keys(header.epoch)?.clone();
                let (inner_type, content) = open_protected(
                    self.suite,
                    &keys.key,
                    &keys.iv,
                    &header,
                    body,
                    cid.as_ref(),
                )?;
                if inner_type == CONTENT_HANDSHAKE {
                    self.handle_handshake_bytes(&content)?;
                } else if inner_type == CONTENT_APPLICATION_DATA {
                    self.app_inbox.push(content);
                }
            }
            // Other content types (alert, ACK) are ignored in this release.
        }
        Ok(())
    }

    /// Parse (and reassemble, if fragmented) a handshake message and dispatch.
    fn handle_handshake_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut r = crate::wire::Reader::new(bytes);
        let msg_type = HandshakeType::from_code(r.read_u8()?)?;
        let _length = r.read_u24()?;
        let msg_seq = r.read_u16()?;
        let frag_offset = r.read_u24()?;
        let frag_length = r.read_u24()?;
        let frag = r.read_bytes(frag_length as usize)?;

        if frag_offset == 0 && frag_length as usize == frag.len() {
            let body = HandshakeBody::parse(msg_type, frag)?;
            let msg = HandshakeMessage {
                msg_type,
                message_seq: msg_seq,
                body,
            };
            self.on_handshake_message(msg)?;
        } else {
            // Fragmented: reassemble (rare for our handshake messages).
            let total = _length;
            let mut reass = handshake::Reassembler::new(msg_seq, total);
            if let Some(full) = reass.add(frag_offset, frag)? {
                let body = HandshakeBody::parse(msg_type, &full)?;
                self.on_handshake_message(HandshakeMessage {
                    msg_type,
                    message_seq: msg_seq,
                    body,
                })?;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------------
    // Handshake message dispatch
    // -------------------------------------------------------------------

    /// Dispatch a fully-parsed handshake message to the role/state-specific
    /// handler. The message is *not* added to the transcript here; the
    /// handlers append it (or its verified content) as appropriate.
    fn on_handshake_message(&mut self, msg: HandshakeMessage) -> Result<()> {
        match self.role {
            ConnectionRole::Client => self.client_on_message(msg),
            ConnectionRole::Server => self.server_on_message(msg),
        }
    }

    fn client_on_message(&mut self, msg: HandshakeMessage) -> Result<()> {
        match &msg.body {
            HandshakeBody::ServerHello(sh) if sh.is_hello_retry_request() => {
                if self.state != State::ClientWaitServerHello {
                    return Err(DtlsError::UnexpectedHandshake(msg.msg_type));
                }
                self.handle_hrr(msg)
            }
            HandshakeBody::ServerHello(sh) => {
                if self.state != State::ClientWaitServerHello {
                    return Err(DtlsError::UnexpectedHandshake(msg.msg_type));
                }
                self.handle_server_hello(sh.clone(), msg.message_seq)
            }
            HandshakeBody::EncryptedExtensions(_)
            | HandshakeBody::Certificate(_)
            | HandshakeBody::CertificateVerify(_)
            | HandshakeBody::Finished(_) => {
                if self.state != State::ClientWaitServerFlight {
                    return Err(DtlsError::UnexpectedHandshake(msg.msg_type));
                }
                self.handle_server_flight_message(msg)
            }
            _ => Err(DtlsError::UnexpectedHandshake(msg.msg_type)),
        }
    }

    /// Client: handle a HelloRetryRequest carrying a stateless cookie.
    fn handle_hrr(&mut self, msg: HandshakeMessage) -> Result<()> {
        // The transcript must include the received HRR (CH1 || HRR || CH2 ||
        // ServerHello is the handshake-context hash input).
        let bytes = msg.encode();
        self.transcript.extend_from_slice(&bytes);
        let hrr = match &msg.body {
            HandshakeBody::ServerHello(h) => h.clone(),
            _ => unreachable!(),
        };
        self.pending_cookie = hrr.cookie.clone();
        // Resend ClientHello with the cookie, reusing the same random.
        self.state = State::ClientWaitServerHello;
        let ch = self.build_client_hello(true)?;
        self.send_handshake(HandshakeBody::ClientHello(ch))?;
        self.arm_flight();
        Ok(())
    }

    /// Client: handle the real ServerHello, derive handshake keys, and prepare
    /// to receive the server's encrypted flight.
    fn handle_server_hello(&mut self, sh: ServerHello, msg_seq: u16) -> Result<()> {
        self.server_random = sh.random;
        let ks_entry = sh
            .key_share
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("server hello missing key_share"))?;
        let client_ks = self
            .client_ks
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("no client key share"))?;
        let dhe = client_ks.agree(&ks_entry.key_exchange)?;
        self.dhe = Some(dhe);
        // Append this SH, then derive handshake keys over CH1||HRR||CH2||SH.
        let sh_bytes = HandshakeMessage::new(HandshakeBody::ServerHello(sh), msg_seq).encode();
        self.transcript.extend_from_slice(&sh_bytes);
        self.derive_handshake_secrets(dhe)?;
        self.state = State::ClientWaitServerFlight;
        self.clear_flight();
        Ok(())
    }

    /// Client: process one message of the server's encrypted flight
    /// (EE/Cert/CV/Finished). Verifies CV and Finished inline.
    fn handle_server_flight_message(&mut self, msg: HandshakeMessage) -> Result<()> {
        match &msg.body {
            HandshakeBody::Certificate(c) => {
                if !self.verifier.verify(&c.cert_data) {
                    return Err(DtlsError::CertificateVerifyFailed);
                }
                self.peer_raw_pubkey = Some(c.cert_data.clone());
                let bytes = msg.encode();
                self.transcript.extend_from_slice(&bytes);
            }
            HandshakeBody::CertificateVerify(cv) => {
                let ts = self.tx_hash();
                self.verify_cv(SERVER_CV_CONTEXT, &ts, cv)?;
                let bytes = msg.encode();
                self.transcript.extend_from_slice(&bytes);
            }
            HandshakeBody::Finished(f) => {
                let ts = self.tx_hash();
                let keys = self
                    .server_hs
                    .as_ref()
                    .ok_or(DtlsError::HandshakeIncomplete("server hs keys"))?;
                let fk = keys.finished_key(&self.ks);
                let expected = self.ks.finished_verify_data(&fk, &ts);
                if !crate::replay::ct_eq(&expected, &f.verify_data) {
                    return Err(DtlsError::FinishedMismatch);
                }
                let bytes = msg.encode();
                self.transcript.extend_from_slice(&bytes);
                // Server authenticated; send our flight now.
                self.send_client_flight()?;
            }
            HandshakeBody::EncryptedExtensions(_) => {
                let bytes = msg.encode();
                self.transcript.extend_from_slice(&bytes);
            }
            _ => return Err(DtlsError::UnexpectedHandshake(msg.msg_type)),
        }
        Ok(())
    }

    /// Client: send Certificate / CertificateVerify / Finished under the
    /// client handshake keys, then derive application keys and connect.
    fn send_client_flight(&mut self) -> Result<()> {
        let cert = Certificate {
            request_context: Vec::new(),
            cert_data: self.identity.public_bytes().to_vec(),
        };
        self.send_handshake(HandshakeBody::Certificate(cert))?;

        let ts = self.tx_hash();
        let cv = self.build_cv(CLIENT_CV_CONTEXT, &ts)?;
        self.send_handshake(HandshakeBody::CertificateVerify(cv))?;

        let ts = self.tx_hash();
        let keys = self
            .client_hs
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("client hs keys"))?;
        let fk = keys.finished_key(&self.ks);
        let vd = self.ks.finished_verify_data(&fk, &ts);
        self.send_handshake(HandshakeBody::Finished(Finished { verify_data: vd }))?;

        self.derive_app_secrets()?;
        self.connected = true;
        self.state = State::ClientConnected;
        self.arm_flight();
        Ok(())
    }

    // -------------------------------------------------------------------
    // Server-side handlers
    // -------------------------------------------------------------------

    fn server_on_message(&mut self, msg: HandshakeMessage) -> Result<()> {
        match &msg.body {
            HandshakeBody::ClientHello(_) => {
                if self.state != State::ServerWaitClientHello
                    && self.state != State::ServerWaitClientHelloCookie
                {
                    return Err(DtlsError::UnexpectedHandshake(msg.msg_type));
                }
                self.handle_client_hello(msg)
            }
            HandshakeBody::Certificate(_)
            | HandshakeBody::CertificateVerify(_)
            | HandshakeBody::Finished(_) => {
                if self.state != State::ServerWaitClientFlight {
                    return Err(DtlsError::UnexpectedHandshake(msg.msg_type));
                }
                self.handle_client_flight_message(msg)
            }
            _ => Err(DtlsError::UnexpectedHandshake(msg.msg_type)),
        }
    }

    /// Server: process a ClientHello. If it carries no cookie, reply with a
    /// HelloRetryRequest (stateless cookie). Otherwise verify the cookie and
    /// proceed with the handshake.
    fn handle_client_hello(&mut self, msg: HandshakeMessage) -> Result<()> {
        let ch = match &msg.body {
            HandshakeBody::ClientHello(c) => c.clone(),
            _ => unreachable!(),
        };
        // Record the ClientHello in the transcript (CH1 or CH2).
        let ch_bytes = msg.encode();
        self.transcript.extend_from_slice(&ch_bytes);

        if ch.cookie.is_none() {
            // First ClientHello: issue a stateless cookie via HRR.
            let maker = self
                .cookie_maker
                .as_ref()
                .ok_or(DtlsError::HandshakeIncomplete("no cookie maker"))?;
            let cookie = maker.generate(&self.client_address, &ch.random);
            let hrr = ServerHello {
                random: HRR_RANDOM,
                session_id_echo: ch.session_id.clone(),
                cipher_suite: self.suite.code(),
                key_share: None,
                connection_id: self.send_cid.clone(),
                cookie: Some(cookie),
            };
            self.send_handshake(HandshakeBody::ServerHello(hrr))?;
            self.state = State::ServerWaitClientHelloCookie;
            self.clear_flight();
            self.arm_flight();
            return Ok(());
        }

        // Second ClientHello with a cookie: verify it.
        let maker = self
            .cookie_maker
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("no cookie maker"))?;
        let expected = maker.generate(&self.client_address, &ch.random);
        if !crate::replay::ct_eq(&expected, ch.cookie.as_ref().unwrap()) {
            return Err(DtlsError::CookieMismatch);
        }
        let ks_entry = ch
            .key_share
            .first()
            .ok_or(DtlsError::HandshakeIncomplete("client hello missing key_share"))?;
        let server_ks = self
            .server_ks
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("no server key share"))?;
        let dhe = server_ks.agree(&ks_entry.key_exchange)?;
        self.dhe = Some(dhe);

        // Send the real ServerHello (cleartext, epoch 0).
        let sh = ServerHello {
            random: self.server_random,
            session_id_echo: ch.session_id.clone(),
            cipher_suite: self.suite.code(),
            key_share: Some(KeyShareEntry {
                group: handshake::group::X25519,
                key_exchange: server_ks.public.to_vec(),
            }),
            connection_id: self.send_cid.clone(),
            cookie: None,
        };
        self.send_handshake(HandshakeBody::ServerHello(sh))?;
        self.derive_handshake_secrets(dhe)?;
        self.send_server_flight()?;
        self.state = State::ServerWaitClientFlight;
        self.clear_flight();
        self.arm_flight();
        Ok(())
    }

    /// Server: send EncryptedExtensions / Certificate / CertificateVerify /
    /// Finished under the server handshake keys.
    fn send_server_flight(&mut self) -> Result<()> {
        self.send_handshake(HandshakeBody::EncryptedExtensions(EncryptedExtensions::default()))?;

        let cert = Certificate {
            request_context: Vec::new(),
            cert_data: self.identity.public_bytes().to_vec(),
        };
        self.send_handshake(HandshakeBody::Certificate(cert))?;

        let ts = self.tx_hash();
        let cv = self.build_cv(SERVER_CV_CONTEXT, &ts)?;
        self.send_handshake(HandshakeBody::CertificateVerify(cv))?;

        let ts = self.tx_hash();
        let keys = self
            .server_hs
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("server hs keys"))?;
        let fk = keys.finished_key(&self.ks);
        let vd = self.ks.finished_verify_data(&fk, &ts);
        self.send_handshake(HandshakeBody::Finished(Finished { verify_data: vd }))?;
        Ok(())
    }

    /// Server: process one message of the client's encrypted flight.
    fn handle_client_flight_message(&mut self, msg: HandshakeMessage) -> Result<()> {
        match &msg.body {
            HandshakeBody::Certificate(c) => {
                if !self.verifier.verify(&c.cert_data) {
                    return Err(DtlsError::CertificateVerifyFailed);
                }
                self.peer_raw_pubkey = Some(c.cert_data.clone());
                let bytes = msg.encode();
                self.transcript.extend_from_slice(&bytes);
            }
            HandshakeBody::CertificateVerify(cv) => {
                let ts = self.tx_hash();
                self.verify_cv(CLIENT_CV_CONTEXT, &ts, cv)?;
                let bytes = msg.encode();
                self.transcript.extend_from_slice(&bytes);
            }
            HandshakeBody::Finished(f) => {
                let ts = self.tx_hash();
                let keys = self
                    .client_hs
                    .as_ref()
                    .ok_or(DtlsError::HandshakeIncomplete("client hs keys"))?;
                let fk = keys.finished_key(&self.ks);
                let expected = self.ks.finished_verify_data(&fk, &ts);
                if !crate::replay::ct_eq(&expected, &f.verify_data) {
                    return Err(DtlsError::FinishedMismatch);
                }
                let bytes = msg.encode();
                self.transcript.extend_from_slice(&bytes);
                // Client authenticated; derive app keys and connect.
                self.derive_app_secrets()?;
                self.connected = true;
                self.state = State::ServerConnected;
                self.clear_flight();
            }
            _ => return Err(DtlsError::UnexpectedHandshake(msg.msg_type)),
        }
        Ok(())
    }

    // -------------------------------------------------------------------
    // Key schedule / signing helpers
    // -------------------------------------------------------------------

    /// Build the ClientHello body (with or without the echoed cookie).
    fn build_client_hello(&self, with_cookie: bool) -> Result<ClientHello> {
        let ks = self
            .client_ks
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("no client key share"))?;
        Ok(ClientHello {
            random: self.client_random,
            session_id: Vec::new(),
            cipher_suites: vec![self.suite.code()],
            groups: vec![handshake::group::X25519],
            sig_algs: vec![handshake::sigscheme::ED25519],
            key_share: vec![KeyShareEntry {
                group: handshake::group::X25519,
                key_exchange: ks.public.to_vec(),
            }],
            cookie: if with_cookie {
                self.pending_cookie.clone()
            } else {
                None
            },
            connection_id: self.send_cid.clone(),
        })
    }

    /// Build a `CertificateVerify` signing `context || 0x20 || ts`.
    fn build_cv(&self, context: &[u8], ts: &[u8]) -> Result<CertificateVerify> {
        let mut msg = Vec::with_capacity(context.len() + 1 + ts.len());
        msg.extend_from_slice(context);
        msg.push(0x20);
        msg.extend_from_slice(ts);
        let sig = self.identity.sign(&msg);
        Ok(CertificateVerify {
            algorithm: handshake::sigscheme::ED25519,
            signature: sig.to_vec(),
        })
    }

    /// Verify a peer `CertificateVerify` over `context || 0x20 || ts`.
    fn verify_cv(&self, context: &[u8], ts: &[u8], cv: &CertificateVerify) -> Result<()> {
        let mut msg = Vec::with_capacity(context.len() + 1 + ts.len());
        msg.extend_from_slice(context);
        msg.push(0x20);
        msg.extend_from_slice(ts);
        let pk = self
            .peer_raw_pubkey
            .as_ref()
            .ok_or(DtlsError::HandshakeIncomplete("no peer public key"))?;
        if !crate::crypto::ed25519_verify(pk, &msg, &cv.signature) {
            return Err(DtlsError::CertificateVerifyFailed);
        }
        Ok(())
    }

    /// Derive the handshake traffic secrets from the (EC)DHE shared secret
    /// over the transcript CH1||HRR||CH2||ServerHello.
    fn derive_handshake_secrets(&mut self, dhe: [u8; 32]) -> Result<()> {
        let hl = self.hash.output_len();
        let pki = vec![0u8; hl];
        let early = self.ks.extract(Some(&pki), &pki);
        let derived = self.ks.expand_label(&early, "derived", &[], hl);
        let hs_secret = self.ks.extract(Some(&derived), &dhe);
        let hs_hash = self.tx_hash();
        let c_hs = self.ks.derive_secret(&hs_secret, "c hs traffic", &hs_hash);
        let s_hs = self.ks.derive_secret(&hs_secret, "s hs traffic", &hs_hash);
        self.client_hs = Some(TrafficKeys::from_secret(&self.ks, self.suite, &c_hs));
        self.server_hs = Some(TrafficKeys::from_secret(&self.ks, self.suite, &s_hs));
        self.handshake_secret = Some(hs_secret);
        Ok(())
    }

    /// Derive the application-traffic secrets over the transcript that
    /// includes the client Finished.
    fn derive_app_secrets(&mut self) -> Result<()> {
        let hs = self
            .handshake_secret
            .clone()
            .ok_or(DtlsError::HandshakeIncomplete("no handshake secret"))?;
        let hl = self.hash.output_len();
        let pki = vec![0u8; hl];
        let derived2 = self.ks.expand_label(&hs, "derived", &[], hl);
        let master = self.ks.extract(Some(&derived2), &pki);
        let app_hash = self.tx_hash();
        let c_app = self.ks.derive_secret(&master, "c ap traffic", &app_hash);
        let s_app = self.ks.derive_secret(&master, "s ap traffic", &app_hash);
        self.client_app = Some(TrafficKeys::from_secret(&self.ks, self.suite, &c_app));
        self.server_app = Some(TrafficKeys::from_secret(&self.ks, self.suite, &s_app));
        Ok(())
    }

    // -------------------------------------------------------------------
    // Application data
    // -------------------------------------------------------------------

    /// Encrypt and queue one application-data record (epoch 2). Only valid
    /// once [`is_connected`](Connection::is_connected) is true.
    pub fn send_app_data(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(DtlsError::HandshakeIncomplete("not connected"));
        }
        let datagram = self.encrypt(2, CONTENT_APPLICATION_DATA, data)?;
        self.out.push(datagram);
        Ok(())
    }

    /// Pop the next decrypted application-data record received, if any.
    pub fn recv_app_data(&mut self) -> Option<Vec<u8>> {
        if self.app_inbox.is_empty() {
            None
        } else {
            Some(self.app_inbox.remove(0))
        }
    }
}
