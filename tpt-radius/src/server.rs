// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RADIUS server: a pluggable [`AuthBackend`] trait, request processing, and a
//! blocking UDP listener.

use std::net::UdpSocket;
use std::sync::Arc;

use crate::attribute::{Attribute, AttributeType};
use crate::error::RadiusError;
use crate::packet::{Packet, PacketCode, MAX_PACKET_LEN};

/// The decision a backend returns for an authentication request.
#[derive(Debug, Clone)]
pub enum AuthDecision {
    /// Accept the user; `attributes` are appended to the `Access-Accept`.
    Accept {
        /// Attributes to include in the `Access-Accept`.
        attributes: Vec<Attribute>,
    },
    /// Reject the user; `message` becomes a `Reply-Message` when set.
    Reject {
        /// Optional human-readable rejection reason.
        message: Option<String>,
    },
    /// Issue a challenge (RFC 2865 §4.4); `state` becomes a `State` attribute.
    Challenge {
        /// Opaque state echoed by the NAS on the next `Access-Request`.
        state: Vec<u8>,
        /// Optional challenge prompt (`Reply-Message`).
        reply_message: Option<String>,
        /// Additional attributes to include in the `Access-Challenge`.
        attributes: Vec<Attribute>,
    },
}

/// A normalized view of an incoming `Access-Request`, passed to the backend.
#[derive(Debug)]
pub struct AuthRequest<'a> {
    /// The raw request packet.
    pub packet: &'a Packet,
    /// The `User-Name` value, if present and valid UTF-8.
    pub username: Option<&'a str>,
    /// The decrypted PAP `User-Password`, if present.
    pub password: Option<Vec<u8>>,
    /// The `State` value (from a prior challenge), if present.
    pub state: Option<&'a [u8]>,
    /// All request attributes, in wire order.
    pub attributes: &'a [Attribute],
}

/// Authentication backend for [`Server`].
///
/// Implementors decide accept/reject/challenge for each request. The optional
/// [`account`][Self::account] method receives accounting requests; the default
/// implementation ignores them.
pub trait AuthBackend: Send + Sync {
    /// Authenticate an `Access-Request`.
    fn authenticate(&self, request: &AuthRequest<'_>) -> AuthDecision;

    /// Handle an `Accounting-Request` (RFC 2866). Default: ignore.
    fn account(&self, _request: &Packet) {}
}

/// A RADIUS server bound to a shared secret and an [`AuthBackend`].
pub struct Server<B: AuthBackend> {
    backend: Arc<B>,
    secret: Vec<u8>,
}

impl<B: AuthBackend> Server<B> {
    /// Create a server. The shared secret must be non-empty.
    pub fn new(backend: Arc<B>, secret: impl Into<Vec<u8>>) -> Result<Server<B>, RadiusError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(RadiusError::EmptySecret);
        }
        Ok(Server {
            backend: Arc::clone(&backend),
            secret,
        })
    }

    /// Process a decoded packet, returning the reply packet (if any).
    ///
    /// Returns `Ok(None)` for packet codes this server does not answer (and for
    /// requests whose authenticator fails verification, which are silently
    /// discarded per RFC 2865 §3 / RFC 2866 §3).
    pub fn process(&self, packet: &Packet) -> Result<Option<Packet>, RadiusError> {
        match packet.code {
            PacketCode::AccessRequest => self.process_access_request(packet),
            PacketCode::AccountingRequest => self.process_accounting(packet),
            _ => Ok(None),
        }
    }

    /// Decode and process a packet from wire bytes.
    pub fn process_bytes(&self, buf: &[u8]) -> Result<Option<Vec<u8>>, RadiusError> {
        let packet = Packet::decode(buf)?;
        let reply = self.process(&packet)?;
        Ok(reply.map(|p| p.encode()))
    }

    /// Run a blocking UDP listener that answers requests forever.
    ///
    /// Each datagram is decoded and, if it yields a reply, the reply is sent
    /// back to the sender. Malformed or unverifiable datagrams are dropped.
    pub fn run(&self, addr: &str) -> std::io::Result<()> {
        let socket = UdpSocket::bind(addr)?;
        let mut buf = [0u8; MAX_PACKET_LEN];
        loop {
            let (n, src) = socket.recv_from(&mut buf)?;
            if let Ok(Some(reply)) = self.process_bytes(&buf[..n]) {
                let _ = socket.send_to(&reply, src);
            }
        }
    }

    fn process_access_request(&self, request: &Packet) -> Result<Option<Packet>, RadiusError> {
        if request.attribute(AttributeType::EAP_MESSAGE).is_some()
            && !request.verify_message_authenticator(&self.secret)
        {
            // RFC 3579: a request with EAP-Message but an invalid
            // Message-Authenticator is silently discarded.
            return Ok(None);
        }

        let username = request
            .attribute(AttributeType::USER_NAME)
            .and_then(|a| a.as_text().ok());
        let password = if request.attribute(AttributeType::USER_PASSWORD).is_some() {
            Some(request.user_password(&self.secret)?)
        } else {
            None
        };
        let state = request
            .attribute(AttributeType::STATE)
            .map(|a| a.value.as_slice());
        let auth_request = AuthRequest {
            packet: request,
            username,
            password,
            state,
            attributes: &request.attributes,
        };

        let decision = self.backend.authenticate(&auth_request);
        let proxy_state: Vec<Attribute> = request
            .attributes
            .iter()
            .filter(|a| a.type_ == AttributeType::PROXY_STATE)
            .cloned()
            .collect();

        let mut reply = match decision {
            AuthDecision::Accept { mut attributes } => {
                attributes.extend(proxy_state);
                Packet::new(
                    PacketCode::AccessAccept,
                    request.identifier,
                    request.authenticator,
                    attributes,
                )
            }
            AuthDecision::Reject { message } => {
                let mut attributes = Vec::new();
                if let Some(msg) = message {
                    attributes.push(Attribute::reply_message(&msg));
                }
                attributes.extend(proxy_state);
                Packet::new(
                    PacketCode::AccessReject,
                    request.identifier,
                    request.authenticator,
                    attributes,
                )
            }
            AuthDecision::Challenge {
                state,
                reply_message,
                mut attributes,
            } => {
                if !state.is_empty() {
                    attributes.push(Attribute::state(&state));
                }
                if let Some(msg) = reply_message {
                    attributes.push(Attribute::reply_message(&msg));
                }
                attributes.extend(proxy_state);
                Packet::new(
                    PacketCode::AccessChallenge,
                    request.identifier,
                    request.authenticator,
                    attributes,
                )
            }
        };
        reply.set_response_authenticator(&request.authenticator, &self.secret);
        Ok(Some(reply))
    }

    fn process_accounting(&self, request: &Packet) -> Result<Option<Packet>, RadiusError> {
        if !request.verify_accounting_request_authenticator(&self.secret) {
            return Ok(None);
        }
        self.backend.account(request);
        let proxy_state: Vec<Attribute> = request
            .attributes
            .iter()
            .filter(|a| a.type_ == AttributeType::PROXY_STATE)
            .cloned()
            .collect();
        let mut reply = Packet::new(
            PacketCode::AccountingResponse,
            request.identifier,
            request.authenticator,
            proxy_state,
        );
        reply.set_response_authenticator(&request.authenticator, &self.secret);
        Ok(Some(reply))
    }
}
