// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RADIUS client: request construction, shared-secret verification, and a
//! blocking UDP transport.

use std::net::UdpSocket;
use std::time::Duration;

use getrandom::getrandom;

use crate::attribute::Attribute;
use crate::error::RadiusError;
use crate::packet::{Packet, PacketCode, MAX_PACKET_LEN};

/// Default UDP destination port for RADIUS authentication (RFC 2865).
pub const RADIUS_AUTH_PORT: u16 = 1812;
/// Default UDP destination port for RADIUS accounting (RFC 2866).
pub const RADIUS_ACCT_PORT: u16 = 1813;

/// A RADIUS client bound to a shared secret.
///
/// The client allocates identifiers and (for `Access-Request`) a random
/// request authenticator. Replies are verified against the shared secret using
/// the response/accounting authenticator (RFC 2865 §3, RFC 2866 §3).
pub struct Client {
    secret: Vec<u8>,
    next_id: u8,
}

impl Client {
    /// Create a client with the given shared secret, starting identifiers at 0.
    pub fn new(secret: impl Into<Vec<u8>>) -> Client {
        Client {
            secret: secret.into(),
            next_id: 0,
        }
    }

    /// Create a client with the given shared secret and starting identifier.
    pub fn new_with_id(secret: impl Into<Vec<u8>>, start_id: u8) -> Client {
        Client {
            secret: secret.into(),
            next_id: start_id,
        }
    }

    /// Borrow the shared secret.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Allocate the next request identifier (wrapping at 256).
    pub fn next_identifier(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Generate a cryptographically random 16-octet request authenticator.
    pub fn random_authenticator() -> [u8; 16] {
        let mut auth = [0u8; 16];
        getrandom(&mut auth).expect("getrandom failed to obtain randomness");
        auth
    }

    /// Build an `Access-Request` with a hidden PAP `User-Password`.
    pub fn access_request(
        &mut self,
        user_name: &str,
        password: &str,
    ) -> Result<Packet, RadiusError> {
        Packet::access_request(
            self.next_identifier(),
            Self::random_authenticator(),
            &self.secret,
            user_name,
            password,
        )
    }

    /// Build an `Access-Request` from arbitrary attributes. Callers using
    /// `EAP-Message` (79) should follow up with
    /// [`Packet::set_message_authenticator`] before sending.
    pub fn access_request_with(&mut self, attributes: Vec<Attribute>) -> Packet {
        Packet::new(
            PacketCode::AccessRequest,
            self.next_identifier(),
            Self::random_authenticator(),
            attributes,
        )
    }

    /// Verify a reply (Accept/Reject/Challenge) against its request.
    ///
    /// Returns `false` for non-access reply codes, or if the response
    /// authenticator does not match (forged/mis-keyed reply).
    pub fn verify_response(&self, request: &Packet, response: &Packet) -> bool {
        let is_access_reply = matches!(
            response.code,
            PacketCode::AccessAccept | PacketCode::AccessReject | PacketCode::AccessChallenge
        );
        is_access_reply
            && request.code == PacketCode::AccessRequest
            && response.verify_response_authenticator(&request.authenticator, &self.secret)
    }

    /// Build an `Accounting-Request` (RFC 2866) with the given status type and
    /// additional attributes. The accounting authenticator is computed and set.
    pub fn accounting_request(
        &mut self,
        status_type: u32,
        mut attributes: Vec<Attribute>,
    ) -> Result<Packet, RadiusError> {
        if self.secret.is_empty() {
            return Err(RadiusError::EmptySecret);
        }
        attributes.insert(0, Attribute::acct_status_type(status_type));
        let mut packet = Packet::new(
            PacketCode::AccountingRequest,
            self.next_identifier(),
            [0u8; 16],
            attributes,
        );
        packet.set_accounting_request_authenticator(&self.secret);
        Ok(packet)
    }

    /// Verify an `Accounting-Response` against its request.
    pub fn verify_accounting_response(&self, request: &Packet, response: &Packet) -> bool {
        response.code == PacketCode::AccountingResponse
            && request.code == PacketCode::AccountingRequest
            && response.verify_response_authenticator(&request.authenticator, &self.secret)
    }

    /// Send a request over UDP and await a single reply.
    ///
    /// Suitable for tests and simple callers; production use should layer
    /// retransmission/timeout handling per RFC 5080 on top.
    pub fn exchange(
        &mut self,
        server: &str,
        request: &Packet,
        timeout: Duration,
    ) -> std::io::Result<Packet> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(timeout))?;
        socket.send_to(&request.encode(), server)?;
        let mut rbuf = [0u8; MAX_PACKET_LEN];
        let (n, _) = socket.recv_from(&mut rbuf)?;
        Packet::decode(&rbuf[..n])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}
