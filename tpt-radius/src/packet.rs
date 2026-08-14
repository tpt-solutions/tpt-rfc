// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RADIUS packet encode/decode and shared-secret cryptography.
//!
//! A RADIUS packet is `Code (1) | Identifier (1) | Length (2) | Authenticator
//! (16) | Attributes…` (RFC 2865 §3). This module provides [`Packet`] with
//! wire (`encode`/`decode`), attribute accessors, the PAP password hiding of
//! §5.2, the response/accounting authenticator computation of §3, and the
//! `Message-Authenticator` HMAC of RFC 3579 §3.2.

use crate::attribute::{Attribute, AttributeType};
use crate::crypto::{hmac_md5, md5, md5_concat};
use crate::error::{DecodeError, RadiusError};

/// Size of the fixed RADIUS header (Code + Identifier + Length + Authenticator).
pub const HEADER_LEN: usize = 20;
/// Size of the 16-octet Authenticator field.
pub const AUTHENTICATOR_LEN: usize = 16;
/// Maximum permitted RADIUS packet length (RFC 2865 §3).
pub const MAX_PACKET_LEN: usize = 4096;
/// Maximum value length that fits in a single attribute (Length field is 1 byte).
pub const MAX_ATTR_VALUE_LEN: usize = 253;

/// The RADIUS packet code (the 1-octet `Code` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketCode {
    /// `Access-Request` (1).
    AccessRequest,
    /// `Access-Accept` (2).
    AccessAccept,
    /// `Access-Reject` (3).
    AccessReject,
    /// `Accounting-Request` (RFC 2866, 4).
    AccountingRequest,
    /// `Accounting-Response` (RFC 2866, 5).
    AccountingResponse,
    /// `Access-Challenge` (11).
    AccessChallenge,
    /// Any other (experimental/reserved) code.
    Other(u8),
}

impl PacketCode {
    /// Map a raw code byte to a [`PacketCode`].
    pub fn from_u8(v: u8) -> PacketCode {
        match v {
            1 => PacketCode::AccessRequest,
            2 => PacketCode::AccessAccept,
            3 => PacketCode::AccessReject,
            4 => PacketCode::AccountingRequest,
            5 => PacketCode::AccountingResponse,
            11 => PacketCode::AccessChallenge,
            other => PacketCode::Other(other),
        }
    }

    /// Map a [`PacketCode`] to its raw byte.
    pub fn to_u8(self) -> u8 {
        match self {
            PacketCode::AccessRequest => 1,
            PacketCode::AccessAccept => 2,
            PacketCode::AccessReject => 3,
            PacketCode::AccountingRequest => 4,
            PacketCode::AccountingResponse => 5,
            PacketCode::AccessChallenge => 11,
            PacketCode::Other(v) => v,
        }
    }
}

/// A complete RADIUS packet in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The packet code (request/response type).
    pub code: PacketCode,
    /// The 1-octet identifier, used to match requests and replies.
    pub identifier: u8,
    /// The 16-octet authenticator (random for Access-Request, a signature
    /// elsewhere).
    pub authenticator: [u8; 16],
    /// The attribute list (AVPs), in wire order.
    pub attributes: Vec<Attribute>,
}

impl Packet {
    /// Build a packet from its parts.
    pub fn new(
        code: PacketCode,
        identifier: u8,
        authenticator: [u8; 16],
        attributes: Vec<Attribute>,
    ) -> Packet {
        Packet {
            code,
            identifier,
            authenticator,
            attributes,
        }
    }

    /// Construct an `Access-Request` carrying a hidden `User-Password`.
    ///
    /// The supplied `authenticator` should be unpredictable (e.g. from
    /// [`crate::Client::random_authenticator`]). The password is hidden with
    /// the shared secret per RFC 2865 §5.2.
    pub fn access_request(
        identifier: u8,
        authenticator: [u8; 16],
        secret: &[u8],
        user_name: &str,
        password: &str,
    ) -> Result<Packet, RadiusError> {
        let mut packet = Packet::new(
            PacketCode::AccessRequest,
            identifier,
            authenticator,
            vec![Attribute::user_name(user_name)],
        );
        packet.hide_user_password(secret, password.as_bytes())?;
        Ok(packet)
    }

    /// Decode a packet from its wire representation.
    ///
    /// Octets beyond the `Length` field are ignored (padding); a packet shorter
    /// than `Length` is rejected (RFC 2865 §3).
    pub fn decode(buf: &[u8]) -> Result<Packet, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if declared < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if declared > buf.len() {
            return Err(DecodeError::LengthMismatch {
                declared,
                available: buf.len(),
            });
        }

        let code = PacketCode::from_u8(buf[0]);
        let identifier = buf[1];
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&buf[4..HEADER_LEN]);

        let mut attributes = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < declared {
            if offset + 2 > declared {
                return Err(DecodeError::AttributeTruncated {
                    offset,
                    len: declared - offset,
                    end: declared,
                });
            }
            let type_code = buf[offset];
            let attr_len = buf[offset + 1] as usize;
            if attr_len < 2 {
                return Err(DecodeError::AttributeTooShort {
                    offset,
                    len: attr_len,
                });
            }
            if offset + attr_len > declared {
                return Err(DecodeError::AttributeTruncated {
                    offset,
                    len: attr_len,
                    end: declared,
                });
            }
            let value = buf[offset + 2..offset + attr_len].to_vec();
            attributes.push(Attribute::new(AttributeType(type_code), value));
            offset += attr_len;
        }

        Ok(Packet {
            code,
            identifier,
            authenticator,
            attributes,
        })
    }

    /// Encode the packet to its wire representation, computing the `Length`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.encoded_attrs_len());
        buf.push(self.code.to_u8());
        buf.push(self.identifier);
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&self.authenticator);
        for attr in &self.attributes {
            let vlen = attr.value.len();
            debug_assert!(vlen <= MAX_ATTR_VALUE_LEN);
            buf.push(attr.type_.0);
            buf.push((vlen + 2) as u8);
            buf.extend_from_slice(&attr.value);
        }
        let len = buf.len() as u16;
        buf[2] = (len >> 8) as u8;
        buf[3] = (len & 0xff) as u8;
        buf
    }

    fn encoded_attrs_len(&self) -> usize {
        self.attributes.iter().map(|a| a.value.len() + 2).sum()
    }

    /// Find the first attribute with the given type.
    pub fn attribute(&self, type_: AttributeType) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.type_ == type_)
    }

    /// Iterate over all attributes with the given type, in wire order.
    pub fn attributes(&self, type_: AttributeType) -> impl Iterator<Item = &Attribute> {
        self.attributes.iter().filter(move |a| a.type_ == type_)
    }

    /// Borrow the `User-Name` (1) value as text, if present.
    pub fn user_name(&self) -> Option<&str> {
        self.attribute(AttributeType::USER_NAME)
            .and_then(|a| a.as_text().ok())
    }

    /// Append an attribute.
    pub fn add(&mut self, attribute: Attribute) {
        self.attributes.push(attribute);
    }

    /// Hide a PAP password into the `User-Password` attribute (RFC 2865 §5.2).
    ///
    /// The password is null-padded to a multiple of 16 octets and XORed with a
    /// chain of `MD5(secret || previous-block)`, where the first "previous
    /// block" is the request authenticator. Any existing `User-Password`
    /// attribute is replaced.
    pub fn hide_user_password(
        &mut self,
        secret: &[u8],
        password: &[u8],
    ) -> Result<(), RadiusError> {
        if secret.is_empty() {
            return Err(RadiusError::EmptySecret);
        }
        if self.code != PacketCode::AccessRequest {
            return Err(RadiusError::NotAccessRequest);
        }
        let ra = self.authenticator;
        let mut pw = password.to_vec();
        while pw.len() % 16 != 0 {
            pw.push(0);
        }
        let mut cipher = Vec::with_capacity(pw.len());
        let mut prev = ra.to_vec();
        for chunk in pw.chunks(16) {
            let digest = md5_concat(secret, &prev);
            let mut block = [0u8; 16];
            for (j, &b) in chunk.iter().enumerate() {
                block[j] = b ^ digest[j];
            }
            cipher.extend_from_slice(&block);
            prev.copy_from_slice(&block);
        }
        self.attributes
            .retain(|a| a.type_ != AttributeType::USER_PASSWORD);
        self.attributes
            .push(Attribute::user_password_hidden(&cipher));
        Ok(())
    }

    /// Recover the PAP password from the `User-Password` attribute (RFC 2865 §5.2).
    pub fn user_password(&self, secret: &[u8]) -> Result<Vec<u8>, RadiusError> {
        if secret.is_empty() {
            return Err(RadiusError::EmptySecret);
        }
        let attr = self
            .attribute(AttributeType::USER_PASSWORD)
            .ok_or(RadiusError::MissingPassword)?;
        let c = &attr.value;
        if c.is_empty() || c.len() % 16 != 0 {
            return Err(RadiusError::PasswordLength(c.len()));
        }
        let mut pw = Vec::with_capacity(c.len());
        let mut prev = self.authenticator.to_vec();
        for chunk in c.chunks(16) {
            let digest = md5_concat(secret, &prev);
            for (j, &b) in chunk.iter().enumerate() {
                pw.push(b ^ digest[j]);
            }
            prev.copy_from_slice(chunk);
        }
        while pw.last() == Some(&0) {
            pw.pop();
        }
        Ok(pw)
    }

    /// Add an `EAP-Message` (79) payload, splitting it into 253-octet fragments
    /// as required by RFC 3579.
    pub fn add_eap_message(&mut self, data: &[u8]) {
        for chunk in data.chunks(MAX_ATTR_VALUE_LEN) {
            self.attributes.push(Attribute::eap_message(chunk));
        }
    }

    /// Concatenate all `EAP-Message` (79) fragments into a single payload.
    pub fn eap_message(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for a in &self.attributes {
            if a.type_ == AttributeType::EAP_MESSAGE {
                out.extend_from_slice(&a.value);
            }
        }
        out
    }

    /// Compute the response authenticator for this packet (RFC 2865 §3).
    ///
    /// `request_auth` is the authenticator of the corresponding request:
    /// the random `Access-Request` authenticator for access replies, or the
    /// computed `Accounting-Request` authenticator for accounting replies.
    ///
    /// `ResponseAuth = MD5(Code | Identifier | Length | RequestAuth | Attributes | Secret)`.
    pub fn response_authenticator(&self, request_auth: &[u8; 16], secret: &[u8]) -> [u8; 16] {
        self.md5_authenticator(secret, Some(request_auth))
    }

    /// Set this packet's authenticator field to the computed response
    /// authenticator for the given request authenticator and secret.
    pub fn set_response_authenticator(&mut self, request_auth: &[u8; 16], secret: &[u8]) {
        self.authenticator = self.response_authenticator(request_auth, secret);
    }

    /// Compute the `Accounting-Request` authenticator (RFC 2866 §3).
    ///
    /// Unlike `Access-Request`, the accounting authenticator is a signature:
    /// `MD5(Code | Identifier | Length | 16 zero octets | Attributes | Secret)`.
    pub fn accounting_request_authenticator(&self, secret: &[u8]) -> [u8; 16] {
        self.md5_authenticator(secret, None)
    }

    /// Set this `Accounting-Request`'s authenticator field to its computed
    /// signature value.
    pub fn set_accounting_request_authenticator(&mut self, secret: &[u8]) {
        self.authenticator = self.accounting_request_authenticator(secret);
    }

    /// Recompute and compare the response authenticator; `true` if it matches.
    pub fn verify_response_authenticator(&self, request_auth: &[u8; 16], secret: &[u8]) -> bool {
        self.response_authenticator(request_auth, secret) == self.authenticator
    }

    /// Recompute and compare the accounting-request authenticator; `true` if it matches.
    pub fn verify_accounting_request_authenticator(&self, secret: &[u8]) -> bool {
        self.accounting_request_authenticator(secret) == self.authenticator
    }

    /// Compute the `Message-Authenticator` HMAC-MD5 (RFC 3579 §3.2).
    ///
    /// The `Message-Authenticator` attribute in this packet (if any) is treated
    /// as 16 zero octets during the computation.
    pub fn compute_message_authenticator(&self, secret: &[u8]) -> [u8; 16] {
        let mut buf = self.encode();
        zero_message_authenticator(&mut buf);
        hmac_md5(secret, &buf)
    }

    /// Add (or refresh) a `Message-Authenticator` (80) attribute computed over
    /// this packet and the shared secret.
    pub fn set_message_authenticator(&mut self, secret: &[u8]) {
        if self
            .attribute(AttributeType::MESSAGE_AUTHENTICATOR)
            .is_none()
        {
            self.attributes
                .push(Attribute::message_authenticator(&[0u8; 16]));
        }
        let tag = self.compute_message_authenticator(secret);
        for a in &mut self.attributes {
            if a.type_ == AttributeType::MESSAGE_AUTHENTICATOR {
                a.value = tag.to_vec();
            }
        }
    }

    /// Verify the `Message-Authenticator` (80) attribute, if present.
    pub fn verify_message_authenticator(&self, secret: &[u8]) -> bool {
        match self.attribute(AttributeType::MESSAGE_AUTHENTICATOR) {
            Some(attr) if attr.value.len() == 16 => {
                let expected = self.compute_message_authenticator(secret);
                attr.value.as_slice() == expected.as_slice()
            }
            _ => false,
        }
    }

    fn md5_authenticator(&self, secret: &[u8], request_auth: Option<&[u8; 16]>) -> [u8; 16] {
        let mut buf = self.encode();
        match request_auth {
            Some(ra) => buf[4..HEADER_LEN].copy_from_slice(ra),
            None => {
                for b in &mut buf[4..HEADER_LEN] {
                    *b = 0;
                }
            }
        }
        buf.extend_from_slice(secret);
        md5(&buf)
    }
}

/// Zero the value of a `Message-Authenticator` (type 80) attribute inside an
/// already-encoded packet, as required during its HMAC computation.
fn zero_message_authenticator(buf: &mut [u8]) {
    if buf.len() < HEADER_LEN {
        return;
    }
    let end = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut offset = HEADER_LEN;
    while offset + 2 <= end && offset < buf.len() {
        let type_code = buf[offset];
        let attr_len = buf[offset + 1] as usize;
        if type_code == 80 && attr_len >= 18 {
            for b in &mut buf[offset + 2..offset + 18] {
                *b = 0;
            }
            break;
        }
        if attr_len < 2 {
            break;
        }
        offset += attr_len;
    }
}
