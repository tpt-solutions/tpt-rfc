// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DHCPv6 message: a 1-byte message type, a 3-byte transaction id, and a
//! variable options field (RFC 8415 §7.1, §21), with clean-room encode/decode
//! and typed option accessors.

use crate::error::DecodeError;
use crate::options::{Dhcpv6Option, Duid, IaNa, IaPd, IaTa, MessageType};

/// A DHCPv6 message.
///
/// The fixed header is just `msg-type` (1 byte) + `transaction-id` (3 bytes);
/// everything else (client/server DUIDs, Identity Associations, requested
/// options, status) rides in [`Dhcpv6Message::options`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6Message {
    /// The message type (SOLICIT, ADVERTISE, REQUEST, REPLY, …).
    pub msg_type: MessageType,
    /// Transaction id, echoed by the server to correlate replies.
    pub transaction_id: [u8; 3],
    /// The options carried by the message.
    pub options: Vec<Dhcpv6Option>,
}

impl Dhcpv6Message {
    /// Construct a message of `msg_type` with a zero transaction id and no
    /// options.
    pub fn new(msg_type: MessageType) -> Self {
        Self {
            msg_type,
            transaction_id: [0; 3],
            options: Vec::new(),
        }
    }

    /// Find an option by code.
    pub fn find_option(&self, code: u16) -> Option<&Dhcpv6Option> {
        self.options.iter().find(|o| o.code() == code)
    }

    /// Append an option, replacing any existing option with the same code so a
    /// message never carries a duplicate.
    pub fn set_option(&mut self, opt: Dhcpv6Option) {
        let code = opt.code();
        self.options.retain(|o| o.code() != code);
        self.options.push(opt);
    }

    /// The Client Identifier DUID (option 1), if present.
    pub fn client_id(&self) -> Option<&Duid> {
        match self.find_option(crate::options::OPTION_CLIENTID)? {
            Dhcpv6Option::ClientId(d) => Some(d),
            _ => None,
        }
    }

    /// The Server Identifier DUID (option 2), if present.
    pub fn server_id(&self) -> Option<&Duid> {
        match self.find_option(crate::options::OPTION_SERVERID)? {
            Dhcpv6Option::ServerId(d) => Some(d),
            _ => None,
        }
    }

    /// The IA_NA containers (option 3) in this message.
    pub fn ia_nas(&self) -> Vec<&IaNa> {
        self.options
            .iter()
            .filter_map(|o| match o {
                Dhcpv6Option::IaNa(ia) => Some(ia),
                _ => None,
            })
            .collect()
    }

    /// The IA_TA containers (option 4) in this message.
    pub fn ia_tas(&self) -> Vec<&IaTa> {
        self.options
            .iter()
            .filter_map(|o| match o {
                Dhcpv6Option::IaTa(ia) => Some(ia),
                _ => None,
            })
            .collect()
    }

    /// The IA_PD containers (option 25) in this message.
    pub fn ia_pds(&self) -> Vec<&IaPd> {
        self.options
            .iter()
            .filter_map(|o| match o {
                Dhcpv6Option::IaPd(ia) => Some(ia),
                _ => None,
            })
            .collect()
    }

    /// The Option Request Option (option 6) codes, if present.
    pub fn oro(&self) -> Option<&[u16]> {
        match self.find_option(crate::options::OPTION_ORO)? {
            Dhcpv6Option::Oro(codes) => Some(codes),
            _ => None,
        }
    }

    /// The top-level Status Code (option 13), if present.
    pub fn status_code(&self) -> Option<(u16, &str)> {
        match self.find_option(crate::options::OPTION_STATUS_CODE)? {
            Dhcpv6Option::StatusCode(s) => Some((s.code, s.message.as_str())),
            _ => None,
        }
    }

    /// Whether the Rapid Commit option (14) is present.
    pub fn rapid_commit(&self) -> bool {
        self.find_option(crate::options::OPTION_RAPID_COMMIT).is_some()
    }

    /// Encode the message to its on-the-wire byte form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.options.len() * 8);
        buf.push(self.msg_type.to_u8());
        buf.extend_from_slice(&self.transaction_id);
        for opt in &self.options {
            buf.extend(opt.encode());
        }
        buf
    }

    /// Decode a message from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Dhcpv6Message, DecodeError> {
        const HEADER_LEN: usize = 4;
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::TruncatedHeader {
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let msg_type = MessageType::from_u8(bytes[0]).ok_or(DecodeError::BadMessageType(bytes[0]))?;
        let transaction_id = [bytes[1], bytes[2], bytes[3]];
        let options = crate::options::parse_options(&bytes[HEADER_LEN..]);
        Ok(Dhcpv6Message {
            msg_type,
            transaction_id,
            options,
        })
    }
}
