// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SNMP manager (client) supporting v1/v2c community messages and v3 (USM).
//!
//! The manager builds request datagrams and parses responses. It is
//! transport-agnostic: a caller sends the bytes produced by `build_*` to an
//! agent and feeds the reply into [`Manager::parse_response`].

use crate::error::SnmpError;
use crate::oid::ObjectIdentifier;
use crate::pdu::{Message, MessageData, Pdu, PduType, SnmpVersion};
use crate::usm::{
    decrypt_scoped, encrypt_scoped, localize_key, localize_priv_key, password_to_auth_key,
    AuthProtocol, PrivProtocol,
};
use crate::v3::{
    decode_scoped, encode_scoped, HeaderData, UsmSecurityParameters, V3Data, V3Message,
};
use crate::value::{SnmpValue, VarBind, VarBindList};

/// An SNMP manager that can issue `Get`/`GetNext`/`Set` and (for v3) perform
/// engine discovery and authenticated/encrypted exchanges.
pub struct Manager {
    community: Option<Vec<u8>>,
    username: Vec<u8>,
    engine_id: Vec<u8>,
    boots: u32,
    time: u32,
    auth_proto: AuthProtocol,
    priv_proto: PrivProtocol,
    auth_key: Vec<u8>,
    priv_key: [u8; 16],
    salt_counter: u64,
    msg_id: i64,
    request_id: i32,
}

impl Manager {
    /// Create a community-string (v2c) manager.
    pub fn v2c(community: &[u8]) -> Self {
        Manager {
            community: Some(community.to_vec()),
            username: Vec::new(),
            engine_id: Vec::new(),
            boots: 0,
            time: 0,
            auth_proto: AuthProtocol::None,
            priv_proto: PrivProtocol::None,
            auth_key: Vec::new(),
            priv_key: [0u8; 16],
            salt_counter: 0,
            msg_id: 1,
            request_id: 1,
        }
    }

    /// Create a v3 (USM) manager, localizing its keys against `engine_id`.
    pub fn v3(
        username: &[u8],
        engine_id: &[u8],
        auth_proto: AuthProtocol,
        auth_password: &[u8],
        priv_proto: PrivProtocol,
        priv_password: &[u8],
    ) -> Self {
        let auth_key = if auth_proto == AuthProtocol::None {
            Vec::new()
        } else {
            let nak = password_to_auth_key(auth_proto, auth_password);
            localize_key(&nak, engine_id)
        };
        let priv_key = if priv_proto == PrivProtocol::None {
            [0u8; 16]
        } else {
            let pk = password_to_auth_key(auth_proto, priv_password);
            localize_priv_key(&pk, engine_id)
        };
        Manager {
            community: None,
            username: username.to_vec(),
            engine_id: engine_id.to_vec(),
            boots: 0,
            time: 0,
            auth_proto,
            priv_proto,
            auth_key,
            priv_key,
            salt_counter: 0,
            msg_id: 1,
            request_id: 1,
        }
    }

    /// Whether this manager uses SNMPv3.
    pub fn is_v3(&self) -> bool {
        self.community.is_none()
    }

    /// The authoritative engine ID currently known to the manager (after
    /// discovery or after processing a response).
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    /// Update the authoritative engine identity learned during discovery.
    pub fn set_engine(&mut self, engine_id: &[u8], boots: u32, time: u32) {
        self.engine_id = engine_id.to_vec();
        self.boots = boots;
        self.time = time;
    }

    fn next_msg_id(&mut self) -> i64 {
        let id = self.msg_id;
        self.msg_id += 1;
        id
    }

    fn next_request_id(&mut self) -> i32 {
        let id = self.request_id;
        self.request_id += 1;
        id
    }

    fn next_salt(&mut self) -> [u8; 8] {
        let salt = self.salt_counter.to_be_bytes();
        self.salt_counter = self.salt_counter.wrapping_add(1);
        salt
    }

    /// Build a `GetRequest` datagram for `oid`.
    pub fn build_get(&mut self, oid: &ObjectIdentifier) -> Vec<u8> {
        let req = self.request(
            PduType::GetRequest,
            vec![VarBind::new(oid.clone(), SnmpValue::Integer(0))],
        );
        self.encode_request(req)
    }

    /// Build a `GetNextRequest` datagram for `oid`.
    pub fn build_get_next(&mut self, oid: &ObjectIdentifier) -> Vec<u8> {
        let req = self.request(
            PduType::GetNextRequest,
            vec![VarBind::new(oid.clone(), SnmpValue::Integer(0))],
        );
        self.encode_request(req)
    }

    /// Build a `SetRequest` datagram.
    pub fn build_set(&mut self, vb: VarBind) -> Vec<u8> {
        let req = self.request(PduType::SetRequest, vec![vb]);
        self.encode_request(req)
    }

    /// Build a `GetBulkRequest` datagram (non-repeaters, max-repetitions).
    pub fn build_get_bulk(
        &mut self,
        repeaters: &[ObjectIdentifier],
        non_repeaters: &[ObjectIdentifier],
        max_repetitions: i32,
    ) -> Vec<u8> {
        let mut binds = non_repeaters
            .iter()
            .map(|o| VarBind::new(o.clone(), SnmpValue::Integer(0)))
            .collect::<Vec<_>>();
        for o in repeaters {
            binds.push(VarBind::new(o.clone(), SnmpValue::Integer(0)));
        }
        let req = Pdu::new(
            PduType::GetBulkRequest,
            self.next_request_id(),
            non_repeaters.len() as i32,
            max_repetitions,
            VarBindList(binds),
        );
        self.encode_request(req)
    }

    /// Build a reportable discovery request (no auth, empty engine/user) used to
    /// learn the authoritative engine identity.
    pub fn build_discovery_request(&mut self, oid: &ObjectIdentifier) -> Vec<u8> {
        let req = Pdu::new(
            PduType::GetRequest,
            self.next_request_id(),
            0,
            0,
            VarBindList(vec![VarBind::new(oid.clone(), SnmpValue::Integer(0))]),
        );
        let scoped = crate::v3::ScopedPdu {
            context_engine_id: Vec::new(),
            context_name: Vec::new(),
            pdu: req,
        };
        let msg = V3Message {
            header: HeaderData {
                msg_id: self.next_msg_id(),
                msg_max_size: 65507,
                msg_flags: 0x04, // reportable
                msg_security_model: 3,
            },
            security_parameters: UsmSecurityParameters {
                authoritative_engine_id: Vec::new(),
                authoritative_engine_boots: 0,
                authoritative_engine_time: 0,
                user_name: Vec::new(),
                auth_parameters: [0; 12],
                priv_parameters: [0; 8],
            },
            data: V3Data::Plain(scoped),
        };
        msg.encode()
    }

    fn request(&mut self, pdu_type: PduType, varbinds: Vec<VarBind>) -> Pdu {
        Pdu::new(
            pdu_type,
            self.next_request_id(),
            0,
            0,
            VarBindList(varbinds),
        )
    }

    fn encode_request(&mut self, req: Pdu) -> Vec<u8> {
        if let Some(community) = &self.community {
            return Message {
                version: SnmpVersion::V2c,
                community: community.clone(),
                data: MessageData::Pdu(req),
            }
            .encode();
        }
        let scoped = crate::v3::ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: Vec::new(),
            pdu: req,
        };
        let mut flags: u8 = 0;
        let mut priv_parameters = [0u8; 8];
        let data = if self.priv_proto != PrivProtocol::None {
            let salt = self.next_salt();
            priv_parameters = salt;
            flags |= 0x02;
            let ct = encrypt_scoped(
                &encode_scoped(&scoped),
                &self.priv_key,
                self.priv_proto,
                self.boots,
                self.time,
                &salt,
            );
            V3Data::Encrypted(ct)
        } else {
            V3Data::Plain(scoped)
        };
        if self.auth_proto != AuthProtocol::None {
            flags |= 0x01;
        }
        let msg = V3Message {
            header: HeaderData {
                msg_id: self.next_msg_id(),
                msg_max_size: 65507,
                msg_flags: flags,
                msg_security_model: 3,
            },
            security_parameters: UsmSecurityParameters {
                authoritative_engine_id: self.engine_id.clone(),
                authoritative_engine_boots: self.boots,
                authoritative_engine_time: self.time,
                user_name: self.username.clone(),
                auth_parameters: [0; 12],
                priv_parameters,
            },
            data,
        };
        msg.encode_signed(
            if self.auth_proto != AuthProtocol::None {
                Some(&self.auth_key)
            } else {
                None
            },
            self.auth_proto,
        )
    }

    /// Decode a response datagram and return its variable bindings. For v3 it
    /// verifies authentication and decrypts privacy as needed, and records the
    /// authoritative engine time for subsequent requests.
    pub fn parse_response(&mut self, bytes: &[u8]) -> Result<VarBindList, SnmpError> {
        if let Ok(msg) = Message::decode(bytes) {
            if let MessageData::Pdu(p) = msg.data {
                return Ok(p.varbinds);
            }
            return Err(SnmpError::Malformed);
        }
        let v3 = V3Message::decode(bytes)?;
        if v3.header.auth() && !v3.verify_auth(bytes, &self.auth_key, self.auth_proto) {
            return Err(SnmpError::AuthFailure);
        }
        // Record engine time from the response for synchronisation.
        if !v3.security_parameters.authoritative_engine_id.is_empty() {
            self.boots = v3.security_parameters.authoritative_engine_boots;
            self.time = v3.security_parameters.authoritative_engine_time;
            self.engine_id = v3.security_parameters.authoritative_engine_id.clone();
        }
        let scoped = match &v3.data {
            V3Data::Plain(s) => s.clone(),
            V3Data::Encrypted(ct) => {
                let pt = decrypt_scoped(
                    ct,
                    &self.priv_key,
                    self.priv_proto,
                    v3.security_parameters.authoritative_engine_boots,
                    v3.security_parameters.authoritative_engine_time,
                    &v3.security_parameters.priv_parameters,
                )?;
                decode_scoped(&pt)?
            }
        };
        Ok(scoped.pdu.varbinds)
    }
}
