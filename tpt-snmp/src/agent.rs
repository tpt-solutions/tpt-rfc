// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SNMP agent (server) supporting v1/v2c community messages and v3 (USM).
//!
//! The agent owns a pluggable [`MibHandler`] and a set of local USM users. Its
//! transport-agnostic [`Agent::process`] turns a received datagram into an
//! optional response datagram; a caller wires this to UDP (or any transport).

use std::collections::HashMap;

use crate::mib::MibHandler;
use crate::oid::ObjectIdentifier;
use crate::pdu::{Message, MessageData, Pdu, PduType};
use crate::usm::{
    decrypt_scoped, encrypt_scoped, localize_key, localize_priv_key, password_to_auth_key,
    AuthProtocol, PrivProtocol,
};
use crate::v3::{
    decode_scoped, encode_scoped, HeaderData, ScopedPdu, UsmSecurityParameters, V3Data, V3Message,
};
use crate::value::{SnmpValue, VarBind, VarBindList};

use crate::pdu::{missing_binding, response_for};

/// `usmStatsUnknownEngineIDs` (RFC 3414 §5) — reported during engine discovery.
pub const OID_USM_UNKNOWN_ENGINE: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0];

#[derive(Clone)]
struct AgentUser {
    auth_proto: AuthProtocol,
    priv_proto: PrivProtocol,
    auth_key: Vec<u8>,
    priv_key: [u8; 16],
}

/// An SNMP agent backed by a [`MibHandler`] and configured USM users.
pub struct Agent<M: MibHandler> {
    mib: M,
    engine_id: Vec<u8>,
    engine_boots: u32,
    engine_time: u32,
    users: HashMap<Vec<u8>, AgentUser>,
    salt_counter: u64,
}

impl<M: MibHandler> Agent<M> {
    /// Create an agent with a MIB and an `engineID`. A real engine should use a
    /// unique, stable `engineID` (RFC 3411 §5).
    pub fn new(mib: M, engine_id: Vec<u8>) -> Self {
        Agent {
            mib,
            engine_id,
            engine_boots: 0,
            engine_time: 0,
            users: HashMap::new(),
            salt_counter: 0,
        }
    }

    /// Set the authoritative engine boots/time values.
    pub fn set_engine_time(&mut self, boots: u32, time: u32) {
        self.engine_boots = boots;
        self.engine_time = time;
    }

    /// Register a USM user,_localizing its keys against this engine's `engineID`.
    pub fn add_user(
        &mut self,
        username: &[u8],
        auth_proto: AuthProtocol,
        auth_password: &[u8],
        priv_proto: PrivProtocol,
        priv_password: &[u8],
    ) {
        let auth_key = if auth_proto == AuthProtocol::None {
            Vec::new()
        } else {
            let nak = password_to_auth_key(auth_proto, auth_password);
            localize_key(&nak, &self.engine_id)
        };
        let priv_key = if priv_proto == PrivProtocol::None {
            [0u8; 16]
        } else {
            // RFC 3414 §11: the privacy key is derived from the privacy
            // password with the authentication protocol's hash, then localized
            // against this engine's snmpEngineID.
            let pk = password_to_auth_key(auth_proto, priv_password);
            localize_priv_key(&pk, &self.engine_id)
        };
        self.users.insert(
            username.to_vec(),
            AgentUser {
                auth_proto,
                priv_proto,
                auth_key,
                priv_key,
            },
        );
    }

    fn next_salt(&mut self) -> [u8; 8] {
        let salt = self.salt_counter.to_be_bytes();
        self.salt_counter = self.salt_counter.wrapping_add(1);
        salt
    }

    /// Process one received datagram, returning the response datagram if any.
    pub fn process(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        if let Ok(msg) = Message::decode(bytes) {
            return self.process_community(msg);
        }
        if let Ok(v3) = V3Message::decode(bytes) {
            return self.process_v3(v3, bytes);
        }
        None
    }

    fn process_request(&mut self, req: &Pdu) -> VarBindList {
        match req.pdu_type {
            PduType::GetRequest | PduType::GetNextRequest => {
                let mut out = Vec::new();
                for vb in &req.varbinds.0 {
                    let b = if req.pdu_type == PduType::GetNextRequest {
                        self.mib.get_next(&vb.oid)
                    } else {
                        self.mib.get(&vb.oid)
                    }
                    .unwrap_or_else(|| missing_binding(&vb.oid));
                    out.push(b);
                }
                VarBindList(out)
            }
            PduType::SetRequest => {
                let mut out = Vec::new();
                for vb in &req.varbinds.0 {
                    match self.mib.set(vb) {
                        Ok(()) => out.push(vb.clone()),
                        Err(_) => out.push(missing_binding(&vb.oid)),
                    }
                }
                VarBindList(out)
            }
            PduType::GetBulkRequest => {
                let non_repeaters = req.error_status.max(0) as usize;
                let max_reps = req.error_index.max(0) as usize;
                let binds = &req.varbinds.0;
                let mut out = Vec::new();
                for vb in binds.iter().take(non_repeaters) {
                    let b = self
                        .mib
                        .get(&vb.oid)
                        .unwrap_or_else(|| missing_binding(&vb.oid));
                    out.push(b);
                }
                for vb in &binds[non_repeaters.min(binds.len())..] {
                    let mut cur = vb.oid.clone();
                    for _ in 0..max_reps {
                        match self.mib.get_next(&cur) {
                            Some(b) => {
                                cur = b.oid.clone();
                                out.push(b);
                            }
                            None => break,
                        }
                    }
                }
                VarBindList(out)
            }
            _ => req.varbinds.clone(),
        }
    }

    fn process_community(&mut self, msg: Message) -> Option<Vec<u8>> {
        if let MessageData::Pdu(req) = msg.data {
            let bindings = self.process_request(&req);
            let resp = response_for(&req, bindings);
            return Some(
                Message {
                    version: msg.version,
                    community: msg.community,
                    data: MessageData::Pdu(resp),
                }
                .encode(),
            );
        }
        None
    }

    fn process_v3(&mut self, v3: V3Message, raw: &[u8]) -> Option<Vec<u8>> {
        let usm = &v3.security_parameters;

        // Authentication verification.
        if v3.header.auth() {
            match self.users.get(&usm.user_name) {
                Some(u) if u.auth_proto != AuthProtocol::None => {
                    if !v3.verify_auth(raw, &u.auth_key, u.auth_proto) {
                        return None;
                    }
                }
                _ => return None,
            }
        }

        // Decrypt the scoped PDU if privacy was requested.
        let scoped = match &v3.data {
            V3Data::Plain(s) => s.clone(),
            V3Data::Encrypted(ct) => {
                if !v3.header.is_priv() {
                    return None;
                }
                let u = self.users.get(&usm.user_name)?;
                if u.priv_proto == PrivProtocol::None {
                    return None;
                }
                let pt = decrypt_scoped(
                    ct,
                    &u.priv_key,
                    u.priv_proto,
                    usm.authoritative_engine_boots,
                    usm.authoritative_engine_time,
                    &usm.priv_parameters,
                )
                .ok()?;
                decode_scoped(&pt).ok()?
            }
        };

        // Engine discovery: a request without auth (and an unknown/empty engine)
        // is answered with a reportable Report carrying our engine identity.
        let known_user = self.users.contains_key(&usm.user_name);
        if !v3.header.auth() && (usm.authoritative_engine_id.is_empty() || !known_user) {
            return Some(self.build_discovery(&v3, &scoped.pdu));
        }

        let bindings = self.process_request(&scoped.pdu);
        let resp_pdu = response_for(&scoped.pdu, bindings);
        let resp_scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: scoped.context_name.clone(),
            pdu: resp_pdu,
        };

        let mut resp_flags: u8 = 0;
        if v3.header.auth() {
            resp_flags |= 0x01;
        }
        let respond_priv = v3.header.is_priv();
        if respond_priv {
            resp_flags |= 0x02;
        }

        let user = self.users.get(&usm.user_name).cloned();
        let auth_proto = if resp_flags & 0x01 != 0 {
            user.as_ref()
                .map(|u| u.auth_proto)
                .unwrap_or(AuthProtocol::None)
        } else {
            AuthProtocol::None
        };
        let auth_key = if resp_flags & 0x01 != 0 {
            user.as_ref().map(|u| u.auth_key.clone())
        } else {
            None
        };

        let mut resp_usm = UsmSecurityParameters {
            authoritative_engine_id: self.engine_id.clone(),
            authoritative_engine_boots: self.engine_boots,
            authoritative_engine_time: self.engine_time,
            user_name: usm.user_name.clone(),
            auth_parameters: [0; 12],
            priv_parameters: [0; 8],
        };

        let data = if respond_priv {
            let u = user?;
            let salt = self.next_salt();
            resp_usm.priv_parameters = salt;
            let ct = encrypt_scoped(
                &encode_scoped(&resp_scoped),
                &u.priv_key,
                u.priv_proto,
                self.engine_boots,
                self.engine_time,
                &salt,
            );
            V3Data::Encrypted(ct)
        } else {
            V3Data::Plain(resp_scoped)
        };

        let resp = V3Message {
            header: HeaderData {
                msg_id: v3.header.msg_id,
                msg_max_size: v3.header.msg_max_size,
                msg_flags: resp_flags,
                msg_security_model: 3,
            },
            security_parameters: resp_usm,
            data,
        };
        Some(resp.encode_signed(auth_key.as_deref(), auth_proto))
    }

    fn build_discovery(&self, v3: &V3Message, req: &Pdu) -> Vec<u8> {
        let report = Pdu::new(
            PduType::Report,
            req.request_id,
            0,
            0,
            VarBindList(vec![VarBind::new(
                ObjectIdentifier::new(OID_USM_UNKNOWN_ENGINE.to_vec()),
                SnmpValue::Counter32(1),
            )]),
        );
        let scoped = ScopedPdu {
            context_engine_id: self.engine_id.clone(),
            context_name: Vec::new(),
            pdu: report,
        };
        let resp = V3Message {
            header: HeaderData {
                msg_id: v3.header.msg_id,
                msg_max_size: v3.header.msg_max_size,
                // reportable only (RFC 3414 §5); no auth/priv for a discovery reply
                msg_flags: 0x04,
                msg_security_model: 3,
            },
            security_parameters: UsmSecurityParameters {
                authoritative_engine_id: self.engine_id.clone(),
                authoritative_engine_boots: self.engine_boots,
                authoritative_engine_time: self.engine_time,
                user_name: Vec::new(),
                auth_parameters: [0; 12],
                priv_parameters: [0; 8],
            },
            data: V3Data::Plain(scoped),
        };
        resp.encode()
    }
}
