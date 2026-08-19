// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Service-side AP-REQ/AP-REP handling (RFC 4120 §5.5).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::asn1::{Cursor, Principal};
use crate::crypto::{self, Enctype};
use crate::error::{Error, Result};
use crate::types::*;
use crate::types::EncryptionKey;

use super::key_usage;

/// A service accepting AP-REQ messages for a single service principal.
pub struct Service {
    principal: Principal,
    key: EncryptionKey,
    enct: Enctype,
}

impl Service {
    /// Create a service bound to `service@realm` with its long-term `key`.
    pub fn new(principal: Principal, key: EncryptionKey) -> Result<Self> {
        let enct = Enctype::from_etype(key.keytype as u32)?;
        Ok(Service {
            principal,
            key,
            enct,
        })
    }

    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Accept an AP-REQ (DER bytes of APPLICATION 14), decrypting the ticket
    /// with the service's long-term key and the authenticator with the ticket
    /// session key. Returns the authenticated client identity and the ticket
    /// session key on success.
    pub fn accept(&self, apreq_bytes: &[u8]) -> Result<ApAccepted> {
        let ap = ApReq::decode_application(apreq_bytes)?;
        // The ticket must be for this service.
        if Principal::new(
            &ap.ticket.sname.name_string.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &ap.ticket.realm,
            ap.ticket.sname.name_type,
        ) != self.principal
        {
            return Err(Error::Unexpected("AP-REQ ticket not for this service"));
        }

        let ticket_enct = Enctype::from_etype(ap.ticket.enc_part.etype as u32)?;
        let tkt_plain = crypto::decrypt(
            &ticket_enct,
            &self.key.keyvalue,
            key_usage::TICKET,
            &ap.ticket.enc_part.cipher,
        )?;
        let mut cur = Cursor::new(&tkt_plain);
        let etp = EncTicketPart::decode(&mut cur)?;
        let now = self.now();
        if etp.endtime < now {
            return Err(Error::KrbError { code: 41, etext: Some("ticket expired".into()) });
        }
        if etp.flags & crate::kdc::flags::INITIAL == 0 && etp.flags & crate::kdc::flags::FORWARDABLE == 0 {
            // Allow either; this is an informational check only.
        }

        let session_enct = Enctype::from_etype(etp.key.keytype as u32)?;
        let auth_plain = crypto::decrypt(
            &session_enct,
            &etp.key.keyvalue,
            key_usage::AP_REQ_AUTH,
            &ap.authenticator.cipher,
        )?;
        let mut acur = Cursor::new(&auth_plain);
        let auth = Authenticator::decode(&mut acur)?;
        if auth.ctime > now + 300 || auth.ctime + 300 < now {
            return Err(Error::PreauthRequired);
        }
        let client = Principal {
            name: auth.cname.clone(),
            realm: auth.crealm.clone(),
        };
        Ok(ApAccepted {
            client,
            session_key: etp.key.clone(),
            auth_time: etp.authtime,
            end_time: etp.endtime,
        })
    }

    /// Build an AP-REP (APPLICATION 15) in response to an accepted AP-REQ, using
    /// the ticket session key and a caller-supplied client timestamp. The
    /// returned message proves possession of the service key to the client.
    pub fn make_ap_rep(&self, session_key: &EncryptionKey, ctime: u64, cusec: u32) -> Result<Vec<u8>> {
        let session_enct = Enctype::from_etype(session_key.keytype as u32)?;
        let enc = EncApRepPart {
            ctime,
            cusec,
            subkey: None,
            seq_number: None,
        };
        let enc_part = crypto::encrypt(
            &session_enct,
            &session_key.keyvalue,
            key_usage::AP_REP,
            &enc.encode(),
        )?;
        let rep = ApRep {
            pvno: 5,
            msg_type: 15,
            enc_part: EncryptedData {
                etype: session_enct.etype as i32,
                kvno: None,
                cipher: enc_part,
            },
        };
        Ok(rep.encode_application())
    }
}

/// The result of successfully accepting an AP-REQ.
#[derive(Debug, Clone)]
pub struct ApAccepted {
    pub client: Principal,
    pub session_key: EncryptionKey,
    pub auth_time: u64,
    pub end_time: u64,
}
