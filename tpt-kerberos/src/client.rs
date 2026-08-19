// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kerberos client: the AS-REQ/AS-REP and TGS-REQ/TGS-REP exchanges plus a
//! minimal credential cache.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::asn1::{self, Principal, PrincipalName};
use crate::crypto::{self, Enctype};
use crate::error::{Error, Result};
use crate::kdc::Kdc;
use crate::types::*;
use crate::types::EncryptionKey;

use super::key_usage;

/// A cached Ticket-Granting Ticket (TGT) and its session key.
#[derive(Debug, Clone)]
pub struct CachedTicket {
    pub ticket: Ticket,
    pub session_key: EncryptionKey,
    pub crealm: String,
    pub cname: PrincipalName,
    pub sname: PrincipalName,
    pub authtime: u64,
    pub endtime: u64,
}

/// A Kerberos client for a single user principal.
pub struct Client {
    pub principal: Principal,
    password: String,
    enct: Enctype,
    tgt: Option<CachedTicket>,
    /// Service tickets keyed by `service@realm`.
    svc_tickets: HashMap<String, CachedTicket>,
}

impl Client {
    /// Create a client for `name@realm`.
    pub fn new(name: &str, realm: &str) -> Self {
        Client {
            principal: Principal::new(&[name], realm, NT_PRINCIPAL),
            password: String::new(),
            enct: Enctype::from_etype(crypto::ENCTYPE_AES256_CTS_HMAC_SHA1_96).expect("enctype"),
            tgt: None,
            svc_tickets: HashMap::new(),
        }
    }

    /// Set the client's password (used to derive the long-term key for
    /// pre-authentication).
    pub fn set_password(&mut self, password: &str) {
        self.password = password.to_string();
    }

    fn salt(&self) -> Vec<u8> {
        format!("{}{}", self.principal.realm, self.principal.name.name_string.join("/"))
            .into_bytes()
    }

    fn long_term_key(&self) -> Result<Vec<u8>> {
        crypto::string2key(
            self.enct.etype,
            self.password.as_bytes(),
            &self.salt(),
            crypto::DEFAULT_STRING2KEY_ITER,
        )
    }

    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Perform the AS-REQ/AS-REP exchange against `kdc` and cache the TGT.
    pub fn authenticate<K: Kdc>(&mut self, kdc: &K, password: &str) -> Result<()> {
        self.set_password(password);
        let ltk = self.long_term_key()?;
        let now = self.now();

        // PA-ENC-TIMESTAMP
        let ts = pa_enc_ts::PaEncTsEnc {
            patimestamp: now,
            pausec: None,
        };
        let ts_enc = crypto::encrypt(
            &self.enct,
            &ltk,
            key_usage::PA_ENC_TIMESTAMP,
            &ts.encode(),
        )?;
        let padata = vec![PaData {
            padata_type: PA_ENC_TIMESTAMP,
            padata_value: EncryptedData {
                etype: self.enct.etype as i32,
                kvno: None,
                cipher: ts_enc,
            }
            .encode_implicit(0),
        }];

        let nonce = 0x1234_5678u32;
        let req_body = KdcReqBody {
            kdc_options: 0x0000_0000,
            cname: Some(self.principal.name.clone()),
            realm: self.principal.realm.clone(),
            sname: None,
            from: None,
            till: now + 3600 * 24,
            rtime: None,
            nonce,
            etype: vec![self.enct.etype as i32],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
        let req = KdcReq {
            pvno: 5,
            msg_type: 10, // AS-REQ
            padata: Some(padata),
            req_body,
        };
        let rep_bytes = kdc.as_req(&req)?;
        let rep = KdcRep::decode_application(11, &rep_bytes)?;

        // Decrypt EncASRepPart with the long-term key.
        let plain = crypto::decrypt(
            &self.enct,
            &ltk,
            key_usage::AS_REP,
            &rep.enc_part.cipher,
        )?;
        let mut cur = asn1::Cursor::new(&plain);
        let ek = EncKdcRepPart::decode(&mut cur)?;

        self.tgt = Some(CachedTicket {
            ticket: rep.ticket.clone(),
            session_key: ek.key.clone(),
            crealm: ek.srealm.clone(),
            cname: rep.cname.clone(),
            sname: ek.sname.clone(),
            authtime: ek.authtime,
            endtime: ek.endtime,
        });
        Ok(())
    }

    /// Return a reference to the cached TGT.
    pub fn tgt(&self) -> Option<&CachedTicket> {
        self.tgt.as_ref()
    }

    /// Build a TGS-REQ (PA-TGS-REQ) for `service` and cache the resulting
    /// service ticket.
    pub fn service_ticket<K: Kdc>(&mut self, kdc: &K, service: &str) -> Result<CachedTicket> {
        let tgt = self
            .tgt
            .clone()
            .ok_or_else(|| Error::Constraint("not authenticated; call authenticate() first"))?;
        let svc = Principal::parse(service)?;
        let tgt_session_enct = Enctype::from_etype(tgt.session_key.keytype as u32)?;
        let now = self.now();

        // Build AP-REQ authenticator.
        let authen = Authenticator {
            authenticator_vno: 5,
            crealm: tgt.crealm.clone(),
            cname: tgt.cname.clone(),
            checksum: None,
            cusec: 0,
            ctime: now,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let auth_enc = crypto::encrypt(
            &tgt_session_enct,
            &tgt.session_key.keyvalue,
            key_usage::AP_REQ_AUTH,
            &authen.encode(),
        )?;
        let apreq = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: 0,
            ticket: tgt.ticket.clone(),
            authenticator: EncryptedData {
                etype: tgt_session_enct.etype as i32,
                kvno: None,
                cipher: auth_enc,
            },
        };
        let pa_tgs = PaData {
            padata_type: PA_TGS_REQ,
            padata_value: apreq.encode_application(),
        };

        let nonce = 0x9ABC_DEF0u32;
        let req_body = KdcReqBody {
            kdc_options: 0x0000_0000,
            cname: None,
            realm: tgt.crealm.clone(),
            sname: Some(svc.name.clone()),
            from: None,
            till: now + 3600 * 24,
            rtime: None,
            nonce,
            etype: vec![tgt_session_enct.etype as i32],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
        let req = KdcReq {
            pvno: 5,
            msg_type: 12, // TGS-REQ
            padata: Some(vec![pa_tgs]),
            req_body,
        };
        let rep_bytes = kdc.tgs_req(&req)?;
        let rep = KdcRep::decode_application(13, &rep_bytes)?;

        // Decrypt EncTGSRepPart with the TGT session key.
        let plain = crypto::decrypt(
            &tgt_session_enct,
            &tgt.session_key.keyvalue,
            key_usage::TGS_REP,
            &rep.enc_part.cipher,
        )?;
        let mut cur = asn1::Cursor::new(&plain);
        let ek = EncKdcRepPart::decode(&mut cur)?;

        let cached = CachedTicket {
            ticket: rep.ticket.clone(),
            session_key: ek.key.clone(),
            crealm: ek.srealm.clone(),
            cname: rep.cname.clone(),
            sname: ek.sname.clone(),
            authtime: ek.authtime,
            endtime: ek.endtime,
        };
        self.svc_tickets
            .insert(format!("{}@{}", svc.name.name_string.join("/"), svc.realm), cached.clone());
        Ok(cached)
    }

    /// Build an AP-REQ for a previously obtained service ticket. Returns the
    /// DER-encoded APPLICATION 14 message for transmission to the service.
    pub fn make_ap_req(&self, service: &str) -> Result<Vec<u8>> {
        let svc = Principal::parse(service)?;
        let cached = self
            .svc_tickets
            .get(&format!("{}@{}", svc.name.name_string.join("/"), svc.realm))
            .ok_or_else(|| Error::Constraint("no service ticket; call service_ticket() first"))?;
        let svc_session_enct = Enctype::from_etype(cached.session_key.keytype as u32)?;
        let now = self.now();
        let authen = Authenticator {
            authenticator_vno: 5,
            crealm: cached.crealm.clone(),
            cname: cached.cname.clone(),
            checksum: None,
            cusec: 0,
            ctime: now,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let auth_enc = crypto::encrypt(
            &svc_session_enct,
            &cached.session_key.keyvalue,
            key_usage::AP_REQ_AUTH,
            &authen.encode(),
        )?;
        let apreq = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: 0,
            ticket: cached.ticket.clone(),
            authenticator: EncryptedData {
                etype: svc_session_enct.etype as i32,
                kvno: None,
                cipher: auth_enc,
            },
        };
        Ok(apreq.encode_application())
    }

    /// Cached service ticket for `service`.
    pub fn cached_service_ticket(&self, service: &str) -> Option<&CachedTicket> {
        let svc = Principal::parse(service).ok()?;
        self.svc_tickets
            .get(&format!("{}@{}", svc.name.name_string.join("/"), svc.realm))
    }
}
