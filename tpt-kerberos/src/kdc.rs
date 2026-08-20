// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A from-spec Kerberos Key Distribution Centre (KDC).
//!
//! [`MemoryKdc`] is a self-contained KDC usable for testing and examples: it
//! stores principals' long-term keys, issues Ticket-Granting Tickets in the
//! AS-REQ exchange and service tickets in the TGS-REQ exchange, and enforces
//! pre-authentication (`PA-ENC-TIMESTAMP`). The [`Kdc`] trait abstracts the
//! exchange so a network transport could be substituted later.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::asn1::{self, Cursor, Principal};
use crate::crypto::{self, Enctype, ENCTYPE_AES256_CTS_HMAC_SHA1_96};
use crate::error::{Error, Result};
use crate::types::EncryptionKey;
use crate::types::*;
use der::asn1::Any;
use der::Decode;

/// Default ticket lifetime: 10 hours (in seconds).
pub const DEFAULT_LIFETIME: u64 = 10 * 3600;
/// Permitted clock skew: 5 minutes.
pub const CLOCK_SKEW: u64 = 5 * 60;
/// Protocol version number.
pub const PVNO: i32 = 5;

/// Ticket flags (RFC 4120 §5.3 — `TicketFlags`).
pub mod flags {
    pub const RESERVED: u32 = 1 << 31;
    pub const FORWARDABLE: u32 = 1 << 30;
    pub const FORWARDED: u32 = 1 << 29;
    pub const PROXIABLE: u32 = 1 << 28;
    pub const PROXY: u32 = 1 << 27;
    pub const MAY_POSTDATE: u32 = 1 << 26;
    pub const POSTDATED: u32 = 1 << 25;
    pub const INVALID: u32 = 1 << 24;
    pub const RENEWABLE: u32 = 1 << 23;
    pub const INITIAL: u32 = 1 << 22;
    pub const PRE_AUTHENT: u32 = 1 << 21;
    pub const HW_AUTHENT: u32 = 1 << 20;
}

/// A stored principal entry.
#[derive(Debug, Clone)]
pub struct PrincipalEntry {
    pub principal: Principal,
    pub key: EncryptionKey,
    pub salt: Vec<u8>,
    pub etype: u32,
}

/// A KDC that can process AS-REQ and TGS-REQ exchanges.
pub trait Kdc {
    /// Process an AS-REQ, returning the DER-encoded AS-REP (APPLICATION 11).
    fn as_req(&self, req: &KdcReq) -> Result<Vec<u8>>;
    /// Process a TGS-REQ, returning the DER-encoded TGS-REP (APPLICATION 13).
    fn tgs_req(&self, req: &KdcReq) -> Result<Vec<u8>>;
}

/// Return the current time as seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// In-memory KDC for testing/self-contained operation.
#[derive(Default)]
pub struct MemoryKdc {
    principals: HashMap<String, PrincipalEntry>,
    krbtgt: HashMap<String, PrincipalEntry>, // keyed by realm
    realm: String,
    krbtgt_etype: u32,
}

impl MemoryKdc {
    /// Create a KDC for `realm`, generating its `krbtgt` principal key.
    pub fn new_with_realm(realm: &str) -> Self {
        let mut kdc = MemoryKdc {
            realm: realm.to_string(),
            krbtgt_etype: ENCTYPE_AES256_CTS_HMAC_SHA1_96,
            ..Default::default()
        };
        let enct = Enctype::from_etype(kdc.krbtgt_etype).expect("enctype");
        let mut raw = vec![0u8; enct.keylen];
        let _ = getrandom_fill(&mut raw);
        let krbtgt_principal = Principal::new(&["krbtgt", realm], realm, NT_SRV_INST);
        let entry = PrincipalEntry {
            principal: krbtgt_principal.clone(),
            key: EncryptionKey {
                keytype: enct.etype as i32,
                keyvalue: raw,
            },
            salt: format!("KRBTGT{}", realm).into_bytes(),
            etype: enct.etype,
        };
        kdc.krbtgt.insert(realm.to_string(), entry);
        kdc
    }

    /// Create a KDC for the `EXAMPLE.COM` realm (convenience).
    pub fn new() -> Self {
        Self::new_with_realm("EXAMPLE.COM")
    }

    /// Add a user principal with a password-derived key.
    pub fn add_principal(
        &mut self,
        name: &str,
        realm: &str,
        password: &str,
        etype: u32,
    ) -> Result<()> {
        let enct = Enctype::from_etype(etype)?;
        let salt = format!("{}{}", realm, name).into_bytes();
        let keyval = crypto::string2key(
            etype,
            password.as_bytes(),
            &salt,
            crypto::DEFAULT_STRING2KEY_ITER,
        )?;
        let principal = Principal::new(&[name], realm, NT_PRINCIPAL);
        self.principals.insert(
            format!("{}@{}", name, realm),
            PrincipalEntry {
                principal,
                key: EncryptionKey {
                    keytype: enct.etype as i32,
                    keyvalue: keyval,
                },
                salt,
                etype,
            },
        );
        Ok(())
    }

    /// Add a service principal with a password-derived key.
    pub fn add_service(
        &mut self,
        service: &str,
        realm: &str,
        password: &str,
        etype: u32,
    ) -> Result<()> {
        let enct = Enctype::from_etype(etype)?;
        let salt = format!("{}{}", realm, service).into_bytes();
        let keyval = crypto::string2key(
            etype,
            password.as_bytes(),
            &salt,
            crypto::DEFAULT_STRING2KEY_ITER,
        )?;
        // service components split on '/'
        let comps: Vec<&str> = service.split('/').collect();
        let principal = Principal::new(&comps, realm, NT_SRV_INST);
        self.principals.insert(
            format!("{}@{}", service, realm),
            PrincipalEntry {
                principal,
                key: EncryptionKey {
                    keytype: enct.etype as i32,
                    keyvalue: keyval,
                },
                salt,
                etype,
            },
        );
        Ok(())
    }

    fn krbtgt_entry(&self) -> Result<&PrincipalEntry> {
        self.krbtgt()
            .ok_or_else(|| Error::Constraint("no krbtgt key"))
    }

    fn krbtgt(&self) -> Option<&PrincipalEntry> {
        self.krbtgt.get(&self.realm)
    }

    fn lookup(&self, p: &Principal) -> Option<&PrincipalEntry> {
        self.principals
            .get(&format!("{}@{}", p.name.name_string.join("/"), p.realm))
    }

    /// Generate a random session key for the given enctype.
    fn random_session_key(&self, etype: u32) -> Result<EncryptionKey> {
        let enct = Enctype::from_etype(etype)?;
        let mut raw = vec![0u8; enct.keylen];
        getrandom_fill(&mut raw)?;
        Ok(EncryptionKey {
            keytype: enct.etype as i32,
            keyvalue: raw,
        })
    }
}

fn getrandom_fill(buf: &mut [u8]) -> Result<()> {
    ::getrandom::getrandom(buf).map_err(Error::from)
}

impl Kdc for MemoryKdc {
    fn as_req(&self, req: &KdcReq) -> Result<Vec<u8>> {
        let enct_pvno = req.pvno;
        if enct_pvno != PVNO {
            return Err(Error::Unexpected("bad pvno"));
        }
        let body = &req.req_body;
        let cname = body
            .cname
            .clone()
            .ok_or(Error::MissingField("AS-REQ cname"))?;
        let crealm = body.realm.clone();
        let client = Principal {
            name: cname.clone(),
            realm: crealm.clone(),
        };
        let entry = self
            .lookup(&client)
            .ok_or_else(|| Error::Principal(format!("unknown client {}", client.to_string())))?;
        let enct = Enctype::from_etype(entry.etype)?;

        // Verify PA-ENC-TIMESTAMP pre-authentication.
        let pa = req.padata.as_ref().ok_or(Error::PreauthRequired)?;
        let ts_pa = pa
            .iter()
            .find(|p| p.padata_type == PA_ENC_TIMESTAMP)
            .ok_or(Error::PreauthRequired)?;
        let enc = EncryptedData::decode_implicit(
            0,
            &Any::from_der(&ts_pa.padata_value).map_err(|_| Error::PreauthRequired)?,
        )
        .map_err(|_| Error::PreauthRequired)?;
        let plain = crypto::decrypt(
            &enct,
            &entry.key.keyvalue,
            crate::key_usage::PA_ENC_TIMESTAMP,
            &enc.cipher,
        )?;
        let ts = pa_enc_ts::PaEncTsEnc::decode(&plain)?;
        let now = now_secs();
        if ts.patimestamp > now + CLOCK_SKEW || ts.patimestamp + CLOCK_SKEW < now {
            return Err(Error::PreauthRequired);
        }

        // Issue a TGT (Ticket-Granting Ticket).
        let session = self.random_session_key(entry.etype)?;
        let krbtgt = self.krbtgt_entry()?;
        let krbtgt_enct = Enctype::from_etype(krbtgt.etype)?;
        let now = now_secs();
        let etp = EncTicketPart {
            flags: flags::INITIAL | flags::PRE_AUTHENT | flags::RENEWABLE,
            key: session.clone(),
            crealm: crealm.clone(),
            cname: cname.clone(),
            transited: TransitedEncoding {
                tr_type: 1,
                contents: Vec::new(),
            },
            authtime: now,
            starttime: Some(now),
            endtime: now + DEFAULT_LIFETIME,
            renew_till: Some(now + DEFAULT_LIFETIME),
            caddr: None,
            authorization_data: None,
        };
        let ticket_enc = crypto::encrypt(
            &krbtgt_enct,
            &krbtgt.key.keyvalue,
            crate::key_usage::TICKET,
            &etp.encode(),
        )?;
        let tgt = Ticket {
            tkt_vno: 5,
            realm: crealm.clone(),
            sname: Principal::new(&["krbtgt", &crealm], &crealm, NT_SRV_INST).name,
            enc_part: EncryptedData {
                etype: krbtgt_enct.etype as i32,
                kvno: Some(1),
                cipher: ticket_enc,
            },
        };

        let enc_as_rep = EncKdcRepPart {
            key: session.clone(),
            last_req: Vec::new(),
            nonce: body.nonce,
            key_expiration: None,
            flags: flags::INITIAL | flags::PRE_AUTHENT | flags::RENEWABLE,
            authtime: now,
            starttime: Some(now),
            endtime: now + DEFAULT_LIFETIME,
            renew_till: Some(now + DEFAULT_LIFETIME),
            srealm: crealm.clone(),
            sname: Principal::new(&["krbtgt", &crealm], &crealm, NT_SRV_INST).name,
            caddr: None,
        };
        let enc_part = crypto::encrypt(
            &enct,
            &entry.key.keyvalue,
            crate::key_usage::AS_REP,
            &enc_as_rep.encode(),
        )?;

        let rep = KdcRep {
            pvno: PVNO,
            msg_type: 11, // AS-REP
            padata: None,
            crealm: crealm.clone(),
            cname,
            ticket: tgt,
            enc_part: EncryptedData {
                etype: enct.etype as i32,
                kvno: None,
                cipher: enc_part,
            },
        };
        Ok(rep.encode_application(11))
    }

    fn tgs_req(&self, req: &KdcReq) -> Result<Vec<u8>> {
        let body = &req.req_body;
        let crealm = body.realm.clone();
        let sname = body
            .sname
            .clone()
            .ok_or(Error::MissingField("TGS-REQ sname"))?;

        // Locate the AP-REQ in PA-TGS-REQ.
        let pa = req.padata.as_ref().ok_or(Error::PreauthRequired)?;
        let tgs_pa = pa
            .iter()
            .find(|p| p.padata_type == PA_TGS_REQ)
            .ok_or(Error::PreauthRequired)?;
        let ap = ApReq::decode_application(&tgs_pa.padata_value)?;

        // Decrypt the TGT with the krbtgt key.
        let krbtgt = self.krbtgt_entry()?;
        let krbtgt_enct = Enctype::from_etype(krbtgt.etype)?;
        let tgt_plain = crypto::decrypt(
            &krbtgt_enct,
            &krbtgt.key.keyvalue,
            crate::key_usage::TICKET,
            &ap.ticket.enc_part.cipher,
        )?;
        let mut tgt_cur = Cursor::new(&tgt_plain);
        let etp = EncTicketPart::decode(&mut tgt_cur)?;
        if etp.crealm != crealm {
            return Err(Error::Unexpected("TGT realm mismatch"));
        }
        let now = now_secs();
        if etp.endtime < now {
            return Err(Error::KrbError {
                code: 41,
                etext: Some("TGT expired".into()),
            });
        }

        // Decrypt the authenticator with the TGT session key.
        let tgt_session_enct = Enctype::from_etype(etp.key.keytype as u32)?;
        let auth_plain = crypto::decrypt(
            &tgt_session_enct,
            &etp.key.keyvalue,
            crate::key_usage::AP_REQ_AUTH,
            &ap.authenticator.cipher,
        )?;
        let mut auth_cur = Cursor::new(&auth_plain);
        let auth = Authenticator::decode(&mut auth_cur)?;
        if auth.ctime > now + CLOCK_SKEW || auth.ctime + CLOCK_SKEW < now {
            return Err(Error::PreauthRequired);
        }
        if auth.cname != etp.cname {
            return Err(Error::Unexpected("authenticator/client mismatch"));
        }

        // Look up the target service key.
        let service = Principal {
            name: sname.clone(),
            realm: crealm.clone(),
        };
        let svc_entry = self
            .lookup(&service)
            .ok_or_else(|| Error::Principal(format!("unknown service {}", service.to_string())))?;
        let svc_enct = Enctype::from_etype(svc_entry.etype)?;

        // Issue a service ticket.
        let svc_session = self.random_session_key(svc_entry.etype)?;
        let now = now_secs();
        let svc_etp = EncTicketPart {
            flags: flags::FORWARDABLE | flags::RENEWABLE,
            key: svc_session.clone(),
            crealm: etp.crealm.clone(),
            cname: etp.cname.clone(),
            transited: TransitedEncoding {
                tr_type: 1,
                contents: Vec::new(),
            },
            authtime: etp.authtime,
            starttime: Some(now),
            endtime: etp.endtime,
            renew_till: etp.renew_till,
            caddr: None,
            authorization_data: None,
        };
        let ticket_enc = crypto::encrypt(
            &svc_enct,
            &svc_entry.key.keyvalue,
            crate::key_usage::TICKET,
            &svc_etp.encode(),
        )?;
        let ticket = Ticket {
            tkt_vno: 5,
            realm: crealm.clone(),
            sname: sname.clone(),
            enc_part: EncryptedData {
                etype: svc_enct.etype as i32,
                kvno: Some(1),
                cipher: ticket_enc,
            },
        };

        // EncTGSRepPart is encrypted with the TGT session key.
        let enc_tgs = EncKdcRepPart {
            key: svc_session.clone(),
            last_req: Vec::new(),
            nonce: body.nonce,
            key_expiration: None,
            flags: flags::FORWARDABLE | flags::RENEWABLE,
            authtime: etp.authtime,
            starttime: Some(now),
            endtime: etp.endtime,
            renew_till: etp.renew_till,
            srealm: crealm.clone(),
            sname,
            caddr: None,
        };
        let enc_part = crypto::encrypt(
            &tgt_session_enct,
            &etp.key.keyvalue,
            crate::key_usage::TGS_REP,
            &enc_tgs.encode(),
        )?;

        let rep = KdcRep {
            pvno: PVNO,
            msg_type: 13, // TGS-REP
            padata: None,
            crealm: crealm.clone(),
            cname: etp.cname.clone(),
            ticket,
            enc_part: EncryptedData {
                etype: tgt_session_enct.etype as i32,
                kvno: None,
                cipher: enc_part,
            },
        };
        Ok(rep.encode_application(13))
    }
}

// Re-export for convenience in tests/examples.
pub use asn1::Principal as PrincipalRef;
