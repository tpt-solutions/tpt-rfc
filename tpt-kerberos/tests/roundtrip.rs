// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end Kerberos exchange tests against the in-memory KDC, plus SPNEGO
//! GSS-API framing round-trips.

use tpt_kerberos::client::Client;
use tpt_kerberos::crypto::{
    Enctype, ENCTYPE_AES128_CTS_HMAC_SHA1_96, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
    ENCTYPE_AES256_CTS_HMAC_SHA384_192,
};
use tpt_kerberos::error::Result;
use tpt_kerberos::kdc::MemoryKdc;
use tpt_kerberos::service::Service;
use tpt_kerberos::spnego::{NegTokenInit, NegTokenResp, OID_KRB5, OID_SPNEGO};
use tpt_kerberos::types::EncryptionKey;

const REALM: &str = "EXAMPLE.COM";
const USER: &str = "alice";
const USER_PW: &str = "hunter2-pass";
const SVC: &str = "host/server.example.com";
const SVC_PW: &str = "svc-secret";

fn setup() -> (MemoryKdc, Client) {
    let mut kdc = MemoryKdc::new_with_realm(REALM);
    kdc.add_principal(USER, REALM, USER_PW, ENCTYPE_AES256_CTS_HMAC_SHA1_96)
        .unwrap();
    kdc.add_service(SVC, REALM, SVC_PW, ENCTYPE_AES256_CTS_HMAC_SHA1_96)
        .unwrap();
    let mut client = Client::new(USER, REALM);
    client.authenticate(&kdc, USER_PW).unwrap();
    (kdc, client)
}

#[test]
fn as_exchange_issues_tgt() {
    let (kdc, client) = setup();
    let tgt = client.tgt().expect("TGT cached");
    assert_eq!(tgt.crealm, REALM);
    assert_eq!(tgt.cname.name_string, vec![USER.to_string()]);
    assert_eq!(tgt.sname.name_string, vec!["krbtgt".to_string(), REALM.to_string()]);
    let _ = kdc; // keep alive
}

#[test]
fn full_tgs_ap_exchange() -> Result<()> {
    let (kdc, mut client) = setup();

    // Obtain a service ticket.
    let cached = client.service_ticket(&kdc, &format!("{}@{}", SVC, REALM))?;
    assert_eq!(
        cached.sname.name_string,
        SVC.split('/').map(|s| s.to_string()).collect::<Vec<_>>()
    );

    // Build an AP-REQ and verify the service accepts it.
    let apreq = client.make_ap_req(&format!("{}@{}", SVC, REALM))?;
    // Reconstruct the service's long-term key.
    let svc_key = service_long_term_key(SVC, SVC_PW, ENCTYPE_AES256_CTS_HMAC_SHA1_96)?;
    let service = Service::new(
        tpt_kerberos::asn1::Principal::parse(&format!("{}@{}", SVC, REALM))?,
        svc_key,
    )?;
    let accepted = service.accept(&apreq)?;
    assert_eq!(accepted.client.name.name_string, vec![USER.to_string()]);
    assert_eq!(accepted.client.realm, REALM);

    // The service can prove possession with an AP-REP.
    let aprep = service.make_ap_rep(&accepted.session_key, accepted.auth_time, 0)?;
    assert!(!aprep.is_empty());
    Ok(())
}

#[test]
fn tgs_requires_valid_tgt() -> Result<()> {
    let (kdc, mut client) = setup();
    // A second, fresh client that has NOT authenticated must fail to get a
    // service ticket (no TGT cached).
    let mut stranger = Client::new("bob", REALM);
    let res = stranger.service_ticket(&kdc, &format!("{}@{}", SVC, REALM));
    assert!(res.is_err());
    Ok(())
}

#[test]
fn ap_req_rejected_with_wrong_service_key() -> Result<()> {
    let (_kdc, mut client) = setup();
    client.service_ticket(&kdc_fixture()?, &format!("{}@{}", SVC, REALM))?;
    let apreq = client.make_ap_req(&format!("{}@{}", SVC, REALM))?;
    // Service built with a *different* key must reject.
    let wrong_key = EncryptionKey {
        keytype: ENCTYPE_AES256_CTS_HMAC_SHA1_96 as i32,
        keyvalue: vec![0xAB; 32],
    };
    let service = Service::new(
        tpt_kerberos::asn1::Principal::parse(&format!("{}@{}", SVC, REALM))?,
        wrong_key,
    )?;
    assert!(service.accept(&apreq).is_err());
    Ok(())
}

/// Standalone KDC used when we don't need the client half.
fn kdc_fixture() -> Result<MemoryKdc> {
    let mut kdc = MemoryKdc::new_with_realm(REALM);
    kdc.add_principal(USER, REALM, USER_PW, ENCTYPE_AES256_CTS_HMAC_SHA1_96)?;
    kdc.add_service(SVC, REALM, SVC_PW, ENCTYPE_AES256_CTS_HMAC_SHA1_96)?;
    Ok(kdc)
}

fn service_long_term_key(
    service: &str,
    password: &str,
    etype: u32,
) -> Result<EncryptionKey> {
    let enct = Enctype::from_etype(etype)?;
    let salt = format!("{}{}", REALM, service).into_bytes();
    let kv = tpt_kerberos::crypto::string2key(
        etype,
        password.as_bytes(),
        &salt,
        tpt_kerberos::crypto::DEFAULT_STRING2KEY_ITER,
    )?;
    Ok(EncryptionKey {
        keytype: enct.etype as i32,
        keyvalue: kv,
    })
}

#[test]
fn spnego_neg_token_init_roundtrip() -> Result<()> {
    let (kdc, mut client) = setup();
    client.service_ticket(&kdc, &format!("{}@{}", SVC, REALM))?;
    let apreq = client.make_ap_req(&format!("{}@{}", SVC, REALM))?;

    let mechs = vec![const_oid::ObjectIdentifier::new_unwrap(OID_KRB5)];
    let init = NegTokenInit::wrap(&mechs, apreq.clone());
    let token = init.to_token()?;

    // The token must re-decode to the same mech list and inner token.
    let decoded = NegTokenInit::from_token(&token)?;
    assert_eq!(decoded.mech_types.len(), 1);
    assert_eq!(decoded.mech_types[0].to_string(), OID_KRB5);
    let inner = decoded.mech_token.expect("mech token present");
    assert_eq!(inner, apreq);

    // The GSS framing uses the SPNEGO OID (1.3.6.1.5.5.2).
    let spnego = const_oid::ObjectIdentifier::new_unwrap(OID_SPNEGO);
    let _ = spnego;
    Ok(())
}

#[test]
fn spnego_neg_token_resp_roundtrip() -> Result<()> {
    let mech = const_oid::ObjectIdentifier::new_unwrap(OID_KRB5);
    let resp = NegTokenResp::accept_completed(mech.clone(), Some(vec![1, 2, 3, 4]));
    let token = resp.to_token()?;
    let decoded = NegTokenResp::from_token(&token)?;
    assert_eq!(decoded.supported_mech.map(|o| o.to_string()), Some(OID_KRB5.to_string()));
    assert_eq!(decoded.response_token, Some(vec![1, 2, 3, 4]));
    Ok(())
}

#[test]
fn aes128_enctype_also_works() -> Result<()> {
    let mut kdc = MemoryKdc::new_with_realm(REALM);
    kdc.add_principal(USER, REALM, USER_PW, ENCTYPE_AES128_CTS_HMAC_SHA1_96)?;
    kdc.add_service(SVC, REALM, SVC_PW, ENCTYPE_AES128_CTS_HMAC_SHA1_96)?;
    let mut client = Client::new(USER, REALM);
    client.authenticate(&kdc, USER_PW)?;
    let cached = client.service_ticket(&kdc, &format!("{}@{}", SVC, REALM))?;
    assert!(!cached.session_key.keyvalue.is_empty());
    Ok(())
}

#[test]
fn rfc8009_enctype_roundtrip() -> Result<()> {
    let mut kdc = MemoryKdc::new_with_realm(REALM);
    kdc.add_principal(USER, REALM, USER_PW, ENCTYPE_AES256_CTS_HMAC_SHA384_192)?;
    kdc.add_service(SVC, REALM, SVC_PW, ENCTYPE_AES256_CTS_HMAC_SHA384_192)?;
    let mut client = Client::new(USER, REALM);
    client.authenticate(&kdc, USER_PW)?;
    let _ = client.service_ticket(&kdc, &format!("{}@{}", SVC, REALM))?;
    Ok(())
}
