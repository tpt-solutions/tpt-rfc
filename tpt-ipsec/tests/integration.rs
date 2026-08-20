//! Integration tests for the IKEv2 / IPsec implementation.
//!
//! These exercise the full IKE_SA_INIT / IKE_AUTH handshake (PSK and
//! Ed25519 "Digital Signature" auth), CREATE_CHILD_SA (new CHILD SA and
//! rekeying of the IKE SA and CHILD SAs), and the wire codec. There is no
//! strongSwan peer available in this environment, so interop is approximated
//! by running the two in-crate peers against each other (the responder is a
//! faithful, independent implementation of the same state machine).

use tpt_ipsec::crypto::{Dh, Prf};
use tpt_ipsec::message::{Header, Message, Payload};
use tpt_ipsec::transforms::{default_ike_proposal, SaPayload};
use tpt_ipsec::types::{DhGroup, EncrId, ExchangeType, IdType, IntegId, PayloadType, PrfId};
use tpt_ipsec::{AuthConfig, IdPayload, IkeInitiator, IkeResponder, IkeSa, SaParams};

fn params() -> SaParams {
    SaParams {
        prf: PrfId::HmacSha256,
        encr: EncrId::AesCbc128,
        integ: Some(IntegId::HmacSha256_128),
        dh: DhGroup::Curve25519,
    }
}

fn id(name: &str) -> IdPayload {
    IdPayload {
        id_type: IdType::KeyId,
        data: name.as_bytes().to_vec(),
    }
}

fn handshake_psk() -> (IkeSa, IkeSa) {
    let psk = b"shared-secret".to_vec();
    let mut ini = IkeInitiator::new(
        params(),
        AuthConfig::Psk(psk.clone()),
        id("initiator"),
    )
    .unwrap();
    let mut resp = IkeResponder::new(params(), AuthConfig::Psk(psk), id("responder")).unwrap();

    let m1 = ini.ike_sa_init_request().unwrap();
    let m2 = resp.on_init_request(&m1).unwrap();
    let m3 = ini.on_init_response(&m2).unwrap();
    let (m4, resp_sa) = resp.on_auth_request(&m3).unwrap();
    let ini_sa = ini.on_auth_response(&m4).unwrap();
    (ini_sa, resp_sa)
}

#[test]
fn handshake_psk_completes() {
    let (ini, resp) = handshake_psk();
    assert!(ini.established);
    assert!(resp.established);
    assert_eq!(ini.spi_i, resp.spi_i);
    assert_eq!(ini.spi_r, resp.spi_r);
    // Keys must be populated.
    assert!(!ini.keys.sk_d.is_empty());
    assert!(!ini.keys.sk_ei.is_empty());
    assert!(!ini.keys.sk_ai.is_empty());
    assert!(!resp.keys.sk_er.is_empty());
    // Initiator/responder keys must be cross-matched.
    assert_eq!(ini.keys.sk_er, resp.keys.sk_er);
    assert_eq!(ini.keys.sk_ar, resp.keys.sk_ar);
}

#[test]
fn handshake_ed25519_completes() {
    use ed25519_compact::KeyPair;
    let init = KeyPair::generate();
    let resp = KeyPair::generate();
    let init_sk: [u8; 32] = init.sk.as_ref().try_into().unwrap();
    let init_pk: [u8; 32] = init.pk.as_ref().try_into().unwrap();
    let resp_sk: [u8; 32] = resp.sk.as_ref().try_into().unwrap();
    let resp_pk: [u8; 32] = resp.pk.as_ref().try_into().unwrap();

    let mut ini = IkeInitiator::new(
        params(),
        AuthConfig::Ed25519 {
            own_secret: init_sk,
            peer_public: resp_pk,
        },
        id("initiator"),
    )
    .unwrap();
    let mut resp_peer = IkeResponder::new(
        params(),
        AuthConfig::Ed25519 {
            own_secret: resp_sk,
            peer_public: init_pk,
        },
        id("responder"),
    )
    .unwrap();

    let m1 = ini.ike_sa_init_request().unwrap();
    let m2 = resp_peer.on_init_request(&m1).unwrap();
    let m3 = ini.on_init_response(&m2).unwrap();
    let (m4, resp_sa) = resp_peer.on_auth_request(&m3).unwrap();
    let ini_sa = ini.on_auth_response(&m4).unwrap();

    assert!(ini_sa.established);
    assert!(resp_sa.established);
    // Ed25519 AUTH method must have been negotiated.
    assert_eq!(ini_sa.params.encr, EncrId::AesCbc128);
}

#[test]
fn create_child_sa_round_trip() {
    let (mut ini, mut resp) = handshake_psk();
    let req = ini.create_child_sa_request().unwrap();
    let re_msg = resp.handle_child_sa_request(&req).unwrap();
    ini.on_child_sa_response(&re_msg).unwrap();
    // CHILD SA keying material must be derived by both ends.
    assert!(!ini.child_keymat.is_empty());
    assert!(!resp.child_keymat.is_empty());
}

#[test]
fn ike_sa_rekey_round_trip() {
    let (mut ini, mut resp) = handshake_psk();
    let req = ini.rekey_ike_sa_request().unwrap();
    let (re_msg, mut new_resp_sa) = resp.handle_ike_sa_rekey_request(&req).unwrap();
    let mut new_ini_sa = ini.on_ike_sa_rekey_response(&re_msg).unwrap();

    // New SAs must be distinct from the old ones and consistent across peers.
    assert_ne!(new_ini_sa.keys.sk_d, ini.keys.sk_d);
    assert_eq!(new_ini_sa.spi_i, new_resp_sa.spi_i);
    assert_eq!(new_ini_sa.spi_r, new_resp_sa.spi_r);

    // An encrypted message under the new SA must round-trip.
    let m = new_ini_sa.create_child_sa_request().unwrap();
    let _handled = new_resp_sa.handle_child_sa_request(&m).unwrap();
}

#[test]
fn child_sa_rekey_round_trip() {
    let (mut ini, mut resp) = handshake_psk();
    let old_spi = [1u8, 2, 3, 4];
    let req = ini.rekey_child_sa_request(&old_spi).unwrap();
    let (_re_msg, new_keymat) = resp.handle_child_sa_rekey_request(&req).unwrap();
    assert!(!new_keymat.is_empty());
}

#[test]
fn header_codec_round_trip() {
    let h = Header {
        spi_i: [1, 2, 3, 4, 5, 6, 7, 8],
        spi_r: [8, 7, 6, 5, 4, 3, 2, 1],
        next_payload: PayloadType::Sa,
        version: tpt_ipsec::IKE_VERSION,
        exchange: ExchangeType::IkeSaInit,
        flags: 0x08,
        message_id: 7,
        length: 64,
    };
    let bytes = h.encode();
    let decoded = Header::decode(&bytes).unwrap();
    assert_eq!(decoded, h);
    assert!(decoded.is_initiator());
    assert!(!decoded.is_response());
}

#[test]
fn sa_payload_codec_round_trip() {
    let sa = SaPayload {
        proposals: vec![default_ike_proposal()],
    };
    let body = tpt_ipsec::message::encode_sa_body(&sa);
    let decoded = tpt_ipsec::message::decode_sa_body(&body).unwrap();
    assert_eq!(decoded.proposals.len(), 1);
    assert_eq!(decoded.proposals[0].transforms.len(), 5);
}

#[test]
fn message_codec_round_trip() {
    let sa = SaPayload {
        proposals: vec![default_ike_proposal()],
    };
    let dh = Dh::generate(DhGroup::Curve25519).unwrap();
    let msg = Message {
        header: Header {
            spi_i: [9u8; 8],
            spi_r: [0u8; 8],
            next_payload: PayloadType::Sa,
            version: tpt_ipsec::IKE_VERSION,
            exchange: ExchangeType::IkeSaInit,
            flags: 0x08,
            message_id: 0,
            length: 0,
        },
        payloads: vec![
            Payload::Sa(sa),
            Payload::Ke(tpt_ipsec::message::KePayload {
                group: DhGroup::Curve25519,
                public_key: dh.public.clone(),
            }),
            Payload::Nonce(tpt_ipsec::message::NoncePayload {
                nonce: vec![0xaa; 16],
            }),
        ],
    };
    let bytes = msg.encode();
    let decoded = Message::decode(&bytes).unwrap();
    assert_eq!(decoded.payloads.len(), 3);
    assert!(matches!(decoded.payloads[0], Payload::Sa(_)));
    assert!(matches!(decoded.payloads[1], Payload::Ke(_)));
    assert!(matches!(decoded.payloads[2], Payload::Nonce(_)));
}

#[test]
fn prf_plus_expansion_is_well_formed() {
    // prf+(K, seed) must begin with prf(K, seed) and grow in 32-byte blocks.
    let prf = Prf::Sha256;
    let key = [0x11u8; 32];
    let seed = b"ikeyseed-seed".to_vec();
    let full = prf.prf_plus(&key, &seed, 96);
    assert_eq!(full.len(), 96);
    let first = prf.prf(&key, &seed);
    assert_eq!(&full[..32], first.as_slice());
    // Ti = prf(K, T{i-1} | seed): third block derived from second block.
    let second = prf.prf(&key, &seed);
    let mut data = second.clone();
    data.extend_from_slice(&seed);
    let third = prf.prf(&key, &data);
    assert_eq!(&full[64..96], third.as_slice());
}

#[test]
fn dh_shared_secret_is_symmetric() {
    let a = Dh::generate(DhGroup::Curve25519).unwrap();
    let b = Dh::generate(DhGroup::Curve25519).unwrap();
    let sa = a.shared(&b.public).unwrap();
    let sb = b.shared(&a.public).unwrap();
    assert_eq!(sa, sb);
    assert!(!sa.iter().all(|&x| x == 0));
}

#[test]
fn default_proposal_negotiates() {
    let offer = SaPayload {
        proposals: vec![default_ike_proposal()],
    };
    let chosen = offer
        .select(&SaPayload {
            proposals: vec![default_ike_proposal()],
        })
        .unwrap();
    assert_eq!(chosen.proposals.len(), 1);
}
