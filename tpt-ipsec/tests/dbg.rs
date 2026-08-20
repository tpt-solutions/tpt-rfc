use tpt_ipsec::message::{decode_sa_body, encode_sa_body, Header, Message, Payload};
use tpt_ipsec::types::PayloadType;
use tpt_ipsec::transforms::default_ike_proposal;
use tpt_ipsec::types::{DhGroup, ExchangeType, EncrId, IntegId, PrfId};
use tpt_ipsec::crypto::Dh;

fn params() -> tpt_ipsec::SaParams {
    tpt_ipsec::SaParams {
        prf: PrfId::HmacSha256,
        encr: EncrId::AesCbc128,
        integ: Some(IntegId::HmacSha256_128),
        dh: DhGroup::Curve25519,
    }
}

#[test]
fn dbg_sa() {
    let sa = tpt_ipsec::transforms::SaPayload {
        proposals: vec![default_ike_proposal()],
    };
    let body = encode_sa_body(&sa);
    eprintln!("SA body len = {}", body.len());
    match decode_sa_body(&body) {
        Ok(d) => eprintln!("decoded ok, proposals={}", d.proposals.len()),
        Err(e) => eprintln!("decode err: {:?}", e),
    }
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
    let e = msg.encode();
    eprintln!("msg len = {}", e.len());
    match Message::decode(&e) {
        Ok(_) => eprintln!("msg decode ok"),
        Err(e2) => eprintln!("msg decode err: {:?}", e2),
    }
    let _ = params();
}
