//! IKEv2 IKE SA state machine, key derivation, and AUTH (RFC 7296).
//!
//! Two peers exchange IKE_SA_INIT and IKE_AUTH (`IkeInitiator` /
//! `IkeResponder`). After the handshake both sides hold an established
//! [`IkeSa`] that can drive CREATE_CHILD_SA exchanges (new CHILD SAs and
//! rekeying of the IKE SA and CHILD SAs).
//!
//! AUTH follows RFC 7296 §2.15 (PSK: `AUTH = prf(PSK, Ni | Nr)`) and RFC 7420
//! (Digital Signature / Ed25519: `AuthData = RealMessage{1,2} | Nonce |
//! prf+(SK_p, ID)`, `AUTH = Ed25519_sign(AuthData)`).

use crate::crypto::{random_bytes, Dh, Encr, Integ, Prf};
use crate::error::{Error, Result};
use crate::message::{
    self, AuthPayload, CertPayload, EncryptedPayload, Header, IdPayload, KePayload, Message,
    NoncePayload, NotifyPayload, Payload, TsPayload, TrafficSelector,
};
use crate::transforms::{child_keymat_len, SaPayload};
use crate::types::{
    flags, AuthMethod, CertEncoding, DhGroup, EncrId, ExchangeType, IdType, IntegId, PayloadType,
    PrfId, ProtocolId,
};
use ed25519_compact::{KeyPair, PublicKey, Signature};
use subtle::ConstantTimeEq;

/// IKE SA rekey notification (RFC 7296 §3.10.2, status type).
const REKEY_SA: u16 = 16393;

/// Negotiated algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaParams {
    pub prf: PrfId,
    pub encr: EncrId,
    pub integ: Option<IntegId>,
    pub dh: DhGroup,
}

impl SaParams {
    pub fn prf(self) -> Prf {
        Prf::from_id(self.prf)
    }
    pub fn encr(self) -> Encr {
        Encr::from_id(self.encr)
    }
    pub fn integ(self) -> Option<Integ> {
        self.integ.map(Integ::from_id)
    }
}

/// The seven IKE SA keys (RFC 7296 §2.14).
#[derive(Debug, Clone)]
pub struct IkeSaKeys {
    pub sk_d: Vec<u8>,
    pub sk_ai: Vec<u8>,
    pub sk_ar: Vec<u8>,
    pub sk_ei: Vec<u8>,
    pub sk_er: Vec<u8>,
    pub sk_pi: Vec<u8>,
    pub sk_pr: Vec<u8>,
}

/// Authentication configuration for a peer.
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// Shared-key message integrity (RFC 7296 §2.15).
    Psk(Vec<u8>),
    /// Digital Signature authentication (RFC 7420) with Ed25519.
    Ed25519 {
        own_secret: [u8; 32],
        peer_public: [u8; 32],
    },
}

impl AuthConfig {
    fn method(&self) -> AuthMethod {
        match self {
            AuthConfig::Psk(_) => AuthMethod::Psk,
            AuthConfig::Ed25519 { .. } => AuthMethod::DigitalSignature,
        }
    }
}

// ---------------------------------------------------------------------------
// Key derivation (RFC 7296 §2.13–§2.18)
// ---------------------------------------------------------------------------

/// Derive the seven IKE SA keys (RFC 7296 §2.14).
pub fn derive_keys(
    params: SaParams,
    ni: &[u8],
    nr: &[u8],
    spii: &[u8; 8],
    spir: &[u8; 8],
    gir: &[u8],
) -> IkeSaKeys {
    let prf = params.prf();
    let skeyseed = prf.prf(&concat(ni, nr), gir);
    derive_keys_from_skeyseed(params, &skeyseed, ni, nr, spii, spir)
}

fn derive_keys_from_skeyseed(
    params: SaParams,
    skeyseed: &[u8],
    ni: &[u8],
    nr: &[u8],
    spii: &[u8; 8],
    spir: &[u8; 8],
) -> IkeSaKeys {
    let prf = params.prf();
    let encr = params.encr();
    let integ = params.integ();
    let seed = concat4(ni, nr, spii, spir);
    let encr_key_len = encr.key_len() + if encr.is_aead() { 4 } else { 0 };
    let li = integ.map(|i| i.key_len()).unwrap_or(0);
    let lp = prf.output_len();
    let needed = lp + 2 * li + 2 * encr_key_len + 2 * lp;
    let km = prf.prf_plus(skeyseed, &seed, needed);
    let mut o = 0;
    let sk_d = km[o..o + lp].to_vec();
    o += lp;
    let sk_ai = km[o..o + li].to_vec();
    o += li;
    let sk_ar = km[o..o + li].to_vec();
    o += li;
    let sk_ei = km[o..o + encr_key_len].to_vec();
    o += encr_key_len;
    let sk_er = km[o..o + encr_key_len].to_vec();
    o += encr_key_len;
    let sk_pi = km[o..o + lp].to_vec();
    o += lp;
    let sk_pr = km[o..o + lp].to_vec();
    IkeSaKeys {
        sk_d,
        sk_ai,
        sk_ar,
        sk_ei,
        sk_er,
        sk_pi,
        sk_pr,
    }
}

/// Rekey the IKE SA (RFC 7296 §2.18): `SKEYSEED = prf(SK_d(old), g^ir | Ni | Nr)`.
pub fn rekey_ike_keys(
    params: SaParams,
    sk_d_old: &[u8],
    ni: &[u8],
    nr: &[u8],
    new_spii: &[u8; 8],
    new_spir: &[u8; 8],
    gir_new: &[u8],
) -> IkeSaKeys {
    let prf = params.prf();
    let mut base = gir_new.to_vec();
    base.extend_from_slice(ni);
    base.extend_from_slice(nr);
    let skeyseed = prf.prf(sk_d_old, &base);
    derive_keys_from_skeyseed(params, &skeyseed, ni, nr, new_spii, new_spir)
}

/// Derive CHILD SA keying material (RFC 7296 §2.17).
pub fn child_keymat(params: SaParams, sk_d: &[u8], ni: &[u8], nr: &[u8], len: usize) -> Vec<u8> {
    let prf = params.prf();
    prf.prf_plus(sk_d, &concat(ni, nr), len)
}

/// Rekey a CHILD SA: `KEYMAT = prf+(SK_d(parent), g^ir | Ni | Nr)` (RFC 7296 §2.17).
pub fn child_keymat_rekey(
    params: SaParams,
    sk_d: &[u8],
    gir_new: &[u8],
    ni: &[u8],
    nr: &[u8],
    len: usize,
) -> Vec<u8> {
    let prf = params.prf();
    let mut base = gir_new.to_vec();
    base.extend_from_slice(ni);
    base.extend_from_slice(nr);
    prf.prf_plus(sk_d, &base, len)
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = a.to_vec();
    v.extend_from_slice(b);
    v
}
fn concat4(a: &[u8], b: &[u8], c: &[u8], d: &[u8]) -> Vec<u8> {
    let mut v = a.to_vec();
    v.extend_from_slice(b);
    v.extend_from_slice(c);
    v.extend_from_slice(d);
    v
}

fn random_spi8() -> [u8; 8] {
    loop {
        let s = random_bytes(8);
        if s.iter().any(|&x| x != 0) {
            let mut a = [0u8; 8];
            a.copy_from_slice(&s);
            return a;
        }
    }
}
fn random_spi4() -> [u8; 4] {
    random_bytes(4).try_into().unwrap()
}

fn encoded_payload(p: &Payload, next: PayloadType) -> Vec<u8> {
    let mut b = Vec::new();
    message::encode_payload(&mut b, p, next);
    b
}

/// Re-encode header + the given payloads (the `RealMessage` truncation for
/// AUTH: header + SA + KE, excluding the Nonce).
fn real_message(header: &Header, payloads: &[Payload]) -> Vec<u8> {
    let m = Message {
        header: header.clone(),
        payloads: payloads.to_vec(),
    };
    m.encode()
}

/// Encode a Nonce payload (header + body) for AUTH concatenation.
fn nonce_payload_bytes(nonce: &[u8]) -> Vec<u8> {
    let p = Payload::Nonce(NoncePayload {
        nonce: nonce.to_vec(),
    });
    encoded_payload(&p, PayloadType::None)
}

// ===========================================================================
// Initiator
// ===========================================================================

/// IKE_SA_INIT / IKE_AUTH initiator.
pub struct IkeInitiator {
    pub params: SaParams,
    pub auth: AuthConfig,
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    pub ni: Vec<u8>,
    pub nr: Vec<u8>,
    pub dh: Dh,
    pub peer_dh_pub: Vec<u8>,
    pub keys: IkeSaKeys,
    pub id_i: IdPayload,
    pub id_r: IdPayload,
    real_init_request: Vec<u8>,
    real_init_response: Vec<u8>,
    established: bool,
    message_id: u32,
}

impl IkeInitiator {
    /// Begin a handshake.
    pub fn new(params: SaParams, auth: AuthConfig, id_i: IdPayload) -> Result<IkeInitiator> {
        let spi_i = random_spi8();
        let ni = random_bytes(32);
        let dh = Dh::generate(params.dh)?;
        Ok(IkeInitiator {
            params,
            auth,
            spi_i,
            spi_r: [0u8; 8],
            ni,
            nr: Vec::new(),
            dh,
            peer_dh_pub: Vec::new(),
            keys: zero_keys(),
            id_i,
            id_r: IdPayload {
                id_type: IdType::KeyId,
                data: Vec::new(),
            },
            real_init_request: Vec::new(),
            real_init_response: Vec::new(),
            established: false,
            message_id: 0,
        })
    }

    /// Build the IKE_SA_INIT request.
    pub fn ike_sa_init_request(&mut self) -> Result<Message> {
        let sa = SaPayload {
            proposals: vec![crate::transforms::default_ike_proposal()],
        };
        let ke = KePayload {
            group: self.params.dh,
            public_key: self.dh.public.clone(),
        };
        let nonce = NoncePayload {
            nonce: self.ni.clone(),
        };
        let header = Header {
            spi_i: self.spi_i,
            spi_r: [0u8; 8],
            next_payload: PayloadType::Sa,
            version: crate::types::IKE_VERSION,
            exchange: ExchangeType::IkeSaInit,
            flags: flags::INITIATOR,
            message_id: 0,
            length: 0,
        };
        let full = Message {
            header: header.clone(),
            payloads: vec![Payload::Sa(sa), Payload::Ke(ke), Payload::Nonce(nonce)],
        };
        let bytes = full.encode();
        self.real_init_request = real_message(
            &header,
            &[full.payloads[0].clone(), full.payloads[1].clone()],
        );
        Ok(Message::decode(&bytes)?)
    }

    /// Process the IKE_SA_INIT response and build the IKE_AUTH request.
    pub fn on_init_response(&mut self, resp: &Message) -> Result<Message> {
        if resp.header.spi_i != self.spi_i {
            return Err(Error::Other("SPI mismatch".into()));
        }
        self.spi_r = resp.header.spi_r;
        self.nr = extract_nonce(resp)?;
        self.peer_dh_pub = extract_ke(resp)?;
        self.id_r.data = self.id_i.data.clone();
        let gir = self.dh.shared(&self.peer_dh_pub)?;
        self.keys = derive_keys(
            self.params,
            &self.ni,
            &self.nr,
            &self.spi_i,
            &self.spi_r,
            &gir,
        );
        let (sa, ke) = sa_and_ke(resp)?;
        self.real_init_response = real_message(&resp.header, &[sa, ke]);
        self.build_auth_request()
    }

    fn build_auth_request(&mut self) -> Result<Message> {
        self.message_id = 1;
        let child_spi = random_spi4();
        let (inner, id_bytes) = self.build_auth_inner(true, Some(child_spi))?;
        let auth_data = self.compute_auth(true, &id_bytes)?;

        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next_payload: PayloadType::Sk,
            version: crate::types::IKE_VERSION,
            exchange: ExchangeType::IkeAuth,
            flags: flags::INITIATOR,
            message_id: self.message_id,
            length: 0,
        };
        let sk = self.encrypt_inner(&header, inner, &self.keys.sk_ei, &self.keys.sk_ai, auth_data, true)?;
        let msg = Message {
            header,
            payloads: vec![Payload::Sk(sk)],
        };
        let bytes = msg.encode();
        Ok(Message::decode(&bytes)?)
    }

    fn build_auth_inner(
        &self,
        is_initiator: bool,
        child_spi: Option<[u8; 4]>,
    ) -> Result<(Vec<Payload>, Vec<u8>)> {
        let id = if is_initiator {
            self.id_i.clone()
        } else {
            self.id_r.clone()
        };
        let id_payload = if is_initiator {
            Payload::Idi(id.clone())
        } else {
            Payload::Idr(id.clone())
        };
        let next = if matches!(self.auth, AuthConfig::Ed25519 { .. }) {
            PayloadType::Cert
        } else {
            PayloadType::Auth
        };
        let id_bytes = encoded_payload(&id_payload, next);

        let mut inner: Vec<Payload> = Vec::new();
        inner.push(id_payload);

        if let AuthConfig::Ed25519 { peer_public, .. } = &self.auth {
            inner.push(Payload::Cert(CertPayload {
                encoding: CertEncoding::RawPublicKey,
                data: peer_public.to_vec(),
            }));
        }

        inner.push(Payload::Auth(AuthPayload {
            method: self.auth.method(),
            data: Vec::new(),
        }));

        if let Some(spi) = child_spi {
            let sa = SaPayload {
                proposals: vec![crate::transforms::default_esp_proposal(&spi)],
            };
            inner.push(Payload::Sa(sa));
            inner.push(Payload::TSi(any_ts()));
            inner.push(Payload::TSr(any_ts()));
        }
        Ok((inner, id_bytes))
    }

    fn compute_auth(&self, is_initiator: bool, id_bytes: &[u8]) -> Result<Vec<u8>> {
        let prf = self.params.prf();
        match &self.auth {
            AuthConfig::Psk(psk) => Ok(prf.prf(psk, &concat(&self.ni, &self.nr))),
            AuthConfig::Ed25519 { own_secret, .. } => {
                let (real, nonce, sk_p) = if is_initiator {
                    (&self.real_init_request, &self.ni, &self.keys.sk_pi)
                } else {
                    (&self.real_init_response, &self.nr, &self.keys.sk_pr)
                };
                let np = nonce_payload_bytes(nonce);
                let maced = prf.prf_plus(sk_p, id_bytes, prf.output_len());
                let mut data = real.clone();
                data.extend_from_slice(&np);
                data.extend_from_slice(&maced);
                let kp = KeyPair::from_slice(own_secret)
                    .map_err(|e| Error::Ed25519(e.to_string()))?;
                let sig: Signature = kp.sk.sign(&data, None);
                Ok(sig.to_vec())
            }
        }
    }

    fn encrypt_inner(
        &self,
        header: &Header,
        inner: Vec<Payload>,
        sk_e: &[u8],
        sk_a: &[u8],
        _auth_placeholder: Vec<u8>,
        is_initiator: bool,
    ) -> Result<EncryptedPayload> {
        let id_for_auth = find_id_bytes(&inner)?;
        let auth_data = self.compute_auth(is_initiator, &id_for_auth)?;
        seal(self.params, header, inner, sk_e, sk_a, auth_data)
    }

    /// Process the IKE_AUTH response; returns the established SA.
    pub fn on_auth_response(&mut self, resp: &Message) -> Result<IkeSa> {
        if !resp.header.is_response() {
            return Err(Error::Other("expected response".into()));
        }
        let (sa, ke) = sa_and_ke(resp)?;
        self.real_init_response = real_message(&resp.header, &[sa, ke]);

        let sk = extract_sk(resp)?;
        let encr = self.params.encr();
        let (sk_e_key, salt) = if encr.is_aead() {
            (self.keys.sk_ei[4..].to_vec(), self.keys.sk_ei[..4].to_vec())
        } else {
            (self.keys.sk_ei.clone(), Vec::new())
        };
        let inner = sk.decrypt(
            encr,
            self.params.integ(),
            &resp.header,
            &sk_e_key,
            &self.keys.sk_ai,
            &salt,
        )?;
        let idr_bytes = find_id_bytes_in(&inner, PayloadType::Idr)?;
        let expected = self.compute_auth_peer(false, &idr_bytes)?;
        let auth = inner
            .iter()
            .find_map(|p| {
                if let Payload::Auth(a) = p {
                    Some(a)
                } else {
                    None
                }
            })
            .ok_or(Error::Other("missing AUTH".into()))?;
        verify_auth(&self.auth, &expected, &auth.data)?;
        self.established = true;
        Ok(self.to_established())
    }

    fn compute_auth_peer(&self, is_initiator: bool, id_bytes: &[u8]) -> Result<Vec<u8>> {
        let prf = self.params.prf();
        match &self.auth {
            AuthConfig::Psk(psk) => Ok(prf.prf(psk, &concat(&self.ni, &self.nr))),
            AuthConfig::Ed25519 { .. } => {
                let (real, nonce, sk_p) = if is_initiator {
                    (&self.real_init_request, &self.ni, &self.keys.sk_pi)
                } else {
                    (&self.real_init_response, &self.nr, &self.keys.sk_pr)
                };
                let np = nonce_payload_bytes(nonce);
                let maced = prf.prf_plus(sk_p, id_bytes, prf.output_len());
                let mut data = real.clone();
                data.extend_from_slice(&np);
                data.extend_from_slice(&maced);
                Ok(data)
            }
        }
    }

    fn to_established(&self) -> IkeSa {
        let child = crate::transforms::default_esp_proposal(&[0; 4]);
        let len = child_keymat_len(&child);
        let child_keymat = child_keymat(self.params, &self.keys.sk_d, &self.ni, &self.nr, len);
        IkeSa {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            is_initiator: true,
            params: self.params,
            keys: self.keys.clone(),
            established: true,
            message_id: self.message_id,
            rekey_dh: None,
            rekey_ni: Vec::new(),
            rekey_spii: [0u8; 8],
            child_ni: self.ni.clone(),
            child_keymat,
        }
    }
}

// ===========================================================================
// Responder
// ===========================================================================

/// IKE_SA_INIT / IKE_AUTH responder.
pub struct IkeResponder {
    pub params: SaParams,
    pub auth: AuthConfig,
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    pub ni: Vec<u8>,
    pub nr: Vec<u8>,
    pub dh: Dh,
    pub peer_dh_pub: Vec<u8>,
    pub keys: IkeSaKeys,
    pub id_i: IdPayload,
    pub id_r: IdPayload,
    real_init_request: Vec<u8>,
    real_init_response: Vec<u8>,
    established: bool,
    message_id: u32,
}

impl IkeResponder {
    pub fn new(params: SaParams, auth: AuthConfig, id_r: IdPayload) -> Result<IkeResponder> {
        Ok(IkeResponder {
            params,
            auth,
            spi_i: [0u8; 8],
            spi_r: random_spi8(),
            ni: Vec::new(),
            nr: random_bytes(32),
            dh: Dh::generate(params.dh)?,
            peer_dh_pub: Vec::new(),
            keys: zero_keys(),
            id_i: IdPayload {
                id_type: IdType::KeyId,
                data: Vec::new(),
            },
            id_r,
            real_init_request: Vec::new(),
            real_init_response: Vec::new(),
            established: false,
            message_id: 0,
        })
    }

    /// Handle the IKE_SA_INIT request, returning the response.
    pub fn on_init_request(&mut self, req: &Message) -> Result<Message> {
        self.spi_i = req.header.spi_i;
        self.ni = extract_nonce(req)?;
        self.peer_dh_pub = extract_ke(req)?;
        let gir = self.dh.shared(&self.peer_dh_pub)?;
        self.keys = derive_keys(
            self.params,
            &self.ni,
            &self.nr,
            &self.spi_i,
            &self.spi_r,
            &gir,
        );
        let (sa, ke) = sa_and_ke(req)?;
        self.real_init_request = real_message(&req.header, &[sa, ke]);

        let sa = SaPayload {
            proposals: vec![crate::transforms::default_ike_proposal()],
        };
        let ke = KePayload {
            group: self.params.dh,
            public_key: self.dh.public.clone(),
        };
        let nonce = NoncePayload {
            nonce: self.nr.clone(),
        };
        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next_payload: PayloadType::Sa,
            version: crate::types::IKE_VERSION,
            exchange: ExchangeType::IkeSaInit,
            flags: flags::RESPONSE,
            message_id: 0,
            length: 0,
        };
        let full = Message {
            header: header.clone(),
            payloads: vec![
                Payload::Sa(sa),
                Payload::Ke(ke),
                Payload::Nonce(nonce),
            ],
        };
        let bytes = full.encode();
        self.real_init_response = real_message(
            &header,
            &[full.payloads[0].clone(), full.payloads[1].clone()],
        );
        Ok(Message::decode(&bytes)?)
    }

    /// Handle the IKE_AUTH request, returning the response and the established SA.
    pub fn on_auth_request(&mut self, req: &Message) -> Result<(Message, IkeSa)> {
        let sk = extract_sk(req)?;
        let encr = self.params.encr();
        let (sk_e_key, salt) = if encr.is_aead() {
            (self.keys.sk_ei[4..].to_vec(), self.keys.sk_ei[..4].to_vec())
        } else {
            (self.keys.sk_ei.clone(), Vec::new())
        };
        let inner = sk.decrypt(
            encr,
            self.params.integ(),
            &req.header,
            &sk_e_key,
            &self.keys.sk_ai,
            &salt,
        )?;
        let idi_bytes = find_id_bytes_in(&inner, PayloadType::Idi)?;
        let expected = self.compute_auth_peer(true, &idi_bytes)?;
        let auth = inner
            .iter()
            .find_map(|p| {
                if let Payload::Auth(a) = p {
                    Some(a)
                } else {
                    None
                }
            })
            .ok_or(Error::Other("missing AUTH".into()))?;
        verify_auth(&self.auth, &expected, &auth.data)?;
        self.id_i.data = idi_bytes[4..].to_vec();
        self.message_id = req.header.message_id;

        let child_spi = random_spi4();
        let (inner_resp, idr_bytes) = self.build_auth_inner(false, Some(child_spi))?;
        let auth_data = self.compute_auth(false, &idr_bytes)?;

        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next_payload: PayloadType::Sk,
            version: crate::types::IKE_VERSION,
            exchange: ExchangeType::IkeAuth,
            flags: flags::RESPONSE,
            message_id: self.message_id,
            length: 0,
        };
        let sk = seal(self.params, &header, inner_resp, &self.keys.sk_er, &self.keys.sk_ar, auth_data)?;
        let msg = Message {
            header,
            payloads: vec![Payload::Sk(sk)],
        };
        let bytes = msg.encode();
        self.established = true;
        let sa = self.to_established();
        Ok((Message::decode(&bytes)?, sa))
    }

    fn build_auth_inner(
        &self,
        is_initiator: bool,
        child_spi: Option<[u8; 4]>,
    ) -> Result<(Vec<Payload>, Vec<u8>)> {
        let id = if is_initiator {
            self.id_i.clone()
        } else {
            self.id_r.clone()
        };
        let id_payload = if is_initiator {
            Payload::Idi(id.clone())
        } else {
            Payload::Idr(id.clone())
        };
        let next = if matches!(self.auth, AuthConfig::Ed25519 { .. }) {
            PayloadType::Cert
        } else {
            PayloadType::Auth
        };
        let id_bytes = encoded_payload(&id_payload, next);
        let mut inner: Vec<Payload> = vec![id_payload];
        if let AuthConfig::Ed25519 { peer_public, .. } = &self.auth {
            inner.push(Payload::Cert(CertPayload {
                encoding: CertEncoding::RawPublicKey,
                data: peer_public.to_vec(),
            }));
        }
        inner.push(Payload::Auth(AuthPayload {
            method: self.auth.method(),
            data: Vec::new(),
        }));
        if let Some(spi) = child_spi {
            inner.push(Payload::Sa(SaPayload {
                proposals: vec![crate::transforms::default_esp_proposal(&spi)],
            }));
            inner.push(Payload::TSi(any_ts()));
            inner.push(Payload::TSr(any_ts()));
        }
        Ok((inner, id_bytes))
    }

    fn compute_auth(&self, is_initiator: bool, id_bytes: &[u8]) -> Result<Vec<u8>> {
        let prf = self.params.prf();
        match &self.auth {
            AuthConfig::Psk(psk) => Ok(prf.prf(psk, &concat(&self.ni, &self.nr))),
            AuthConfig::Ed25519 { own_secret, .. } => {
                let (real, nonce, sk_p) = if is_initiator {
                    (&self.real_init_request, &self.ni, &self.keys.sk_pi)
                } else {
                    (&self.real_init_response, &self.nr, &self.keys.sk_pr)
                };
                let np = nonce_payload_bytes(nonce);
                let maced = prf.prf_plus(sk_p, id_bytes, prf.output_len());
                let mut data = real.clone();
                data.extend_from_slice(&np);
                data.extend_from_slice(&maced);
                let kp = KeyPair::from_slice(own_secret)
                    .map_err(|e| Error::Ed25519(e.to_string()))?;
                let sig: Signature = kp.sk.sign(&data, None);
                Ok(sig.to_vec())
            }
        }
    }

    fn compute_auth_peer(&self, is_initiator: bool, id_bytes: &[u8]) -> Result<Vec<u8>> {
        let prf = self.params.prf();
        match &self.auth {
            AuthConfig::Psk(psk) => Ok(prf.prf(psk, &concat(&self.ni, &self.nr))),
            AuthConfig::Ed25519 { .. } => {
                let (real, nonce, sk_p) = if is_initiator {
                    (&self.real_init_request, &self.ni, &self.keys.sk_pi)
                } else {
                    (&self.real_init_response, &self.nr, &self.keys.sk_pr)
                };
                let np = nonce_payload_bytes(nonce);
                let maced = prf.prf_plus(sk_p, id_bytes, prf.output_len());
                let mut data = real.clone();
                data.extend_from_slice(&np);
                data.extend_from_slice(&maced);
                Ok(data)
            }
        }
    }

    fn to_established(&self) -> IkeSa {
        let child = crate::transforms::default_esp_proposal(&[0; 4]);
        let len = child_keymat_len(&child);
        let child_keymat = child_keymat(self.params, &self.keys.sk_d, &self.ni, &self.nr, len);
        IkeSa {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            is_initiator: false,
            params: self.params,
            keys: self.keys.clone(),
            established: true,
            message_id: self.message_id,
            rekey_dh: None,
            rekey_ni: Vec::new(),
            rekey_spii: [0u8; 8],
            child_ni: self.ni.clone(),
            child_keymat,
        }
    }
}

// ===========================================================================
// Established IKE SA
// ===========================================================================

/// An established IKE SA, capable of CREATE_CHILD_SA exchanges (new CHILD SAs
/// and rekeying of the IKE SA and CHILD SAs).
#[derive(Debug, Clone)]
pub struct IkeSa {
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    pub is_initiator: bool,
    pub params: SaParams,
    pub keys: IkeSaKeys,
    pub established: bool,
    pub message_id: u32,
    pub child_keymat: Vec<u8>,
    rekey_dh: Option<Dh>,
    rekey_ni: Vec<u8>,
    rekey_spii: [u8; 8],
    child_ni: Vec<u8>,
}

impl IkeSa {
    fn dir_keys(&self, initiator_side: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let encr = self.params.encr();
        if initiator_side {
            if encr.is_aead() {
                (self.keys.sk_ei[4..].to_vec(), self.keys.sk_ai.clone(), self.keys.sk_ei[..4].to_vec())
            } else {
                (self.keys.sk_ei.clone(), self.keys.sk_ai.clone(), Vec::new())
            }
        } else if encr.is_aead() {
            (self.keys.sk_er[4..].to_vec(), self.keys.sk_ar.clone(), self.keys.sk_er[..4].to_vec())
        } else {
            (self.keys.sk_er.clone(), self.keys.sk_ar.clone(), Vec::new())
        }
    }

    /// CREATE_CHILD_SA creating a new CHILD SA (no rekey).
    pub fn create_child_sa_request(&mut self) -> Result<Message> {
        self.message_id += 1;
        let ni = random_bytes(32);
        self.child_ni = ni.clone();
        let child_spi = random_spi4();
        let sa = SaPayload {
            proposals: vec![crate::transforms::default_esp_proposal(&child_spi)],
        };
        let nonce = NoncePayload { nonce: ni.clone() };
        let inner: Vec<Payload> = vec![
            Payload::Sa(sa),
            Payload::Nonce(nonce),
            Payload::TSi(any_ts()),
            Payload::TSr(any_ts()),
        ];
        let (sk_e, sk_a, salt) = self.dir_keys(self.is_initiator);
        self.encrypted(self.message_id, ExchangeType::CreateChildSa, inner, &sk_e, &sk_a, &salt)
    }

    /// Handle an incoming CREATE_CHILD_SA request (responder side).
    pub fn handle_child_sa_request(&mut self, req: &Message) -> Result<Message> {
        let (sk_e, sk_a, salt) = self.dir_keys(false);
        let encr = self.params.encr();
        let sk = extract_sk(req)?;
        let inner = sk.decrypt(encr, self.params.integ(), &req.header, &sk_e, &sk_a, &salt)?;
        let ni = extract_nonce_inner(&inner)?;
        let nr = random_bytes(32);
        let child_spi = random_spi4();
        let sa = Payload::Sa(SaPayload {
            proposals: vec![crate::transforms::default_esp_proposal(&child_spi)],
        });
        let nonce = NoncePayload { nonce: nr.clone() };
        let inner_resp: Vec<Payload> = vec![
            sa,
            Payload::Nonce(nonce),
            Payload::TSi(any_ts()),
            Payload::TSr(any_ts()),
        ];
        let (sk_e_r, sk_a_r, salt_r) = self.dir_keys(false);
        let msg = self.encrypted(req.header.message_id, ExchangeType::CreateChildSa, inner_resp, &sk_e_r, &sk_a_r, &salt_r)?;
        let len = child_keymat_len(&crate::transforms::default_esp_proposal(&child_spi));
        self.child_keymat = child_keymat(self.params, &self.keys.sk_d, &ni, &nr, len);
        Ok(msg)
    }

    /// Finalize CHILD SA keying material from a CREATE_CHILD_SA response.
    pub fn on_child_sa_response(&mut self, resp: &Message) -> Result<()> {
        let (sk_e, sk_a, salt) = self.dir_keys(false);
        let encr = self.params.encr();
        let sk = extract_sk(resp)?;
        let inner = sk.decrypt(encr, self.params.integ(), &resp.header, &sk_e, &sk_a, &salt)?;
        let nr = extract_nonce_inner(&inner)?;
        let len = child_keymat_len(&crate::transforms::default_esp_proposal(&[0; 4]));
        self.child_keymat = child_keymat(self.params, &self.keys.sk_d, &self.child_ni, &nr, len);
        Ok(())
    }

    /// Rekey the IKE SA: CREATE_CHILD_SA carrying a new KE and a REKEY_SA notify
    /// (RFC 7296 §2.18). Returns the request message.
    pub fn rekey_ike_sa_request(&mut self) -> Result<Message> {
        self.message_id += 1;
        let new_spii = random_spi8();
        let dh = Dh::generate(self.params.dh)?;
        let ni = random_bytes(32);
        self.rekey_dh = Some(dh.clone());
        self.rekey_ni = ni.clone();
        self.rekey_spii = new_spii;

        let sa = SaPayload {
            proposals: vec![crate::transforms::ike_proposal_with_spi(&new_spii)],
        };
        let ke = KePayload {
            group: self.params.dh,
            public_key: dh.public.clone(),
        };
        let nonce = NoncePayload { nonce: ni.clone() };
        let notify = rekey_notify(ProtocolId::Ike, &self.spi_i);
        let inner: Vec<Payload> = vec![
            Payload::Sa(sa),
            Payload::Ke(ke),
            Payload::Nonce(nonce),
            Payload::Notify(notify),
        ];
        let (sk_e, sk_a, salt) = self.dir_keys(self.is_initiator);
        self.encrypted(self.message_id, ExchangeType::CreateChildSa, inner, &sk_e, &sk_a, &salt)
    }

    /// Handle an incoming IKE SA rekey request (responder side).
    pub fn handle_ike_sa_rekey_request(&mut self, req: &Message) -> Result<(Message, IkeSa)> {
        let (sk_e, sk_a, salt) = self.dir_keys(false);
        let encr = self.params.encr();
        let sk = extract_sk(req)?;
        let inner = sk.decrypt(encr, self.params.integ(), &req.header, &sk_e, &sk_a, &salt)?;
        let (sa, ke) = sa_and_ke_inner(&inner)?;
        let ni = extract_nonce_inner(&inner)?;
        let new_spii = sa_spi8(&sa).ok_or(Error::Other("missing new SPIi".into()))?;
        let dh = Dh::generate(self.params.dh)?;
        let gir_new = dh.shared(&ke.public_key)?;
        let nr = random_bytes(32);
        let new_spir = random_spi8();
        let new_keys = rekey_ike_keys(
            self.params,
            &self.keys.sk_d,
            &ni,
            &nr,
            &new_spii,
            &new_spir,
            &gir_new,
        );

        let resp_sa = SaPayload {
            proposals: vec![crate::transforms::ike_proposal_with_spi(&new_spir)],
        };
        let resp_ke = KePayload {
            group: self.params.dh,
            public_key: dh.public.clone(),
        };
        let nonce = NoncePayload { nonce: nr.clone() };
        let notify = rekey_notify(ProtocolId::Ike, &self.spi_r);
        let inner_resp: Vec<Payload> = vec![
            Payload::Sa(resp_sa),
            Payload::Ke(resp_ke),
            Payload::Nonce(nonce),
            Payload::Notify(notify),
        ];
        let (sk_e_r, sk_a_r, salt_r) = self.dir_keys(false);
        let msg = self.encrypted(req.header.message_id, ExchangeType::CreateChildSa, inner_resp, &sk_e_r, &sk_a_r, &salt_r)?;
        let new_sa = IkeSa {
            spi_i: new_spii,
            spi_r: new_spir,
            is_initiator: false,
            params: self.params,
            keys: new_keys,
            established: true,
            message_id: req.header.message_id,
            rekey_dh: None,
            rekey_ni: Vec::new(),
            rekey_spii: [0u8; 8],
            child_ni: Vec::new(),
            child_keymat: Vec::new(),
        };
        Ok((msg, new_sa))
    }

    /// Process an IKE SA rekey response (initiator side), returning the new SA.
    pub fn on_ike_sa_rekey_response(&mut self, resp: &Message) -> Result<IkeSa> {
        let (sk_e, sk_a, salt) = self.dir_keys(false);
        let encr = self.params.encr();
        let sk = extract_sk(resp)?;
        let inner = sk.decrypt(encr, self.params.integ(), &resp.header, &sk_e, &sk_a, &salt)?;
        let (sa, ke) = sa_and_ke_inner(&inner)?;
        let nr = extract_nonce_inner(&inner)?;
        let new_spir = sa_spi8(&sa).ok_or(Error::Other("missing new SPIr".into()))?;
        let dh = self.rekey_dh.take().ok_or(Error::Other("no rekey in progress".into()))?;
        let gir_new = dh.shared(&ke.public_key)?;
        let new_keys = rekey_ike_keys(
            self.params,
            &self.keys.sk_d,
            &self.rekey_ni,
            &nr,
            &self.rekey_spii,
            &new_spir,
            &gir_new,
        );
        Ok(IkeSa {
            spi_i: self.rekey_spii,
            spi_r: new_spir,
            is_initiator: true,
            params: self.params,
            keys: new_keys,
            established: true,
            message_id: resp.header.message_id,
            rekey_dh: None,
            rekey_ni: Vec::new(),
            rekey_spii: [0u8; 8],
            child_ni: Vec::new(),
            child_keymat: Vec::new(),
        })
    }

    /// Rekey a CHILD SA: CREATE_CHILD_SA with a new KE and REKEY_SA notify
    /// carrying the old CHILD SA SPI. Returns the request.
    pub fn rekey_child_sa_request(&mut self, old_child_spi: &[u8; 4]) -> Result<Message> {
        self.message_id += 1;
        let dh = Dh::generate(self.params.dh)?;
        let ni = random_bytes(32);
        self.rekey_dh = Some(dh.clone());
        self.rekey_ni = ni.clone();
        let new_spi = random_spi4();
        let sa = SaPayload {
            proposals: vec![crate::transforms::esp_proposal_with_spi(&new_spi)],
        };
        let ke = KePayload {
            group: self.params.dh,
            public_key: dh.public.clone(),
        };
        let nonce = NoncePayload { nonce: ni.clone() };
        let notify = rekey_notify(ProtocolId::Esp, old_child_spi);
        let inner: Vec<Payload> = vec![
            Payload::Sa(sa),
            Payload::Ke(ke),
            Payload::Nonce(nonce),
            Payload::Notify(notify),
        ];
        let (sk_e, sk_a, salt) = self.dir_keys(self.is_initiator);
        self.encrypted(self.message_id, ExchangeType::CreateChildSa, inner, &sk_e, &sk_a, &salt)
    }

    /// Handle an incoming CHILD SA rekey request (responder side).
    pub fn handle_child_sa_rekey_request(&mut self, req: &Message) -> Result<(Message, Vec<u8>)> {
        let (sk_e, sk_a, salt) = self.dir_keys(false);
        let encr = self.params.encr();
        let sk = extract_sk(req)?;
        let inner = sk.decrypt(encr, self.params.integ(), &req.header, &sk_e, &sk_a, &salt)?;
        let (sa, ke) = sa_and_ke_inner(&inner)?;
        let ni = extract_nonce_inner(&inner)?;
        let new_spi = sa_spi4(&sa).ok_or(Error::Other("missing new CHILD SPI".into()))?;
        let dh = Dh::generate(self.params.dh)?;
        let gir_new = dh.shared(&ke.public_key)?;
        let nr = random_bytes(32);
        let len = child_keymat_len(&crate::transforms::default_esp_proposal(&new_spi));
        let new_keymat = child_keymat_rekey(self.params, &self.keys.sk_d, &gir_new, &ni, &nr, len);
        let resp_sa = SaPayload {
            proposals: vec![crate::transforms::esp_proposal_with_spi(&new_spi)],
        };
        let resp_ke = KePayload {
            group: self.params.dh,
            public_key: dh.public.clone(),
        };
        let nonce = NoncePayload { nonce: nr.clone() };
        let inner_resp: Vec<Payload> = vec![
            Payload::Sa(resp_sa),
            Payload::Ke(resp_ke),
            Payload::Nonce(nonce),
        ];
        let (sk_e_r, sk_a_r, salt_r) = self.dir_keys(false);
        let msg = self.encrypted(req.header.message_id, ExchangeType::CreateChildSa, inner_resp, &sk_e_r, &sk_a_r, &salt_r)?;
        Ok((msg, new_keymat))
    }

    fn encrypted(
        &self,
        message_id: u32,
        exchange: ExchangeType,
        inner: Vec<Payload>,
        sk_e: &[u8],
        sk_a: &[u8],
        _salt: &[u8],
    ) -> Result<Message> {
        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next_payload: PayloadType::Sk,
            version: crate::types::IKE_VERSION,
            exchange,
            flags: if self.is_initiator { flags::INITIATOR } else { 0 },
            message_id,
            length: 0,
        };
        let encr = self.params.encr();
        let (sk_e_key, salt_opt) = if encr.is_aead() {
            (sk_e[4..].to_vec(), Some(sk_e[..4].to_vec()))
        } else {
            (sk_e.to_vec(), None)
        };
        let next = inner.first().map(|p| p.ptype()).unwrap_or(PayloadType::None);
        let sk = EncryptedPayload::encrypt(
            encr,
            self.params.integ(),
            &header,
            next,
            &inner,
            &sk_e_key,
            sk_a,
            None,
            salt_opt.as_deref(),
        )?;
        let msg = Message {
            header,
            payloads: vec![Payload::Sk(sk)],
        };
        let bytes = msg.encode();
        Message::decode(&bytes)
    }
}

/// Encrypt inner payloads, filling the AUTH payload with `auth_data`.
fn seal(
    params: SaParams,
    header: &Header,
    mut inner: Vec<Payload>,
    sk_e: &[u8],
    sk_a: &[u8],
    auth_data: Vec<u8>,
) -> Result<EncryptedPayload> {
    for p in inner.iter_mut() {
        if let Payload::Auth(a) = p {
            a.data = auth_data.clone();
        }
    }
    let encr = params.encr();
    let (sk_e_key, salt) = if encr.is_aead() {
        (sk_e[4..].to_vec(), Some(sk_e[..4].to_vec()))
    } else {
        (sk_e.to_vec(), None)
    };
    let next = inner.first().map(|p| p.ptype()).unwrap_or(PayloadType::None);
    EncryptedPayload::encrypt(
        encr,
        params.integ(),
        header,
        next,
        &inner,
        &sk_e_key,
        sk_a,
        None,
        salt.as_deref(),
    )
}

// ===========================================================================
// Helpers
// ===========================================================================

fn rekey_notify(protocol: ProtocolId, spi: &[u8]) -> NotifyPayload {
    NotifyPayload {
        protocol: protocol.to_u8(),
        spi: spi.to_vec(),
        notify_type: REKEY_SA,
        data: Vec::new(),
    }
}

fn verify_auth(config: &AuthConfig, expected: &[u8], received: &[u8]) -> Result<()> {
    match config {
        AuthConfig::Psk(_) => {
            if expected.len() == received.len() && bool::from(expected.ct_eq(received)) {
                Ok(())
            } else {
                Err(Error::IntegrityCheckFailed)
            }
        }
        AuthConfig::Ed25519 { peer_public, .. } => {
            let pk = PublicKey::from_slice(peer_public)
                .map_err(|e| Error::Ed25519(e.to_string()))?;
            let sig = Signature::from_slice(received)
                .map_err(|e| Error::Ed25519(e.to_string()))?;
            pk.verify(expected, &sig).map_err(|_| Error::IntegrityCheckFailed)
        }
    }
}

fn extract_nonce(msg: &Message) -> Result<Vec<u8>> {
    msg.payloads
        .iter()
        .find_map(|p| {
            if let Payload::Nonce(n) = p {
                Some(n.nonce.clone())
            } else {
                None
            }
        })
        .ok_or(Error::Other("missing nonce".into()))
}

fn extract_ke(msg: &Message) -> Result<Vec<u8>> {
    msg.payloads
        .iter()
        .find_map(|p| {
            if let Payload::Ke(k) = p {
                Some(k.public_key.clone())
            } else {
                None
            }
        })
        .ok_or(Error::Other("missing KE".into()))
}

fn sa_and_ke(msg: &Message) -> Result<(Payload, Payload)> {
    let sa = msg
        .payloads
        .iter()
        .find(|p| matches!(p, Payload::Sa(_)))
        .cloned()
        .ok_or(Error::Other("missing SA".into()))?;
    let ke = msg
        .payloads
        .iter()
        .find(|p| matches!(p, Payload::Ke(_)))
        .cloned()
        .ok_or(Error::Other("missing KE".into()))?;
    Ok((sa, ke))
}

fn sa_and_ke_inner(inner: &[Payload]) -> Result<(Payload, KePayload)> {
    let sa = inner
        .iter()
        .find_map(|p| {
            if let Payload::Sa(s) = p {
                Some(s.clone())
            } else {
                None
            }
        })
        .ok_or(Error::Other("missing SA".into()))?;
    let ke = inner
        .iter()
        .find_map(|p| {
            if let Payload::Ke(k) = p {
                Some(k.clone())
            } else {
                None
            }
        })
        .ok_or(Error::Other("missing KE".into()))?;
    Ok((Payload::Sa(sa), ke))
}

fn extract_nonce_inner(inner: &[Payload]) -> Result<Vec<u8>> {
    inner
        .iter()
        .find_map(|p| {
            if let Payload::Nonce(n) = p {
                Some(n.nonce.clone())
            } else {
                None
            }
        })
        .ok_or(Error::Other("missing nonce".into()))
}

fn sa_spi8(sa: &Payload) -> Option<[u8; 8]> {
    if let Payload::Sa(s) = sa {
        if let Some(p) = s.proposals.first() {
            if p.spi.len() == 8 {
                let mut a = [0u8; 8];
                a.copy_from_slice(&p.spi);
                return Some(a);
            }
        }
    }
    None
}

fn sa_spi4(sa: &Payload) -> Option<[u8; 4]> {
    if let Payload::Sa(s) = sa {
        if let Some(p) = s.proposals.first() {
            if p.spi.len() == 4 {
                let mut a = [0u8; 4];
                a.copy_from_slice(&p.spi);
                return Some(a);
            }
        }
    }
    None
}

fn extract_sk(msg: &Message) -> Result<EncryptedPayload> {
    msg.payloads
        .iter()
        .find_map(|p| {
            if let Payload::Sk(s) = p {
                Some(s.clone())
            } else {
                None
            }
        })
        .ok_or(Error::Other("missing SK".into()))
}

fn find_id_bytes(inner: &[Payload]) -> Result<Vec<u8>> {
    find_id_bytes_in(inner, PayloadType::Idi)
}

fn find_id_bytes_in(inner: &[Payload], which: PayloadType) -> Result<Vec<u8>> {
    for i in 0..inner.len() {
        if inner[i].ptype() == which {
            let next = if i + 1 < inner.len() {
                inner[i + 1].ptype()
            } else {
                PayloadType::None
            };
            return Ok(encoded_payload(&inner[i], next));
        }
    }
    Err(Error::Other("missing ID payload".into()))
}

fn any_ts() -> TsPayload {
    TsPayload {
        selectors: vec![TrafficSelector {
            ts_type: crate::types::ts_type::IPV4_ADDR_RANGE,
            iproto: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0, 0, 0, 0],
            end_addr: vec![255, 255, 255, 255],
        }],
    }
}

/// Placeholder zeroed keys (replaced before use).
fn zero_keys() -> IkeSaKeys {
    IkeSaKeys {
        sk_d: Vec::new(),
        sk_ai: Vec::new(),
        sk_ar: Vec::new(),
        sk_ei: Vec::new(),
        sk_er: Vec::new(),
        sk_pi: Vec::new(),
        sk_pr: Vec::new(),
    }
}
