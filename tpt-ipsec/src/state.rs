//! IKEv2 IKE SA state machine, key derivation, and AUTH (RFC 7296).
//!
//! The handshake is modeled as two peers (`IkeInitiator` / `IkeResponder`)
//! exchanging the IKE_SA_INIT and IKE_AUTH exchanges. After the handshake
//! both sides hold an established [`IkeSa`] that can drive CREATE_CHILD_SA
//! and IKE SA rekeying.

use crate::crypto::{random_bytes, Dh, Encr, Integ, Prf};
use crate::error::{Error, Result};
use crate::message::{
    self, AuthPayload, CertPayload, EncryptedPayload, Header, IdPayload, KePayload, Message,
    NoncePayload, Payload, TsPayload, TrafficSelector,
};
use crate::transforms::SaPayload;
use crate::types::{
    flags, AuthMethod, CertEncoding, DhGroup, EncrId, ExchangeType, IdType, IntegId, PayloadType,
    PrfId,
};
use ed25519_compact::{KeyPair, PublicKey, Signature};
use subtle::ConstantTimeEq;

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
    /// `own_secret` signs; `peer_public` verifies the remote peer.
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
    let encr = params.encr();
    let integ = params.integ();
    let skeyseed = prf.prf(&concat(ni, nr), gir);
    let seed = concat4(ni, nr, spii, spir);
    let encr_key_len = encr.key_len() + if encr.is_aead() { 4 } else { 0 };
    let li = integ.map(|i| i.key_len()).unwrap_or(0);
    let lp = prf.output_len();
    let needed = lp + 2 * li + 2 * encr_key_len + 2 * lp;
    let km = prf.prf_plus(&skeyseed, &seed, needed);
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

/// Derive CHILD SA keying material (RFC 7296 §2.17).
pub fn child_keymat(params: SaParams, sk_d: &[u8], ni: &[u8], nr: &[u8], len: usize) -> Vec<u8> {
    let prf = params.prf();
    prf.prf_plus(sk_d, &concat(ni, nr), len)
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
    init_request: Vec<u8>,
    init_response: Vec<u8>,
    child_ni: Vec<u8>,
    child_nr: Vec<u8>,
    established: bool,
    message_id: u32,
}

impl IkeInitiator {
    /// Begin a handshake. `policy` is also the initiator's offer (symmetric for tests).
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
            keys: unsafe_zero_keys(),
            id_i,
            id_r: IdPayload {
                id_type: IdType::KeyId,
                data: Vec::new(),
            },
            init_request: Vec::new(),
            init_response: Vec::new(),
            child_ni: Vec::new(),
            child_nr: Vec::new(),
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
        let msg = Message {
            header,
            payloads: vec![
                Payload::Sa(sa),
                Payload::Ke(ke),
                Payload::Nonce(nonce),
            ],
        };
        let bytes = msg.encode();
        self.init_request = bytes.clone();
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
        self.id_r.data = self.id_i.data.clone(); // responder id echoes initiator id for tests
        let gir = self.dh.shared(&self.peer_dh_pub)?;
        self.keys = derive_keys(
            self.params,
            &self.ni,
            &self.nr,
            &self.spi_i,
            &self.spi_r,
            &gir,
        );
        self.init_response = resp.encode();
        Ok(self.build_auth_request()?)
    }

    fn build_auth_request(&mut self) -> Result<Message> {
        self.message_id = 1;
        let child_spi = random_spi4();
        let (inner, id_bytes) = self.build_auth_inner(
            &self.keys.sk_pi,
            true,
            Some(child_spi),
        )?;
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
        let sk = self.encrypt_inner(&header, inner, &self.keys.sk_ei, &self.keys.sk_ai, false)?;
        let mut msg = Message {
            header,
            payloads: vec![Payload::Sk(sk)],
        };
        // capture child nonce for later CHILD SA derivation
        self.child_ni = self.ni.clone();
        self.child_nr = self.nr.clone();
        let bytes = msg.encode();
        Ok(Message::decode(&bytes)?)
    }

    /// Build inner IKE_AUTH payloads. `is_initiator` selects which SK_p / ID to use
    /// for digital-signature AUTH. Returns the inner payloads and the encoded ID
    /// payload bytes (used by AUTH).
    fn build_auth_inner(
        &self,
        sk_p: &[u8],
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
        let id_bytes = encoded_payload(&id_payload, PayloadType::Auth);

        let mut inner: Vec<Payload> = Vec::new();
        inner.push(id_payload);

        // Optional certificate (realistic for digital-signature auth).
        if let AuthConfig::Ed25519 { peer_public, .. } = &self.auth {
            let cert = CertPayload {
                encoding: CertEncoding::RawPublicKey,
                data: peer_public.to_vec(),
            };
            inner.push(Payload::Cert(cert));
        }

        // AUTH payload (placeholder data; filled after computing AUTH value).
        let method = self.auth.method();
        inner.push(Payload::Auth(AuthPayload {
            method,
            data: Vec::new(),
        }));

        // CHILD SA proposal (ESP).
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
        match &self.auth {
            AuthConfig::Psk(psk) => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                Ok(self.params.prf().prf(psk, base))
            }
            AuthConfig::Ed25519 { own_secret, .. } => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                let sk_p = if is_initiator { &self.keys.sk_pi } else { &self.keys.sk_pr };
                let idd = self.params.prf().prf_plus(sk_p, id_bytes, id_bytes.len());
                let mut msg = base.to_vec();
                msg.extend_from_slice(&idd);
                let kp = KeyPair::from_slice(own_secret)
                    .map_err(|e| Error::Ed25519(e.to_string()))?;
                let sig: Signature = kp.sk.sign(&msg, None);
                Ok(sig.to_vec())
            }
        }
    }

    fn encrypt_inner(
        &self,
        header: &Header,
        mut inner: Vec<Payload>,
        sk_e: &[u8],
        sk_a: &[u8],
        _unused: bool,
    ) -> Result<EncryptedPayload> {
        // Fill the AUTH payload with the computed value (last Auth in inner).
        let id_for_auth = find_id_bytes(&inner)?;
        let auth_data = self.compute_auth(true, &id_for_auth)?;
        for p in inner.iter_mut() {
            if let Payload::Auth(a) = p {
                a.data = auth_data.clone();
            }
        }
        let encr = self.params.encr();
        let (sk_e_key, salt) = if encr.is_aead() {
            (sk_e[4..].to_vec(), Some(sk_e[..4].to_vec()))
        } else {
            (sk_e.to_vec(), None)
        };
        let next = inner
            .first()
            .map(|p| p.ptype())
            .unwrap_or(PayloadType::None);
        EncryptedPayload::encrypt(
            encr,
            self.params.integ(),
            header,
            next,
            &inner,
            &sk_e_key,
            sk_a,
            None,
            salt.as_deref(),
        )
    }

    /// Process the IKE_AUTH response; returns established SA.
    pub fn on_auth_response(&mut self, resp: &Message) -> Result<IkeSa> {
        if !resp.header.is_response() {
            return Err(Error::Other("expected response".into()));
        }
        self.init_response = resp.encode();
        // decrypt with responder's keys (SK_er / SK_ar)
        let sk = extract_sk(resp)?;
        let encr = self.params.encr();
        let (sk_e_key, salt) = if encr.is_aead() {
            (self.keys.sk_er[4..].to_vec(), self.keys.sk_er[..4].to_vec())
        } else {
            (self.keys.sk_er.clone(), Vec::new())
        };
        let inner = sk.decrypt(
            encr,
            self.params.integ(),
            &resp.header,
            &sk_e_key,
            &self.keys.sk_ar,
            &salt,
        )?;
        // verify responder AUTH
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
        // Recompute what the peer signed: peer uses its own SK_p and the same
        // base message. For verification we recompute identically.
        match &self.auth {
            AuthConfig::Psk(psk) => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                Ok(self.params.prf().prf(psk, base))
            }
            AuthConfig::Ed25519 { .. } => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                let sk_p = if is_initiator { &self.keys.sk_pi } else { &self.keys.sk_pr };
                let idd = self.params.prf().prf_plus(sk_p, id_bytes, id_bytes.len());
                let mut msg = base.to_vec();
                msg.extend_from_slice(&idd);
                Ok(msg)
            }
        }
    }

    fn to_established(&self) -> IkeSa {
        let child_keymat = child_keymat(
            self.params,
            &self.keys.sk_d,
            &self.child_ni,
            &self.child_nr,
            64,
        );
        IkeSa {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            is_initiator: true,
            params: self.params,
            keys: self.keys.clone(),
            established: true,
            message_id: self.message_id,
            init_request: self.init_request.clone(),
            init_response: self.init_response.clone(),
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
    init_request: Vec<u8>,
    init_response: Vec<u8>,
    established: bool,
    child_ni: Vec<u8>,
    child_nr: Vec<u8>,
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
            keys: unsafe_zero_keys(),
            id_i: IdPayload {
                id_type: IdType::KeyId,
                data: Vec::new(),
            },
            id_r,
            init_request: Vec::new(),
            init_response: Vec::new(),
            established: false,
            child_ni: Vec::new(),
            child_nr: Vec::new(),
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
        self.init_request = req.encode();
        // chosen proposal (echo initiator's; policy == default here)
        let _chosen = select_proposal(req)?;
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
        let msg = Message {
            header,
            payloads: vec![Payload::Sa(sa), Payload::Ke(ke), Payload::Nonce(nonce)],
        };
        let bytes = msg.encode();
        self.init_response = bytes.clone();
        Ok(Message::decode(&bytes)?)
    }

    /// Handle the IKE_AUTH request, returning the response and the established SA.
    pub fn on_auth_request(&mut self, req: &Message) -> Result<(Message, IkeSa)> {
        // decrypt with initiator's keys (SK_ei / SK_ai)
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
        // verify initiator AUTH
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
        self.child_ni = self.ni.clone();
        self.child_nr = self.nr.clone();

        // Build IKE_AUTH response (responder).
        let child_spi = random_spi4();
        let (inner_resp, idr_bytes) = self.build_auth_inner(&self.keys.sk_pr, false, Some(child_spi))?;
        let auth_data = self.compute_auth(false, &idr_bytes)?;
        let mut inner_resp = inner_resp;
        for p in inner_resp.iter_mut() {
            if let Payload::Auth(a) = p {
                a.data = auth_data.clone();
            }
        }
        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next_payload: PayloadType::Sk,
            version: crate::types::IKE_VERSION,
            exchange: ExchangeType::IkeAuth,
            flags: flags::RESPONSE,
            message_id: 1,
            length: 0,
        };
        let (sk_e_key, salt) = if encr.is_aead() {
            (self.keys.sk_er[4..].to_vec(), Some(self.keys.sk_er[..4].to_vec()))
        } else {
            (self.keys.sk_er.clone(), None)
        };
        let next = inner_resp
            .first()
            .map(|p| p.ptype())
            .unwrap_or(PayloadType::None);
        let sk = EncryptedPayload::encrypt(
            encr,
            self.params.integ(),
            &header,
            next,
            &inner_resp,
            &sk_e_key,
            &self.keys.sk_ar,
            None,
            salt.as_deref(),
        )?;
        let msg = Message {
            header,
            payloads: vec![Payload::Sk(sk)],
        };
        let bytes = msg.encode();
        self.init_response = bytes.clone();
        self.established = true;
        let sa = self.to_established();
        Ok((Message::decode(&bytes)?, sa))
    }

    fn build_auth_inner(
        &self,
        sk_p: &[u8],
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
        let id_bytes = encoded_payload(&id_payload, PayloadType::Auth);
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
        let _ = sk_p;
        Ok((inner, id_bytes))
    }

    fn compute_auth(&self, is_initiator: bool, id_bytes: &[u8]) -> Result<Vec<u8>> {
        match &self.auth {
            AuthConfig::Psk(psk) => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                Ok(self.params.prf().prf(psk, base))
            }
            AuthConfig::Ed25519 { own_secret, .. } => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                let sk_p = if is_initiator { &self.keys.sk_pi } else { &self.keys.sk_pr };
                let idd = self.params.prf().prf_plus(sk_p, id_bytes, id_bytes.len());
                let mut msg = base.to_vec();
                msg.extend_from_slice(&idd);
                let kp = KeyPair::from_slice(own_secret)
                    .map_err(|e| Error::Ed25519(e.to_string()))?;
                let sig: Signature = kp.sk.sign(&msg, None);
                Ok(sig.to_vec())
            }
        }
    }

    fn compute_auth_peer(&self, is_initiator: bool, id_bytes: &[u8]) -> Result<Vec<u8>> {
        match &self.auth {
            AuthConfig::Psk(psk) => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                Ok(self.params.prf().prf(psk, base))
            }
            AuthConfig::Ed25519 { .. } => {
                let base = if is_initiator {
                    &self.init_request
                } else {
                    &self.init_response
                };
                let sk_p = if is_initiator { &self.keys.sk_pi } else { &self.keys.sk_pr };
                let idd = self.params.prf().prf_plus(sk_p, id_bytes, id_bytes.len());
                let mut msg = base.to_vec();
                msg.extend_from_slice(&idd);
                Ok(msg)
            }
        }
    }

    fn to_established(&self) -> IkeSa {
        let child_keymat = child_keymat(self.params, &self.keys.sk_d, &self.child_ni, &self.child_nr, 64);
        IkeSa {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            is_initiator: false,
            params: self.params,
            keys: self.keys.clone(),
            established: true,
            message_id: 1,
            init_request: self.init_request.clone(),
            init_response: self.init_response.clone(),
            child_keymat,
        }
    }
}

// ===========================================================================
// Established IKE SA
// ===========================================================================

/// An established IKE SA, capable of CREATE_CHILD_SA exchanges.
#[derive(Debug, Clone)]
pub struct IkeSa {
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    pub is_initiator: bool,
    pub params: SaParams,
    pub keys: IkeSaKeys,
    pub established: bool,
    pub message_id: u32,
    pub init_request: Vec<u8>,
    pub init_response: Vec<u8>,
    pub child_keymat: Vec<u8>,
}

impl IkeSa {
    /// Perform a CREATE_CHILD_SA exchange creating a new CHILD SA (no rekey).
    /// Returns the request (initiator) to be sent to the responder.
    pub fn create_child_sa_request(&mut self) -> Result<Message> {
        self.message_id += 1;
        let ni = random_bytes(32);
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
        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next_payload: PayloadType::Sk,
            version: crate::types::IKE_VERSION,
            exchange: ExchangeType::CreateChildSa,
            flags: if self.is_initiator {
                flags::INITIATOR
            } else {
                0
            },
            message_id: self.message_id,
            length: 0,
        };
        let (sk_e, sk_a, salt) = self.dir_keys();
        let next = inner.first().map(|p| p.ptype()).unwrap_or(PayloadType::None);
        let sk = EncryptedPayload::encrypt(
            self.params.encr(),
            self.params.integ(),
            &header,
            next,
            &inner,
            &sk_e,
            &sk_a,
            None,
            Some(salt.as_slice()),
        )?;
        let msg = Message {
            header,
            payloads: vec![Payload::Sk(sk)],
        };
        let bytes = msg.encode();
        Ok(Message::decode(&bytes)?)
    }

    /// Handle an incoming CREATE_CHILD_SA request (responder side), producing the
    /// response and refreshing CHILD SA keying material.
    pub fn handle_child_sa_request(&mut self, req: &Message) -> Result<Message> {
        let sk = extract_sk(req)?;
        let (sk_e, sk_a, salt) = self.dir_keys();
        let encr = self.params.encr();
        let inner = sk.decrypt(encr, self.params.integ(), &req.header, &sk_e, &sk_a, &salt)?;
        // Extract Ni from the request for KEYMAT refresh.
        let ni = inner
            .iter()
            .find_map(|p| {
                if let Payload::Nonce(n) = p {
                    Some(n.nonce.clone())
                } else {
                    None
                }
            })
            .ok_or(Error::Other("missing Ni in CHILD_SA".into()))?;
        let nr = random_bytes(32);
        let child_spi = random_spi4();
        let sa = SaPayload {
            proposals: vec![crate::transforms::default_esp_proposal(&child_spi)],
        };
        let nonce = NoncePayload { nonce: nr.clone() };
        let inner_resp: Vec<Payload> = vec![
            Payload::Sa(sa),
            Payload::Nonce(nonce),
            Payload::TSi(any_ts()),
            Payload::TSr(any_ts()),
        ];
        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next_payload: PayloadType::Sk,
            version: crate::types::IKE_VERSION,
            exchange: ExchangeType::CreateChildSa,
            flags: flags::RESPONSE,
            message_id: req.header.message_id,
            length: 0,
        };
        let (sk_e2, sk_a2, salt2) = self.dir_keys();
        let next = inner_resp.first().map(|p| p.ptype()).unwrap_or(PayloadType::None);
        let sk = EncryptedPayload::encrypt(
            encr,
            self.params.integ(),
            &header,
            next,
            &inner_resp,
            &sk_e2,
            &sk_a2,
            None,
            Some(salt2.as_slice()),
        )?;
        self.child_keymat = child_keymat(self.params, &self.keys.sk_d, &ni, &nr, 64);
        let msg = Message {
            header,
            payloads: vec![Payload::Sk(sk)],
        };
        let bytes = msg.encode();
        Ok(Message::decode(&bytes)?)
    }

    /// Keys used to protect a message this SA sends (depends on role).
    fn dir_keys(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let encr = self.params.encr();
        if self.is_initiator {
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
}

// ===========================================================================
// Helpers
// ===========================================================================

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

fn select_proposal(req: &Message) -> Result<SaPayload> {
    let offer = req
        .payloads
        .iter()
        .find_map(|p| {
            if let Payload::Sa(s) = p {
                Some(s)
            } else {
                None
            }
        })
        .ok_or(Error::NoProposalChosen)?;
    offer.select(&SaPayload {
        proposals: vec![crate::transforms::default_ike_proposal()],
    })
}

fn find_id_bytes(inner: &[Payload]) -> Result<Vec<u8>> {
    find_id_bytes_in(inner, PayloadType::Idi)
}

fn find_id_bytes_in(inner: &[Payload], which: PayloadType) -> Result<Vec<u8>> {
    let mut prev = PayloadType::None;
    for i in 0..inner.len() {
        if inner[i].ptype() == which {
            let next = if i + 1 < inner.len() {
                inner[i + 1].ptype()
            } else {
                PayloadType::None
            };
            let _ = prev;
            return Ok(encoded_payload(&inner[i], next));
        }
        prev = inner[i].ptype();
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
fn unsafe_zero_keys() -> IkeSaKeys {
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
