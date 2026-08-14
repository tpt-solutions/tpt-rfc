//! Minimal RFC 3161 Time-Stamp Authority (TSA) responder.
//!
//! Given a `TimeStampReq`, it validates the request, builds the `TSTInfo`, and
//! signs it into a CMS `SignedData` `timeStampToken`, returning a
//! `TimeStampResp`. This is the part of RFC 3161 that is missing under a clean
//! dual license (existing crates such as `freetsa` only cover the client).

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use const_oid::ObjectIdentifier;
use der::{
    asn1::{GeneralizedTime, OctetStringRef, UintRef},
    Decode, Encode, Sequence,
};
use spki::AlgorithmIdentifierRef;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

use crate::error::{Result, TspError};
use crate::hash::HashAlgorithm;
use crate::oids;
use crate::signer::{uint_be, SigningKey};
use crate::wire::*;

/// OIDs that are referenced for the lifetime of the whole program (so their
/// `ObjectIdentifierRef` can be `'static` and used inside locally-borrowed DER
/// structs without lifetime friction).
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap(oids::ID_SIGNED_DATA);
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap(oids::ID_CT_TST_INFO);

/// A minimal time-stamp authority.
pub struct Tsa {
    cert: Certificate,
    cert_der: Vec<u8>,
    signer: SigningKey,
    default_policy: ObjectIdentifier,
}

impl Tsa {
    /// Build a TSA from a DER-encoded signer certificate, the matching private
    /// key, and a default TSA policy OID (used when the request omits one).
    pub fn new(cert_der: &[u8], signer: SigningKey, default_policy: ObjectIdentifier) -> Result<Self> {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| TspError::Crypto(format!("invalid signer certificate: {e}")))?;
        Ok(Tsa {
            cert,
            cert_der: cert_der.to_vec(),
            signer,
            default_policy,
        })
    }

    /// Issue a `TimeStampResp` (DER) for a DER-encoded `TimeStampReq`.
    pub fn issue(&self, request_der: &[u8]) -> Result<Vec<u8>> {
        let req = TimeStampReq::from_der(request_der)
            .map_err(|e| TspError::Crypto(format!("invalid request: {e}")))?;

        let hash = HashAlgorithm::from_oid(&req.message_imprint.hash_algorithm.oid)?;
        let hashed_message = req.message_imprint.hashed_message.as_bytes().to_vec();

        let gen_time = now_generalized()?;
        let gen_time_der = gen_time.to_der().map_err(der_err)?;
        let serial = serial_from(
            &hashed_message,
            req.nonce
                .as_ref()
                .map(|n| n.as_bytes().to_vec())
                .unwrap_or_default(),
        );

        let policy: ObjectIdentifier = match &req.req_policy {
            Some(p) => p.to_owned(),
            None => self.default_policy.clone(),
        };
        let hash_oid = hash.oid();
        let econtent_oid = ID_CT_TST_INFO;

        // --- TSTInfo (borrows local buffers below) ---
        let version = uint_be(1);
        let serial_bytes = uint_be(serial);
        let tst = TstInfo {
            version: UintRef::new(&version).map_err(der_err)?,
            policy: (&policy).into(),
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierRef {
                    oid: (&hash_oid).into(),
                    parameters: None,
                },
                hashed_message: OctetStringRef::new(&hashed_message).map_err(der_err)?,
            },
            serial_number: UintRef::new(&serial_bytes).map_err(der_err)?,
            gen_time,
            accuracy: None,
            ordering: None,
            nonce: req
                .nonce
                .as_ref()
                .map(|n| UintRef::new(n.as_bytes()).map_err(der_err))
                .transpose()?,
            tsa: None,
            extensions: None,
        };
        let e_content = tst.to_der().map_err(der_err)?;

        // --- Signed attributes ---
        let digest = hash.digest(&e_content);
        let content_type_attr = cms_attribute(&oids::oid(oids::CONTENT_TYPE), &id_ct_tst_info_der())?;
        let md_attr = cms_attribute(&oids::oid(oids::MESSAGE_DIGEST), &octet_string_der(&digest))?;
        let st_attr = cms_attribute(&oids::oid(oids::SIGNING_TIME), &gen_time_der)?;
        let mut attrs = vec![content_type_attr, md_attr, st_attr];
        attrs.sort();
        let signed_attrs_content: Vec<u8> = attrs.concat();

        // Signature computed over the DER encoding of the SignedAttributes SET
        // (RFC 5652 §5.4): tag SET (0x31) + length + content.
        let signed_attrs_set = signed_attrs_set_tlv(&signed_attrs_content);
        let to_be_signed = hash.digest(&signed_attrs_set);

        let (sig_oid, signature) = self.signer.sign(hash, &to_be_signed)?;

        // --- SignerInfo ---
        let cert_serial = self.cert.tbs_certificate().serial_number().as_bytes().to_vec();
        let issuer = self.cert.tbs_certificate().issuer().clone();
        let sid_version = uint_be(3);
        let signer_info = SignerInfo {
            version: UintRef::new(&sid_version).map_err(der_err)?,
            sid: SignerIdentifier(IssuerAndSerialNumber {
                issuer,
                serial_number: UintRef::new(&cert_serial).map_err(der_err)?,
            }),
            digest_algorithm: AlgorithmIdentifierRef {
                oid: (&hash_oid).into(),
                parameters: None,
            },
            signed_attrs: Some(RawContent(signed_attrs_content)),
            signature_algorithm: AlgorithmIdentifierRef {
                oid: sig_oid,
                parameters: None,
            },
            signature: OctetStringRef::new(&signature).map_err(der_err)?,
        };

        // --- SignedData ---
        let os_der = OctetStringRef::new(&e_content).map_err(der_err)?.to_der().map_err(der_err)?;
        let e_content_any = der::asn1::AnyRef::from_der(&os_der).map_err(der_err)?;
        let cert_set_content = {
            let mut v = vec![self.cert_der.to_vec()];
            v.sort();
            v.concat()
        };
        let sd_version = uint_be(3);
        let signed_data = SignedData {
            version: UintRef::new(&sd_version).map_err(der_err)?,
            digest_algorithms: DigestAlgorithmIdentifiers(vec![AlgorithmIdentifierRef {
                oid: (&hash_oid).into(),
                parameters: None,
            }]),
            encap_content_info: EncapsulatedContentInfo {
                e_content_type: (&econtent_oid).into(),
                e_content: Some(e_content_any),
            },
            certificates: Some(RawContent(cert_set_content)),
            crls: None,
            signer_infos: SignerInfos(vec![signer_info]),
        };
        let signed_data_der = signed_data.to_der().map_err(der_err)?;
        let signed_data_any = der::asn1::AnyRef::from_der(&signed_data_der).map_err(der_err)?;

        // --- ContentInfo + TimeStampResp ---
        let ci = ContentInfo {
            content_type: (&ID_SIGNED_DATA).into(),
            content: signed_data_any,
        };
        let resp = TimeStampResp {
            status: PkiStatusInfo {
                status: UintRef::new(&[0]).map_err(der_err)?,
                status_string: None,
                fail_info: None,
            },
            token: Some(ci),
        };
        resp.to_der().map_err(der_err)
    }
}

// --- small helpers ---

fn der_err(e: der::Error) -> TspError {
    TspError::Der(e)
}

fn now_generalized() -> Result<GeneralizedTime> {
    let dt = der::DateTime::try_from(SystemTime::now())
        .map_err(|e| TspError::Crypto(format!("system time: {e}")))?;
    Ok(GeneralizedTime::from(dt))
}

fn serial_from(hashed: &[u8], nonce: Vec<u8>) -> u64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(hashed);
    h.update(&nonce);
    let d = h.finalize();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&d[0..8]);
    u64::from_be_bytes(buf) | 1
}

fn octet_string_der(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&der::Length::try_from(data.len()).unwrap().to_der().unwrap());
    out.extend_from_slice(data);
    out
}

fn id_ct_tst_info_der() -> Vec<u8> {
    ID_CT_TST_INFO.to_der().unwrap()
}

// A deterministic demo policy OID used by `self_signed_demo`.
const DEMO_POLICY: &str = "1.3.6.1.4.1.9999.1";

impl Tsa {
    /// Build a TSA backed by a freshly minted, self-signed P-256 certificate.
    ///
    /// This is intended for examples, tests, and local interop; a production
    /// deployment should load a real TSA certificate/key pair instead.
    pub fn self_signed_demo() -> Result<Self> {
        use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};

        // Deterministic demo key (not for production use).
        let mut seed = [0x42u8; 32];
        seed[0] = 0x01;
        let signer = P256SigningKey::from_bytes(&seed).expect("valid P-256 seed");
        let spki = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key())
            .map_err(|e| TspError::Crypto(e.to_string()))?;

        struct DemoProfile;
        impl BuilderProfile for DemoProfile {
            fn get_issuer(&self, _subject: &Name) -> Name {
                Name::from_str("CN=TPT Demo TSA").unwrap()
            }
            fn get_subject(&self) -> Name {
                Name::from_str("CN=TPT Demo TSA").unwrap()
            }
            fn build_extensions(
                &self,
                _spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
                _issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
                _tbs: &x509_cert::certificate::TbsCertificate,
            ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
                Ok(vec![])
            }
        }

        let validity = Validity::from_now(Duration::new(3600 * 24 * 365 * 10, 0))
            .map_err(|e| TspError::Crypto(e.to_string()))?;
        let serial = SerialNumber::from(1u64);
        let mut builder = CertificateBuilder::new(DemoProfile, serial, validity, spki)
            .map_err(|e| TspError::Crypto(e.to_string()))?;
        let cert = builder
            .build::<_, P256Signature>(&signer)
            .map_err(|e| TspError::Crypto(e.to_string()))?;
        let cert_der = cert.to_der().map_err(|e| TspError::Crypto(e.to_string()))?;
        Tsa::new(&cert_der, SigningKey::EcdsaP256(signer), oids::oid(DEMO_POLICY))
    }
}
