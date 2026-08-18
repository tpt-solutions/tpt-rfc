//! RFC 3161 `TimeStampResp` — parsing, verification, and the TSA responder.
//!
//! ```text
//! TimeStampResp ::= SEQUENCE  {
//!    status                  PKIStatusInfo,
//!    timeStampToken          TimeStampToken     OPTIONAL  }
//!
//! PKIStatusInfo ::= SEQUENCE  {
//!    status                  PKIStatus,
//!    statusString            PKIFreeText        OPTIONAL,
//!    failInfo                PKIFailureInfo     OPTIONAL  }
//!
//! PKIStatus ::= INTEGER {
//!    granted                (0),
//!    grantedWithMods        (1),
//!    rejection              (2),
//!    waiting                (3),
//!    revocationWarning      (4),
//!    revocationNotification (5) }
//! ```

use const_oid::ObjectIdentifier;
use der::{Decode, Tag, Tagged};

use x509_cert::Certificate;
use crate::crypto::SigningKey;
use crate::error::{TspError, Result};
use crate::request::TimestampRequest;
use crate::token::{build_timestamp_token, verify_timestamp_token, TstInfo};
use crate::wire;
use x509_cert::Certificate as X509Certificate;

/// RFC 3161 `TimeStampResp`.
#[derive(Clone, Debug)]
pub struct TimestampResponse {
    /// The `PKIStatus` (0 = granted, 1 = grantedWithMods, 2+ = error/waiting).
    pub status: u8,
    /// Optional human-readable status string.
    pub status_string: Option<String>,
    /// The `TimeStampToken` DER (CMS `SignedData`), present only on success.
    pub token: Option<Vec<u8>>,
}

impl TimestampResponse {
    /// Encode `TimeStampResp` to DER.
    pub fn to_der(&self) -> Vec<u8> {
        let mut status_parts = vec![wire::integer_u64(self.status as u64)];
        if let Some(s) = &self.status_string {
            // PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
            let utf8 = wire::tlv(0x0C, s.as_bytes());
            status_parts.push(wire::sequence(&[utf8]));
        }
        let status_info = wire::sequence(&status_parts);
        let mut parts = vec![status_info];
        if let Some(tok) = &self.token {
            parts.push(wire::sequence(&[wire::oid_der(&oid_signed_data()), wire::ctx(0, tok)]));
        }
        wire::sequence(&parts)
    }

    /// Parse a `TimeStampResp` from DER.
    pub fn from_der(der_bytes: &[u8]) -> Result<TimestampResponse> {
        let seq = der::Any::from_der(der_bytes).map_err(TspError::Asn1)?;
        wire::ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = wire::Cursor::new(seq.value());

        let status_info = c.take()?;
        wire::ensure_tag(status_info.tag(), Tag::Sequence)?;
        let mut si = wire::Cursor::new(status_info.value());
        let status = wire::integer_value(&si.take()?)?;
        if status.len() > 1 {
            return Err(TspError::Crypto("PKIStatus too large".into()));
        }
        let status = status[0];
        let status_string = if !si.at_end() && si.peek_tag() == Some(Tag::Sequence) {
            let ft = si.take()?;
            let mut fti = wire::Cursor::new(ft.value());
            let utf8 = fti.take()?;
            Some(String::from_utf8_lossy(utf8.value()).into_owned())
        } else {
            None
        };

        let token = if c.at_end() {
            None
        } else {
            let tok_seq = c.take()?;
            wire::ensure_tag(tok_seq.tag(), Tag::Sequence)?;
            let mut ti = wire::Cursor::new(tok_seq.value());
            let _ct = ti.take()?;
            let inner = ti.take()?;
            wire::ensure_tag(inner.tag(), wire::ctx_tag(0))?;
            Some(inner.value().to_vec())
        };

        Ok(TimestampResponse {
            status,
            status_string,
            token,
        })
    }

    /// True when `status` is `granted` (0) or `grantedWithMods` (1).
    pub fn is_success(&self) -> bool {
        self.status == 0 || self.status == 1
    }

    /// Verify the response token against the original request and (optionally)
    /// a set of trust anchors. Returns the verified `TSTInfo`.
    pub fn verify(&self, req: &TimestampRequest, anchors: &[Certificate]) -> Result<TstInfo> {
        if !self.is_success() {
            return Err(TspError::PkiStatus(self.status));
        }
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| TspError::Crypto("success response missing timeStampToken".into()))?;
        let tst = verify_timestamp_token(token, anchors)?;

        // TSTInfo.messageImprint must equal the request's messageImprint.
        let req_imprint = req.message_imprint();
        if tst.message_imprint != req_imprint {
            return Err(TspError::TstInfoMismatch(
                "messageImprint does not match the request".into(),
            ));
        }
        // Nonce must match when present in the request.
        if let Some(req_nonce) = req.nonce() {
            match tst.nonce {
                Some(n) if n == req_nonce => {}
                _ => return Err(TspError::NonceMismatch),
            }
        }
        Ok(tst)
    }
}

fn oid_signed_data() -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2")
}

// ---------------------------------------------------------------------------
// TSA responder
// ---------------------------------------------------------------------------

/// A minimal TSA responder configuration.
pub struct TimestampAuthority {
    /// The TSA's signing key.
    pub signer: SigningKey,
    /// The TSA's signing certificate (included in the token when `certReq` is set).
    pub cert: X509Certificate,
    /// The default policy OID to assert when the request omits one.
    pub policy: ObjectIdentifier,
}

impl TimestampAuthority {
    /// Build a `TimeStampResp` (granted, with a `TimeStampToken`) for a DER
    /// `TimeStampReq`. Rejects the request unless the message-imprint hash
    /// algorithm is supported and (when the request carried a nonce) echoes it.
    pub fn respond(&self, req_der: &[u8]) -> Result<TimestampResponse> {
        let req = crate::request::parse_timestamp_req(req_der)?;
        let imprint = req.message_imprint();

        let tst = TstInfo::from_request(
            req.policy().cloned().unwrap_or_else(|| self.policy.clone()),
            &imprint,
            random_serial(),
            der::DateTime::try_from(std::time::SystemTime::now())
                .map_err(|e| TspError::Crypto(e.to_string()))?,
            req.nonce(),
        );

        let token = build_timestamp_token(&tst, &self.signer, &self.cert)?;
        Ok(TimestampResponse {
            status: 0,
            status_string: None,
            token: Some(token),
        })
    }

    /// Build a `TimeStampResp` rejecting the request with the given `PKIStatus`.
    pub fn reject(&self, status: u8, message: Option<&str>) -> TimestampResponse {
        TimestampResponse {
            status,
            status_string: message.map(|s| s.to_string()),
            token: None,
        }
    }
}

fn random_serial() -> u64 {
    use rand_core::RngCore;
    let mut rng = rand_core::OsRng;
    rng.next_u64()
}
