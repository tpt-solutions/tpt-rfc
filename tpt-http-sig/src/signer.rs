// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! High-level signing and verification API (RFC 9421 §3.1 / §3.2).

use crate::algorithm::{Algorithm, SigningKey, VerifyingKey};
use crate::components::ComponentId;
use crate::error::{HttpSigError, Result};
use crate::headers::parse_signature_input_value;
use crate::message::HttpMessage;
use crate::sf::{serialize_inner_list, SfParam, InnerList};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the signature base (RFC 9421 §2.5) from the covered components and
/// signature parameters, against the target message. The `req` parameter, if
/// present on a component, draws its value from `req`.
pub fn build_signature_base(
    components: &[ComponentId],
    params: &[(String, SfParam)],
    msg: &dyn HttpMessage,
    req: Option<&dyn HttpMessage>,
) -> Result<String> {
    let mut out = String::new();
    let mut seen = std::collections::HashSet::new();
    for c in components {
        let serialized = c.serialize();
        if !seen.insert(serialized.clone()) {
            return Err(HttpSigError::SignatureBase(format!(
                "duplicate covered component: {serialized}"
            )));
        }
        out.push_str(&serialized);
        out.push_str(": ");
        out.push_str(&c.value(msg, req)?);
        out.push('\n');
    }
    out.push_str("\"@signature-params\": ");
    let inner = InnerList {
        items: components
            .iter()
            .map(|c| (c.name.clone(), c.params.clone()))
            .collect(),
        params: params.to_vec(),
    };
    out.push_str(&serialize_inner_list(&inner));
    Ok(out)
}

/// Output of [`Signer::sign`]: the `Signature-Input` value and the raw
/// signature bytes (to be base64-encoded into the `Signature` header).
pub struct SignatureOutput {
    /// The value assigned to `label=` in the `Signature-Input` header.
    pub input_value: String,
    /// The raw signature bytes stored in the `Signature` header.
    pub signature: Vec<u8>,
}

/// Builder for producing a signature over a message.
pub struct Signer<'a> {
    alg: Algorithm,
    key: &'a SigningKey,
    label: String,
    keyid: Option<String>,
    created: Option<i64>,
    expires: Option<i64>,
    nonce: Option<String>,
    tag: Option<String>,
}

impl<'a> Signer<'a> {
    /// Create a signer for the given algorithm and key.
    pub fn new(alg: Algorithm, key: &'a SigningKey) -> Self {
        Signer {
            alg,
            key,
            label: "sig1".to_string(),
            keyid: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        }
    }

    /// Set the signature label (defaults to `sig1`).
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Set the `keyid` parameter.
    pub fn keyid(mut self, keyid: impl Into<String>) -> Self {
        self.keyid = Some(keyid.into());
        self
    }

    /// Set the `created` parameter (UNIX timestamp). Defaults to the current
    /// time.
    pub fn created(mut self, created: i64) -> Self {
        self.created = Some(created);
        self
    }

    /// Set the `expires` parameter (UNIX timestamp).
    pub fn expires(mut self, expires: i64) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Set the `nonce` parameter.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Set the `tag` parameter.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Sign `msg` covering the given components. The `alg` parameter is
    /// always written into the signature parameters for interoperability.
    pub fn sign<M: HttpMessage>(&self, msg: &M, components: &[ComponentId]) -> Result<SignatureOutput> {
        if self.key.algorithm() != self.alg {
            return Err(HttpSigError::UnsupportedAlgorithm(format!(
                "key algorithm {} does not match requested {}",
                self.key.algorithm(),
                self.alg
            )));
        }
        let created = self.created.unwrap_or_else(now_secs);
        let mut params: Vec<(String, SfParam)> = vec![("created".into(), SfParam::Int(created))];
        if let Some(k) = &self.keyid {
            params.push(("keyid".into(), SfParam::Str(k.clone())));
        }
        params.push(("alg".into(), SfParam::Str(self.alg.name().to_string())));
        if let Some(e) = self.expires {
            params.push(("expires".into(), SfParam::Int(e)));
        }
        if let Some(n) = &self.nonce {
            params.push(("nonce".into(), SfParam::Str(n.clone())));
        }
        if let Some(t) = &self.tag {
            params.push(("tag".into(), SfParam::Str(t.clone())));
        }

        let base = build_signature_base(components, &params, msg, msg.request_context())?;
        let sig = self.key.sign(base.as_bytes())?;
        let input = serialize_inner_list(&InnerList {
            items: components
                .iter()
                .map(|c| (c.name.clone(), c.params.clone()))
                .collect(),
            params,
        });
        let _ = &self.label;
        Ok(SignatureOutput {
            input_value: input,
            signature: sig,
        })
    }
}

/// Builder/config for verifying a signature.
pub struct Verifier {
    allowed: Vec<Algorithm>,
    require_created: bool,
    max_age: Option<Duration>,
    now: Option<i64>,
}

impl Default for Verifier {
    fn default() -> Self {
        Verifier {
            allowed: Vec::new(),
            require_created: false,
            max_age: None,
            now: None,
        }
    }
}

impl Verifier {
    /// Create a verifier that accepts any algorithm.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict the set of acceptable algorithms. Calling this multiple times
    /// accumulates allowed algorithms.
    pub fn allow(mut self, alg: Algorithm) -> Self {
        self.allowed.push(alg);
        self
    }

    /// Require the `created` parameter to be present.
    pub fn require_created(mut self) -> Self {
        self.require_created = true;
        self
    }

    /// Reject signatures older than `max_age` relative to `created`.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Override the verification clock (useful for deterministic tests).
    pub fn now(mut self, now: SystemTime) -> Self {
        self.now = Some(
            now.duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );
        self
    }

    /// Verify `signature` (the bytes stored in the `Signature` header) over
    /// `msg`, given the `Signature-Input` value `input_value` (the text after
    /// `label=`) and the verifying `key`.
    pub fn verify<M: HttpMessage>(
        &self,
        msg: &M,
        input_value: &str,
        signature: &[u8],
        key: &VerifyingKey,
    ) -> Result<()> {
        let parsed = parse_signature_input_value(input_value)?;
        let alg = key.algorithm();
        if !self.allowed.is_empty() && !self.allowed.contains(&alg) {
            return Err(HttpSigError::Policy(format!(
                "algorithm {alg} is not in the allowed set"
            )));
        }
        // Cross-check the `alg` parameter when present.
        if let Some(SfParam::Str(s)) = parsed
            .params
            .iter()
            .find(|(k, _)| k == "alg")
            .map(|(_, v)| v)
        {
            let declared = Algorithm::from_name(s)?;
            if declared != alg {
                return Err(HttpSigError::Policy(
                    "declared `alg` parameter does not match the key material".into(),
                ));
            }
        }

        let now = self.now.unwrap_or_else(now_secs);
        let created = parsed
            .params
            .iter()
            .find(|(k, _)| k == "created")
            .and_then(|(_, v)| if let SfParam::Int(n) = v { Some(*n) } else { None });
        let expires = parsed
            .params
            .iter()
            .find(|(k, _)| k == "expires")
            .and_then(|(_, v)| if let SfParam::Int(n) = v { Some(*n) } else { None });

        if self.require_created && created.is_none() {
            return Err(HttpSigError::Policy("`created` parameter is required".into()));
        }
        if let Some(e) = expires {
            if now > e {
                return Err(HttpSigError::Policy("signature has expired".into()));
            }
        }
        if let Some(c) = created {
            if let Some(max) = self.max_age {
                if now.saturating_sub(c) > max.as_secs() as i64 {
                    return Err(HttpSigError::Policy("signature is too old".into()));
                }
            }
        }

        let base = build_signature_base(
            &parsed.components,
            &parsed.params,
            msg,
            msg.request_context(),
        )?;
        key.verify(base.as_bytes(), signature)
    }
}
