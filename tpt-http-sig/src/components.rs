// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP Message Component identifiers (RFC 9421 §2) and derivation of their
//! canonicalized values from a target message.

use crate::error::{HttpSigError, Result};
use crate::message::HttpMessage;
use crate::sf::{parse_component_item, serialize_params, SfParam};

/// An HTTP Message Component identifier: a name (a lowercased field name, or
/// a `@`-prefixed derived component name) plus any parameters attached to it
/// (`req`, `sf`, `key`, `bs`, `tr`, `name`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentId {
    /// Component name. Lowercased for header-field components; kept verbatim
    /// for derived components (which start with `@`).
    pub name: String,
    /// Parameters in order, e.g. `("name", Str("Pet"))` or `("req", Bool(true))`.
    pub params: Vec<(String, SfParam)>,
}

impl ComponentId {
    /// Parse a component identifier such as `"@query-param";name="Pet"` or
    /// `"date"`. Header-field names are lowercased per RFC 9421 §2.1.
    pub fn parse(s: &str) -> Result<Self> {
        let (name, params) = parse_component_item(s)?;
        if name.is_empty() {
            return Err(HttpSigError::InvalidComponent("empty name".into()));
        }
        let effective = if name.starts_with('@') {
            name
        } else {
            name.to_ascii_lowercase()
        };
        Ok(ComponentId {
            name: effective,
            params,
        })
    }

    /// Serialize back to its Structured Field representation (used when
    /// building the signature base and `Signature-Input`).
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        out.push('"');
        out.push_str(&self.name);
        out.push('"');
        out.push_str(&serialize_params(&self.params));
        out
    }

    fn param_str(&self, name: &str) -> Option<&str> {
        self.params.iter().find_map(|(k, v)| {
            if k == name {
                if let SfParam::Str(s) = v {
                    Some(s.as_str())
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    fn param_bool(&self, name: &str) -> bool {
        self.params
            .iter()
            .any(|(k, v)| k == name && matches!(v, SfParam::Bool(true)))
    }

    /// Derive the canonicalized component value from the target message. The
    /// `req` parameter shifts the value source to the related request message.
    pub fn value(&self, msg: &dyn HttpMessage, req: Option<&dyn HttpMessage>) -> Result<String> {
        let req_param = self.param_bool("req");
        let ctx: &dyn HttpMessage = if req_param {
            req.ok_or_else(|| {
                HttpSigError::InvalidComponent(
                    "`req` used but no request context available".into(),
                )
            })?
        } else {
            msg
        };

        if self.name.starts_with('@') {
            if self.name == "@query-param" {
                return derive_query_param(self.param_str("name"), ctx);
            }
            return derive_derived(&self.name, ctx, req_param);
        }
        derive_field(&self.name, ctx, &self.params)
    }
}

fn derive_query_param(param_name: Option<&str>, ctx: &dyn HttpMessage) -> Result<String> {
    let pn = param_name.ok_or_else(|| {
        HttpSigError::InvalidComponent("@query-param requires a `name` parameter".into())
    })?;
    let query = ctx
        .query()
        .ok_or_else(|| HttpSigError::ComponentNotFound("@query".into()))?;
    // `query` includes the leading '?'.
    let q = query.strip_prefix('?').unwrap_or(query);
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if k == pn {
            return Ok(v.to_string());
        }
    }
    Err(HttpSigError::ComponentNotFound(format!(
        "@query-param name '{pn}' not found in query"
    )))
}

fn derive_derived(name: &str, ctx: &dyn HttpMessage, req_param: bool) -> Result<String> {
    if matches!(
        name,
        "@method" | "@authority" | "@scheme" | "@target-uri" | "@request-target" | "@path"
            | "@query" | "@query-param"
    ) {
        if ctx.kind().is_response() && !req_param {
            return Err(HttpSigError::ComponentNotFound(format!(
                "{name} is a request component but target is a response"
            )));
        }
    }
    match name {
        "@method" => ctx
            .method()
            .map(str::to_string)
            .ok_or_else(|| HttpSigError::ComponentNotFound("@method".into())),
        "@authority" => ctx
            .authority()
            .map(str::to_string)
            .ok_or_else(|| HttpSigError::ComponentNotFound("@authority".into())),
        "@scheme" => ctx
            .scheme()
            .map(str::to_string)
            .ok_or_else(|| HttpSigError::ComponentNotFound("@scheme".into())),
        "@target-uri" => ctx
            .target_uri()
            .map(str::to_string)
            .ok_or_else(|| HttpSigError::ComponentNotFound("@target-uri".into())),
        "@request-target" => ctx
            .request_target()
            .map(str::to_string)
            .ok_or_else(|| HttpSigError::ComponentNotFound("@request-target".into())),
        "@path" => ctx
            .path()
            .map(str::to_string)
            .ok_or_else(|| HttpSigError::ComponentNotFound("@path".into())),
        "@query" => ctx
            .query()
            .map(str::to_string)
            .ok_or_else(|| HttpSigError::ComponentNotFound("@query".into())),
        "@status" => match ctx.status() {
            Some(s) => Ok(s.to_string()),
            None => Err(HttpSigError::ComponentNotFound(
                "@status is a response component but target is a request".into(),
            )),
        },
        other => Err(HttpSigError::InvalidComponent(format!(
            "unknown derived component {other}"
        ))),
    }
}

fn derive_field(name: &str, ctx: &dyn HttpMessage, params: &[(String, SfParam)]) -> Result<String> {
    // Trailer fields (`tr`) are not currently sourced from a separate trailer
    // store; treat as unavailable.
    if params
        .iter()
        .any(|(k, v)| k == "tr" && matches!(v, SfParam::Bool(true)))
    {
        return Err(HttpSigError::InvalidComponent(
            "the `tr` (trailer) parameter is not supported by this implementation".into(),
        ));
    }
    // Structured-field strict serialization (`sf`), dictionary member
    // selection (`key`), and binary wrapping (`bs`) require a Structured
    // Fields (RFC 8941) implementation that is not bundled here yet.
    if params.iter().any(|(k, _)| k == "sf" || k == "key" || k == "bs") {
        return Err(HttpSigError::InvalidComponent(
            "the `sf`, `key`, and `bs` parameters are not yet supported".into(),
        ));
    }

    ctx.header(name).ok_or_else(|| {
        HttpSigError::ComponentNotFound(format!("header field '{name}' not present"))
    })
}
