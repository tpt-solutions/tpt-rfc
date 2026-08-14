// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Result-reference resolution (RFC 8620 §3.4).

use serde_json::{Map, Value};

use crate::error::MethodError;
use crate::types::Invocation;

/// A result reference is encoded as a JSON object `{"#": "<reference>"}`, or as
/// a bare string beginning with `#`. Returns the referenced value (resolved
/// from earlier responses) or an `invalidResultReference` error.
pub(crate) fn resolve(
    value: Value,
    responses: &std::collections::HashMap<String, Value>,
) -> Result<Value, MethodError> {
    match value {
        // Bare string reference of the form "#clientId/path" (a creation-id key
        // such as "#1" intentionally has no '/', so it is left untouched).
        Value::String(s) if s.starts_with('#') && s.contains('/') => {
            resolve_reference(&s, responses)
        }
        // Object-form value reference: exactly one property "#" (RFC 8620 §3.4.1).
        Value::Object(map) if map.len() == 1 && map.contains_key("#") => {
            let ref_str = map
                .get("#")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    MethodError::invalid_result_reference("#", "reference value must be a string")
                })?
                .to_owned();
            resolve_reference(&ref_str, responses)
        }
        // Ordinary object: recurse into values, and resolve any key that is a
        // result reference of the form "#clientId/path" (RFC 8620 §3.4.2).
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                if k.starts_with('#') && k.contains('/') {
                    let resolved_key = match resolve_reference(&k, responses)? {
                        Value::String(id) => id,
                        _ => {
                            return Err(MethodError::invalid_result_reference(
                                &k,
                                "a key reference must resolve to a string id",
                            ))
                        }
                    };
                    out.insert(resolved_key, resolve(v, responses)?);
                } else {
                    out.insert(k, resolve(v, responses)?);
                }
            }
            Ok(Value::Object(out))
        }
        // Recurse into arrays.
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(resolve(v, responses)?);
            }
            Ok(Value::Array(out))
        }
        // Primitive — no reference possible.
        other => Ok(other),
    }
}

/// Resolve a reference string of the form `#clientId` or
/// `#clientId/property.path` against the collected responses.
fn resolve_reference(
    reference: &str,
    responses: &std::collections::HashMap<String, Value>,
) -> Result<Value, MethodError> {
    debug_assert!(reference.starts_with('#'));
    let body = &reference[1..];
    let (client_id, prop_path) = match body.split_once('/') {
        Some((id, path)) => (id, Some(path)),
        None => (body, None),
    };

    let response = responses.get(client_id).ok_or_else(|| {
        MethodError::invalid_result_reference(reference, "no such client id in this request")
    })?;

    let mut current = response.clone();
    if let Some(path) = prop_path {
        for segment in path.split(['.', '/']).filter(|s| !s.is_empty()) {
            current = match current {
                Value::Object(map) => map.get(segment).cloned().ok_or_else(|| {
                    MethodError::invalid_result_reference(
                        reference,
                        &format!("property '{segment}' not found"),
                    )
                })?,
                Value::Array(arr) => {
                    let idx: usize = segment.parse().map_err(|_| {
                        MethodError::invalid_result_reference(
                            reference,
                            &format!("array index '{segment}' is not a number"),
                        )
                    })?;
                    arr.get(idx).cloned().ok_or_else(|| {
                        MethodError::invalid_result_reference(
                            reference,
                            &format!("array index {idx} out of bounds"),
                        )
                    })?
                }
                _ => {
                    return Err(MethodError::invalid_result_reference(
                        reference,
                        "cannot descend into a non-structured value",
                    ))
                }
            };
        }
    }
    Ok(current)
}

/// Convenience: resolve references in the `args` of an `Invocation` that is
/// about to be dispatched.
pub(crate) fn resolve_args(
    invocation: &Invocation,
    responses: &std::collections::HashMap<String, Value>,
) -> Result<Value, MethodError> {
    resolve(invocation.args.clone(), responses)
}
