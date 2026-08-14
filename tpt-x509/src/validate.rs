//! The X.509 path-building and path-validation engine (RFC 5280 §6.1).

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::Encode;
use x509_cert::{crl::CertificateList, ext::pkix::certpolicy::CertificatePolicies, Certificate};

use crate::{
    cert::{basic_constraints, extended_key_usage, is_self_issued, key_usage, name_constraints, subject_der, issuer_der, TrustAnchor},
    constraints::{check_constraints, GeneralSubtreeLike},
    crl,
    error::ValidationError,
    verify::verify_signature,
};

/// OID for `anyPolicy` (RFC 5280 §4.2.1.4).
pub const ANY_POLICY: &str = "2.5.29.32.0";

fn any_policy_oid() -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(ANY_POLICY)
}

/// Configuration for a single path-validation run.
#[derive(Clone, Debug)]
pub struct ValidationConfig {
    /// Trust anchors (typically self-signed root certificates).
    pub trust_anchors: Vec<TrustAnchor>,
    /// Candidate intermediate certificates (unordered pool).
    pub intermediates: Vec<Certificate>,
    /// The time at which the path is evaluated.
    pub time: SystemTime,
    /// A required extended-key-usage purpose (e.g. `id-kp-serverAuth`).
    pub required_eku: Option<ObjectIdentifier>,
    /// Initial policy set. Defaults to `{ anyPolicy }`.
    pub initial_policies: Vec<ObjectIdentifier>,
    /// Whether to consult supplied CRLs for revocation.
    pub check_revocation: bool,
    /// CRLs supplied by the caller (verified against CA keys in the path).
    pub crls: Vec<CertificateList>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            trust_anchors: Vec::new(),
            intermediates: Vec::new(),
            time: SystemTime::now(),
            required_eku: None,
            initial_policies: vec![any_policy_oid()],
            check_revocation: false,
            crls: Vec::new(),
        }
    }
}

/// The path validator.
#[derive(Clone, Debug)]
pub struct PathValidator {
    config: ValidationConfig,
}

impl PathValidator {
    /// Create a validator from the given configuration.
    pub fn new(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a certification path for `ee` (the end-entity certificate).
    ///
    /// On success returns the validated path ordered from the trust-anchor
    /// (top) certificate down to the end entity.
    pub fn validate(&self, ee: &Certificate) -> Result<Vec<Certificate>, ValidationError> {
        if self.config.trust_anchors.is_empty() {
            return Err(ValidationError::Config(
                "no trust anchors configured".to_string(),
            ));
        }
        let chains = self.build_chains(ee);
        let mut last_err = None;
        for (path, anchor_idx) in chains {
            match self.validate_chain(&path, anchor_idx) {
                Ok(validated) => return Ok(validated),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(ValidationError::NoPath))
    }

    /// Build all simple candidate paths for `ee`, ordered top-to-EE, paired with
    /// the index of the matching trust anchor.
    fn build_chains(&self, ee: &Certificate) -> Vec<(Vec<Certificate>, usize)> {
        let mut out = Vec::new();
        let mut chain = vec![ee.clone()];
        self.recurse(ee, &mut chain, &mut out, 0);
        out
    }

    fn recurse(
        &self,
        last: &Certificate,
        chain: &mut Vec<Certificate>,
        out: &mut Vec<(Vec<Certificate>, usize)>,
        depth: usize,
    ) {
        if depth > 16 {
            return;
        }
        // Look for issuers among the intermediates.
        for cand in &self.config.intermediates {
            if chain.iter().any(|c| subject_der(c).ok() == subject_der(cand).ok()) {
                continue;
            }
            if is_issuer_of(cand, last) {
                chain.push(cand.clone());
                self.recurse(cand, chain, out, depth + 1);
                chain.pop();
            }
        }
        // Can `last` terminate the path against a trust anchor?
        if let Some(ai) = self.matches_anchor(last) {
            let mut ordered = chain.clone();
            ordered.reverse(); // [top .. EE]
            // Prepend the anchor's certificate so the returned path runs from
            // the trust anchor (root) down to the end entity.
            if let Some(root) = &self.config.trust_anchors[ai].cert {
                ordered.insert(0, root.clone());
            }
            out.push((ordered, ai));
        }
    }

    /// Returns the anchor index if `cert` chains to (is issued and signed by)
    /// a trust anchor: its issuer name matches the anchor name and the anchor's
    /// public key verifies `cert`'s signature.
    fn matches_anchor(&self, cert: &Certificate) -> Option<usize> {
        let issuer = issuer_der(cert).ok()?;
        for (i, a) in self.config.trust_anchors.iter().enumerate() {
            let a_name = a.name.to_der().ok()?;
            if issuer.as_slice() == a_name.as_slice() && verify_signature(cert, &a.spki).is_ok() {
                return Some(i);
            }
        }
        None
    }

    /// Run the RFC 5280 §6.1 procedure over a single candidate path.
    fn validate_chain(
        &self,
        path: &[Certificate],
        anchor_idx: usize,
    ) -> Result<Vec<Certificate>, ValidationError> {
        let anchor = &self.config.trust_anchors[anchor_idx];
        let n = path.len();
        let mut max_path_len: Option<u8> = anchor.path_len;
        let mut permitted: Option<Vec<GeneralSubtreeLike>> =
            anchor.permitted_subtrees.clone();
        let mut excluded: Vec<GeneralSubtreeLike> =
            anchor.excluded_subtrees.clone().unwrap_or_default();
        let mut eku_allowed: Option<Vec<ObjectIdentifier>> = None;
        let any = any_policy_oid();

        for (k, cert) in path.iter().enumerate() {
            let is_ee = k == n - 1;
            let subject_label = subject_der(cert)
                .map(|d| format!("{d:?}"))
                .unwrap_or_else(|_| "<ee>".to_string());

            // (b) signature: verify against the working key.
            let working_spki = if k == 0 {
                &anchor.spki
            } else {
                &path[k - 1].tbs_certificate().subject_public_key_info()
            };
            verify_signature(cert, working_spki).map_err(|e| match e {
                ValidationError::Signature { reason, .. } => ValidationError::Signature {
                    issuer: subject_label.clone(),
                    reason,
                },
                other => other,
            })?;

            // (c) validity period.
            if !validity_covers(cert, self.config.time) {
                return Err(ValidationError::InvalidValidity);
            }

            // (d) path length decrement for non-self-issued certificates.
            let self_issued = is_self_issued(cert);
            if !self_issued {
                if let Some(ml) = max_path_len {
                    if ml == 0 {
                        return Err(ValidationError::PathLen {
                            depth: k,
                            limit: 0,
                        });
                    }
                    max_path_len = Some(ml - 1);
                }
            }

            // (e) basic constraints.
            let bc = basic_constraints(cert);
            if is_ee {
                if bc.as_ref().map(|b| b.ca).unwrap_or(false) {
                    return Err(ValidationError::NotCa(subject_label));
                }
            } else {
                if !bc.as_ref().map(|b| b.ca).unwrap_or(false) {
                    return Err(ValidationError::NotCa(subject_label));
                }
                if let Some(pl) = bc.as_ref().and_then(|b| b.path_len_constraint) {
                    max_path_len = Some(match max_path_len {
                        Some(cur) => cur.min(pl),
                        None => pl,
                    });
                }
            }

            // (f) key usage: CAs must assert keyCertSign.
            if !is_ee {
                if let Some(ku) = key_usage(cert) {
                    if !ku.key_cert_sign() {
                        return Err(ValidationError::MissingKeyCertSign(subject_label));
                    }
                }
            }

            // (g) name constraints.
            check_constraints(
                cert,
                permitted.as_deref().unwrap_or(&[]),
                &excluded,
            )?;

            // Accumulate name constraints from CA certificates.
            if !is_ee {
                if let Some(nc) = name_constraints(cert) {
                    if let Some(p) = nc.permitted_subtrees {
                        let p: Vec<GeneralSubtreeLike> =
                            p.into_iter().map(GeneralSubtreeLike::from).collect();
                        permitted = Some(match permitted {
                            Some(prev) => intersect_subtrees(prev, &p),
                            None => p,
                        });
                    }
                    if let Some(e) = nc.excluded_subtrees {
                        excluded.extend(e.into_iter().map(GeneralSubtreeLike::from));
                    }
                }
            }

            // (h) extended key usage accumulation.
            if !is_ee {
                if let Some(eku) = extended_key_usage(cert) {
                    let set = eku.0;
                    eku_allowed = Some(match eku_allowed {
                        Some(prev) => intersect_oids(prev, &set),
                        None => set,
                    });
                }
            }

            // (i) revocation (CRL).
            if self.config.check_revocation {
                if let Some(err) = crl::check_revocation(cert, &self.config.crls, path, anchor) {
                    return Err(err);
                }
            }
        }

        // (j) extended key usage end-entity check.
        if let Some(req) = self.config.required_eku {
            let leaf_eku = path
                .last()
                .and_then(|c| extended_key_usage(c))
                .map(|e| e.0);
            if let Some(set) = &eku_allowed {
                if !set.iter().any(|o| *o == req || *o == any) {
                    return Err(ValidationError::EkuViolation(req.to_string()));
                }
            }
            if let Some(set) = &leaf_eku {
                if !set.iter().any(|o| *o == req) {
                    return Err(ValidationError::EkuViolation(req.to_string()));
                }
            }
            if let Some(set) = &eku_allowed {
                if let Some(leaf) = &leaf_eku {
                    for e in leaf {
                        if *e != any && !set.iter().any(|o| *o == *e) {
                            return Err(ValidationError::EkuViolation(e.to_string()));
                        }
                    }
                }
            }
        }

        // (k) policy check.
        self.check_policy(path)?;

        Ok(path.to_vec())
    }

    fn check_policy(&self, path: &[Certificate]) -> Result<(), ValidationError> {
        let initial = &self.config.initial_policies;
        if initial.iter().any(|o| *o == any_policy_oid()) {
            return Ok(()); // anyPolicy accepted
        }
        // Require a non-empty intersection along the chain.
        let mut allowed: Option<Vec<ObjectIdentifier>> = None;
        for cert in path {
            let policies = cert_policies(cert);
            // anyPolicy in a cert means it's valid for any policy.
            if policies.iter().any(|p| p == &any_policy_oid()) {
                continue;
            }
            allowed = Some(match allowed {
                None => policies,
                Some(prev) => intersect_oids(prev, &policies),
            });
        }
        match allowed {
            None => Ok(()),
            Some(set) if set.iter().any(|p| initial.contains(p)) => Ok(()),
            Some(_) => Err(ValidationError::Policy(
                "initial policy set not satisfied by the path".to_string(),
            )),
        }
    }
}

/// Returns `true` if `issuer` issued `subject`: the names line up, `issuer`
/// asserts CA, and `subject`'s signature verifies under `issuer`'s key.
fn is_issuer_of(issuer: &Certificate, subject: &Certificate) -> bool {
    let i_subj = match subject_der(issuer) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let s_iss = match issuer_der(subject) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if i_subj != s_iss {
        return false;
    }
    if !basic_constraints(issuer).map(|b| b.ca).unwrap_or(false) {
        return false;
    }
    verify_signature(subject, &issuer.tbs_certificate().subject_public_key_info()).is_ok()
}

fn validity_covers(cert: &Certificate, time: SystemTime) -> bool {
    let v = cert.tbs_certificate().validity();
    let nb = v.not_before.to_system_time();
    let na = v.not_after.to_system_time();
    time >= nb && time <= na
}

fn cert_policies(cert: &Certificate) -> Vec<ObjectIdentifier> {
    cert.tbs_certificate()
        .get_extension::<CertificatePolicies>()
        .ok()
        .flatten()
        .map(|(_, cp)| cp.0.into_iter().map(|pi| pi.policy_identifier).collect())
        .unwrap_or_default()
}

fn intersect_subtrees(
    a: Vec<GeneralSubtreeLike>,
    b: &[GeneralSubtreeLike],
) -> Vec<GeneralSubtreeLike> {
    a.into_iter()
        .filter(|x| b.iter().any(|y| y.base == x.base))
        .collect()
}

fn intersect_oids(a: Vec<ObjectIdentifier>, b: &[ObjectIdentifier]) -> Vec<ObjectIdentifier> {
    a.into_iter()
        .filter(|x| b.iter().any(|y| y == x))
        .collect()
}
