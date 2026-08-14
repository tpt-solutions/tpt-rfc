//! Name-constraint evaluation (RFC 5280 §4.2.1.10).

use std::net::IpAddr;

use der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;

use crate::{
    cert::{subject_alt_name, subject_der},
    error::ValidationError,
};

/// An owned, constraint-friendly view of a [`GeneralName`].
#[derive(Clone, Debug, PartialEq)]
pub enum GeneralNameLike {
    /// A DNS name (e.g. `example.com`).
    Dns(String),
    /// An IP address.
    Ip(IpAddr),
    /// A directory (distinguished) name.
    Dir(x509_cert::name::Name),
    /// An unconstrained name type (OtherName / rfc822 / URI / registeredID).
    /// These are not constraint-checked, so they never satisfy a constraint.
    Other,
}

impl From<GeneralName> for GeneralNameLike {
    fn from(gn: GeneralName) -> Self {
        match gn {
            GeneralName::DnsName(d) => GeneralNameLike::Dns(d.as_str().to_string()),
            GeneralName::IpAddress(o) => {
                let b = o.as_bytes();
                GeneralNameLike::Ip(octets_to_ip(b))
            }
            GeneralName::DirectoryName(n) => GeneralNameLike::Dir(n),
            // OtherName / rfc822 / URI / registeredID are not constraint-checked.
            _ => GeneralNameLike::Other,
        }
    }
}

/// An owned name-constraint subtree.
#[derive(Clone, Debug)]
pub struct GeneralSubtreeLike {
    /// The base name of the constraint.
    pub base: GeneralNameLike,
    /// Minimum base distance (unused by this implementation).
    pub minimum: u32,
    /// Maximum base distance (unused by this implementation).
    pub maximum: Option<u32>,
}

impl From<GeneralSubtree> for GeneralSubtreeLike {
    fn from(s: GeneralSubtree) -> Self {
        GeneralSubtreeLike {
            base: GeneralNameLike::from(s.base),
            minimum: s.minimum,
            maximum: s.maximum,
        }
    }
}

fn octets_to_ip(b: &[u8]) -> IpAddr {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match b.len() {
        4 => IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

/// Check that a certificate's name(s) satisfy the accumulated `permitted` and
/// `excluded` name constraints.
///
/// `permitted` / `excluded` are expected to be the *accumulated* constraint
/// sets (intersection of permitted, union of excluded) for the path so far.
pub fn check_constraints(
    cert: &x509_cert::Certificate,
    permitted: &[GeneralSubtreeLike],
    excluded: &[GeneralSubtreeLike],
) -> Result<(), ValidationError> {
    let names = candidate_names(cert);
    for name in &names {
        if excluded.iter().any(|c| matches(name, &c.base)) {
            return Err(ValidationError::NameConstraint(format!(
                "{name:?} is in an excluded subtree"
            )));
        }
        let has_type = permitted.iter().any(|c| same_kind(&c.base, name));
        if has_type && !permitted.iter().any(|c| matches(name, &c.base)) {
            return Err(ValidationError::NameConstraint(format!(
                "{name:?} is not within a permitted subtree"
            )));
        }
    }
    Ok(())
}

fn candidate_names(cert: &x509_cert::Certificate) -> Vec<GeneralNameLike> {
    if let Some(san) = subject_alt_name(cert) {
        san.0
            .iter()
            .map(|gn| GeneralNameLike::from(gn.clone()))
            .collect()
    } else {
        // No SAN: fall back to the subject distinguished name.
        subject_der(cert)
            .ok()
            .and_then(|d| x509_cert::name::Name::from_der(&d).ok())
            .map(|n| vec![GeneralNameLike::Dir(n)])
            .unwrap_or_default()
    }
}

fn same_kind(a: &GeneralNameLike, b: &GeneralNameLike) -> bool {
    matches!(
        (a, b),
        (GeneralNameLike::Dns(_), GeneralNameLike::Dns(_))
            | (GeneralNameLike::Ip(_), GeneralNameLike::Ip(_))
            | (GeneralNameLike::Dir(_), GeneralNameLike::Dir(_))
    )
}

fn matches(name: &GeneralNameLike, base: &GeneralNameLike) -> bool {
    match (name, base) {
        (GeneralNameLike::Dns(n), GeneralNameLike::Dns(b)) => dns_within(n, b),
        (GeneralNameLike::Ip(ip), GeneralNameLike::Ip(_)) => ip_within(*ip, base),
        (GeneralNameLike::Dir(dn), GeneralNameLike::Dir(b)) => dn_within(dn, b),
        _ => false,
    }
}

fn dns_within(name: &str, base: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let base = base.to_ascii_lowercase();
    if name == base {
        return true;
    }
    // base is treated as a domain suffix (RFC requires a trailing dot, but we
    // accept either form for interoperability).
    let suffixed = if let Some(stripped) = base.strip_prefix('.') {
        stripped
    } else {
        base.as_str()
    };
    name.ends_with(&format!(".{suffixed}"))
}

fn ip_within(ip: IpAddr, base: &GeneralNameLike) -> bool {
    let GeneralNameLike::Ip(b) = base else {
        return false;
    };
    match (ip, b) {
        (IpAddr::V4(a), IpAddr::V4(b4)) => a == *b4,
        (IpAddr::V6(a), IpAddr::V6(b6)) => a == *b6,
        _ => false,
    }
}

fn dn_within(dn: &x509_cert::name::Name, base: &x509_cert::name::Name) -> bool {
    // Best-effort: the constraint DN must appear as a suffix of the certificate
    // DN's RDN sequence (matching RDN by DER).
    let dn_der = match dn.to_der() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let base_der = match base.to_der() {
        Ok(d) => d,
        Err(_) => return false,
    };
    dn_der
        .windows(base_der.len())
        .any(|w| w == base_der.as_slice())
}
