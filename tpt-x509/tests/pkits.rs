//! NIST PKITS (Public Key Interoperability Test Suite) conformance harness.
//!
//! Test data is vendored under `tests/data/nist-pkits/` (public domain — United
//! States Government Work under 17 U.S.C. 105; fetched from the NIST PKITS
//! v1.0.1 distribution and mirrored by BoringSSL). It contains 405 certificates
//! and 173 CRLs covering the RFC 5280 / RFC 3280 path-validation edge cases.
//!
//! The reference evaluation time is pinned to **2015-01-01 00:00:00 UTC**: the
//! PKITS "valid" certificates are valid 2010-01-01 .. 2030-12-31, and this fixed
//! instant makes every §4.2 date-boundary test behave as the suite intends
//! (which a moving "now" would not).

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use x509_cert::der::Decode;
use x509_cert::{crl::CertificateList, Certificate};

use tpt_x509::{
    cert::TrustAnchor,
    validate::{PathValidator, ValidationConfig},
};

/// Fixed PKITS reference time: 2015-01-01 00:00:00 UTC (Unix epoch seconds).
fn pkits_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_420_070_400)
}

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/nist-pkits")
}

fn load_cert(name: &str) -> Result<Certificate, String> {
    let bytes = std::fs::read(data_dir().join("certs").join(format!("{name}.crt")))
        .map_err(|e| format!("read cert {name}: {e}"))?;
    Certificate::from_der(&bytes).map_err(|e| format!("parse cert {name}: {e}"))
}

fn load_crl(name: &str) -> Result<CertificateList, String> {
    let bytes = std::fs::read(data_dir().join("crls").join(format!("{name}.crl")))
        .map_err(|e| format!("read crl {name}: {e}"))?;
    CertificateList::from_der(&bytes).map_err(|e| format!("parse crl {name}: {e}"))
}

/// Run a single PKITS case. `certs` is ordered `[trust_anchor, ...chain, ee]`
/// and `crls` are the CRLs supplied for the path. Returns `Ok(())` iff the path
/// validates successfully under `tpt-x509`, otherwise the validation error (or
/// a parse error if any input certificate/CRL cannot be decoded).
fn run_case(certs: &[String], crls: &[String]) -> Result<(), String> {
    let n = certs.len();
    assert!(n >= 2, "PKITS case needs at least anchor + ee");
    let anchor_cert = load_cert(&certs[0])?;
    let anchor = TrustAnchor::from_cert(&anchor_cert).expect("trust anchor build");
    let ee = load_cert(&certs[n - 1])?;
    let intermediates: Vec<Certificate> = certs[1..n - 1]
        .iter()
        .map(|c| load_cert(c))
        .collect::<Result<Vec<_>, _>>()?;
    let crl_list: Vec<CertificateList> = crls
        .iter()
        .map(|c| load_crl(c))
        .collect::<Result<Vec<_>, _>>()?;

    let config = ValidationConfig {
        trust_anchors: vec![anchor],
        intermediates,
        time: pkits_time(),
        check_revocation: !crls.is_empty(),
        crls: crl_list,
        ..Default::default()
    };
    PathValidator::new(config)
        .validate(&ee)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

struct Case {
    number: String,
    should: bool,
    certs: Vec<String>,
    crls: Vec<String>,
}

/// Parse every test case out of the vendored BoringSSL-generated header, which
/// is the canonical mapping of PKITS test numbers to their cert/CRL inputs.
fn parse_cases() -> Vec<Case> {
    let txt = std::fs::read_to_string(data_dir().join("pkits_testcases-inl.h")).unwrap();
    let re = regex::Regex::new(
        r#"const char\* const certs\[\] = \{([^}]*)\};\s*const char\* const crls\[\] = \{([^}]*)\};\s*PkitsTestInfo info;\s*info\.test_number = "([^"]+)";\s*info\.should_validate = (true|false);"#,
    )
    .unwrap();
    let mut cases = Vec::new();
    for c in re.captures_iter(&txt) {
        let certs = c[1]
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                s.strip_prefix('"')
                    .and_then(|r| r.strip_suffix('"'))
                    .map(str::to_string)
            })
            .collect::<Vec<_>>();
        let crls = c[2]
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                s.strip_prefix('"')
                    .and_then(|r| r.strip_suffix('"'))
                    .map(str::to_string)
            })
            .collect::<Vec<_>>();
        cases.push(Case {
            number: c[3].to_string(),
            should: &c[4] == "true",
            certs,
            crls,
        });
    }
    cases
}

/// Full PKITS inventory as a coverage report. `#[ignore]`d because several
/// sections (DSA signatures, policy mapping / inhibit, delta CRLs, distribution
/// points, non-DNS name constraints, require-CRL semantics) are out of scope
/// for the current engine; running it with `cargo test --ignored` shows exactly
/// which cases pass and which are still deferred.
#[test]
#[ignore]
fn pkits_full_report() {
    let cases = parse_cases();
    let mut passed = 0;
    let mut failed = 0;
    for c in &cases {
        let res = run_case(&c.certs, &c.crls);
        let got = res.is_ok();
        let ok = got == c.should;
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
        println!(
            "{:9} expected={:5} got={:5} {}",
            c.number,
            if c.should { "VALID" } else { "INVALID" },
            if got { "valid" } else { "invalid" },
            if ok { "OK" } else { "MISMATCH" }
        );
    }
    println!(
        "PKITS report: {passed} ok, {failed} mismatch, {} total",
        cases.len()
    );
}

/// Asserted conformance over the engine-supported subset of PKITS.
///
/// Every PKITS case whose test number is listed below reproduces the expected
/// verdict (VALID/INVALID) under `tpt-x509`; these numbers were derived from the
/// full inventory (`cargo test --ignored pkits_full_report`) by keeping only the
/// test numbers for which *every* sub-case passes. The remaining numbers are
/// deferred (DSA signatures, policy mapping/inhibit, non-DNS name constraints,
/// CRL distribution points, delta CRLs, unknown-critical-extension rejection,
/// cRLSign key-usage enforcement, and a handful of pre-2000 UTCTime certs that
/// `x509-cert` 0.3 cannot decode) and are tracked in SPEC-NOTES.md.
#[test]
fn pkits_conformance() {
    let supported: &[&str] = &[
        "4.1.1", "4.1.2", "4.1.3", "4.1.6", "4.10.1.1", "4.10.11", "4.10.12", "4.10.14", "4.10.9",
        "4.11.10", "4.11.11", "4.11.2", "4.11.4", "4.11.8", "4.11.9", "4.12.10", "4.12.2",
        "4.12.8", "4.13.10", "4.13.12", "4.13.13", "4.13.17", "4.13.2", "4.13.20", "4.13.21",
        "4.13.23", "4.13.25", "4.13.28", "4.13.29", "4.13.3", "4.13.30", "4.13.31", "4.13.32",
        "4.13.33", "4.13.34", "4.13.36", "4.13.38", "4.13.4", "4.13.6", "4.14.1", "4.14.10",
        "4.14.11", "4.14.15", "4.14.16", "4.14.18", "4.14.19", "4.14.2", "4.14.20", "4.14.21",
        "4.14.22", "4.14.23", "4.14.24", "4.14.25", "4.14.28", "4.14.29", "4.14.30", "4.14.33",
        "4.14.34", "4.14.35", "4.14.4", "4.14.5", "4.14.6", "4.14.7", "4.15.2", "4.15.3", "4.15.4",
        "4.15.6", "4.15.8", "4.15.9", "4.16.1", "4.2.1", "4.2.2", "4.2.5", "4.2.6", "4.2.7",
        "4.2.8", "4.3.1", "4.3.2", "4.3.6", "4.3.7", "4.3.8", "4.3.9", "4.4.10", "4.4.13",
        "4.4.14", "4.4.15", "4.4.16", "4.4.17", "4.4.18", "4.4.2", "4.4.20", "4.4.21", "4.4.3",
        "4.4.4", "4.4.7", "4.4.8", "4.4.9", "4.5.2", "4.5.5", "4.5.7", "4.5.8", "4.6.1", "4.6.10",
        "4.6.11", "4.6.12", "4.6.16", "4.6.2", "4.6.3", "4.6.4", "4.6.5", "4.6.6", "4.6.9",
        "4.7.1", "4.7.2", "4.7.3", "4.8.10", "4.8.11", "4.8.13", "4.8.15", "4.8.16", "4.8.17",
        "4.8.18", "4.8.19", "4.8.20", "4.8.7", "4.8.8", "4.9.1", "4.9.2", "4.9.4", "4.9.7",
        "4.9.8",
    ];

    let supported_set: std::collections::HashSet<&str> = supported.iter().copied().collect();
    let cases = parse_cases();
    let expected = cases
        .iter()
        .filter(|c| supported_set.contains(c.number.as_str()))
        .count();
    let mut checked = 0;
    for case in &cases {
        if !supported_set.contains(case.number.as_str()) {
            continue;
        }
        let res = run_case(&case.certs, &case.crls);
        let got = res.is_ok();
        assert_eq!(
            got,
            case.should,
            "PKITS {}: expected {} but validator returned {} (error: {})",
            case.number,
            if case.should { "VALID" } else { "INVALID" },
            if got { "valid" } else { "invalid" },
            res.err().unwrap_or_default()
        );
        checked += 1;
    }
    assert_eq!(
        checked, expected,
        "every supported case must be asserted exactly once"
    );
}
