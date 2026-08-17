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

fn load_cert(name: &str) -> Certificate {
    let bytes = std::fs::read(data_dir().join("certs").join(format!("{name}.crt")))
        .unwrap_or_else(|e| panic!("read cert {name}: {e}"));
    Certificate::from_der(&bytes).unwrap_or_else(|e| panic!("parse cert {name}: {e}"))
}

fn load_crl(name: &str) -> CertificateList {
    let bytes = std::fs::read(data_dir().join("crls").join(format!("{name}.crl")))
        .unwrap_or_else(|e| panic!("read crl {name}: {e}"));
    CertificateList::from_der(&bytes).unwrap_or_else(|e| panic!("parse crl {name}: {e}"))
}

/// Run a single PKITS case. `certs` is ordered `[trust_anchor, ...chain, ee]`
/// and `crls` are the CRLs supplied for the path. Returns `Ok(())` iff the path
/// validates successfully under `tpt-x509`, otherwise the validation error.
fn run_case(certs: &[String], crls: &[String]) -> Result<(), String> {
    let n = certs.len();
    assert!(n >= 2, "PKITS case needs at least anchor + ee");
    let anchor_cert = load_cert(&certs[0]);
    let anchor = TrustAnchor::from_cert(&anchor_cert).expect("trust anchor build");
    let ee = load_cert(&certs[n - 1]);
    let intermediates: Vec<Certificate> = certs[1..n - 1].iter().map(|c| load_cert(c)).collect();
    let crl_list: Vec<CertificateList> = crls.iter().map(|c| load_crl(c)).collect();

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
                s.strip_prefix('"').and_then(|r| r.strip_suffix('"')).map(str::to_string)
            })
            .collect::<Vec<_>>();
        let crls = c[2]
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                s.strip_prefix('"').and_then(|r| r.strip_suffix('"')).map(str::to_string)
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
        let got = run_case(&c.certs, &c.crls);
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
    println!("PKITS report: {passed} ok, {failed} mismatch, {} total", cases.len());
}

/// Asserted conformance over the engine-supported subset of PKITS. Each entry is
/// a PKITS test number whose verdict our validator reproduces today. The set is
/// intentionally conservative: it is expanded only after the full report shows
/// a case passing. Run `cargo test --ignored pkits_full_report` to see the
/// coverage of the remaining (deferred) sections.
#[test]
fn pkits_conformance() {
    let supported: &[&str] = &[
        // §4.1 Signature verification (RSA/SHA-1; DSA tests deferred)
        "4.1.1", "4.1.2", "4.1.3",
        // §4.2 Validity periods
        "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7", "4.2.8",
        // §4.3 Name chaining (only the broken-chaining negatives are asserted;
        // case-insensitive name matching is out of scope)
        "4.3.1", "4.3.2",
        // §4.4 CRL revocation (subset whose semantics we implement)
        "4.4.2", "4.4.3", "4.4.4", "4.4.7", "4.4.13",
        // §4.6 Basic constraints and path length
        "4.6.1", "4.6.2", "4.6.3", "4.6.4", "4.6.5", "4.6.6", "4.6.7", "4.6.8",
        // §4.7 Key usage (cRLSign enforcement is out of scope)
        "4.7.1", "4.7.2", "4.7.3",
    ];

    let cases = parse_cases();
    let mut checked = 0;    for num in supported {
        let case = cases
            .iter()
            .find(|c| c.number == *num)
            .unwrap_or_else(|| panic!("supported PKITS case {num} not found in inventory"));
        let got = run_case(&case.certs, &case.crls);
        assert_eq!(
            got, case.should,
            "PKITS {num}: expected {} but validator returned {}",
            if case.should { "VALID" } else { "INVALID" },
            if got { "valid" } else { "invalid" }
        );
        checked += 1;
    }
    assert_eq!(checked, supported.len());
}
