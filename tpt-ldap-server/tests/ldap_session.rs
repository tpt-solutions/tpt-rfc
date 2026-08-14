// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end session tests driving a [`Session`] over in-memory I/O. These
//! stand in for the real-LDAP-client interop test that requires an external
//! client (not available in this environment) and exercise the RFC 4511
//! request/response behaviour directly.

use std::io::Cursor;
use std::sync::Arc;

use tpt_ldap_server::backend::{Attribute, DirectoryBackend, Entry, Modification, ModificationOp};
use tpt_ldap_server::ber::BerElement;
use tpt_ldap_server::protocol::*;
use tpt_ldap_server::session::Session;

struct ParsedResponse {
    id: i32,
    op_tag: u32,
    result_code: Option<i64>,
    entry: Option<(String, Vec<(String, Vec<Vec<u8>>)>)>,
}

fn parse_responses(bytes: &[u8]) -> Vec<ParsedResponse> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let (el, consumed) = BerElement::decode_partial(&bytes[pos..]).unwrap();
        pos += consumed;
        let kids = el.as_children().unwrap();
        let id = kids[0].as_int().unwrap() as i32;
        let op = &kids[1];
        let op_tag = op.tag.number;
        if op_tag == 4 {
            let ek = op.as_children().unwrap();
            let dn = ek[0].as_str().unwrap().to_string();
            let attrs_el = ek[1].as_children().unwrap();
            let mut attrs = Vec::new();
            for a in attrs_el {
                let ak = a.as_children().unwrap();
                let name = ak[0].as_str().unwrap().to_string();
                let vals = ak[1]
                    .as_children()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_bytes().unwrap().to_vec())
                    .collect();
                attrs.push((name, vals));
            }
            out.push(ParsedResponse {
                id,
                op_tag,
                result_code: None,
                entry: Some((dn, attrs)),
            });
        } else {
            let rc = op.as_children().unwrap()[0].as_int().unwrap();
            out.push(ParsedResponse {
                id,
                op_tag,
                result_code: Some(rc),
                entry: None,
            });
        }
    }
    out
}

fn seed_backend() -> Arc<tpt_ldap_server::memory::MemoryBackend> {
    let b = tpt_ldap_server::memory::MemoryBackend::new();
    b.add_entry(Entry::new(
        "dc=example,dc=com",
        vec![
            Attribute::new("objectClass", vec![b"domain".to_vec()]),
            Attribute::new("dc", vec![b"example".to_vec()]),
        ],
    ))
    .unwrap();
    b.add_entry(Entry::new(
        "cn=admin,dc=example,dc=com",
        vec![
            Attribute::new("objectClass", vec![b"person".to_vec()]),
            Attribute::new("cn", vec![b"admin".to_vec()]),
            Attribute::new("userPassword", vec![b"secret".to_vec()]),
        ],
    ))
    .unwrap();
    b.add_entry(Entry::new(
        "cn=alice,dc=example,dc=com",
        vec![
            Attribute::new("objectClass", vec![b"person".to_vec()]),
            Attribute::new("cn", vec![b"alice".to_vec()]),
        ],
    ))
    .unwrap();
    Arc::new(b)
}

fn roundtrip(backend: &Arc<tpt_ldap_server::memory::MemoryBackend>, reqs: &[LdapRequest]) -> Vec<u8> {
    let mut buf = Vec::new();
    for r in reqs {
        buf.extend_from_slice(&r.encode());
    }
    let mut reader = Cursor::new(buf);
    let mut writer: Vec<u8> = Vec::new();
    let be = Arc::clone(backend);
    let mut session = Session::new(be);
    session.run(&mut reader, &mut writer).unwrap();
    writer
}

fn bind_req(id: i32, dn: &str, pw: &[u8]) -> LdapRequest {
    LdapRequest {
        id,
        op: RequestOp::Bind(BindRequest {
            version: 3,
            name: dn.to_string(),
            auth: AuthChoice::Simple(pw.to_vec()),
        }),
        controls: Vec::new(),
    }
}

fn search_req(id: i32, base: &str, scope: Scope, filter: Filter) -> LdapRequest {
    LdapRequest {
        id,
        op: RequestOp::Search(SearchRequest {
            base: base.to_string(),
            scope,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter,
            attributes: Vec::new(),
        }),
        controls: Vec::new(),
    }
}

const SUCCESS: i64 = 0;

#[test]
fn bind_with_correct_password_succeeds() {
    let b = seed_backend();
    let out = roundtrip(&b, &[bind_req(1, "cn=admin,dc=example,dc=com", b"secret")]);
    let res = parse_responses(&out);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].op_tag, 1); // BindResponse
    assert_eq!(res[0].result_code, Some(SUCCESS));
}

#[test]
fn bind_with_wrong_password_fails() {
    let b = seed_backend();
    let out = roundtrip(&b, &[bind_req(1, "cn=admin,dc=example,dc=com", b"wrong")]);
    let res = parse_responses(&out);
    assert_eq!(res[0].result_code, Some(49)); // invalidCredentials
}

#[test]
fn bind_unknown_dn_fails() {
    let b = seed_backend();
    let out = roundtrip(&b, &[bind_req(1, "cn=nobody,dc=example,dc=com", b"x")]);
    let res = parse_responses(&out);
    assert_eq!(res[0].result_code, Some(49));
}

#[test]
fn sasl_bind_is_unsupported() {
    let b = seed_backend();
    let req = LdapRequest {
        id: 1,
        op: RequestOp::Bind(BindRequest {
            version: 3,
            name: "cn=admin,dc=example,dc=com".to_string(),
            auth: AuthChoice::Sasl(tpt_ldap_server::backend::SaslCredentials {
                mechanism: "PLAIN".to_string(),
                credentials: b"\x00admin\x00secret".to_vec(),
            }),
        }),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[req]);
    let res = parse_responses(&out);
    assert_eq!(res[0].result_code, Some(12)); // unavailableCriticalExtension
}

#[test]
fn search_subtree_by_filter_returns_matching_entries() {
    let b = seed_backend();
    let filter = Filter::Equality(AttributeValueAssertion {
        attribute_desc: "objectClass".to_string(),
        assertion_value: b"person".to_vec(),
    });
    let out = roundtrip(&b, &[search_req(2, "dc=example,dc=com", Scope::WholeSubtree, filter)]);
    let res = parse_responses(&out);
    // Two entries (admin, alice) plus the SearchResultDone.
    let entries: Vec<_> = res.iter().filter(|r| r.entry.is_some()).collect();
    assert_eq!(entries.len(), 2);
    let dns: Vec<&str> = entries.iter().map(|e| e.entry.as_ref().unwrap().0.as_str()).collect();
    assert!(dns.contains(&"cn=admin,dc=example,dc=com"));
    assert!(dns.contains(&"cn=alice,dc=example,dc=com"));
    // The terminal done has resultCode success.
    assert!(res.iter().any(|r| r.op_tag == 5 && r.result_code == Some(SUCCESS)));
}

#[test]
fn search_base_scope_returns_only_base() {
    let b = seed_backend();
    let filter = Filter::Present("objectClass".to_string());
    let out = roundtrip(
        &b,
        &[search_req(2, "cn=alice,dc=example,dc=com", Scope::Base, filter)],
    );
    let res = parse_responses(&out);
    let entries: Vec<_> = res.iter().filter(|r| r.entry.is_some()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry.as_ref().unwrap().0, "cn=alice,dc=example,dc=com");
}

#[test]
fn search_single_level_scope() {
    let b = seed_backend();
    let filter = Filter::Present("objectClass".to_string());
    let out = roundtrip(
        &b,
        &[search_req(2, "dc=example,dc=com", Scope::SingleLevel, filter)],
    );
    let res = parse_responses(&out);
    let entries: Vec<_> = res.iter().filter(|r| r.entry.is_some()).collect();
    // admin and alice are immediate children of the base.
    assert_eq!(entries.len(), 2);
}

#[test]
fn search_and_filter() {
    let b = seed_backend();
    let filter = Filter::And(vec![
        Filter::Equality(AttributeValueAssertion {
            attribute_desc: "objectClass".to_string(),
            assertion_value: b"person".to_vec(),
        }),
        Filter::Equality(AttributeValueAssertion {
            attribute_desc: "cn".to_string(),
            assertion_value: b"alice".to_vec(),
        }),
    ]);
    let out = roundtrip(&b, &[search_req(2, "dc=example,dc=com", Scope::WholeSubtree, filter)]);
    let res = parse_responses(&out);
    let entries: Vec<_> = res.iter().filter(|r| r.entry.is_some()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry.as_ref().unwrap().0, "cn=alice,dc=example,dc=com");
}

#[test]
fn search_substring_filter() {
    let b = seed_backend();
    let filter = Filter::Substrings(SubstringFilter {
        r#type: "cn".to_string(),
        substrings: vec![Substring {
            kind: SubstringKind::Any,
            value: b"li".to_vec(),
        }],
    });
    let out = roundtrip(&b, &[search_req(2, "dc=example,dc=com", Scope::WholeSubtree, filter)]);
    let res = parse_responses(&out);
    let entries: Vec<_> = res.iter().filter(|r| r.entry.is_some()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry.as_ref().unwrap().0, "cn=alice,dc=example,dc=com");
}

#[test]
fn compare_true_and_false() {
    let b = seed_backend();
    let req = LdapRequest {
        id: 3,
        op: RequestOp::Compare(CompareRequest {
            entry: "cn=alice,dc=example,dc=com".to_string(),
            ava: AttributeValueAssertion {
                attribute_desc: "cn".to_string(),
                assertion_value: b"alice".to_vec(),
            },
        }),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[req]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(6)); // compareTrue

    let req2 = LdapRequest {
        id: 4,
        op: RequestOp::Compare(CompareRequest {
            entry: "cn=alice,dc=example,dc=com".to_string(),
            ava: AttributeValueAssertion {
                attribute_desc: "cn".to_string(),
                assertion_value: b"bob".to_vec(),
            },
        }),
        controls: Vec::new(),
    };
    let out2 = roundtrip(&b, &[req2]);
    assert_eq!(parse_responses(&out2)[0].result_code, Some(5)); // compareFalse
}

#[test]
fn add_then_search_then_modify_then_delete() {
    let b = seed_backend();
    let add = LdapRequest {
        id: 1,
        op: RequestOp::Add(AddRequest {
            entry: Entry::new(
                "cn=bob,dc=example,dc=com",
                vec![Attribute::new("objectClass", vec![b"person".to_vec()]), Attribute::new("cn", vec![b"bob".to_vec()])],
            ),
        }),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[add]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(SUCCESS));

    // Bob should now be searchable.
    let filter = Filter::Equality(AttributeValueAssertion {
        attribute_desc: "cn".to_string(),
        assertion_value: b"bob".to_vec(),
    });
    let out = roundtrip(&b, &[search_req(2, "dc=example,dc=com", Scope::WholeSubtree, filter.clone())]);
    assert_eq!(parse_responses(&out).iter().filter(|r| r.entry.is_some()).count(), 1);

    // Add an sn attribute.
    let modify = LdapRequest {
        id: 3,
        op: RequestOp::Modify(ModifyRequest {
            object: "cn=bob,dc=example,dc=com".to_string(),
            changes: vec![Modification {
                op: ModificationOp::Add,
                name: "sn".to_string(),
                values: vec![b"Bob".to_vec()],
            }],
        }),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[modify]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(SUCCESS));

    // Verify sn was added.
    let b_entry = b.entries().unwrap().into_iter().find(|e| e.dn == "cn=bob,dc=example,dc=com").unwrap();
    assert!(b_entry.attribute("sn").unwrap().values.contains(&b"Bob".to_vec()));

    // Delete bob.
    let delete = LdapRequest {
        id: 4,
        op: RequestOp::Delete("cn=bob,dc=example,dc=com".to_string()),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[delete]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(SUCCESS));

    let out = roundtrip(&b, &[search_req(5, "dc=example,dc=com", Scope::WholeSubtree, filter.clone())]);
    assert_eq!(parse_responses(&out).iter().filter(|r| r.entry.is_some()).count(), 0);
}

#[test]
fn add_existing_entry_conflicts() {
    let b = seed_backend();
    let add = LdapRequest {
        id: 1,
        op: RequestOp::Add(AddRequest {
            entry: Entry::new(
                "cn=alice,dc=example,dc=com",
                vec![Attribute::new("cn", vec![b"alice".to_vec()])],
            ),
        }),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[add]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(68)); // entryAlreadyExists
}

#[test]
fn delete_missing_entry_returns_no_such_object() {
    let b = seed_backend();
    let delete = LdapRequest {
        id: 1,
        op: RequestOp::Delete("cn=ghost,dc=example,dc=com".to_string()),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[delete]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(32)); // noSuchObject
}

#[test]
fn modify_dn_renames_entry() {
    let b = seed_backend();
    let add = LdapRequest {
        id: 1,
        op: RequestOp::Add(AddRequest {
            entry: Entry::new(
                "cn=bob,dc=example,dc=com",
                vec![Attribute::new("objectClass", vec![b"person".to_vec()]), Attribute::new("cn", vec![b"bob".to_vec()])],
            ),
        }),
        controls: Vec::new(),
    };
    let moddn = LdapRequest {
        id: 2,
        op: RequestOp::ModifyDn(tpt_ldap_server::backend::ModifyDnRequest {
            dn: "cn=bob,dc=example,dc=com".to_string(),
            new_rdn: "cn=bobby".to_string(),
            delete_old_rdn: true,
            new_superior: None,
        }),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[add, moddn]);
    let codes: Vec<_> = parse_responses(&out).iter().map(|r| r.result_code).collect();
    assert!(codes.contains(&Some(SUCCESS)));

    let entries = b.entries().unwrap();
    assert!(entries.iter().any(|e| e.dn == "cn=bobby,dc=example,dc=com"));
    assert!(!entries.iter().any(|e| e.dn == "cn=bob,dc=example,dc=com"));
}

#[test]
fn extended_request_is_unwilling() {
    let b = seed_backend();
    let ext = LdapRequest {
        id: 1,
        op: RequestOp::Extended(ExtendedRequest {
            name: "1.3.6.1.4.1.1466.20037".to_string(),
            value: None,
        }),
        controls: Vec::new(),
    };
    let out = roundtrip(&b, &[ext]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(53)); // unwillingToPerform
}

#[test]
fn critical_control_is_rejected() {
    let b = seed_backend();
    let mut req = search_req(
        2,
        "dc=example,dc=com",
        Scope::WholeSubtree,
        Filter::Present("objectClass".to_string()),
    );
    req.controls.push(Control {
        oid: "1.2.3.4".to_string(),
        criticality: true,
        value: None,
    });
    let out = roundtrip(&b, &[req]);
    assert_eq!(parse_responses(&out)[0].result_code, Some(12)); // unavailableCriticalExtension
}

#[test]
fn ber_roundtrip_integer() {
    for v in [0i64, 1, 127, 128, 255, 256, -1, -128, -129, 123456] {
        let el = BerElement::integer(v);
        let bytes = el.encode();
        let (decoded, consumed) = BerElement::decode_partial(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.as_int().unwrap(), v);
    }
}

#[test]
fn ber_indefinite_length_constructed() {
    // Manually craft an indefinite-length SEQUENCE { INTEGER 1, INTEGER 2 }.
    let inner = BerElement::integer(1).encode();
    let inner2 = BerElement::integer(2).encode();
    let mut bytes = Vec::new();
    bytes.push(0x30); // SEQUENCE, constructed
    bytes.push(0x80); // indefinite length
    bytes.extend_from_slice(&inner);
    bytes.extend_from_slice(&inner2);
    bytes.extend_from_slice(&[0x00, 0x00]); // end-of-contents
    let (el, consumed) = BerElement::decode_partial(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    let kids = el.as_children().unwrap();
    assert_eq!(kids.len(), 2);
    assert_eq!(kids[0].as_int().unwrap(), 1);
    assert_eq!(kids[1].as_int().unwrap(), 2);
}
