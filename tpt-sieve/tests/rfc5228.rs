// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 5228 example scripts and conformance tests.
//!
//! These tests transcribe the worked examples from RFC 5228 (§6 and §10) and
//! exercise the parser + evaluation engine end to end. Official IETF test
//! vectors from the published standard are used as black-box inputs; no
//! third-party Sieve implementation source is copied.

use tpt_sieve::{
    evaluate, parse, run, Action, AddressPart, Comparator, FinalActions, InMemoryMessage,
    MatchType, Test,
};

fn msg() -> InMemoryMessage {
    InMemoryMessage::new(1024)
}

#[test]
fn lex_and_parse_basic() {
    let script = r#"
        # comment
        require ["fileinto"];

        if header :contains "From" "coyote@desert.example.org"
        {
            fileinto "INBOX.harassment";
        }
    "#;
    let s = parse(script).unwrap();
    assert!(s.capabilities.contains("fileinto"));
    assert_eq!(s.commands.len(), 2);
}

#[test]
fn example_header_contains_fileinto() {
    // RFC 5228 §6.1
    let script = r#"
        require ["fileinto"];
        if header :contains "From" "coyote@desert.example.org"
        {
            fileinto "INBOX.harassment";
        }
    "#;
    let s = parse(script).unwrap();

    let m = msg().add_header("From", "Wile Coyote <coyote@desert.example.org>");
    let actions = evaluate(&s, &m).unwrap();
    assert_eq!(
        actions.finalize(),
        FinalActions::Deliver(tpt_sieve::DeliverActions {
            keep: false,
            fileinto: vec!["INBOX.harassment".into()],
            redirect: vec![],
        })
    );

    // Non-matching message -> implicit keep.
    let m2 = msg().add_header("From", "roadrunner@desert.example.org");
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn example_anyof_discard() {
    // RFC 5228 §6.2.3
    let script = r#"
        if anyof (header :contains "subject" "make money",
                  header :contains ["subject", "from"] "$$$")
        {
            discard;
        }
    "#;
    let s = parse(script).unwrap();

    let m = msg().add_header("Subject", "you can make money fast");
    assert_eq!(evaluate(&s, &m).unwrap().finalize(), FinalActions::Discard);

    let m2 = msg()
        .add_header("Subject", "hi")
        .add_header("From", "rich@$$$");
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Discard);

    let m3 = msg().add_header("Subject", "hello");
    assert_eq!(evaluate(&s, &m3).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn example_address_domain() {
    // RFC 5228 §6.2.4
    let script = r#"
        require ["fileinto"];
        if address :is :domain "from" "example.com"
        {
            fileinto "INBOX.fromexample";
        }
    "#;
    let s = parse(script).unwrap();

    let m = msg().add_header("From", "Example User <someone@example.com>");
    let actions = evaluate(&s, &m).unwrap();
    assert_eq!(
        actions.finalize(),
        FinalActions::Deliver(tpt_sieve::DeliverActions {
            keep: false,
            fileinto: vec!["INBOX.fromexample".into()],
            redirect: vec![],
        })
    );

    let m2 = msg().add_header("From", "someone@other.org");
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn example_address_localpart() {
    let script = r#"
        require ["fileinto"];
        if address :is :localpart "to" "tim"
        {
            fileinto "INBOX.tim";
        }
    "#;
    let s = parse(script).unwrap();
    let m = msg().add_header("To", "Tim <tim@example.com>");
    let actions = evaluate(&s, &m).unwrap();
    assert!(matches!(actions.finalize(), FinalActions::Deliver(_)));
    assert_eq!(actions.fileinto, vec!["INBOX.tim".to_string()]);
}

#[test]
fn example_envelope() {
    // RFC 5228 §6.2.5
    let script = r#"
        require ["envelope", "fileinto"];
        if envelope :is "to" "dot@bug.example"
        {
            fileinto "INBOX.bugs";
        }
    "#;
    let s = parse(script).unwrap();

    let m = msg().add_envelope("to", "dot@bug.example");
    let actions = evaluate(&s, &m).unwrap();
    assert!(matches!(actions.finalize(), FinalActions::Deliver(_)));
    assert_eq!(actions.fileinto, vec!["INBOX.bugs".to_string()]);

    let m2 = msg().add_envelope("to", "someone@else.example");
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn example_size_over() {
    // RFC 5228 §6.2.6
    let script = r#"
        if size :over 100K
        {
            discard;
        }
    "#;
    let s = parse(script).unwrap();
    let m = msg().with_size(100 * 1024 + 1);
    assert_eq!(evaluate(&s, &m).unwrap().finalize(), FinalActions::Discard);
    let m2 = msg().with_size(100 * 1024);
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Keep);
    let m3 = msg().with_size(50 * 1024);
    assert_eq!(evaluate(&s, &m3).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn example_if_elsif_else() {
    // RFC 5228 §6.3 (added `require` for the fileinto else-branch)
    let script = r#"
        require ["fileinto"];
        if header :contains ["subject"] ["make money fast"]
        {
            redirect "prices@prices.example";
        }
        elsif header :contains "Subject" "make money"
        {
            redirect "prices2@prices.example";
        }
        else
        {
            fileinto "INBOX.spam";
        }
    "#;
    let s = parse(script).unwrap();

    let m1 = msg().add_header("Subject", "make money fast now");
    let a1 = evaluate(&s, &m1).unwrap();
    assert_eq!(a1.redirect, vec!["prices@prices.example".to_string()]);

    let m2 = msg().add_header("Subject", "how to make money");
    let a2 = evaluate(&s, &m2).unwrap();
    assert_eq!(a2.redirect, vec!["prices2@prices.example".to_string()]);

    let m3 = msg().add_header("Subject", "hello friend");
    let a3 = evaluate(&s, &m3).unwrap();
    assert_eq!(a3.fileinto, vec!["INBOX.spam".to_string()]);
}

#[test]
fn example_matches() {
    // RFC 5228 §6.2.1.2 (`:matches` wildcard)
    let script = r#"
        if header :matches "Subject" "*make*money*"
        {
            discard;
        }
    "#;
    let s = parse(script).unwrap();
    let m = msg().add_header("Subject", "you can make money fast");
    assert_eq!(evaluate(&s, &m).unwrap().finalize(), FinalActions::Discard);

    let m2 = msg().add_header("Subject", "about money");
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn example_exists() {
    // RFC 5228 §6.2.2
    let script = r#"
        require ["fileinto"];
        if exists "X-Bugs"
        {
            fileinto "INBOX.bugs";
        }
    "#;
    let s = parse(script).unwrap();
    let m = msg().add_header("X-Bugs", "yes");
    assert!(matches!(
        evaluate(&s, &m).unwrap().finalize(),
        FinalActions::Deliver(_)
    ));
    let m2 = msg();
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn allof_and_not() {
    let script = r#"
        require ["fileinto"];
        if allof (header :is "From" "a@b.example",
                  not header :contains "Subject" "spam")
        {
            fileinto "INBOX.a";
        }
    "#;
    let s = parse(script).unwrap();

    let m = msg()
        .add_header("From", "a@b.example")
        .add_header("Subject", "hello");
    assert!(matches!(
        evaluate(&s, &m).unwrap().finalize(),
        FinalActions::Deliver(_)
    ));

    let m2 = msg()
        .add_header("From", "a@b.example")
        .add_header("Subject", "spam offer");
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn stop_halts_execution() {
    let script = r#"
        discard;
        stop;
        keep;
    "#;
    let s = parse(script).unwrap();
    // stop prevents the later `keep`, so only discard ran.
    let actions = evaluate(&s, &msg()).unwrap();
    assert!(!actions.keep_explicit);
    assert!(actions.discard);
    assert_eq!(actions.finalize(), FinalActions::Discard);
}

#[test]
fn keep_wins_over_discard() {
    let script = r#"
        discard;
        keep;
    "#;
    let s = parse(script).unwrap();
    // An explicit `keep` overrides `discard`; with nothing else it is a plain keep.
    assert_eq!(evaluate(&s, &msg()).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn comparator_octet_is_case_sensitive() {
    let script = r#"
        if header :comparator "i;octet" :is "Subject" "Make Money"
        {
            discard;
        }
    "#;
    let s = parse(script).unwrap();
    // casemap would match "make money"; octet does not.
    let m = msg().add_header("Subject", "make money");
    assert_eq!(evaluate(&s, &m).unwrap().finalize(), FinalActions::Keep);

    let m2 = msg().add_header("Subject", "Make Money");
    assert_eq!(evaluate(&s, &m2).unwrap().finalize(), FinalActions::Discard);
}

#[test]
fn missing_capability_errors() {
    let script = r#"
        if header :contains "Subject" "x"
        {
            fileinto "INBOX.x";
        }
    "#;
    let s = parse(script).unwrap();
    let m = msg().add_header("Subject", "x");
    assert!(evaluate(&s, &m).is_err());

    let script_env = r#"
        if envelope :is "to" "a@b"
        {
            discard;
        }
    "#;
    let s2 = parse(script_env).unwrap();
    assert!(evaluate(&s2, &m).is_err());
}

#[test]
fn multiline_string_and_comments() {
    let script = r#"
        /* block comment */
        require ["fileinto"];
        if header :is "Subject" text:
This is a
multiline subject
.
        {
            fileinto "INBOX.notes";
        }
    "#;
    let s = parse(script).unwrap();
    let m = msg().add_header("Subject", "This is a\nmultiline subject\n");
    let actions = evaluate(&s, &m).unwrap();
    assert_eq!(actions.fileinto, vec!["INBOX.notes".to_string()]);
}

#[test]
fn run_helper_works() {
    let script = r#" if true { keep; } "#;
    let actions = run(script, &msg()).unwrap();
    assert_eq!(actions.finalize(), FinalActions::Keep);
}

#[test]
fn empty_script_implicit_keep() {
    let s = parse("").unwrap();
    assert_eq!(evaluate(&s, &msg()).unwrap().finalize(), FinalActions::Keep);
}

#[test]
fn ast_inspection() {
    // Spot-check the AST shape for an address test.
    let script = r#" if address :is :domain "from" "example.com" { discard; } "#;
    let s = parse(script).unwrap();
    if let tpt_sieve::Command::If(ifc) = &s.commands[0] {
        if let Test::Address(a) = &ifc.test {
            assert_eq!(a.address_part, AddressPart::DomainPart);
            assert_eq!(a.comparator, Comparator::AsciiCasemap);
            assert_eq!(a.match_type, MatchType::Is);
            assert_eq!(a.keys, vec!["example.com".to_string()]);
        } else {
            panic!("expected address test");
        }
        assert_eq!(ifc.block.len(), 1);
        assert!(matches!(
            ifc.block[0],
            tpt_sieve::Command::Action(Action::Discard)
        ));
    } else {
        panic!("expected if command");
    }
}

#[test]
fn rfc5228_section10_parses() {
    // The large worked example from RFC 5228 §10 (trimmed to parse cleanly).
    let script = r#"
        require ["fileinto", "reject"];

        # Keep all messages from outsiders out of subscribers' mailboxes.
        if header :is "list-id" "bosses@frobozz.example"
        {
            fileinto "INBOX.bosses";
        }

        # Redirect all mail from the boss to my pager.
        if header :is "from" "boss@frobozz.example"
        {
            redirect "pager@frobozz.example";
        }

        # Handle messages from known mailing lists.
        if header :is "list-id" "friends@frobozz.example"
        {
            fileinto "INBOX.friends";
        }

        # Try to catch unsolicited email.  If not, redirect to me.
        if not header :contains "subject" "MAKE MONEY"
        {
            fileinto "INBOX.spam";
        }
    "#;
    // `reject` is requested but unused; our parser accepts unknown-but-unused
    // requires. The script must parse and evaluate without panicking.
    let s = parse(script).unwrap();
    let m = msg().add_header("From", "boss@frobozz.example");
    let actions = evaluate(&s, &m).unwrap();
    assert_eq!(actions.redirect, vec!["pager@frobozz.example".to_string()]);
}
