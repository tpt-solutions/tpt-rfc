// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration / conformance tests for `tpt-sip`.

use tpt_sip::dialog::{Dialog, DialogState};
use tpt_sip::error::Result;
use tpt_sip::headers::parse_via;
use tpt_sip::message::Message;
use tpt_sip::method::Method;
use tpt_sip::methods::{ack, invite, named, register, RequestBuilder, ResponseBuilder};
use tpt_sip::sdp::Sdp;
use tpt_sip::transaction::{Transaction, TxAction, TxEvent, TxState};
use tpt_sip::uri::Uri;

const INVITE_EXAMPLE: &str = "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 5\r\n\
\r\n\
v=0\r\n";

const OK_EXAMPLE: &str = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP server10.biloxi.example.com;branch=z9hG4bK4b43c2ff8.1\r\n\
Via: SIP/2.0/UDP bigbox3.site3.atlanta.example.com;branch=z9hG4bK77ef4c450def\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@192.0.2.4>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 5\r\n\
\r\n\
v=0\r\n";

#[test]
fn parse_invite_example() {
    let msg = Message::parse(INVITE_EXAMPLE.as_bytes()).unwrap();
    assert!(msg.is_request());
    let rl = msg.request_line().unwrap();
    assert_eq!(rl.method, Method::Invite);
    assert_eq!(rl.uri.host, "biloxi.example.com");
    assert_eq!(rl.uri.user.as_deref(), Some("bob"));

    let via = msg.via();
    assert_eq!(via.len(), 1);
    assert_eq!(via[0].branch(), Some("z9hG4bK776asdhds"));
    assert_eq!(via[0].host, "pc33.atlanta.example.com");

    let from = msg.from().unwrap();
    assert_eq!(from.uri.host, "atlanta.example.com");
    assert_eq!(from.tag(), Some("1928301774"));

    let cseq = msg.cseq().unwrap();
    assert_eq!(cseq.seq, 314159);
    assert_eq!(cseq.method, Method::Invite);

    assert_eq!(msg.contact().len(), 1);
    assert_eq!(msg.content_length(), Some(5));
    assert_eq!(msg.body, b"v=0\r\n");
}

#[test]
fn parse_ok_example_multiple_via() {
    let msg = Message::parse(OK_EXAMPLE.as_bytes()).unwrap();
    assert!(msg.is_response());
    let sl = msg.status_line().unwrap();
    assert_eq!(sl.code, 200);
    assert_eq!(sl.reason, "OK");

    let via = msg.via();
    assert_eq!(via.len(), 3);
    assert_eq!(via[0].host, "server10.biloxi.example.com");
    assert_eq!(via[2].branch(), Some("z9hG4bK776asdhds"));

    assert_eq!(msg.to().unwrap().tag(), Some("a6c85cf"));
    assert_eq!(msg.contact()[0].uri.host, "192.0.2.4");
}

#[test]
fn round_trip_serialization() {
    let msg = Message::parse(INVITE_EXAMPLE.as_bytes()).unwrap();
    let bytes = msg.to_bytes();
    // Re-parsing the serialised form must yield the same message.
    let reparsed = Message::parse(&bytes).unwrap();
    assert_eq!(reparsed.request_line().unwrap().method, Method::Invite);
    assert_eq!(reparsed.cseq().unwrap().seq, 314159);
    assert_eq!(reparsed.via().len(), 1);
    assert_eq!(reparsed.body, b"v=0\r\n");
}

#[test]
fn uri_parsing() {
    let u = Uri::parse("sip:alice:secret@example.com:5060;transport=tcp;lr?subject=hi").unwrap();
    assert_eq!(u.scheme, tpt_sip::uri::Scheme::Sip);
    assert_eq!(u.user.as_deref(), Some("alice"));
    assert_eq!(u.password.as_deref(), Some("secret"));
    assert_eq!(u.host, "example.com");
    assert_eq!(u.port, Some(5060));
    assert_eq!(u.transport(), Some("tcp"));
    assert!(u.is_lr());
    assert_eq!(u.headers[0].name, "subject");

    let v6 = Uri::parse("sips:bob@[2001:db8::1]:5061").unwrap();
    assert_eq!(v6.scheme, tpt_sip::uri::Scheme::Sips);
    assert_eq!(v6.host, "2001:db8::1");
    assert_eq!(v6.port, Some(5061));
}

#[test]
fn uri_round_trip() {
    let u = Uri::parse("sip:carol@chicago.example.com;transport=udp").unwrap();
    assert_eq!(u.to_string(), "sip:carol@chicago.example.com;transport=udp");
}

#[test]
fn header_folding() {
    let raw = "INVITE sip:x SIP/2.0\r\n\
Subject: a long\r\n subject that folds\r\n\
Content-Length: 0\r\n\
\r\n";
    let msg = Message::parse(raw.as_bytes()).unwrap();
    assert_eq!(
        msg.header_value("Subject").unwrap(),
        "a long subject that folds"
    );
}

// ---- Transaction FSMs ----

fn invite_request() -> Message {
    let mut from = named(Uri::parse("sip:alice@atlanta.example.com").unwrap());
    tpt_sip::methods::with_tag(&mut from, "1928301774");
    let contact = named(Uri::parse("sip:alice@pc33.atlanta.example.com").unwrap());
    let uri = Uri::parse("sip:bob@biloxi.example.com").unwrap();
    invite(uri, from, contact)
        .call_id("call-1")
        .cseq(1, None)
        .build()
}

fn first_transmit(actions: &[TxAction]) -> &Message {
    actions
        .iter()
        .find_map(|a| match a {
            TxAction::Transmit(m) => Some(m),
            _ => None,
        })
        .unwrap()
}

#[test]
fn client_invite_success() {
    let req = invite_request();
    let (mut tx, actions) = Transaction::client_invite(&req, false).unwrap();
    assert_eq!(tx.state, TxState::ProceedingInvite);
    assert!(actions.iter().any(|a| matches!(a, TxAction::Transmit(_))));
    assert!(actions
        .iter()
        .any(|a| matches!(a, TxAction::StartTimer("B", _))));

    let resp = ResponseBuilder::from_request(&req, 200, "OK")
        .to_tag("svr")
        .build();
    let actions = tx.on_event(TxEvent::Response(resp));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Deliver(_))));
    assert!(actions
        .iter()
        .any(|a| matches!(a, TxAction::StartTimer("M", _))));
    assert_eq!(tx.state, TxState::Accepted);

    let actions = tx.on_event(TxEvent::Timer("M"));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Terminate)));
    assert!(tx.is_terminated());
}

#[test]
fn client_invite_failure_sends_ack() {
    let req = invite_request();
    let (mut tx, _) = Transaction::client_invite(&req, false).unwrap();

    let resp = ResponseBuilder::from_request(&req, 486, "Busy Here")
        .to_tag("svr")
        .build();
    let actions = tx.on_event(TxEvent::Response(resp));
    // Must transmit an ACK and deliver the response.
    let ack = first_transmit(&actions);
    assert_eq!(ack.method(), Some(Method::Ack));
    assert_eq!(ack.call_id(), req.call_id());
    assert!(actions.iter().any(|a| matches!(a, TxAction::Deliver(_))));
    assert_eq!(tx.state, TxState::CompletedInvite);

    let actions = tx.on_event(TxEvent::Timer("D"));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Terminate)));
    assert!(tx.is_terminated());
}

#[test]
fn client_invite_reliable_no_wait() {
    let req = invite_request();
    let (mut tx, _) = Transaction::client_invite(&req, true).unwrap();
    let resp = ResponseBuilder::from_request(&req, 486, "Busy Here")
        .to_tag("svr")
        .build();
    let actions = tx.on_event(TxEvent::Response(resp));
    // On a reliable transport there is no Timer D wait; terminates now.
    assert!(actions.iter().any(|a| matches!(a, TxAction::Terminate)));
    assert!(tx.is_terminated());
}

#[test]
fn client_non_invite() {
    let from = named(Uri::parse("sip:alice@example.com").unwrap());
    let uri = Uri::parse("sip:proxy.example.com").unwrap();
    let req = RequestBuilder::new(Method::Options, uri, from)
        .call_id("call-2")
        .build();
    let (mut tx, _) = Transaction::client_non_invite(&req, false).unwrap();
    assert_eq!(tx.state, TxState::Proceeding);

    let resp = ResponseBuilder::from_request(&req, 200, "OK")
        .to_tag("s")
        .build();
    let actions = tx.on_event(TxEvent::Response(resp));
    assert!(actions
        .iter()
        .any(|a| matches!(a, TxAction::StartTimer("K", _))));
    assert_eq!(tx.state, TxState::Completed);

    let actions = tx.on_event(TxEvent::Timer("K"));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Terminate)));
}

#[test]
fn server_invite_ack_flow() {
    let req = invite_request();
    let (mut tx, _) = Transaction::server_invite(&req, false).unwrap();
    assert_eq!(tx.state, TxState::ProceedingServer);

    // Send a provisional then a failure.
    let prov = ResponseBuilder::from_request(&req, 100, "Trying").build();
    let _ = tx.on_event(TxEvent::Response(prov));
    assert_eq!(tx.state, TxState::ProceedingServer);

    let fail = ResponseBuilder::from_request(&req, 486, "Busy Here")
        .to_tag("svr")
        .build();
    let actions = tx.on_event(TxEvent::Response(fail));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Transmit(_))));
    assert_eq!(tx.state, TxState::CompletedServer);

    // ACK arrives.
    let ack_msg = ack(
        Uri::parse("sip:bob@biloxi.example.com").unwrap(),
        named(Uri::parse("sip:alice@atlanta.example.com").unwrap()),
        named(Uri::parse("sip:bob@biloxi.example.com").unwrap()),
        "call-1",
        1,
        "z9hG4bK776asdhds",
    )
    .unwrap();
    let actions = tx.on_event(TxEvent::Request(ack_msg));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Deliver(_))));
    assert_eq!(tx.state, TxState::ConfirmedServer);

    let actions = tx.on_event(TxEvent::Timer("I"));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Terminate)));
}

#[test]
fn server_invite_2xx_terminates_immediately() {
    let req = invite_request();
    let (mut tx, _) = Transaction::server_invite(&req, false).unwrap();
    let ok = ResponseBuilder::from_request(&req, 200, "OK")
        .to_tag("svr")
        .build();
    let actions = tx.on_event(TxEvent::Response(ok));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Terminate)));
    assert!(tx.is_terminated());
}

#[test]
fn server_non_invite() {
    let from = named(Uri::parse("sip:alice@example.com").unwrap());
    let uri = Uri::parse("sip:proxy.example.com").unwrap();
    let req = RequestBuilder::new(Method::Options, uri, from)
        .call_id("call-3")
        .build();
    let (mut tx, _) = Transaction::server_non_invite(&req, false).unwrap();
    assert_eq!(tx.state, TxState::TryingServer);

    let ok = ResponseBuilder::from_request(&req, 200, "OK")
        .to_tag("s")
        .build();
    let actions = tx.on_event(TxEvent::Response(ok));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Transmit(_))));
    assert!(actions
        .iter()
        .any(|a| matches!(a, TxAction::StartTimer("J", _))));
    assert_eq!(tx.state, TxState::CompletedServerNonInvite);

    let actions = tx.on_event(TxEvent::Timer("J"));
    assert!(actions.iter().any(|a| matches!(a, TxAction::Terminate)));
}

// ---- Dialog ----

#[test]
fn dialog_from_response_confirmed() {
    let req = invite_request();
    let resp = ResponseBuilder::from_request(&req, 200, "OK")
        .to_tag("svrtag")
        .contact(named(Uri::parse("sip:bob@192.0.2.4").unwrap()))
        .build();
    let mut dlg =
        Dialog::from_uac_response(&resp, req.from().unwrap().uri.clone(), "localtag").unwrap();
    assert_eq!(dlg.state, DialogState::Confirmed);
    assert_eq!(dlg.call_id, "call-1");
    assert_eq!(dlg.remote_tag.as_deref(), Some("svrtag"));
    assert_eq!(dlg.remote_target.host, "192.0.2.4");
    assert!(dlg.is_confirmed());
    assert_eq!(dlg.next_cseq(), 1);
    assert_eq!(dlg.next_cseq(), 2);
}

#[test]
fn dialog_early_from_provisional() {
    let req = invite_request();
    let resp = ResponseBuilder::from_request(&req, 180, "Ringing")
        .to_tag("ringingtag")
        .contact(named(Uri::parse("sip:bob@192.0.2.4").unwrap()))
        .build();
    let dlg =
        Dialog::from_uac_response(&resp, req.from().unwrap().uri.clone(), "localtag").unwrap();
    assert_eq!(dlg.state, DialogState::Early);
    assert!(!dlg.is_confirmed());
}

#[test]
fn dialog_from_request() {
    let req = invite_request();
    let dlg = Dialog::from_uas_request(&req, "uastag").unwrap();
    assert_eq!(dlg.state, DialogState::Early);
    assert_eq!(dlg.remote_tag.as_deref(), Some("1928301774"));
    assert_eq!(dlg.local_tag, "uastag");
}

// ---- SDP ----

#[test]
fn sdp_round_trip() {
    let sdp_text = "v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 atlanta.example.com\r\n\
s=-\r\n\
c=IN IP4 pc.atlanta.example.com\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8 97\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:97 iLBC/8000\r\n";
    let sdp = Sdp::parse(sdp_text).unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.media.len(), 1);
    assert_eq!(sdp.media[0].media, "audio");
    assert_eq!(sdp.media[0].port, 49170);
    assert_eq!(sdp.media[0].formats, vec!["0", "8", "97"]);
    assert_eq!(sdp.media[0].attributes.len(), 2);

    let reparsed = Sdp::parse(&sdp.to_string()).unwrap();
    assert_eq!(reparsed.media[0].port, 49170);
    assert_eq!(reparsed.media[0].formats.len(), 3);
}

// ---- End-to-end over UDP ----

#[test]
fn udp_register_round_trip() -> Result<()> {
    use std::net::SocketAddr;
    use tpt_sip::transport::{Transport, UdpTransport};

    let mut server = UdpTransport::bind("127.0.0.1:15061")?;
    let mut client = UdpTransport::bind("127.0.0.1:15062")?;
    let server_addr: SocketAddr = "127.0.0.1:15061".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:15062".parse().unwrap();

    let from = named(Uri::parse("sip:alice@example.com").unwrap());
    let contact = named(Uri::parse("sip:alice@127.0.0.1:15062").unwrap());
    let uri = Uri::parse("sip:example.com").unwrap();
    let reg = register(uri, from, contact).call_id("udp-1").build();
    let bytes = reg.to_bytes();

    client.send_to(server_addr, &bytes)?;
    let (src, recv) = server.recv_from()?;
    assert_eq!(src, client_addr);
    let parsed = Message::parse(&recv)?;
    assert_eq!(parsed.method(), Some(Method::Register));
    assert_eq!(parsed.call_id(), Some("udp-1"));

    // Server answers with a 200 OK.
    let ok = ResponseBuilder::from_request(&parsed, 200, "OK")
        .to_tag("srv")
        .build();
    server.send_to(client_addr, &ok.to_bytes())?;
    let (_, recv2) = client.recv_from()?;
    let parsed2 = Message::parse(&recv2)?;
    assert_eq!(parsed2.status_line().unwrap().code, 200);
    Ok(())
}

// Ensure the Via parser helper is exercised.
#[test]
fn via_parser_helper() {
    let v =
        parse_via("SIP/2.0/UDP host.example.com:5060;branch=z9hG4bKabc, SIP/2.0/TCP other:5070")
            .unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].port, Some(5060));
    assert_eq!(v[0].branch(), Some("z9hG4bKabc"));
    assert_eq!(v[1].protocol, "SIP/2.0/TCP");
    assert_eq!(v[1].port, Some(5070));
}
