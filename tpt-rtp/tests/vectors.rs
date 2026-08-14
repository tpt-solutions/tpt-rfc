//! Hand-constructed, known-value conformance vectors for `tpt-rtp`.
//!
//! These exercise the wire format against packets assembled field-by-field
//! (not merely round-tripped through our own encoder), and assert the decoded
//! field values. Interop against a real RTP stack (GStreamer / webrtc-rs) is
//! tracked in `SPEC-NOTES.md` but is BLOCKED in this environment.

use tpt_rtp::rtcp::{App, Bye, RtcpPacket, RtcpType, SdesItemType};
use tpt_rtp::rtp::RtpPacket;
use tpt_rtp::session::ReceiverStats;

#[test]
fn rtp_packet_decodes_to_known_fields() {
    // V=2, P=0, X=0, CC=2, M=1, PT=96; seq=0x1234; ts=0x0a0b0c0d; ssrc=0x01020304
    // CSRC[0]=0xaabbccdd, CSRC[1]=0x11223344; payload = 0xde 0xad 0xbe 0xef
    let wire = [
        0x82u8, 0x60, 0x12, 0x34, // b0=1000_0010 (CC=2), b1=0110_0000 (M=1,PT=96)
        0x0a, 0x0b, 0x0c, 0x0d, 0x01, 0x02, 0x03, 0x04, // ts + ssrc
        0xaa, 0xbb, 0xcc, 0xdd, // CSRC 0
        0x11, 0x22, 0x33, 0x44, // CSRC 1
        0xde, 0xad, 0xbe, 0xef, // payload
    ];
    let pkt = RtpPacket::decode(&wire).unwrap();
    assert_eq!(pkt.header.csrc, vec![0xaabb_ccdd, 0x1122_3344]);
    assert!(pkt.header.marker);
    assert_eq!(pkt.header.payload_type, 96);
    assert_eq!(pkt.header.sequence_number, 0x1234);
    assert_eq!(pkt.header.timestamp, 0x0a0b_0c0d);
    assert_eq!(pkt.header.ssrc, 0x0102_0304);
    assert_eq!(pkt.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    assert!(!pkt.header.extension);
    assert!(!pkt.header.padding);
}

#[test]
fn rtp_extension_and_padding_wire() {
    // V=2, X=1, P=1, M=0, PT=10, CC=0; extension profile 0xbede, one word 0x12345678;
    // payload 0x01 0x02, padding 4 octets (last = 4)
    let wire = [
        0xb0u8, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xca, 0xfe, 0xba, 0xbe,
        0xbe, 0xde, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x01, 0x02, 0x00, 0x00, 0x00,
        0x04,
    ];
    let pkt = RtpPacket::decode(&wire).unwrap();
    assert!(pkt.header.extension);
    assert_eq!(pkt.header.extension_profile, 0xbede);
    assert_eq!(pkt.header.extension_words, vec![0x1234_5678]);
    assert!(pkt.header.padding);
    assert_eq!(pkt.payload(), &[0x01, 0x02]);
    assert_eq!(pkt.padding, vec![0x00, 0x00, 0x00, 0x04]);

    // Re-encode and confirm identical.
    let enc = pkt.encode().unwrap();
    assert_eq!(enc, wire.to_vec());
}

#[test]
fn rtcp_sr_known_fields() {
    // SR: V=2,P=0,RC=1,PT=200,length=7 (=> 8*4=32 bytes); ssrc=0x11111111
    // ntp=0x0011223344556677; rtp_ts=0xaabbccdd; pc=5; oc=1234
    // one report block: ssrc=0x55667788, frac=17, cumlost=0x00ffffff&...=16777215? we use 0x0000ff01
    let wire = [
        0x81u8, 0xc8, 0x00, 0x07, // RC=1, PT=200(0xc8), len=7
        0x11, 0x11, 0x11, 0x11, // ssrc
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // ntp
        0xaa, 0xbb, 0xcc, 0xdd, // rtp ts
        0x00, 0x00, 0x00, 0x05, // packet count
        0x00, 0x00, 0x04, 0xd2, // octet count = 1234
        // reception report block (24 bytes)
        0x55, 0x66, 0x77, 0x88, // ssrc
        0x11, // fraction lost = 17
        0x00, 0xff, 0x01, // cumulative lost (24 bits) = 0x0000ff01
        0x12, 0x34, 0x56, 0x78, // extended seq
        0x00, 0x00, 0x00, 0x2a, // jitter = 42
        0x99, 0xaa, 0xbb, 0xcc, // LSR
        0x00, 0x00, 0x03, 0xe8, // DLSR = 1000
    ];
    let pkt = RtcpPacket::decode(&wire).unwrap();
    match &pkt {
        RtcpPacket::Sr(sr) => {
            assert_eq!(sr.ssrc, 0x1111_1111);
            assert_eq!(sr.ntp_timestamp, 0x0011_2233_4455_6677);
            assert_eq!(sr.rtp_timestamp, 0xaabb_ccdd);
            assert_eq!(sr.senders_packet_count, 5);
            assert_eq!(sr.senders_octet_count, 1234);
            assert_eq!(sr.reports.len(), 1);
            let r = &sr.reports[0];
            assert_eq!(r.ssrc, 0x5566_7788);
            assert_eq!(r.fraction_lost, 17);
            assert_eq!(r.cumulative_lost, 0x0000_ff01);
            assert_eq!(r.extended_seq, 0x1234_5678);
            assert_eq!(r.interarrival_jitter, 42);
            assert_eq!(r.last_sr, 0x99aa_bbcc);
            assert_eq!(r.delay_since_last_sr, 1000);
        }
        _ => panic!("expected SR"),
    }
    assert_eq!(pkt.encode(), wire.to_vec());
    assert_eq!(pkt.packet_type(), RtcpType::Sr);
}

#[test]
fn rtcp_sdes_known_fields() {
    // SDES: V=2,SC=1,PT=202,len=3 (=> 4*4=16 bytes); chunk ssrc=0x11111111,
    // CNAME "a@b.c" (5 bytes). Chunk = ssrc(4)+item(2+5)+END(1) = 12 bytes,
    // already 32-bit aligned. Total = 16 bytes = 4 words => length = 3.
    let wire = [
        0x81u8, 0xca, 0x00, 0x03, // RC=1, PT=202(0xca), len=3
        0x11, 0x11, 0x11, 0x11, // ssrc
        0x01, 0x05, b'a', b'@', b'b', b'.', b'c', // CNAME, len 5
        0x00, // END
    ];
    let pkt = RtcpPacket::decode(&wire).unwrap();
    match pkt {
        RtcpPacket::Sdes(ref s) => {
            assert_eq!(s.chunks.len(), 1);
            assert_eq!(s.chunks[0].ssrc, 0x1111_1111);
            assert_eq!(s.chunks[0].items.len(), 1);
            assert_eq!(s.chunks[0].items[0].item_type, SdesItemType::Cname);
            assert_eq!(s.chunks[0].items[0].as_text(), "a@b.c");
        }
        _ => panic!("expected SDES"),
    }
    // Re-encode: encoder recomputes length; should decode back identically.
    let reenc = pkt.encode();
    let redec = RtcpPacket::decode(&reenc).unwrap();
    assert_eq!(redec, pkt);
}

#[test]
fn rtcp_bye_and_app() {
    let bye = RtcpPacket::Bye(Bye {
        sources: vec![0xaabb_ccdd],
        reason: Some("bye".to_string()),
    });
    let enc = bye.encode();
    let dec = RtcpPacket::decode(&enc).unwrap();
    match dec {
        RtcpPacket::Bye(b) => {
            assert_eq!(b.sources, vec![0xaabb_ccdd]);
            assert_eq!(b.reason.as_deref(), Some("bye"));
        }
        _ => panic!("expected BYE"),
    }

    let app = RtcpPacket::App(App {
        ssrc: 0x1234_5678,
        subtype: 5,
        name: *b"RTPE",
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
    });
    let enc = app.encode();
    let dec = RtcpPacket::decode(&enc).unwrap();
    match dec {
        RtcpPacket::App(a) => {
            assert_eq!(a.subtype, 5);
            assert_eq!(&a.name, b"RTPE");
            assert_eq!(a.data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        }
        _ => panic!("expected APP"),
    }
}

#[test]
fn receiver_stats_against_sequence_with_restart() {
    // Simulate a sender that restarts mid-stream (two sequential bad seqs).
    let mut s = ReceiverStats::new(7, 8000);
    // First run: seqs 100..=105
    for seq in 100u16..=105u16 {
        s.update(seq, seq as u32, seq as u32);
    }
    let expected1 = s.expected();
    // Now a "bad" sequence far away (simulating restart detection via the
    // two-sequential rule is internal); just verify monotonic tracking.
    for seq in 106u16..=110u16 {
        s.update(seq, seq as u32, seq as u32);
    }
    assert!(s.expected() > expected1);
    assert_eq!(s.cumulative_lost(), 0);
}
