//! Integration and conformance tests for `tpt-bfd`.
//!
//! The core harness drives two [`Session`]s against each other over an
//! in-memory channel (no real socket), exercising the full state
//! machine, timers, demand mode, and authentication. A final test
//! exercises the UDP transport end-to-end against `localhost`.

use std::net::{Ipv4Addr, UdpSocket};
use std::thread;
use std::time::Duration;

use tpt_bfd::packet::{AuthType, Diagnostic, SessionState};
use tpt_bfd::session::{AuthConfig, Role, Session, SessionConfig};

const LOCAL: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

fn base_cfg(local_discr: u32) -> SessionConfig {
    SessionConfig {
        local_discriminator: local_discr,
        desired_min_tx_interval: 1_000_000,
        required_min_rx_interval: 1_000_000,
        detect_mult: 3,
        demand_mode: false,
        control_plane_independent: false,
        role: Role::Active,
        auth: None,
    }
}

/// Exchange one direction's packet between `a` and `b`, including any
/// immediate Final (F) response, then the reverse direction.
fn step_pair(a: &mut Session, b: &mut Session) {
    if let Some(p) = a.next_periodic_packet() {
        let bytes = a.encode_packet(&p);
        if let Some(resp) = b.process_bytes(&bytes).unwrap() {
            let rb = b.encode_packet(&resp);
            let _ = a.process_bytes(&rb);
        }
    }
    if let Some(p) = b.next_periodic_packet() {
        let bytes = b.encode_packet(&p);
        if let Some(resp) = a.process_bytes(&bytes).unwrap() {
            let ra = a.encode_packet(&resp);
            let _ = b.process_bytes(&ra);
        }
    }
}

fn establish(a: &mut Session, b: &mut Session) {
    for _ in 0..10 {
        step_pair(a, b);
        if a.is_up() && b.is_up() {
            return;
        }
    }
}

#[test]
fn packet_round_trip() {
    let mut s = Session::new(base_cfg(0x1122_3344)).unwrap();
    let pkt = s.next_periodic_packet().unwrap();
    let bytes = s.encode_packet(&pkt);
    let decoded = tpt_bfd::packet::ControlPacket::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, pkt);
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.my_discriminator, 0x1122_3344);
    assert_eq!(decoded.detect_mult, 3);
    assert_eq!(decoded.state, SessionState::Down);
}

#[test]
fn handshake_reaches_up() {
    let mut a = Session::new(base_cfg(1)).unwrap();
    let mut b = Session::new(base_cfg(2)).unwrap();
    assert_eq!(a.state(), SessionState::Down);
    assert_eq!(b.state(), SessionState::Down);
    establish(&mut a, &mut b);
    assert!(a.is_up(), "session A not Up: {:?}", a.state());
    assert!(b.is_up(), "session B not Up: {:?}", b.state());
}

#[test]
fn timeout_declares_down() {
    let mut a = Session::new(base_cfg(1)).unwrap();
    let mut b = Session::new(base_cfg(2)).unwrap();
    establish(&mut a, &mut b);
    assert!(a.is_up() && b.is_up());

    let detect = a.detection_time();
    thread::sleep(detect + Duration::from_millis(20));
    assert!(a.check_timeout(), "A should have timed out");
    assert_eq!(a.state(), SessionState::Down);
    assert_eq!(a.local_diag(), Diagnostic::ControlDetectionTimeExpired);
}

#[test]
fn admin_down_then_up() {
    let mut a = Session::new(base_cfg(1)).unwrap();
    let mut b = Session::new(base_cfg(2)).unwrap();
    establish(&mut a, &mut b);

    a.admin_down();
    step_pair(&mut a, &mut b);
    assert_eq!(b.state(), SessionState::Down);
    assert_eq!(b.local_diag(), Diagnostic::NeighborSignaledSessionDown);

    a.admin_up();
    establish(&mut a, &mut b);
    assert!(a.is_up() && b.is_up());
}

#[test]
fn demand_mode_suppresses_periodic() {
    let mut cfg_a = base_cfg(1);
    cfg_a.demand_mode = true;
    let mut cfg_b = base_cfg(2);
    cfg_b.demand_mode = true;
    let mut a = Session::new(cfg_a).unwrap();
    let mut b = Session::new(cfg_b).unwrap();
    establish(&mut a, &mut b);
    assert!(a.is_up() && b.is_up());

    let pkt_a = a.next_periodic_packet().unwrap();
    assert!(pkt_a.demand, "D bit should be set in demand mode");
    // Remote is also Up+demand, so `a` must not send periodic packets.
    assert!(a.next_periodic_packet().is_none());
}

#[test]
fn simple_password_auth_accepts_and_rejects() {
    let auth_ok = AuthConfig {
        auth_type: AuthType::SimplePassword,
        key_id: 1,
        key: b"shared-secret".to_vec(),
    };
    let mut a = Session::new(SessionConfig {
        auth: Some(auth_ok.clone()),
        ..base_cfg(1)
    })
    .unwrap();
    let mut b = Session::new(SessionConfig {
        auth: Some(auth_ok),
        ..base_cfg(2)
    })
    .unwrap();
    establish(&mut a, &mut b);
    assert!(a.is_up() && b.is_up());

    // A session with a mismatched key must never reach Up.
    let mut c = Session::new(SessionConfig {
        auth: Some(AuthConfig {
            auth_type: AuthType::SimplePassword,
            key_id: 1,
            key: b"wrong-key".to_vec(),
        }),
        ..base_cfg(3)
    })
    .unwrap();
    let mut d = Session::new(base_cfg(4)).unwrap();
    for _ in 0..10 {
        step_pair(&mut c, &mut d);
        if c.is_up() && d.is_up() {
            break;
        }
    }
    assert!(!c.is_up());
    assert!(!d.is_up());
}

#[test]
fn keyed_sha1_auth_round_trip() {
    let auth = AuthConfig {
        auth_type: AuthType::KeyedSha1,
        key_id: 7,
        key: b"a-very-secret-key".to_vec(),
    };
    let mut a = Session::new(SessionConfig {
        auth: Some(auth.clone()),
        ..base_cfg(11)
    })
    .unwrap();
    let mut b = Session::new(SessionConfig {
        auth: Some(auth),
        ..base_cfg(12)
    })
    .unwrap();
    establish(&mut a, &mut b);
    assert!(a.is_up() && b.is_up());

    // A packet whose keyed digest cannot be verified must be discarded.
    let mut evil = Session::new(SessionConfig {
        auth: Some(AuthConfig {
            auth_type: AuthType::KeyedSha1,
            key_id: 7,
            key: b"different-key!!".to_vec(),
        }),
        ..base_cfg(13)
    })
    .unwrap();
    let p = evil.next_periodic_packet().unwrap();
    let bytes = evil.encode_packet(&p);
    let before = b.state();
    let resp = b.process_bytes(&bytes).unwrap();
    assert!(resp.is_none());
    assert_eq!(b.state(), before);
}

#[test]
fn udp_transport_reaches_up() {
    let a_sock = UdpSocket::bind((LOCAL, 0)).unwrap();
    let b_sock = UdpSocket::bind((LOCAL, 0)).unwrap();
    let a_real = a_sock.local_addr().unwrap();
    let b_real = b_sock.local_addr().unwrap();

    let mk = |disc: u32| SessionConfig {
        local_discriminator: disc,
        desired_min_tx_interval: 1_000_000,
        required_min_rx_interval: 1_000_000,
        detect_mult: 3,
        demand_mode: false,
        control_plane_independent: false,
        role: Role::Active,
        auth: None,
    };
    let a = Session::new(mk(100)).unwrap();
    let b = Session::new(mk(200)).unwrap();

    let mut ta = tpt_bfd::transport::UdpTransport::new(a, a_sock, b_real).unwrap();
    let mut tb = tpt_bfd::transport::UdpTransport::new(b, b_sock, a_real).unwrap();

    let ha = thread::spawn(move || {
        for _ in 0..60 {
            ta.step().unwrap();
            thread::sleep(Duration::from_millis(10));
        }
        ta.session().is_up()
    });
    let hb = thread::spawn(move || {
        for _ in 0..60 {
            tb.step().unwrap();
            thread::sleep(Duration::from_millis(10));
        }
        tb.session().is_up()
    });

    assert!(ha.join().unwrap(), "UDP session A did not reach Up");
    assert!(hb.join().unwrap(), "UDP session B did not reach Up");
}
