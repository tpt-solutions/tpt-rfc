// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Peer finite-state machine tests (RFC 4271 §8).

use tpt_bgp::fsm::{Fsm, FsmAction, FsmEvent, FsmState};
use tpt_bgp::wire::{err_code, Notification};

fn has_action(actions: &[FsmAction], want: &FsmAction) -> bool {
    actions.iter().any(|a| a == want)
}

#[test]
fn full_establishment() {
    let mut fsm = Fsm::new([10, 0, 0, 1]);

    // Idle -> Connect on ManualStart.
    let a = fsm.on_event(FsmEvent::ManualStart);
    assert_eq!(fsm.state, FsmState::Connect);
    assert!(has_action(&a, &FsmAction::InitiateTcpConnection));

    // Connect -> OpenSent on TCP up.
    let a = fsm.on_event(FsmEvent::TcpConnectionValid);
    assert_eq!(fsm.state, FsmState::OpenSent);
    assert!(has_action(&a, &FsmAction::SendOpen));

    // OpenSent -> OpenConfirm on valid OPEN.
    let a = fsm.on_event(FsmEvent::BgpOpenValid([10, 0, 0, 2]));
    assert_eq!(fsm.state, FsmState::OpenConfirm);
    assert!(has_action(&a, &FsmAction::SendKeepalive));

    // OpenConfirm -> Established on KEEPALIVE.
    let a = fsm.on_event(FsmEvent::KeepaliveReceived);
    assert_eq!(fsm.state, FsmState::Established);
    assert!(has_action(&a, &FsmAction::StartHoldTimer));

    // Stays Established on subsequent KEEPALIVE.
    let _a = fsm.on_event(FsmEvent::KeepaliveReceived);
    assert_eq!(fsm.state, FsmState::Established);
}

#[test]
fn teardown_on_hold_timer() {
    let mut fsm = Fsm::new([10, 0, 0, 1]);
    fsm.on_event(FsmEvent::ManualStart);
    fsm.on_event(FsmEvent::TcpConnectionValid);
    // Still in OpenSent (no OPEN accepted yet): hold-timer expiry sends a
    // HOLD_TIMER_EXPIRED NOTIFICATION.
    let a = fsm.on_event(FsmEvent::HoldTimerExpired);
    assert_eq!(fsm.state, FsmState::Idle);
    assert!(a.iter().any(|x| matches!(
        x,
        FsmAction::SendNotification(n) if n.code == err_code::HOLD_TIMER_EXPIRED
    )));
    assert!(has_action(&a, &FsmAction::ReleaseTcpConnection));
}

#[test]
fn teardown_on_invalid_open() {
    let mut fsm = Fsm::new([10, 0, 0, 1]);
    fsm.on_event(FsmEvent::ManualStart);
    fsm.on_event(FsmEvent::TcpConnectionValid);

    let note = Notification::open_error(2, vec![]);
    let a = fsm.on_event(FsmEvent::BgpOpenInvalid(note));
    assert_eq!(fsm.state, FsmState::Idle);
    assert!(has_action(&a, &FsmAction::ReleaseTcpConnection));
    assert!(has_action(&a, &FsmAction::StartIdleHoldTimer));
}

#[test]
fn collision_detection_higher_id_closes() {
    // A simultaneous open produces two connections. Per RFC 4271 §6.8.2 the
    // higher BGP identifier closes its session; the lower keeps it.
    let mut lower = Fsm::new([10, 0, 0, 1]);
    let mut higher = Fsm::new([10, 0, 0, 9]);

    // Both bring up their primary connection and accept the peer's OPEN.
    for fsm in [&mut lower, &mut higher] {
        fsm.on_event(FsmEvent::ManualStart);
        fsm.on_event(FsmEvent::TcpConnectionValid);
    }
    lower.on_event(FsmEvent::BgpOpenValid([10, 0, 0, 9])); // lower learns higher id
    higher.on_event(FsmEvent::BgpOpenValid([10, 0, 0, 1])); // higher learns lower id

    // A duplicate (passive) connection arrives on each.
    let a_lower = lower.on_event(FsmEvent::TcpConnectionOpened);
    let a_higher = higher.on_event(FsmEvent::TcpConnectionOpened);

    // Lower id (1) <= remote (9): lower keeps its session, drops the new conn.
    assert_eq!(lower.state, FsmState::OpenConfirm);
    assert!(has_action(&a_lower, &FsmAction::ReleaseTcpConnection));

    // Higher id (9) > remote (1): higher closes its whole session.
    assert_eq!(higher.state, FsmState::Idle);
    assert!(has_action(&a_higher, &FsmAction::ReleaseTcpConnection));
}

#[test]
fn active_state_on_connection_failure() {
    let mut fsm = Fsm::new([10, 0, 0, 1]);
    fsm.on_event(FsmEvent::ManualStart);
    let a = fsm.on_event(FsmEvent::TcpConnectionFailed);
    assert_eq!(fsm.state, FsmState::Idle);
    assert!(has_action(&a, &FsmAction::StartIdleHoldTimer));
}
