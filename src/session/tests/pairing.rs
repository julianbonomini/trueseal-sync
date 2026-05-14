use std::sync::{Arc, Mutex};
use std::time::Duration;

use trueseal_noise::{keypair::Keypair, session_xx::accept};

use crate::device::DeviceKeypair;
use crate::keys::NoisePublicKey;

use super::super::test_helpers::*;
use super::super::TruesealSession;

/// After accept_pair, A's manifest contains B as a member.
#[test]
fn pairing_ceremony_creates_manifest_with_new_member() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, nk_rx, true); // A→B

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let session_a = Arc::new(
        TruesealSession::connect(pipe_a_client, relay_pub, device_a, move |_, _, _| {}, nk.factory())
            .expect("session A"),
    );

    let _token = session_a.pairing_token();

    let device_b_noise_pub = device_b.public_key();
    let device_b_signing_pub = device_b.signing_public_key();
    let _session_b =
        TruesealSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("session B");

    let admitted = session_a.accept_pair(device_b_noise_pub, device_b_signing_pub);
    assert!(admitted, "accept_pair must return true when window is open");

    let manifest = session_a.manifest.lock().unwrap();
    assert!(manifest.is_some(), "A must have a manifest after pairing");
    let m = manifest.as_ref().unwrap();
    assert_eq!(m.members.len(), 2, "manifest must have 2 members");
    assert!(
        m.members
            .iter()
            .any(|mb| mb.noise_pub == device_b_noise_pub),
        "B must be in the manifest"
    );
}

#[test]
fn accept_pair_outside_window_is_noop() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, || Err("push factory unused in pairing test".into())).expect("connect");

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    // No window open — should be a noop.
    session.accept_pair(dummy, dummy_signing);

    let _ = session.pairing_token();
    session.cancel_pairing();
    // Window cancelled — accept_pair should return false.
    assert!(!session.accept_pair(dummy, dummy_signing));
}

/// Window stays open until cancelled — no auto-expiry (ADR-0021).
#[test]
fn accept_pair_window_stays_open_until_cancelled() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, || Err("push factory unused in pairing test".into())).expect("connect");

    let _token = session.pairing_token();
    // Sleep well beyond the old 60-second auto-expiry — window must still be open.
    std::thread::sleep(Duration::from_millis(10));

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    assert!(
        session.accept_pair(dummy, dummy_signing),
        "window must still be open after delay — no auto-expiry"
    );
}

/// accept_pair returns true when the window is open, false otherwise.
#[test]
fn accept_pair_returns_bool_reflecting_window_state() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, || Err("push factory unused in pairing test".into())).expect("connect");

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);

    assert!(
        !session.accept_pair(dummy, dummy_signing),
        "no window: should return false"
    );

    let _token = session.pairing_token();
    assert!(
        session.accept_pair(dummy, dummy_signing),
        "open window: should return true"
    );
    assert!(
        !session.accept_pair(dummy, dummy_signing),
        "window consumed: should return false"
    );

    let _token = session.pairing_token();
    session.cancel_pairing();
    assert!(
        !session.accept_pair(dummy, dummy_signing),
        "cancelled window: should return false"
    );
}

/// `accept_outside_window_is_noop` checks the fired flag was NOT set.
/// Kept as a distinct test since the original tested an `on_paired` callback.
/// Now we simply verify accept_pair returns false outside a window.
#[test]
fn no_callback_fired_when_window_closed() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, || Err("push factory unused in pairing test".into())).expect("connect");

    let fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let _fc = fired.clone();

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);

    // No window — no callback.
    let admitted = session.accept_pair(dummy, dummy_signing);
    assert!(!admitted);
    assert!(!*fired.lock().unwrap());
}

/// cancel_pairing clears pending_members so stale tokens can't be used later.
#[test]
fn cancel_pairing_clears_pending_members() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || { let _ = accept(pipe_relay, relay_kp2); });

    let device = DeviceKeypair::generate();
    let session = TruesealSession::connect(
        pipe_client, relay_pub, device, |_, _, _| {},
        || Err("push factory unused".into()),
    ).expect("connect");

    // Open window, inject a fake pending member directly.
    let _token = session.pairing_token();
    let fake_token = "fake-token".to_string();
    session.pending_members.lock().unwrap().insert(
        fake_token.clone(),
        super::super::PendingMember {
            noise_pub: crate::keys::NoisePublicKey([1u8; 32]),
            signing_pub: crate::keys::SigningPublicKey([2u8; 32]),
        },
    );
    assert!(!session.pending_members.lock().unwrap().is_empty(), "setup: token must be present");

    session.cancel_pairing();

    assert!(
        session.pending_members.lock().unwrap().is_empty(),
        "cancel_pairing must clear pending_members"
    );
}
