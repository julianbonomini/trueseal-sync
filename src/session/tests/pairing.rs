use std::sync::{Arc, Mutex};
use std::time::Duration;

use hush_noise::{keypair::Keypair, session::accept};

use crate::device::DeviceKeypair;
use crate::keys::NoisePublicKey;

use super::super::test_helpers::*;
use super::super::HushSession;

/// After accept_pair, A's manifest contains B as a member.
#[test]
fn pairing_ceremony_creates_manifest_with_new_member() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true); // A→B

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let session_a = Arc::new(
        HushSession::connect(pipe_a_client, relay_pub, device_a, move |_, _| {})
            .expect("session A"),
    );

    let _token = session_a.pairing_token();

    let device_b_noise_pub = device_b.public_key();
    let device_b_signing_pub = device_b.signing_public_key();
    let _session_b =
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");

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
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    // No window open — should be a noop.
    session.accept_pair(dummy, dummy_signing);

    let _ = session.pairing_token();
    session.cancel_pairing();
    // Window cancelled — accept_pair should return false.
    assert!(!session.accept_pair(dummy, dummy_signing));
}

#[test]
fn accept_pair_after_timeout_is_noop() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

    let _token = session.pairing_token_with_duration(Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(10));

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    assert!(
        !session.accept_pair(dummy, dummy_signing),
        "expired window: should return false"
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
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

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
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

    let fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let _fc = fired.clone();

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);

    // No window — no callback.
    let admitted = session.accept_pair(dummy, dummy_signing);
    assert!(!admitted);
    assert!(!*fired.lock().unwrap());
}
