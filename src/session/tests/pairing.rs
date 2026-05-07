use std::sync::{Arc, Mutex};
use std::time::Duration;

use hush_noise::{keypair::Keypair, session::accept};

use crate::device::DeviceKeypair;
use crate::keys::NoisePublicKey;
use crate::message::Message;

use super::super::test_helpers::*;
use super::super::HushSession;

#[test]
fn pairing_ceremony_on_paired_fires_with_correct_key() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, false); // B→A

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let pair_msgs: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let pm = pair_msgs.clone();
    let session_a = Arc::new(
        HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _| {
            pm.lock().unwrap().push(msg);
        })
        .expect("session A"),
    );

    let on_paired_fired: Arc<Mutex<Vec<NoisePublicKey>>> = Arc::new(Mutex::new(Vec::new()));
    let opf = on_paired_fired.clone();
    let _payload = session_a.start_pairing(move |k| {
        opf.lock().unwrap().push(k);
    });

    let device_b_noise_pub = device_b.public_key();
    let device_b_signing_pub = device_b.signing_public_key();
    let session_b =
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");

    let pair_msg = Message::Pair {
        noise_pub: device_b_noise_pub.0,
        signing_pub: device_b_signing_pub.0,
    };
    session_b
        .push_message(&pair_msg, session_a.noise_pub())
        .expect("B push Pair");

    std::thread::sleep(Duration::from_millis(100));

    let msgs = pair_msgs.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    if let Message::Pair {
        noise_pub,
        signing_pub,
    } = msgs[0]
    {
        drop(msgs);
        session_a.accept_pair(
            NoisePublicKey(noise_pub),
            crate::keys::SigningPublicKey(signing_pub),
        );
    } else {
        panic!("expected Pair message");
    }

    let paired = on_paired_fired.lock().unwrap();
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].0, device_b_noise_pub.0);
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

    let fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let fc = fired.clone();

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    session.accept_pair(dummy, dummy_signing);
    assert!(!*fired.lock().unwrap());

    let _payload = session.start_pairing(move |_| {
        *fc.lock().unwrap() = true;
    });
    session.cancel_pairing();
    session.accept_pair(dummy, dummy_signing);
    assert!(!*fired.lock().unwrap());
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

    let fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let fc = fired.clone();
    let _payload = session.start_pairing_with_duration(Duration::from_millis(1), move |_| {
        *fc.lock().unwrap() = true;
    });
    std::thread::sleep(Duration::from_millis(10));

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    session.accept_pair(dummy, dummy_signing);
    assert!(!*fired.lock().unwrap());
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

    let _payload = session.start_pairing(|_| {});
    assert!(
        session.accept_pair(dummy, dummy_signing),
        "open window: should return true"
    );
    assert!(
        !session.accept_pair(dummy, dummy_signing),
        "window consumed: should return false"
    );

    let _payload = session.start_pairing(|_| {});
    session.cancel_pairing();
    assert!(
        !session.accept_pair(dummy, dummy_signing),
        "cancelled window: should return false"
    );
}
