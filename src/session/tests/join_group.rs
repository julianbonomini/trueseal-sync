use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::message::Message;

use super::super::test_helpers::*;
use super::super::HushSession;

/// B calls join_group(A.pairing_token()) — A receives a Pair message with B's keys.
#[test]
fn join_group_sends_pair_message_to_initiator() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    // Relay accepts pipe_b_relay (B's relay end) first as src, then pipe_a_relay as dst.
    // a_is_src=true → sess_a (=B's pipe) is src, sess_b (=A's pipe) is dst → B→A routing.
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise_pub = device_b.public_key();
    let b_signing_pub = device_b.signing_public_key();

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();

    // B must connect to pipe_b_client first (relay accepts pipe_b_relay first).
    let session_b =
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");
    let session_a = HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _| {
        rx.lock().unwrap().push(msg);
    })
    .expect("session A");
    let token = session_a.pairing_token();

    let result = session_b.join_group(&token);
    assert!(result.is_ok(), "join_group failed: {:?}", result);

    std::thread::sleep(Duration::from_millis(200));

    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "A should receive exactly one Pair message");
    match msgs[0] {
        Message::Pair {
            noise_pub,
            signing_pub,
        } => {
            assert_eq!(noise_pub, b_noise_pub.0, "noise_pub must match B's");
            assert_eq!(signing_pub, b_signing_pub.0, "signing_pub must match B's");
        }
        _ => panic!("expected Pair message, got {:?}", msgs[0]),
    }
}

/// join_group with a malformed token returns InvalidToken.
#[test]
fn join_group_invalid_token_returns_error() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = hush_noise::session_xx::accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

    let result = session.join_group("not-a-valid-token!!!!");
    assert!(
        matches!(result, Err(super::super::SessionError::InvalidToken)),
        "bad token should return InvalidToken, got {:?}",
        result
    );
}
