use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::HushSession;
use super::make_two_member_manifest;

/// When a Pair message arrives inside an open pairing window,
/// on_member_request fires with a non-empty token and a name.
#[test]
fn pair_inside_window_fires_on_member_request() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let received: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
    let rc = received.clone();

    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        || {},
    )
    .expect("session A");

    // Register the on_member_request callback.
    session_a.set_on_member_request(move |token, name| {
        rc.lock().unwrap().push((token, name));
    });

    // Open a pairing window and give B the token to send a Pair message.
    let pairing_token = session_a.pairing_token();

    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        || {},
    )
    .expect("session B");

    // B sends Pair message to A.
    session_b.join_group(&pairing_token).expect("join");

    std::thread::sleep(Duration::from_millis(200));

    let calls = received.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "on_member_request must fire once");
    let (token, _name) = &calls[0];
    assert!(!token.is_empty(), "token must be non-empty");
}

/// accept_member with a valid token admits the member and returns true.
#[test]
fn accept_member_with_valid_token_returns_true() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let token_received: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let tr = token_received.clone();

    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        || {},
    )
    .expect("session A");

    session_a.set_on_member_request(move |token, _name| {
        *tr.lock().unwrap() = Some(token);
    });

    let pairing_token = session_a.pairing_token();

    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        || {},
    )
    .expect("session B");

    session_b.join_group(&pairing_token).expect("join");
    std::thread::sleep(Duration::from_millis(200));

    let request_token = token_received
        .lock()
        .unwrap()
        .clone()
        .expect("token received");
    let admitted = session_a.accept_member(&request_token);
    assert!(admitted, "accept_member with valid token returns true");
}

/// accept_member with an unknown token returns false.
#[test]
fn accept_member_with_unknown_token_returns_false() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session::accept(pipe_relay, kp);
        });
    }
    let device = DeviceKeypair::generate();
    let session = HushSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        || {},
    )
    .expect("connect");

    let _ = session.pairing_token(); // open window
    let result = session.accept_member("nonexistent-token");
    assert!(!result, "unknown token returns false");
}

/// Pair arriving outside pairing window: on_member_request does not fire.
#[test]
fn pair_outside_window_does_not_fire_callback() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let fired: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let fc = fired.clone();

    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        || {},
    )
    .expect("session A");

    session_a.set_on_member_request(move |_token, _name| {
        *fc.lock().unwrap() += 1;
    });

    // Do NOT open a pairing window — B's Pair message should be discarded.
    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        || {},
    )
    .expect("session B");

    // B sends Pair to A's noise pub directly (no window on A's side).
    // We need a pairing token from A — but A's window is NOT open.
    // Use a fresh device as the "initiator" so B knows where to send.
    let fake_initiator = DeviceKeypair::generate();
    let fake_token = crate::message::pairing_token(
        &fake_initiator.public_key().0,
        &fake_initiator.signing_public_key().0,
    );
    // B tries to join using the fake token — the Pair goes to fake_initiator, not A.
    // This won't fire A's callback. Instead, construct a scenario where B sends to A
    // with no window open: directly use the pairing_token from A but cancel first.
    let a_pairing_token = session_a.pairing_token();
    session_a.cancel_pairing(); // close window before B sends

    let _ = session_b.join_group(&a_pairing_token);
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(
        *fired.lock().unwrap(),
        0,
        "no callback outside pairing window"
    );
}
