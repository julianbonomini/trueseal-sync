use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::HushSession;
use super::make_two_member_manifest;

/// The subscribe handler runs on a background thread inside RelayClient.
/// If the manifest mutex is poisoned, lock().unwrap() panics on that thread,
/// killing it — messages stop arriving silently.
/// After the fix (unwrap_or_else), the handler recovers and keeps delivering.
#[test]
fn subscribe_handler_survives_poisoned_manifest_mutex() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let received: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let rc = received.clone();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        move |_, _| {
            *rc.lock().unwrap() += 1;
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session B");

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    // Poison B's manifest mutex: hold the lock and panic inside catch_unwind.
    let manifest_arc = session_b.manifest.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = manifest_arc.lock().unwrap();
        panic!("intentional poison for test");
    });
    assert!(
        session_b.manifest.is_poisoned(),
        "setup: manifest mutex must be poisoned"
    );

    // A sends a Sync message. B's subscribe handler must survive the poisoned
    // mutex and still deliver the message — not silently kill its thread.
    session_a
        .push_sync(b"hello after poison".to_vec())
        .expect("push");

    wait_for(
        || *received.lock().unwrap() >= 1,
        Duration::from_secs(5),
    );
    assert_eq!(
        *received.lock().unwrap(),
        1,
        "message must be delivered despite poisoned manifest mutex"
    );
}
