use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::TruesealSession;
use super::make_two_member_manifest;

// ── #65 ───────────────────────────────────────────────────────────────────────

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
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay, nk_rx);

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
        TruesealSession::connect(pipe_a_client, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("session A");
    let session_b = TruesealSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        move |_, _, _| {
            *rc.lock().unwrap() += 1;
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        nk.factory(),
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

// ── #67 ───────────────────────────────────────────────────────────────────────

/// push_sync must not panic when the manifest mutex is poisoned.
/// It should return Err(NotInGroup) — not crash the host app.
#[test]
fn push_sync_survives_poisoned_manifest_mutex() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_single_relay(&relay_kp, pipe_relay, nk_rx);

    let device = DeviceKeypair::generate();
    let session =
        TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, nk.factory()).expect("session");

    let manifest_arc = session.manifest.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = manifest_arc.lock().unwrap();
        panic!("intentional poison");
    });
    assert!(session.manifest.is_poisoned(), "setup: manifest must be poisoned");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| session.push_sync(b"hello".to_vec())));
    assert!(
        result.is_ok(),
        "push_sync must not panic with poisoned manifest"
    );
}

/// members() must not panic when the manifest mutex is poisoned.
#[test]
fn members_survives_poisoned_manifest_mutex() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_single_relay(&relay_kp, pipe_relay, nk_rx);

    let device = DeviceKeypair::generate();
    let session =
        TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, nk.factory()).expect("session");

    let manifest_arc = session.manifest.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = manifest_arc.lock().unwrap();
        panic!("intentional poison");
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| session.members()));
    assert!(result.is_ok(), "members() must not panic with poisoned manifest");
    assert_eq!(result.unwrap(), vec![], "poisoned None manifest → empty list");
}

// ── #68 ───────────────────────────────────────────────────────────────────────

/// on_manifest_changed must NOT be called while the manifest lock is held.
/// If it is, a panic inside the callback (e.g. SQLite write fails) poisons
/// the manifest mutex — making the session permanently broken.
/// After the fix, the lock is dropped before the callback fires.
#[test]
fn on_manifest_changed_panic_does_not_poison_manifest_mutex() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let session_a =
        TruesealSession::connect(pipe_a_client, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("session A");
    // B's on_manifest_changed panics — simulates a failing SQLite write.
    let session_b = TruesealSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| panic!("simulated SQLite write failure"),
        || {},
        nk.factory(),
    )
    .expect("session B");

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    // A pushes a v2 manifest to B — B’s on_manifest_changed will panic.
    use crate::manifest::{GroupManifest, ManifestMember};
    use crate::message::Message;
    let group_id = session_a
        .manifest
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .unwrap()
        .group_id;
    let v2 = GroupManifest::new(
        group_id,
        2,
        vec![
            ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
            ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ],
        &a_sk,
    );
    session_a
        .push_message(&Message::GroupManifest { manifest: v2 }, b_noise)
        .ok();

    // Wait for the message to arrive and the callback to fire (and panic).
    std::thread::sleep(Duration::from_millis(300));

    // B’s manifest mutex must NOT be poisoned — the lock must be released
    // before the callback fires.
    assert!(
        !session_b.manifest.is_poisoned(),
        "manifest mutex must not be poisoned after on_manifest_changed panic"
    );
}
