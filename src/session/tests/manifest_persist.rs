/// Integration tests for issue #35 — GroupManifest persistence.
///
/// Verifies that:
/// 1. `on_manifest_changed` fires on `accept_pair` and writes to a `Store`.
/// 2. A new session can restore the persisted manifest from the same store
///    and immediately has the correct 2-member group without re-pairing.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;
use crate::store::Store;

use super::super::test_helpers::*;
use super::super::TruesealSession;

/// Pairing A→B with store-backed on_manifest_changed saves the manifest; a
/// fresh session loaded from the same store has the 2-member group.
#[test]
fn manifest_persists_across_session_restart() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // ── Phase 1: pair A and B ────────────────────────────────────────────────
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx1, nk1) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, nk_rx1, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    // Save private bytes so we can reconstruct in Phase 3 (DeviceKeypair is not Clone).
    let a_noise_priv = device_a.noise.private();
    let a_signing_priv = device_a.signing.to_bytes();
    let b_noise_priv = device_b.noise.private();
    let b_signing_priv = device_b.signing.to_bytes();

    // Store for A — persist manifest on change.
    let dir_a = tempfile::TempDir::new().unwrap();
    let store_a = Arc::new(Mutex::new(Store::open(dir_a.path(), "a").expect("store A")));
    let store_a_cb = store_a.clone();

    // Store for B — persist manifest on change.
    let dir_b = tempfile::TempDir::new().unwrap();
    let store_b = Arc::new(Mutex::new(Store::open(dir_b.path(), "b").expect("store B")));
    let store_b_cb = store_b.clone();

    // A connects first (relay accepts pipe_a_relay first).
    let session_a = TruesealSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |m| {
            let _ = store_a_cb.lock().unwrap().save_group_manifest(m);
        },
        || {},
        nk1.factory(),
    )
    .expect("session A");

    // B connects second, persists received manifests.
    let _session_b = TruesealSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |m| {
            let _ = store_b_cb.lock().unwrap().save_group_manifest(m);
        },
        || {},
        nk1.factory(),
    )
    .expect("session B");

    // A opens pairing window and admits B.
    let _token = session_a.pairing_token();
    let admitted = session_a.accept_pair(b_noise, b_signing);
    assert!(admitted, "accept_pair must return true when window is open");

    // Wait until B has received and persisted the GroupManifest.
    wait_for(|| store_b.lock().unwrap().load_group_manifest().ok().flatten().is_some(), Duration::from_secs(5));

    // ── Phase 2: verify stores have the manifest ─────────────────────────────
    let a_saved = store_a
        .lock()
        .unwrap()
        .load_group_manifest()
        .expect("store A load")
        .expect("A: manifest should be saved");
    assert_eq!(a_saved.members.len(), 2, "A: 2 members persisted");

    let b_saved = store_b
        .lock()
        .unwrap()
        .load_group_manifest()
        .expect("store B load")
        .expect("B: manifest should be saved");
    assert_eq!(b_saved.members.len(), 2, "B: 2 members persisted");

    // Verify both stores agree on the group_id and version.
    assert_eq!(a_saved.group_id, b_saved.group_id, "same group_id");
    assert_eq!(a_saved.version, b_saved.version, "same version");

    // ── Phase 3: drop old sessions, create new sessions, restore manifests ───
    drop(session_a);
    drop(_session_b);

    // New relay for the restored sessions.
    let (pipe_a2_client, pipe_a2_relay) = mem_pipe_pair();
    let (pipe_b2_client, pipe_b2_relay) = mem_pipe_pair();
    let (nk_rx2, nk2) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_a2_relay, pipe_b2_relay, nk_rx2, true);

    let session_a2 = TruesealSession::connect(
        pipe_a2_client,
        relay_pub,
        DeviceKeypair::from_bytes(a_noise_priv, a_signing_priv).unwrap(),
        |_, _, _| {},
        nk2.factory(),
    )
    .expect("session A2");
    let session_b2 = TruesealSession::connect(
        pipe_b2_client,
        relay_pub,
        DeviceKeypair::from_bytes(b_noise_priv, b_signing_priv).unwrap(),
        |_, _, _| {},
        nk2.factory(),
    )
    .expect("session B2");

    // Restore manifests from store — simulating what ffi.rs::create does.
    let restored_a = store_a
        .lock()
        .unwrap()
        .load_group_manifest()
        .expect("store A2 load")
        .expect("A2: manifest should still exist");
    session_a2.set_manifest(restored_a);

    let restored_b = store_b
        .lock()
        .unwrap()
        .load_group_manifest()
        .expect("store B2 load")
        .expect("B2: manifest should still exist");
    session_b2.set_manifest(restored_b);

    // Both sessions should now have a 2-member manifest without re-pairing.
    let a2_m = session_a2.manifest.lock().unwrap();
    assert_eq!(
        a2_m.as_ref().unwrap().members.len(),
        2,
        "A2: 2 members after restore"
    );
    let b2_m = session_b2.manifest.lock().unwrap();
    assert_eq!(
        b2_m.as_ref().unwrap().members.len(),
        2,
        "B2: 2 members after restore"
    );
    assert_eq!(
        a2_m.as_ref().unwrap().group_id,
        b2_m.as_ref().unwrap().group_id,
        "restored sessions share group_id"
    );
}

/// Mirrors the FFI flow: connect_background → load manifest from store →
/// set_manifest → reconnect → push_sync succeeds without re-pairing.
///
/// The key difference from `manifest_persists_across_session_restart`:
/// A2 is created via `connect_background` (starts offline), manifest is
/// restored from the store BEFORE any relay connection is made, then A2
/// connects and can immediately push to B.
#[test]
fn manifest_restore_via_connect_background() {
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use crate::operation_log::MemLog;
    use crate::store::PersistentLog;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // ── Phase 1: pair A and B, persist manifest ───────────────────────────────
    let (pipe_a1_client, pipe_a1_relay) = mem_pipe_pair();
    let (pipe_b1_client, pipe_b1_relay) = mem_pipe_pair();
    let (nk_rx1, nk1) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_a1_relay, pipe_b1_relay, nk_rx1, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise_priv = device_a.noise.private();
    let a_signing_priv = device_a.signing.to_bytes();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let dir_a = tempfile::TempDir::new().unwrap();
    let store_a = Arc::new(Mutex::new(Store::open(dir_a.path(), "a").expect("store A")));
    let store_a_cb = store_a.clone();

    let session_a = TruesealSession::connect_full(
        pipe_a1_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |m| { let _ = store_a_cb.lock().unwrap().save_group_manifest(m); },
        || {},
        nk1.factory(),
    )
    .expect("session A");

    let _session_b1 = TruesealSession::connect(pipe_b1_client, relay_pub,
        DeviceKeypair::from_bytes(
            device_b.noise.private(), device_b.signing.to_bytes()
        ).unwrap(),
        |_, _, _| {},
        nk1.factory(),
    ).expect("session B1");

    let _token = session_a.pairing_token();
    assert!(session_a.accept_pair(b_noise, b_signing), "accept_pair");
    wait_for(|| store_a.lock().unwrap().load_group_manifest().ok().flatten().is_some(), Duration::from_secs(5));

    let a_saved = store_a.lock().unwrap()
        .load_group_manifest().expect("load").expect("saved");
    assert_eq!(a_saved.members.len(), 2, "manifest saved");
    drop(session_a);
    drop(_session_b1);

    // ── Phase 2: A2 via connect_background, manifest from store ──────────────
    let (pipe_a2_client, pipe_a2_relay) = mem_pipe_pair();
    let (pipe_b2_client, pipe_b2_relay) = mem_pipe_pair();
    // A2 connects via reconnect factory (async); B2 connects synchronously.
    // Use parallel relay so accept order doesn't matter.
    let (nk_rx2, nk2) = nk_push_channel();
    spawn_bidirectional_relay_parallel(&relay_kp, pipe_a2_relay, pipe_b2_relay, nk_rx2);

    // Signal: B2 received a message.
    let b2_received: Arc<(Mutex<u32>, Condvar)> = Arc::new((Mutex::new(0), Condvar::new()));
    let br = b2_received.clone();

    let session_b2 = TruesealSession::connect(
        pipe_b2_client, relay_pub,
        DeviceKeypair::from_bytes(device_b.noise.private(), device_b.signing.to_bytes()).unwrap(),
        move |_, _, _| {
            let (lock, cvar) = &*br;
            *lock.lock().unwrap() += 1;
            cvar.notify_all();
        },
        nk2.factory(),
    ).expect("session B2");

    // Store the B2 device private bytes to avoid Clone issue.
    let b_noise_priv = device_b.noise.private();
    let b_signing_priv_bytes = device_b.signing.to_bytes();

    // Restore B2's manifest from the pairing so it can receive from A2.
    // (B2 didn't persist its manifest in phase 1; reconstruct from A's.)
    // A's manifest contains B — B's manifest also has 2 members.
    {
        use ed25519_dalek::SigningKey;
        use crate::manifest::{GroupManifest, ManifestMember};
        let loaded = store_a.lock().unwrap()
            .load_group_manifest().expect("load").expect("manifest");
        session_b2.set_manifest(loaded);
    }

    // A2 starts offline (connect_background), manifest restored before connection.
    let pipe_a2_slot: Arc<Mutex<Option<MemPipeSimple>>> =
        Arc::new(Mutex::new(Some(pipe_a2_client)));
    let pipe_a2_slot2 = pipe_a2_slot.clone();
    let store_a2_cb = store_a.clone();
    let store_a3 = store_a.clone();

    let session_a2: TruesealSession<MemPipeSimple> = TruesealSession::connect_background(
        relay_pub,
        DeviceKeypair::from_bytes(a_noise_priv, a_signing_priv).expect("reconstruct A"),
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |m| { let _ = store_a2_cb.lock().unwrap().save_group_manifest(m); },
        || {},
        move || {
            pipe_a2_slot2.lock().unwrap().take()
                .ok_or_else(|| "exhausted".to_string())
        },
        nk2.factory(), // NK push factory (ADR-0018)
        Some(Duration::from_millis(50)),
        None,
    ).expect("session A2");

    // Restore manifest from store BEFORE any relay connection — this is the FFI flow.
    let restored = store_a3.lock().unwrap()
        .load_group_manifest().expect("load").expect("manifest for A2");
    assert_eq!(restored.members.len(), 2, "A2 manifest has 2 members before connect");
    session_a2.set_manifest(restored);

    // Wait for A2 to reconnect via the factory.
    std::thread::sleep(Duration::from_millis(300));

    // A2 pushes to the group — B2 must receive it.
    session_a2.push_sync(b"restored-push".to_vec()).expect("push_sync");

    let (lock, cvar) = &*b2_received;
    let result = cvar
        .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |n| *n == 0)
        .unwrap();
    assert!(!result.1.timed_out(), "B2 must receive A2's push within 5s");
}
