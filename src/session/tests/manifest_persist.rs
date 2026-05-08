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
use super::super::HushSession;

/// Pairing A→B with store-backed on_manifest_changed saves the manifest; a
/// fresh session loaded from the same store has the 2-member group.
#[test]
fn manifest_persists_across_session_restart() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // ── Phase 1: pair A and B ────────────────────────────────────────────────
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

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
    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        move |m| {
            let _ = store_a_cb.lock().unwrap().save_group_manifest(m);
        },
        || {},
    )
    .expect("session A");

    // B connects second, persists received manifests.
    let _session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        move |m| {
            let _ = store_b_cb.lock().unwrap().save_group_manifest(m);
        },
        || {},
    )
    .expect("session B");

    // A opens pairing window and admits B.
    let _token = session_a.pairing_token();
    let admitted = session_a.accept_pair(b_noise, b_signing);
    assert!(admitted, "accept_pair must return true when window is open");

    // Give B time to receive and persist the GroupManifest.
    std::thread::sleep(Duration::from_millis(200));

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
    spawn_routing_relay(&relay_kp, pipe_a2_relay, pipe_b2_relay, true);

    let session_a2 = HushSession::connect(
        pipe_a2_client,
        relay_pub,
        DeviceKeypair::from_bytes(a_noise_priv, a_signing_priv).unwrap(),
        |_, _| {},
    )
    .expect("session A2");
    let session_b2 = HushSession::connect(
        pipe_b2_client,
        relay_pub,
        DeviceKeypair::from_bytes(b_noise_priv, b_signing_priv).unwrap(),
        |_, _| {},
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
