use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;
use crate::store::Store;

use super::super::test_helpers::*;
use super::super::{HushSession, SessionError};
use super::make_two_member_manifest;

/// destroy_group() fires on_group_destroyed on the initiating device.
#[test]
fn destroy_group_fires_on_group_destroyed_on_initiator() {
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
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let session = HushSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
    )
    .expect("connect");

    session.destroy_group();
    assert_eq!(
        *destroyed.lock().unwrap(),
        1,
        "on_group_destroyed must fire once"
    );
}

/// destroy_group() fires on_group_destroyed on ALL members (A destroys, B fires).
#[test]
fn destroy_group_fires_on_group_destroyed_on_all_members() {
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

    let b_destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let bdc = b_destroyed.clone();

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

    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        move || {
            *bdc.lock().unwrap() += 1;
        },
    )
    .expect("session B");

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    session_a.destroy_group();
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(
        *b_destroyed.lock().unwrap(),
        1,
        "B's on_group_destroyed must fire once"
    );
}

/// After destroy_group(), push_sync returns GroupDestroyed.
#[test]
fn push_sync_after_destroy_returns_group_destroyed() {
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
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let dummy = DeviceKeypair::generate();

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
    let v1 = make_two_member_manifest(
        noise,
        signing,
        &sk,
        dummy.public_key(),
        dummy.signing_public_key(),
    );
    session.set_manifest(v1);

    session.destroy_group();
    let result = session.push_sync(b"should fail".to_vec());
    assert!(
        matches!(result, Err(SessionError::GroupDestroyed)),
        "push_sync after destroy must return GroupDestroyed, got: {result:?}"
    );
}

/// Store::wipe() clears keypair and manifest — both return None after wipe.
#[test]
fn store_wipe_clears_keypair_and_manifest() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path(), "wipe_test").expect("open");

    let kp = DeviceKeypair::generate();
    store.save_keypair(&kp).expect("save keypair");

    let dummy = DeviceKeypair::generate();
    let sk = SigningKey::from_bytes(&kp.signing.to_bytes());
    let manifest = make_two_member_manifest(
        kp.public_key(),
        kp.signing_public_key(),
        &sk,
        dummy.public_key(),
        dummy.signing_public_key(),
    );
    store.save_group_manifest(&manifest).expect("save manifest");

    // Confirm both are persisted.
    assert!(
        store.load_keypair().unwrap().is_some(),
        "keypair before wipe"
    );
    assert!(
        store.load_group_manifest().unwrap().is_some(),
        "manifest before wipe"
    );

    store.wipe().expect("wipe");

    assert!(
        store.load_keypair().unwrap().is_none(),
        "keypair cleared after wipe"
    );
    assert!(
        store.load_group_manifest().unwrap().is_none(),
        "manifest cleared after wipe"
    );
}

/// on_group_destroyed wires wipe: after destroy_group fires the callback,
/// the store is wiped and load_group_manifest returns None.
#[test]
fn on_group_destroyed_callback_wipes_store() {
    let dir = tempfile::TempDir::new().unwrap();
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
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let dummy = DeviceKeypair::generate();

    // Simulate what the FFI does: open a wipe_store, pass its wipe in the closure.
    let wipe_store = Store::open(dir.path(), "ns").expect("open wipe store");
    let check_store = Store::open(dir.path(), "ns").expect("open check store");

    // Pre-populate the store with a keypair and manifest.
    let kp_for_store = DeviceKeypair::generate();
    wipe_store
        .save_keypair(&kp_for_store)
        .expect("pre-save keypair");
    let manifest = make_two_member_manifest(
        noise,
        signing,
        &sk,
        dummy.public_key(),
        dummy.signing_public_key(),
    );
    wipe_store
        .save_group_manifest(&manifest)
        .expect("pre-save manifest");

    let wipe_store = Arc::new(Mutex::new(wipe_store));

    let session = HushSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        || {},
        |_| {},
        move || {
            let _ = wipe_store.lock().unwrap().wipe();
        },
    )
    .expect("connect");

    let v1 = make_two_member_manifest(
        noise,
        signing,
        &sk,
        dummy.public_key(),
        dummy.signing_public_key(),
    );
    session.set_manifest(v1);

    session.destroy_group();

    // The wipe_store's wipe() should have cleared both tables.
    assert!(
        check_store.load_keypair().unwrap().is_none(),
        "keypair cleared after destroy_group"
    );
    assert!(
        check_store.load_group_manifest().unwrap().is_none(),
        "manifest cleared after destroy_group"
    );
}
