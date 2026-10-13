use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;
use crate::store::Store;

use super::super::test_helpers::*;
use super::super::{SessionError, TruesealSession};
use super::make_two_member_manifest;

/// ADR-0029 initiator flow: destroy_group() enters Destroying (no Sync,
/// no callback yet); when the Relay has accepted every queued Revoke the
/// device wipes, rotates and fires on_group_destroyed exactly once.
#[test]
fn destroy_group_completes_after_relay_accepts_revokes() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    {
        let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            // Hold the XX session OPEN for the relay's life: dropping it
            // EOFs the client's receive loop, and the pump only sends while
            // connected — under slow CI the disconnect could win the race
            // against the Revoke push and the Destroy would never complete.
            let Ok(_sess) = crate::version::testutil::xx_accept_after_prefix(pipe_relay, kp) else {
                return;
            };
            while let Ok(p) = nk_rx.recv() {
                let kp2 =
                    trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(p, kp2) {
                        if sess.receive().is_ok() {
                            let _ =
                                sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                        }
                    }
                });
            }
        });
    }
    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let peer = DeviceKeypair::generate();
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let session = TruesealSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        nk.factory(),
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        noise,
        signing,
        &sk,
        peer.public_key(),
        peer.signing_public_key(),
    ));

    session.destroy_group().expect("member can destroy");

    // Destroying: no Sync sends, the callback has NOT fired (the Relay
    // hasn't accepted yet at this synchronous point).
    assert_eq!(
        session.group_status(),
        super::super::GroupStatus::Destroying,
        "destroy_group enters the Destroying state"
    );
    assert!(
        matches!(
            session.push_sync(b"nope".to_vec()),
            Err(SessionError::GroupDestroyed)
        ),
        "no Sync is sent while Destroying"
    );

    // The pump pushes the Revoke, the relay Acks it, the Destroy
    // completes: wipe + rotate + exactly one callback.
    wait_for(|| *destroyed.lock().unwrap() == 1, Duration::from_secs(20));
    assert_eq!(
        session.group_status(),
        super::super::GroupStatus::NotJoined,
        "a completed Destroy ends in notJoined"
    );
    assert!(
        matches!(
            session.push_sync(b"still nope".to_vec()),
            Err(SessionError::NotInGroup)
        ),
        "after the wipe the device is simply not in a group (the object stays usable)"
    );
}

/// destroy_group() fires on_group_destroyed on ALL members (A destroys, B fires).
#[test]
fn destroy_group_fires_on_group_destroyed_on_all_members() {
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

    let b_destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let bdc = b_destroyed.clone();

    let session_a = TruesealSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        nk.factory(),
    )
    .expect("session A");

    let session_b = TruesealSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        move || {
            *bdc.lock().unwrap() += 1;
        },
        nk.factory(),
    )
    .expect("session B");

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    session_a.destroy_group().expect("destroy");
    wait_for(
        || *b_destroyed.lock().unwrap() >= 1,
        Duration::from_secs(20),
    );

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
    let (nk_rx, nk) = nk_push_channel();
    {
        let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            // Hold the XX session OPEN for the relay's life: dropping it
            // EOFs the client's receive loop, and the pump only sends while
            // connected — under slow CI the disconnect could win the race
            // against the Revoke push and the Destroy would never complete.
            let Ok(_sess) = crate::version::testutil::xx_accept_after_prefix(pipe_relay, kp) else {
                return;
            };
            while let Ok(p) = nk_rx.recv() {
                let kp2 =
                    trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(p, kp2) {
                        if sess.receive().is_ok() {
                            let _ =
                                sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                        }
                    }
                });
            }
        });
    }
    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let dummy = DeviceKeypair::generate();

    let session = TruesealSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        nk.factory(),
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

    session.destroy_group().expect("destroy");
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

/// ADR-0029 FFI wiring: on Destroy COMPLETION the identity-rotation
/// callback wipes the store and persists the fresh keypair (the FFI maps
/// that to its rotate_store); on_group_destroyed is a pure notification —
/// wiping there would delete the fresh identity just persisted.
#[test]
fn destroy_completion_wipes_store_and_persists_fresh_identity() {
    let dir = tempfile::TempDir::new().unwrap();
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    {
        let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            // Hold the XX session OPEN for the relay's life: dropping it
            // EOFs the client's receive loop, and the pump only sends while
            // connected — under slow CI the disconnect could win the race
            // against the Revoke push and the Destroy would never complete.
            let Ok(_sess) = crate::version::testutil::xx_accept_after_prefix(pipe_relay, kp) else {
                return;
            };
            while let Ok(p) = nk_rx.recv() {
                let kp2 =
                    trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(p, kp2) {
                        if sess.receive().is_ok() {
                            let _ =
                                sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                        }
                    }
                });
            }
        });
    }

    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let dummy = DeviceKeypair::generate();

    // Simulate what the FFI does: a rotate_store wiped and re-keyed inside
    // on_identity_rotated; a check handle to observe it.
    let rotate_store = Store::open(dir.path(), "ns").expect("open rotate store");
    let check_store = Store::open(dir.path(), "ns").expect("open check store");

    let manifest = make_two_member_manifest(
        noise,
        signing,
        &sk,
        dummy.public_key(),
        dummy.signing_public_key(),
    );
    rotate_store
        .save_group_manifest(&manifest)
        .expect("pre-save manifest");

    let rotate_store = Arc::new(Mutex::new(rotate_store));
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();

    let session = TruesealSession::connect_full_rotating(
        pipe_client,
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        move |fresh: DeviceKeypair, _reason: crate::session::ExitReason| {
            let store = rotate_store.lock().unwrap();
            let _ = store.wipe();
            let _ = store.save_keypair(&fresh);
        },
        nk.factory(),
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

    session.destroy_group().expect("member can destroy");

    // Completion: the relay Acks the Revoke, the wipe + rotation runs, the
    // callback fires once.
    wait_for(|| *destroyed.lock().unwrap() == 1, Duration::from_secs(20));
    assert!(
        check_store.load_group_manifest().unwrap().is_none(),
        "manifest cleared after the Destroy completed"
    );
    let fresh = check_store
        .load_keypair()
        .unwrap()
        .expect("fresh keypair persisted after the wipe");
    assert_ne!(
        fresh.public_key(),
        noise,
        "the persisted identity is the rotated one, not the old device key"
    );
}

/// ADR-0029: destroy_group() drops pending Sync sends WITHOUT reporting
/// them, queues the Revoke, and stays connected — the Revoke IS replayed
/// after reconnect (the old "destroy stops the outbox" behavior is
/// inverted: durability is the whole point). Completion (Relay accepts
/// the Revoke) then wipes and fires on_group_destroyed.
#[test]
fn destroy_group_drops_sync_sends_and_replays_revoke_after_reconnect() {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // Relay: holds the XX Receive Session; counts and Acks pushes on the
    // NK push side (ADR-0018).
    let relay_received: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let rr = relay_received.clone();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    {
        let relay_kp2 =
            trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            // Hold the XX session open — dropping it EOFs the client's
            // receive loop and the reconnect loop would exhaust the one
            // pipe this test provides.
            let Ok(_sess) = crate::version::testutil::xx_accept_after_prefix(pipe_relay, relay_kp2)
            else {
                return;
            };
            while let Ok(p) = nk_rx.recv() {
                let kp =
                    trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
                let rr2 = rr.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(p, kp) {
                        if sess.receive().is_ok() {
                            *rr2.lock().unwrap() += 1;
                            let _ =
                                sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                        }
                    }
                });
            }
        });
    }

    // Pipe slot: only given to factory after destroy, but loop exits before calling it.
    let pipe_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_client)));
    let pipe_slot2 = pipe_slot.clone();

    let destroyed_count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed_count.clone();

    let device = DeviceKeypair::generate();
    let peer = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = ed25519_dalek::SigningKey::from_bytes(&device.signing.to_bytes());
    let p_noise = peer.public_key();
    let p_signing = peer.signing_public_key();

    // Session starts offline; factory initially fails so it never connects.
    let should_connect = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sc = should_connect.clone();
    let session: TruesealSession<MemPipe> = TruesealSession::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        move || {
            if sc.load(std::sync::atomic::Ordering::Acquire) {
                pipe_slot2
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            } else {
                Err("not yet".to_string())
            }
        },
        nk.factory(),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    session.set_manifest(make_two_member_manifest(
        d_noise, d_signing, &d_sk, p_noise, p_signing,
    ));

    // Push 2 blobs while offline.
    session.push_sync(b"blob-1".to_vec()).expect("push 1");
    session.push_sync(b"blob-2".to_vec()).expect("push 2");
    assert_eq!(
        session.op_log.lock().unwrap().undelivered_entries().len(),
        2,
        "2 outbox entries"
    );

    // Destroy BEFORE allowing reconnect: the two Sync sends drop
    // (unreported), one Revoke is queued, the device is Destroying and
    // nothing has fired — the Relay is unreachable, so the Destroy holds.
    session.destroy_group().expect("member can destroy");
    assert_eq!(
        session.group_status(),
        super::super::GroupStatus::Destroying,
        "Destroying holds while the Relay is unreachable (no timeout)"
    );
    {
        let log = session.op_log.lock().unwrap();
        let entries = log.undelivered_entries();
        assert_eq!(entries.len(), 1, "only the queued Revoke survives");
        assert_eq!(
            entries[0].kind,
            crate::operation_log::OutboxKind::Control,
            "the survivor is the control-plane Revoke"
        );
    }
    assert_eq!(
        *destroyed_count.lock().unwrap(),
        0,
        "on_group_destroyed fires only at completion, not at call time"
    );
    assert!(
        matches!(
            session.push_sync(b"after-destroy".to_vec()),
            Err(super::super::SessionError::GroupDestroyed)
        ),
        "no Sync while Destroying"
    );

    // Reconnect: the pump replays the Revoke, the relay receives exactly
    // one push and Acks it — completion wipes and fires once.
    should_connect.store(true, std::sync::atomic::Ordering::Release);
    wait_for(
        || *relay_received.lock().unwrap() >= 1,
        Duration::from_secs(20),
    );
    assert_eq!(
        *relay_received.lock().unwrap(),
        1,
        "exactly the Revoke was replayed — the dropped Sync sends never leave"
    );
    wait_for(
        || *destroyed_count.lock().unwrap() == 1,
        Duration::from_secs(20),
    );
    assert_eq!(
        session.group_status(),
        super::super::GroupStatus::NotJoined,
        "the completed Destroy ends in notJoined"
    );
}
