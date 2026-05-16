use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use trueseal_noise::{keypair::Keypair, session_xx::accept};

use crate::device::DeviceKeypair;
use crate::envelope::Envelope;
use crate::operation_log::MemLog;
use crate::relay::{frame, parse, MsgType};
use crate::store::{PersistentLog, Store};

use super::super::test_helpers::*;
use super::super::TruesealSession;
use super::make_two_member_manifest;

#[test]
fn push_sync_appends_and_marks_delivered() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _s = accept(pipe_relay, relay_kp2).unwrap();
            // Accept NK push connections and drain them so push_send succeeds.
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
                std::thread::spawn(move || {
                    if let Ok(sess) = trueseal_noise::session_nk::accept(nk_pipe, kp) {
                        if sess.receive().is_ok() {
                            let _ = sess.send(&frame(MsgType::Ack, &[]));
                        }
                    }
                });
            }
        });
    }

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let r_noise = recipient.public_key();
    let r_signing = recipient.signing_public_key();
    let session = TruesealSession::connect_with_log(
        pipe_client,
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        nk.factory(),
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise, d_signing, &d_sk, r_noise, r_signing,
    ));

    session.push_sync(b"hello".to_vec()).expect("push");
    wait_for(
        || {
            session
                .op_log
                .lock()
                .unwrap()
                .undelivered_entries()
                .is_empty()
        },
        Duration::from_secs(5),
    );

    let undelivered = session.op_log.lock().unwrap().undelivered_entries();
    assert!(undelivered.is_empty(), "entry should be delivered");
}

#[test]
fn undelivered_entries_replayed_after_reconnect() {
    use std::sync::atomic::Ordering;
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe1_client, pipe1_relay, _close_relay_reader, close_client_reader) =
        mem_pipe_pair_with_close();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _s = accept(pipe1_relay, relay_kp2).unwrap();
            std::thread::sleep(Duration::from_secs(10));
        });
    }

    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    let received_envs: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received_envs.clone();
    {
        let relay_kp3 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _s = accept(pipe2_relay, relay_kp3).unwrap();
            // Accept NK push connections and record their envelope bodies.
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
                let rx2 = rx.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = trueseal_noise::session_nk::accept(nk_pipe, kp) {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                if body.len() >= 32 {
                                    if let Ok(env) = Envelope::decode(&body[32..]) {
                                        rx2.lock().unwrap().push(env);
                                    }
                                }
                                let _ = sess.send(&frame(MsgType::Ack, &[]));
                            }
                        }
                    }
                });
            }
        });
    }

    let pipe2_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe2_client)));
    let pipe2_slot2 = pipe2_slot.clone();

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let r_noise = recipient.public_key();
    let r_signing = recipient.signing_public_key();
    let session = TruesealSession::connect_with_reconnect(
        pipe1_client,
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        move || {
            pipe2_slot2
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "exhausted".into())
        },
        nk.factory(), // NK push factory
        Some(Duration::from_millis(50)),
        None, // on_connection_changed
    )
    .expect("initial connect");
    session.set_manifest(make_two_member_manifest(
        d_noise, d_signing, &d_sk, r_noise, r_signing,
    ));

    close_client_reader.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(300));

    let _r1 = session.push_sync(b"blob1".to_vec());
    let _r2 = session.push_sync(b"blob2".to_vec());
    let _r3 = session.push_sync(b"blob3".to_vec());

    wait_for(
        || received_envs.lock().unwrap().len() == 3,
        Duration::from_secs(10),
    );

    let envs = received_envs.lock().unwrap();
    assert_eq!(envs.len(), 3, "all 3 blobs replayed");
    assert!(envs[0].sequence < envs[1].sequence);
    assert!(envs[1].sequence < envs[2].sequence);
}

/// push_sync while disconnected returns Ok(()) and queues the entry in the outbox.
/// The blob will be delivered on reconnect — callers must not retry (ADR-0017).
#[test]
fn push_sync_while_disconnected_queues_and_returns_ok() {
    use std::sync::atomic::Ordering;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay, _close_relay, close_client) = mem_pipe_pair_with_close();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let s = accept(pipe_relay, relay_kp2).unwrap();
            loop {
                if s.receive().is_err() {
                    break;
                }
            }
        });
    }

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let r_noise = recipient.public_key();
    let r_signing = recipient.signing_public_key();
    let session = TruesealSession::connect_with_log(
        pipe_client,
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || Err("push factory unused: pushes go offline in this test".into()),
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise, d_signing, &d_sk, r_noise, r_signing,
    ));

    close_client.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(100));

    // Offline send must succeed — blob is durably queued for reconnect.
    let result = session.push_sync(b"orphaned".to_vec());
    assert!(
        result.is_ok(),
        "offline send should return Ok(()) — blob queued"
    );

    // Exactly one outbox entry must exist (one recipient, not duplicated by retry).
    let undelivered = session.op_log.lock().unwrap().undelivered_entries();
    assert_eq!(undelivered.len(), 1, "entry should be queued in outbox");
}

/// End-to-end crash recovery: PersistentLog survives session drop and replays
/// undelivered blobs when a new session connects to the relay.
///
/// Simulates: push offline → process crash (session drop) → reopen same DB →
/// new session connects → outbox replayed → relay receives all blobs.
#[test]
fn outbox_survives_crash_and_replays_on_reconnect() {
    // ── Step 1: first session, push blobs while offline ───────────────────────
    let tmp = tempfile::TempDir::new().expect("tmp dir");
    let store1 = Store::open(tmp.path(), "test").expect("open store");
    let log1 = PersistentLog::new(store1);

    let device = DeviceKeypair::generate();
    let peer = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let p_noise = peer.public_key();
    let p_signing = peer.signing_public_key();
    // Save device bytes for reconstruction after simulated crash.
    let device_noise_priv = device.noise.private();
    let device_signing_priv = device.signing.to_bytes();

    // Set up relay2 upfront — the factory provides it after "crash recovery".
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // Relay2 counts received pushes and signals when all arrive.
    let relay2_received: Arc<(Mutex<u32>, Condvar)> = Arc::new((Mutex::new(0), Condvar::new()));
    let rr = relay2_received.clone();
    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    let (nk_rx2, nk2) = nk_push_channel();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _s = accept(pipe2_relay, relay_kp2).unwrap();
            // Count NK push connections as received pushes.
            while let Ok(nk_pipe) = nk_rx2.recv() {
                let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
                let rr2 = rr.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = trueseal_noise::session_nk::accept(nk_pipe, kp) {
                        if sess.receive().is_ok() {
                            let _ = sess.send(&frame(MsgType::Ack, &[]));
                            let (lock, cvar) = &*rr2;
                            *lock.lock().unwrap() += 1;
                            cvar.notify_all();
                        }
                    }
                });
            }
        });
    }

    // Session 1: starts offline (connect_background), pushes 2 blobs to outbox.
    let pipe2_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe2_client)));
    {
        let pipe2_slot2 = pipe2_slot.clone();
        let device1 = DeviceKeypair::from_bytes(device_noise_priv, device_signing_priv)
            .expect("reconstruct device1");
        let session1 = TruesealSession::connect_background(
            relay_pub,
            device1,
            |_, _, _| {},
            Box::new(log1),
            || {},
            |_| {},
            || {},
            move || {
                pipe2_slot2
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            },
            nk2.factory(), // NK push factory: zombie reconnect loop uses this
            Some(Duration::from_millis(50)),
            None,
        )
        .expect("session1");

        session1.set_manifest(make_two_member_manifest(
            d_noise, d_signing, &d_sk, p_noise, p_signing,
        ));

        // Push while offline — queued to PersistentLog.
        session1.push_sync(b"blob-1".to_vec()).expect("push 1");
        session1.push_sync(b"blob-2".to_vec()).expect("push 2");

        let undelivered = session1.op_log.lock().unwrap().undelivered_entries();
        assert_eq!(undelivered.len(), 2, "2 entries in outbox before crash");

        // session1 drops here — simulates process crash.
    }

    // ── Step 2: reopen DB, verify entries persisted ───────────────────────────
    let store2 = Store::open(tmp.path(), "test").expect("reopen store");
    let log2 = PersistentLog::new(store2);
    {
        use crate::operation_log::OperationLog;
        let entries = log2.undelivered_entries();
        assert_eq!(entries.len(), 2, "entries persist across session drop");
    }

    // ── Step 3: new session with same DB, reconnect loop replays outbox ───────
    let device2 = DeviceKeypair::from_bytes(device_noise_priv, device_signing_priv)
        .expect("reconstruct device");
    let session2 = TruesealSession::connect_background(
        relay_pub,
        device2,
        |_, _, _| {},
        Box::new(log2),
        || {},
        |_| {},
        || {},
        move || {
            pipe2_slot
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "exhausted".to_string())
        },
        nk2.factory(), // NK push factory for outbox replay
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session2");

    // Wait until outbox is empty — both entries marked delivered after replay.
    // This is the correct signal: outbox drain happens in the reconnect thread
    // after push_send receives the Ack, which is strictly after the relay
    // increments relay2_received. Waiting on relay count first would race.
    wait_for(
        || {
            session2
                .op_log
                .lock()
                .unwrap()
                .undelivered_entries()
                .is_empty()
        },
        Duration::from_secs(5),
    );
    // Verify the relay also received both replayed blobs.
    let (lock, _) = &*relay2_received;
    assert_eq!(*lock.lock().unwrap(), 2, "relay received exactly 2 pushes");

    // Outbox must be empty after replay.
    let undelivered = session2.op_log.lock().unwrap().undelivered_entries();
    assert!(undelivered.is_empty(), "outbox empty after replay");
}

/// Per ADR-0011: sequence counter must not reuse numbers after restart.
/// Session 2 (same PersistentLog DB) must start at max_sequence + 1, not 0.
#[test]
fn sequence_counter_not_reused_after_restart() {
    let tmp = tempfile::TempDir::new().expect("tmp dir");

    let device_noise_priv;
    let device_signing_priv;
    let p_noise;
    let p_signing;
    let last_seq;

    // ── Session 1: push 3 blobs offline, record max sequence ─────────────────
    {
        let store1 = Store::open(tmp.path(), "test").expect("store");
        let log1 = PersistentLog::new(store1);

        let device = DeviceKeypair::generate();
        let peer = DeviceKeypair::generate();
        device_noise_priv = device.noise.private();
        device_signing_priv = device.signing.to_bytes();
        let d_noise = device.public_key();
        let d_signing = device.signing_public_key();
        let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
        p_noise = peer.public_key();
        p_signing = peer.signing_public_key();

        // Use connect_background (offline) to avoid needing a relay.
        let session1: TruesealSession<MemPipeSimple> = TruesealSession::connect_background(
            // Dummy relay pub — session never connects.
            crate::keys::NoisePublicKey([0u8; 32]),
            device,
            |_, _, _| {},
            Box::new(log1),
            || {},
            |_| {},
            || {},
            || Err("no relay".to_string()),
            || Err("push factory unused: offline test".into()),
            Some(Duration::from_millis(50)),
            None,
        )
        .expect("session1");

        session1.set_manifest(make_two_member_manifest(
            d_noise, d_signing, &d_sk, p_noise, p_signing,
        ));

        // Push 3 blobs offline → sequences 0, 1, 2.
        session1.push_sync(b"a".to_vec()).expect("push a");
        session1.push_sync(b"b".to_vec()).expect("push b");
        session1.push_sync(b"c".to_vec()).expect("push c");

        let entries = session1.op_log.lock().unwrap().undelivered_entries();
        assert_eq!(entries.len(), 3, "3 offline entries");
        last_seq = entries
            .iter()
            .map(|e| e.sequence)
            .max()
            .expect("has entries");
        assert_eq!(last_seq, 2, "max sequence is 2");
        // session1 drops here.
    }

    // ── Session 2: same DB, first push must use sequence last_seq + 1 ────────
    {
        let store2 = Store::open(tmp.path(), "test").expect("reopen store");
        let log2 = PersistentLog::new(store2);
        let d_sk2 = SigningKey::from_bytes(&device_signing_priv);

        let device2 =
            DeviceKeypair::from_bytes(device_noise_priv, device_signing_priv).expect("reconstruct");
        let d_noise2 = device2.public_key();
        let d_signing2 = device2.signing_public_key();

        let session2: TruesealSession<MemPipeSimple> = TruesealSession::connect_background(
            crate::keys::NoisePublicKey([0u8; 32]),
            device2,
            |_, _, _| {},
            Box::new(log2),
            || {},
            |_| {},
            || {},
            || Err("no relay".to_string()),
            || Err("push factory unused: offline test".into()),
            Some(Duration::from_millis(50)),
            None,
        )
        .expect("session2");

        session2.set_manifest(make_two_member_manifest(
            d_noise2, d_signing2, &d_sk2, p_noise, p_signing,
        ));

        // Push one blob offline — must use sequence last_seq + 1 = 3.
        session2.push_sync(b"d".to_vec()).expect("push d");

        let entries = session2.op_log.lock().unwrap().undelivered_entries();
        // 4 entries total: 3 from session1 + 1 from session2.
        assert_eq!(entries.len(), 4, "4 entries total");
        let new_seq = entries
            .iter()
            .map(|e| e.sequence)
            .max()
            .expect("has entries");
        assert_eq!(
            new_seq,
            last_seq + 1,
            "session2 first push uses sequence max+1, not 0"
        );
        // No sequence is shared between sessions.
        let seqs: std::collections::HashSet<u64> = entries.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs.len(), 4, "all 4 sequence numbers are distinct");
    }
}
