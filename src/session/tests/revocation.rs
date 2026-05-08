use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hush_noise::{keypair::Keypair, session_xx::accept};

use crate::device::DeviceKeypair;
use crate::message::Message;
use crate::operation_log::MemLog;
use crate::relay::{frame, parse, MsgType};

use super::super::test_helpers::*;
use super::super::{HushSession, SessionError};
use super::make_two_member_manifest;

/// Regression: after B reconnects, A's destroy_group must still fire B's on_group_destroyed.
#[test]
fn post_reconnect_destroy_fires_on_group_destroyed() {
    use std::sync::atomic::Ordering;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a1_client, pipe_a1_relay, _close_a1_relay, close_a1_client) =
        mem_pipe_pair_with_close();
    let (pipe_b1_client, pipe_b1_relay, _close_b1_relay, close_b1_client) =
        mem_pipe_pair_with_close();
    // Relay 1: initial connection (NK push unused here; pushes happen after reconnect via relay2).
    let (nk_rx1, _nk1) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pipe_a1_relay, pipe_b1_relay, nk_rx1);

    let (pipe_a2_client, pipe_a2_relay) = mem_pipe_pair();
    let (pipe_b2_client, pipe_b2_relay) = mem_pipe_pair();
    let (nk_rx2, nk2) = nk_push_channel();
    spawn_bidirectional_relay_parallel(&relay_kp, pipe_a2_relay, pipe_b2_relay, nk_rx2);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());

    // Condvar: fires when A reconnects via pipe2.
    let a_reconnected = Arc::new((Mutex::new(false), Condvar::new()));
    let a_reconnected2 = a_reconnected.clone();

    // Condvar: fires when B reconnects via pipe2.
    let b_reconnected = Arc::new((Mutex::new(false), Condvar::new()));
    let b_reconnected2 = b_reconnected.clone();

    // Condvar: fires when B's on_group_destroyed is called.
    let b_destroyed: Arc<(Mutex<u32>, Condvar)> = Arc::new((Mutex::new(0), Condvar::new()));
    let bd = b_destroyed.clone();

    let pipe_a2_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_a2_client)));
    let pipe_a2_slot2 = pipe_a2_slot.clone();
    let session_a = Arc::new(
        HushSession::connect_with_reconnect(
            pipe_a1_client,
            relay_pub,
            device_a,
            |_, _| {},
            Box::new(MemLog::new()),
            || {},
            |_| {},
            || {},
            move || {
                pipe_a2_slot2
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            },
            nk2.factory(), // NK push via reconnect relay
            Some(Duration::from_millis(50)),
            Some(Box::new(move |connected| {
                if connected {
                    let (lock, cvar) = &*a_reconnected2;
                    *lock.lock().unwrap() = true;
                    cvar.notify_all();
                }
            })),
        )
        .expect("session A"),
    );

    let pipe_b2_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_b2_client)));
    let pipe_b2_slot2 = pipe_b2_slot.clone();
    let session_b = Arc::new(
        HushSession::connect_with_reconnect(
            pipe_b1_client,
            relay_pub,
            device_b,
            |_, _| {},
            Box::new(MemLog::new()),
            || {},
            |_| {},
            move || {
                let (lock, cvar) = &*bd;
                *lock.lock().unwrap() += 1;
                cvar.notify_all();
            },
            move || {
                pipe_b2_slot2
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            },
            nk2.factory(), // NK push via reconnect relay
            Some(Duration::from_millis(50)),
            Some(Box::new(move |connected| {
                if connected {
                    let (lock, cvar) = &*b_reconnected2;
                    *lock.lock().unwrap() = true;
                    cvar.notify_all();
                }
            })),
        )
        .expect("session B"),
    );

    session_a.set_manifest(make_two_member_manifest(
        a_noise, a_signing, &a_sk, b_noise, b_signing,
    ));
    session_b.set_manifest(make_two_member_manifest(
        b_noise, b_signing, &b_sk, a_noise, a_signing,
    ));

    // Drop pipe1 — triggers reconnect on both sides.
    close_a1_client.store(true, Ordering::Release);
    close_b1_client.store(true, Ordering::Release);

    // Wait until A has reconnected via pipe2 (structural, not sleep-based).
    {
        let (lock, cvar) = &*a_reconnected;
        let result = cvar
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |ok| !*ok)
            .unwrap();
        assert!(!result.1.timed_out(), "A must reconnect within 5s");
    }

    // Wait until B has reconnected via pipe2.
    {
        let (lock, cvar) = &*b_reconnected;
        let result = cvar
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |ok| !*ok)
            .unwrap();
        assert!(!result.1.timed_out(), "B must reconnect within 5s");
    }

    session_a.destroy_group();

    // Wait until B's on_group_destroyed fires (structural, not sleep-based).
    {
        let (lock, cvar) = &*b_destroyed;
        let result = cvar
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |count| {
                *count == 0
            })
            .unwrap();
        assert!(
            !result.1.timed_out(),
            "B's on_group_destroyed must fire after post-reconnect destroy"
        );
        assert_eq!(*result.0, 1, "B's on_group_destroyed must fire exactly once");
    }

    assert!(
        session_b.manifest.lock().unwrap().is_none(),
        "B's manifest must be cleared after destroy"
    );
}

#[test]
fn destroy_group_fires_on_group_destroyed_for_all_members() {
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
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());

    let a_destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let ad = a_destroyed.clone();
    let session_a = Arc::new(
        HushSession::connect_full(
            pipe_a_client,
            relay_pub,
            device_a,
            |_, _| {},
            Box::new(MemLog::new()),
            || {},
            |_| {},
            move || {
                *ad.lock().unwrap() += 1;
            },
            nk.factory(),
        )
        .expect("session A"),
    );

    let b_destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let bd = b_destroyed.clone();
    let session_b = Arc::new(
        HushSession::connect_full(
            pipe_b_client,
            relay_pub,
            device_b,
            |_, _| {},
            Box::new(MemLog::new()),
            || {},
            |_| {},
            move || {
                *bd.lock().unwrap() += 1;
            },
            nk.factory(),
        )
        .expect("session B"),
    );

    session_a.set_manifest(make_two_member_manifest(
        a_noise, a_signing, &a_sk, b_noise, b_signing,
    ));
    session_b.set_manifest(make_two_member_manifest(
        b_noise, b_signing, &b_sk, a_noise, a_signing,
    ));

    session_a.destroy_group();
    wait_for(|| *a_destroyed.lock().unwrap() >= 1, Duration::from_secs(5));
    wait_for(|| *b_destroyed.lock().unwrap() >= 1, Duration::from_secs(5));

    assert_eq!(*a_destroyed.lock().unwrap(), 1, "A on_group_destroyed once");
    assert!(
        session_a.manifest.lock().unwrap().is_none(),
        "A manifest cleared"
    );
    assert_eq!(*b_destroyed.lock().unwrap(), 1, "B on_group_destroyed once");
    assert!(
        session_b.manifest.lock().unwrap().is_none(),
        "B manifest cleared"
    );
}

#[test]
fn revoke_from_unknown_device_is_ignored() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_stranger_client, pipe_stranger_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();

    {
        let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_kp_s = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let sess_a = std::sync::Arc::new(accept(pipe_a_relay, relay_kp_a).unwrap());
            let _sess_s = accept(pipe_stranger_relay, relay_kp_s).unwrap();
            // Route NK pushes from stranger to A (deliberate routing to test discard).
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
                let sess_a2 = sess_a.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = hush_noise::session_nk::accept(nk_pipe, kp) {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                let _ = sess_a2.send(&frame(MsgType::Deliver, body));
                            }
                        }
                    }
                });
            }
        });
    }

    let device_a = DeviceKeypair::generate();
    let device_trusted = DeviceKeypair::generate();
    let device_stranger = DeviceKeypair::generate();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let trusted_noise = device_trusted.public_key();
    let trusted_signing = device_trusted.signing_public_key();

    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let session_a = Arc::new(
        HushSession::connect_full(
            pipe_a_client,
            relay_pub,
            device_a,
            |_, _| {},
            Box::new(MemLog::new()),
            || {},
            |_| {},
            move || {
                *dc.lock().unwrap() += 1;
            },
            nk.factory(),
        )
        .expect("session A"),
    );
    session_a.set_manifest(make_two_member_manifest(
        a_noise,
        a_signing,
        &a_sk,
        trusted_noise,
        trusted_signing,
    ));

    let session_stranger =
        HushSession::connect(pipe_stranger_client, relay_pub, device_stranger, |_, _| {}, nk.factory())
            .expect("stranger");
    session_stranger
        .push_message(&Message::Revoke, session_a.noise_pub())
        .expect("stranger push");

    // Give the message time to arrive, then assert it was dropped.
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(
        *destroyed.lock().unwrap(),
        0,
        "no group_destroyed from stranger"
    );
    assert_eq!(
        session_a
            .manifest
            .lock()
            .unwrap()
            .as_ref()
            .map(|m| m.members.len())
            .unwrap_or(0),
        2,
        "manifest unchanged"
    );
}

/// destroy_group() with no manifest fires on_group_destroyed and sets terminal state.
#[test]
fn destroy_group_with_no_manifest_fires_callback_and_is_terminal() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = accept(pipe_relay, relay_kp2);
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
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        || Err("push factory unused: no manifest".into()),
    )
    .expect("connect");

    assert!(session.manifest.lock().unwrap().is_none());
    session.destroy_group();

    assert_eq!(
        *destroyed.lock().unwrap(),
        1,
        "on_group_destroyed should fire"
    );
    // Session is terminal.
    assert!(
        matches!(
            session.push_sync(b"test".to_vec()),
            Err(SessionError::GroupDestroyed)
        ),
        "session terminal after destroy_group"
    );
}
