use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hush_noise::{keypair::Keypair, session::accept};

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
    spawn_bidirectional_relay(&relay_kp, pipe_a1_relay, pipe_b1_relay);

    let (pipe_a2_client, pipe_a2_relay) = mem_pipe_pair();
    let (pipe_b2_client, pipe_b2_relay) = mem_pipe_pair();
    spawn_bidirectional_relay_parallel(&relay_kp, pipe_a2_relay, pipe_b2_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());

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
            Some(Duration::from_millis(50)),
        )
        .expect("session A"),
    );

    let b_destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let bd = b_destroyed.clone();
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
                *bd.lock().unwrap() += 1;
            },
            move || {
                pipe_b2_slot2
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            },
            Some(Duration::from_millis(50)),
        )
        .expect("session B"),
    );

    session_a.set_manifest(make_two_member_manifest(
        a_noise, a_signing, &a_sk, b_noise, b_signing,
    ));
    session_b.set_manifest(make_two_member_manifest(
        b_noise, b_signing, &b_sk, a_noise, a_signing,
    ));

    close_a1_client.store(true, Ordering::Release);
    close_b1_client.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(500));

    session_a.destroy_group();
    std::thread::sleep(Duration::from_millis(400));

    assert_eq!(
        *b_destroyed.lock().unwrap(),
        1,
        "B's on_group_destroyed must fire after post-reconnect destroy"
    );
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
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

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
    std::thread::sleep(Duration::from_millis(200));

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

    {
        let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_kp_s = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let sess_a = accept(pipe_a_relay, relay_kp_a).unwrap();
            let sess_s = accept(pipe_stranger_relay, relay_kp_s).unwrap();
            loop {
                let raw = match sess_s.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    let _ = sess_a.send(&frame(MsgType::Deliver, body));
                }
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
        HushSession::connect(pipe_stranger_client, relay_pub, device_stranger, |_, _| {})
            .expect("stranger");
    session_stranger
        .push_message(&Message::Revoke, session_a.noise_pub())
        .expect("stranger push");

    std::thread::sleep(Duration::from_millis(100));

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
