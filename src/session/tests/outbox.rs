use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hush_noise::{keypair::Keypair, session::accept};

use crate::device::DeviceKeypair;
use crate::envelope::Envelope;
use crate::operation_log::MemLog;
use crate::relay::{parse, MsgType};

use super::super::test_helpers::*;
use super::super::HushSession;
use super::make_two_member_manifest;

#[test]
fn push_sync_appends_and_marks_delivered() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
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
    let session = HushSession::connect_with_log(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise, d_signing, &d_sk, r_noise, r_signing,
    ));

    session.push_sync(b"hello".to_vec()).expect("push");
    std::thread::sleep(Duration::from_millis(50));

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
    let received_envs: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received_envs.clone();
    {
        let relay_kp3 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let s = accept(pipe2_relay, relay_kp3).unwrap();
            loop {
                match s.receive() {
                    Ok(raw) => {
                        if let Some((MsgType::Push, body)) = parse(&raw) {
                            if let Ok(env) = Envelope::decode(body) {
                                rx.lock().unwrap().push(env);
                            }
                        }
                    }
                    Err(_) => break,
                }
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
    let session = HushSession::connect_with_reconnect(
        pipe1_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        |_| {},
        move || {
            pipe2_slot2
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "exhausted".into())
        },
        Some(Duration::from_millis(50)),
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

    std::thread::sleep(Duration::from_millis(1500));

    let envs = received_envs.lock().unwrap();
    assert_eq!(envs.len(), 3, "all 3 blobs replayed");
    assert!(envs[0].sequence < envs[1].sequence);
    assert!(envs[1].sequence < envs[2].sequence);
}

/// push_sync while disconnected returns PushFailed and entry stays in outbox.
#[test]
fn push_sync_while_disconnected_returns_error_and_stays_in_outbox() {
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
    let session = HushSession::connect_with_log(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise, d_signing, &d_sk, r_noise, r_signing,
    ));

    close_client.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(100));

    let result = session.push_sync(b"orphaned".to_vec());
    assert!(
        matches!(result, Err(super::super::SessionError::PushFailed(_))),
        "should return PushFailed when disconnected"
    );

    let undelivered = session.op_log.lock().unwrap().undelivered_entries();
    assert_eq!(undelivered.len(), 1, "entry should remain in outbox");
}
