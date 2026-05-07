use std::sync::{Arc, Mutex};
use std::time::Duration;

use hush_noise::{keypair::Keypair, session::accept};

use crate::device::DeviceKeypair;
use crate::envelope::Envelope;
use crate::keys::NoisePublicKey;
use crate::message::Message;
use crate::operation_log::MemLog;
use crate::relay::{frame, parse, MsgType};

use super::{test_helpers::*, HushSession};

// ── push / sequence ───────────────────────────────────────────────────────────

#[test]
fn two_sessions_can_exchange_sync_message() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_pub = device_b.public_key();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_| {}).expect("session A");

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    let _session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg| {
        rx.lock().unwrap().push(msg);
    })
    .expect("session B");

    session_a
        .push_sync(b_pub, b"hello from A".to_vec())
        .expect("push_sync");
    std::thread::sleep(Duration::from_millis(100));

    let got = received.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0],
        Message::Sync {
            body: b"hello from A".to_vec()
        }
    );
}

#[test]
fn push_sync_increments_sequence() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();

    let received_envs: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received_envs.clone();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let session = accept(pipe_relay, relay_kp2).unwrap();
            loop {
                let raw = match session.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    if let Ok(env) = Envelope::decode(body) {
                        rx.lock().unwrap().push(env);
                    }
                }
            }
        });
    }

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_| {}).expect("connect");

    session
        .push_sync(recipient.public_key(), b"first".to_vec())
        .expect("first");
    session
        .push_sync(recipient.public_key(), b"second".to_vec())
        .expect("second");
    std::thread::sleep(Duration::from_millis(200));

    let envs = received_envs.lock().unwrap();
    assert_eq!(envs.len(), 2);
    assert_eq!(envs[0].sequence, 0);
    assert_eq!(envs[1].sequence, 1);
}

// ── pairing ───────────────────────────────────────────────────────────────────

#[test]
fn pairing_ceremony_on_paired_fires_with_correct_key() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, false); // B→A

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let pair_msgs: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let pm = pair_msgs.clone();
    let session_a = Arc::new(
        HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg| {
            pm.lock().unwrap().push(msg);
        })
        .expect("session A"),
    );

    let on_paired_fired: Arc<Mutex<Vec<NoisePublicKey>>> = Arc::new(Mutex::new(Vec::new()));
    let opf = on_paired_fired.clone();
    let _payload = session_a.start_pairing(move |k| {
        opf.lock().unwrap().push(k);
    });

    let device_b_noise_pub = device_b.public_key();
    let device_b_signing_pub = device_b.signing_public_key();
    let session_b =
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_| {}).expect("session B");

    let pair_msg = Message::Pair {
        noise_pub: device_b_noise_pub.0,
        signing_pub: device_b_signing_pub.0,
    };
    session_b
        .push_message(&pair_msg, session_a.noise_pub())
        .expect("B push Pair");

    std::thread::sleep(Duration::from_millis(100));

    let msgs = pair_msgs.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    if let Message::Pair {
        noise_pub,
        signing_pub,
    } = msgs[0]
    {
        drop(msgs);
        session_a.accept_pair(
            NoisePublicKey(noise_pub),
            crate::keys::SigningPublicKey(signing_pub),
        );
    } else {
        panic!("expected Pair message");
    }

    let paired = on_paired_fired.lock().unwrap();
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].0, device_b_noise_pub.0);
}

#[test]
fn accept_pair_outside_window_is_noop() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_| {}).expect("connect");

    let fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let fc = fired.clone();

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    session.accept_pair(dummy, dummy_signing); // no window — no-op
    assert!(!*fired.lock().unwrap());

    let _payload = session.start_pairing(move |_| {
        *fc.lock().unwrap() = true;
    });
    session.cancel_pairing();
    session.accept_pair(dummy, dummy_signing);
    assert!(!*fired.lock().unwrap());
}

#[test]
fn accept_pair_after_timeout_is_noop() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_| {}).expect("connect");

    let fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let fc = fired.clone();
    let _payload = session.start_pairing_with_duration(Duration::from_millis(1), move |_| {
        *fc.lock().unwrap() = true;
    });
    std::thread::sleep(Duration::from_millis(10));

    let dummy = NoisePublicKey(make_relay_kp().public_key);
    let dummy_signing = crate::keys::SigningPublicKey([0u8; 32]);
    session.accept_pair(dummy, dummy_signing);
    assert!(!*fired.lock().unwrap());
}

// ── outbox / reconnect ────────────────────────────────────────────────────────

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
    let session = HushSession::connect_with_log(
        pipe_client,
        relay_pub,
        device,
        |_| {},
        Box::new(MemLog::new()),
        |_| {},
    )
    .expect("connect");

    session
        .push_sync(recipient.public_key(), b"hello".to_vec())
        .expect("push");
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
    let session = HushSession::connect_with_reconnect(
        pipe1_client,
        relay_pub,
        device,
        |_| {},
        Box::new(MemLog::new()),
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

    close_client_reader.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(300));

    let _r1 = session.push_sync(recipient.public_key(), b"blob1".to_vec());
    let _r2 = session.push_sync(recipient.public_key(), b"blob2".to_vec());
    let _r3 = session.push_sync(recipient.public_key(), b"blob3".to_vec());

    std::thread::sleep(Duration::from_millis(1500));

    let envs = received_envs.lock().unwrap();
    assert_eq!(envs.len(), 3, "all 3 blobs replayed");
    assert!(envs[0].sequence < envs[1].sequence);
    assert!(envs[1].sequence < envs[2].sequence);
}

// ── revocation ────────────────────────────────────────────────────────────────

#[test]
fn revoke_ceremony_rotates_both_devices_and_clears_paired_lists() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let a_rotated: Arc<Mutex<Vec<[u8; 64]>>> = Arc::new(Mutex::new(Vec::new()));
    let ar = a_rotated.clone();
    let session_a = Arc::new(
        HushSession::connect_with_log(
            pipe_a_client,
            relay_pub,
            device_a,
            |_| {},
            Box::new(MemLog::new()),
            move |bytes| {
                ar.lock().unwrap().push(bytes);
            },
        )
        .expect("session A"),
    );

    let b_rotated: Arc<Mutex<Vec<[u8; 64]>>> = Arc::new(Mutex::new(Vec::new()));
    let br = b_rotated.clone();
    let session_b = Arc::new(
        HushSession::connect_with_log(
            pipe_b_client,
            relay_pub,
            device_b,
            |_| {},
            Box::new(MemLog::new()),
            move |bytes| {
                br.lock().unwrap().push(bytes);
            },
        )
        .expect("session B"),
    );

    session_a.paired.lock().unwrap().add(b_noise, b_signing);
    session_b.paired.lock().unwrap().add(a_noise, a_signing);

    session_a.revoke();
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(a_rotated.lock().unwrap().len(), 1, "A rotated once");
    assert!(
        session_a.paired.lock().unwrap().is_empty(),
        "A paired cleared"
    );
    assert_eq!(b_rotated.lock().unwrap().len(), 1, "B rotated once");
    assert!(
        session_b.paired.lock().unwrap().is_empty(),
        "B paired cleared"
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
    let trusted_noise = device_trusted.public_key();
    let trusted_signing = device_trusted.signing_public_key();

    let rotated: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let rc = rotated.clone();
    let session_a = Arc::new(
        HushSession::connect_with_log(
            pipe_a_client,
            relay_pub,
            device_a,
            |_| {},
            Box::new(MemLog::new()),
            move |_| {
                *rc.lock().unwrap() += 1;
            },
        )
        .expect("session A"),
    );
    session_a
        .paired
        .lock()
        .unwrap()
        .add(trusted_noise, trusted_signing);

    let session_stranger =
        HushSession::connect(pipe_stranger_client, relay_pub, device_stranger, |_| {})
            .expect("stranger");
    session_stranger
        .push_message(&Message::Revoke, session_a.noise_pub())
        .expect("stranger push");

    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(*rotated.lock().unwrap(), 0, "no rotation from stranger");
    assert_eq!(
        session_a.paired.lock().unwrap().len(),
        1,
        "paired unchanged"
    );
}
