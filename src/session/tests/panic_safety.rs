use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::envelope::{Envelope, SigningKeypair};
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::message::Message;
use crate::operation_log::MemLog;
use crate::relay::{frame, parse, MsgType};

use super::super::test_helpers::*;
use super::super::TruesealSession;
use super::make_two_member_manifest;

// ── B7 review fix-forward: the panic-wedge ─────────────────────────────

/// A relay that accepts two XX connections — the initial one and the
/// reconnect — each in its own thread, holds them open, records every
/// client frame, and delivers envelopes on the CURRENT session on demand.
struct TwoConnRelay {
    client_frames: Arc<Mutex<Vec<(u8, Vec<u8>)>>>,
    deliver_tx: mpsc::Sender<(u64, Vec<u8>)>,
    /// Incremented each time an accept completes — the test waits for the
    /// right generation before delivering, so a delivery never goes to a
    /// dying session.
    generation: Arc<AtomicUsize>,
}

impl TwoConnRelay {
    fn spawn(pipe1: MemPipe, pipe2: MemPipe, relay_kp: &trueseal_noise::keypair::Keypair) -> Self {
        let client_frames = Arc::new(Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
        let (deliver_tx, deliver_rx) = mpsc::channel::<(u64, Vec<u8>)>();
        let current: Arc<Mutex<Option<Arc<trueseal_noise::session_xx::Session<MemPipe>>>>> =
            Arc::new(Mutex::new(None));
        let generation = Arc::new(AtomicUsize::new(0));

        // Delivery forwarder: sends on whatever session is active NOW.
        {
            let current = current.clone();
            std::thread::spawn(move || {
                for (blob_id, env_bytes) in deliver_rx {
                    let mut body = blob_id.to_be_bytes().to_vec();
                    body.extend_from_slice(&env_bytes);
                    let sess = current.lock().unwrap().clone();
                    if let Some(sess) = sess {
                        let _ = sess.send(&frame(MsgType::Deliver, &body));
                    }
                }
            });
        }
        // One acceptor thread per connection; the pipe2 acceptor waits for
        // the client's reconnect dial.
        for pipe in [pipe1, pipe2] {
            let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
            let current = current.clone();
            let generation = generation.clone();
            let frames = client_frames.clone();
            std::thread::spawn(move || {
                let session = crate::version::testutil::xx_accept_after_prefix(pipe, kp)
                    .expect("relay accept");
                let session = Arc::new(session);
                *current.lock().unwrap() = Some(session.clone());
                generation.fetch_add(1, Ordering::SeqCst);
                while let Ok(raw) = session.receive() {
                    if let Some((t, body)) = parse(&raw) {
                        frames.lock().unwrap().push((t as u8, body.to_vec()));
                    }
                }
            });
        }
        TwoConnRelay {
            client_frames,
            deliver_tx,
            generation,
        }
    }

    fn deliver(
        &self,
        blob_id: u64,
        msg: &Message,
        recipient: NoisePublicKey,
        sender: &SigningKeypair,
        seq: u64,
    ) {
        let plaintext = msg.encode();
        let payload = crate::crypto::encrypt(recipient, sender.public_key_bytes(), &plaintext);
        let env = Envelope::build(seq, vec![], recipient, sender, payload);
        self.deliver_tx
            .send((blob_id, env.encode()))
            .expect("relay alive");
    }

    fn generation(&self) -> usize {
        self.generation.load(Ordering::SeqCst)
    }

    /// Blob ids the client acked, in order.
    fn deliver_acks(&self) -> Vec<u64> {
        self.client_frames
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t == MsgType::DeliverAck as u8)
            .filter_map(|(_, b)| b.as_slice().try_into().ok().map(u64::from_be_bytes))
            .collect()
    }
}

/// Only the Sync app handler is panic-wrapped (5 attempts, ADR-0026). A
/// panic in a control-plane callback — here `on_manifest_changed`, the
/// app-database-write case — unwinds the receive run-loop. The
/// DisconnectGuard must still clear `is_connected`: the reconnect loop
/// polls it, so missing the store would wedge delivery silently, forever —
/// no reconnect, no signal.
///
/// Here: the first manifest callback panics → the session reports
/// disconnect, reconnects, and handles the NEXT manifest normally.
#[test]
fn manifest_callback_panic_reconnects_and_delivery_recovers() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe1_client, pipe1_relay) = mem_pipe_pair();
    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    let relay = TwoConnRelay::spawn(pipe1_relay, pipe2_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let issuer_bytes: [u8; 32] = rand::random();
    let issuer_sk = SigningKey::from_bytes(&issuer_bytes);
    let issuer_signing_pub = SigningPublicKey(issuer_sk.verifying_key().to_bytes());
    let issuer_kp = || SigningKeypair::from_signing_key(SigningKey::from_bytes(&issuer_bytes));
    let group_id = new_group_id();
    let members = || {
        vec![
            ManifestMember {
                noise_pub: NoisePublicKey([7u8; 32]),
                signing_pub: issuer_signing_pub,
                name: member_name(&issuer_signing_pub),
            },
            ManifestMember {
                noise_pub: device.public_key(),
                signing_pub: device.signing_public_key(),
                name: member_name(&device.signing_public_key()),
            },
        ]
    };
    let v1 = GroupManifest::new(group_id, 1, members(), &issuer_sk);
    let v2 = GroupManifest::new(group_id, 2, members(), &issuer_sk);
    let v3 = GroupManifest::new(group_id, 3, members(), &issuer_sk);

    // The app's manifest callback fails ONCE (a database write error), then
    // recovers.
    let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let calls_cb = calls.clone();
    let events: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
    let ec = events.clone();

    let pipes: Arc<Mutex<Vec<MemPipe>>> = Arc::new(Mutex::new(vec![pipe1_client, pipe2_client]));
    let pipes2 = pipes.clone();
    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(Some(v1))),
        || {},
        move |_m: &GroupManifest| {
            if calls_cb.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("app database write failed");
            }
        },
        || {},
        move || {
            let mut v = pipes2.lock().unwrap();
            if v.is_empty() {
                Err("exhausted".into())
            } else {
                Ok(v.remove(0))
            }
        },
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)), // fast reconnect
        Some(Box::new(move |connected| {
            ec.lock().unwrap().push(connected);
        })),
    )
    .expect("session");

    let device_pub = session.noise_pub();

    // Initial connect.
    wait_for(
        || relay.generation() == 1 && *events.lock().unwrap() == vec![true],
        Duration::from_secs(3),
    );

    // A v2 manifest arrives: the callback panics. The run-loop unwinds; the
    // DisconnectGuard clears is_connected; NO DeliverAck for blob 2 leaves.
    relay.deliver(
        2,
        &Message::GroupManifest { manifest: v2 },
        device_pub,
        &issuer_kp(),
        10,
    );

    // The session must detect the loss and reconnect — not wedge.
    wait_for(
        || {
            let e = events.lock().unwrap();
            relay.generation() == 2 && e.contains(&false) && e.last() == Some(&true)
        },
        Duration::from_secs(5),
    );

    // Delivery recovers: the next manifest is handled normally (the
    // callback's second call does not panic) and acked.
    relay.deliver(
        3,
        &Message::GroupManifest { manifest: v3 },
        device_pub,
        &issuer_kp(),
        11,
    );
    wait_for(|| calls.load(Ordering::SeqCst) >= 2, Duration::from_secs(3));
    wait_for(|| relay.deliver_acks().contains(&3), Duration::from_secs(3));

    assert_eq!(
        session
            .manifest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|m| m.version),
        Some(3),
        "the manifest delivered after the panic-driven reconnect is applied"
    );
    assert!(
        !relay.deliver_acks().contains(&2),
        "blob 2 was never acked — its handling died with the panicking callback"
    );
    let snapshot = events.lock().unwrap().clone();
    assert_eq!(
        snapshot,
        vec![true, false, true],
        "disconnect was signalled and the session reconnected"
    );
}

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

    let session_a = TruesealSession::connect(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("session A");
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

    wait_for(|| *received.lock().unwrap() >= 1, Duration::from_secs(5));
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
        TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, nk.factory())
            .expect("session");

    let manifest_arc = session.manifest.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = manifest_arc.lock().unwrap();
        panic!("intentional poison");
    });
    assert!(
        session.manifest.is_poisoned(),
        "setup: manifest must be poisoned"
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.push_sync(b"hello".to_vec())
    }));
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
        TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, nk.factory())
            .expect("session");

    let manifest_arc = session.manifest.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = manifest_arc.lock().unwrap();
        panic!("intentional poison");
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| session.members()));
    assert!(
        result.is_ok(),
        "members() must not panic with poisoned manifest"
    );
    assert_eq!(
        result.unwrap(),
        vec![],
        "poisoned None manifest → empty list"
    );
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

    let session_a = TruesealSession::connect(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("session A");
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
            ManifestMember {
                noise_pub: a_noise,
                signing_pub: a_signing,
                name: "A".into(),
            },
            ManifestMember {
                noise_pub: b_noise,
                signing_pub: b_signing,
                name: "B".into(),
            },
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
