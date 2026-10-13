//! SYNC-5 (#97), ADR-0026 — the recipient half of the delivery contract:
//! library-owned dedup, handler attempts, ack-after-handler, the manifest
//! rejection taxonomy (ADR-0034 §2/§3), buffered member events, and the
//! single Delivery Issue stream.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::delivery_issue::DeliveryIssue;
use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::message::{message_id, Message};
use crate::operation_log::MemLog;
use crate::store::{PersistentLog, Store};

use super::super::test_helpers::*;
use super::super::TruesealSession;

/// A duplicate delivery (same Envelope, new blob id) is acked silently and
/// the handler runs once. This is the crash-between-dedup-and-ack recovery
/// path: the re-delivery is recognised by its Message ID.
#[test]
fn duplicate_delivery_is_acked_silently_and_handler_runs_once() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let manifest = membership(&device, &sender);

    let device_pub = device.public_key();
    let handled: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let handled_cb = handled.clone();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |msg, _author, _seq| {
            if matches!(msg, Message::Sync { .. }) {
                handled_cb.fetch_add(1, Ordering::SeqCst);
            }
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(manifest);
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    let msg = Message::Sync {
        body: b"same message".to_vec(),
    };
    relay.deliver(1, &msg, device_pub, &sender, 5);
    relay.deliver(2, &msg, device_pub, &sender, 5); // re-delivery, new blob id

    wait_for(|| relay.deliver_acks().len() == 2, Duration::from_secs(3));
    assert_eq!(relay.deliver_acks(), vec![1, 2], "both copies are acked");
    assert_eq!(
        handled.load(Ordering::SeqCst),
        1,
        "the handler runs once — the library dedups by Message ID"
    );
    assert!(
        issues.lock().unwrap().is_empty(),
        "a duplicate is acked SILENTLY — no Delivery Issue"
    );
}

/// A handler that fails all 5 attempts raises `handlerGaveUp` with the
/// Message ID and the Blob is acked (ADR-0026 step 4) — one poison message
/// must not loop forever or block the inbox.
#[test]
fn handler_failing_five_times_gives_up_and_blob_is_acked() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let manifest = membership(&device, &sender);

    let device_pub = device.public_key();
    let attempts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let attempts_cb = attempts.clone();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |msg, _author, _seq| {
            if matches!(msg, Message::Sync { .. }) {
                attempts_cb.fetch_add(1, Ordering::SeqCst);
                panic!("handler boom");
            }
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(manifest);
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    let msg = Message::Sync {
        body: b"poison".to_vec(),
    };
    relay.deliver(9, &msg, device_pub, &sender, 3);

    wait_for(
        || {
            issues
                .lock()
                .unwrap()
                .iter()
                .any(|i| matches!(i, DeliveryIssue::HandlerGaveUp { .. }))
        },
        Duration::from_secs(5),
    );
    let expected_mid = message_id(&sender.public_key_bytes(), 3);
    {
        let issues = issues.lock().unwrap();
        match issues
            .iter()
            .find(|i| matches!(i, DeliveryIssue::HandlerGaveUp { .. }))
        {
            Some(DeliveryIssue::HandlerGaveUp { message_id, error }) => {
                assert_eq!(message_id, &expected_mid);
                assert!(error.contains("handler boom"), "last error: {error}");
            }
            other => panic!("expected HandlerGaveUp, got {other:?}"),
        }
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        5,
        "exactly 5 handler attempts (ADR-0026)"
    );
    // The issue fires inside the dispatch callback and the DeliverAck is
    // sent the moment it returns — wait for it rather than racing it.
    wait_for(|| relay.deliver_acks() == vec![9], Duration::from_secs(3));
    assert_eq!(
        relay.deliver_acks(),
        vec![9],
        "the poison Blob is acked and dropped, not looped forever"
    );
}

/// A handler that fails transiently is retried in memory until it succeeds;
/// the Message ID is recorded and a later re-delivery is silent.
#[test]
fn handler_succeeding_on_retry_is_not_reported_and_deduped() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let manifest = membership(&device, &sender);

    let device_pub = device.public_key();
    let attempts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let attempts_cb = attempts.clone();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |msg, _author, _seq| {
            if matches!(msg, Message::Sync { .. }) {
                // Fail the first two attempts, succeed on the third.
                if attempts_cb.fetch_add(1, Ordering::SeqCst) < 2 {
                    panic!("transient failure");
                }
            }
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(manifest);
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    let msg = Message::Sync {
        body: b"flaky".to_vec(),
    };
    relay.deliver(1, &msg, device_pub, &sender, 7);

    wait_for(|| relay.deliver_acks() == vec![1], Duration::from_secs(3));
    assert_eq!(attempts.load(Ordering::SeqCst), 3, "third attempt succeeds");
    assert!(
        issues.lock().unwrap().is_empty(),
        "a transient handler failure that recovers raises no issue"
    );

    // The Message ID is now recorded: a re-delivery is silent.
    relay.deliver(2, &msg, device_pub, &sender, 7);
    wait_for(
        || relay.deliver_acks() == vec![1, 2],
        Duration::from_secs(3),
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        3,
        "re-delivery after success does not re-run the handler"
    );
    assert!(issues.lock().unwrap().is_empty());
}

/// Crash point (ADR-0026): a crash between the dedup write and the
/// DeliverAck means the Blob is re-delivered, recognised as a duplicate,
/// and acked — the handler does NOT run again. Simulated as a full restart:
/// a new session over the same store sees the persisted dedup record.
#[test]
fn dedup_record_survives_restart_and_prevents_rehandling() {
    let dir = tempfile::TempDir::new().expect("tmp dir");
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();
    let msg = Message::Sync {
        body: b"handled before crash".to_vec(),
    };

    // First "process": handle the message, then die without the relay
    // having seen... anything about the dedup record (it lives locally).
    let device_pub = device.public_key();
    let manifest = membership(&device, &sender);
    {
        let (pipe_client, pipe_relay) = mem_pipe_pair();
        let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
        let handled: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let handled_cb = handled.clone();
        let store = Store::open(dir.path(), "ns").expect("store");
        let device1 = DeviceKeypair::from_bytes(device.noise.private(), device.signing.to_bytes())
            .expect("keypair bytes");
        let _session = TruesealSession::<MemPipe>::connect_full(
            pipe_client,
            relay_pub(&relay_kp),
            device1,
            move |m, _a, _s| {
                if matches!(m, Message::Sync { .. }) {
                    handled_cb.fetch_add(1, Ordering::SeqCst);
                }
            },
            Box::new(PersistentLog::new(store)),
            || {},
            |_| {},
            || {},
            || Err("push factory unused".into()),
        )
        .expect("session");
        _session.set_manifest(manifest.clone());
        relay.deliver(1, &msg, device_pub, &sender, 11);
        wait_for(|| relay.deliver_acks() == vec![1], Duration::from_secs(3));
        assert_eq!(handled.load(Ordering::SeqCst), 1);
        // Session drops here — the "crash". The dedup record is committed.
    }

    // Second "process": same store. The relay re-delivers (it never got an
    // ack for its retransmit queue — simulated with a fresh session).
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let handled: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let handled_cb = handled.clone();
    let store = Store::open(dir.path(), "ns").expect("store");
    let _session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |m, _a, _s| {
            if matches!(m, Message::Sync { .. }) {
                handled_cb.fetch_add(1, Ordering::SeqCst);
            }
        },
        Box::new(PersistentLog::new(store)),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    _session.set_manifest(manifest);
    relay.deliver(2, &msg, device_pub, &sender, 11);
    wait_for(|| relay.deliver_acks() == vec![2], Duration::from_secs(3));
    assert_eq!(
        handled.load(Ordering::SeqCst),
        0,
        "the persisted dedup record prevents re-handling after a restart"
    );
}

/// The mirror of `dedup_record_survives_restart_and_prevents_rehandling`:
/// the ONE sanctioned double-handle (ADR-0026 step 5). A Blob whose handler
/// ran but whose dedup record never committed before the "crash" MUST be
/// re-handled on redelivery — the contract is at-least-once to the handler,
/// and the first handling's effects may have died with the process. Modeled
/// as a restart over durable state that lacks the record (a fresh log).
#[test]
fn crash_before_dedup_commit_rehandles_on_redelivery() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();
    let msg = Message::Sync {
        body: b"handled, then crash before the dedup commit".to_vec(),
    };
    let device_pub = device.public_key();
    let manifest = membership(&device, &sender);

    // First "process": the handler runs and the Blob is acked — then the
    // process dies BEFORE the dedup record reaches durable storage (the
    // in-memory log drops with the session: the commit never happened).
    {
        let (pipe_client, pipe_relay) = mem_pipe_pair();
        let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
        let handled: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let handled_cb = handled.clone();
        let device1 = DeviceKeypair::from_bytes(device.noise.private(), device.signing.to_bytes())
            .expect("keypair bytes");
        let _session = TruesealSession::<MemPipe>::connect_full(
            pipe_client,
            relay_pub(&relay_kp),
            device1,
            move |m, _a, _s| {
                if matches!(m, Message::Sync { .. }) {
                    handled_cb.fetch_add(1, Ordering::SeqCst);
                }
            },
            Box::new(MemLog::new()),
            || {},
            |_| {},
            || {},
            || Err("push factory unused".into()),
        )
        .expect("session");
        _session.set_manifest(manifest.clone());
        relay.deliver(1, &msg, device_pub, &sender, 11);
        wait_for(|| relay.deliver_acks() == vec![1], Duration::from_secs(3));
        assert_eq!(
            handled.load(Ordering::SeqCst),
            1,
            "handler ran before the crash"
        );
        // Session AND its log drop here — the "crash" before the dedup
        // record committed.
    }

    // Second "process": durable state has NO dedup record for this Message
    // ID. The relay re-delivers (new blob id, same Envelope). The library
    // must NOT suppress it: the handler runs again.
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let handled: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let handled_cb = handled.clone();
    let _session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |m, _a, _s| {
            if matches!(m, Message::Sync { .. }) {
                handled_cb.fetch_add(1, Ordering::SeqCst);
            }
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    _session.set_manifest(manifest);
    relay.deliver(2, &msg, device_pub, &sender, 11);
    wait_for(|| relay.deliver_acks() == vec![2], Duration::from_secs(3));
    assert_eq!(
        handled.load(Ordering::SeqCst),
        1,
        "no committed dedup record → the redelivery is re-handled (the one sanctioned duplicate)"
    );
}

/// A replayed or superseded Group Manifest is BENIGN STALE (ADR-0034 §2):
/// acked and dropped with no Delivery Issue and no duplicate member events.
/// Relay re-deliveries and hostile-relay replays land here.
#[test]
fn stale_manifest_replay_is_silent() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let issuer_bytes: [u8; 32] = rand::random();
    let group_id = new_group_id();

    let member_issuer = signing_member(&issuer_bytes, [1u8; 32]);
    let member_device = ManifestMember {
        noise_pub: device.public_key(),
        signing_pub: device.signing_public_key(),
        name: member_name(&device.signing_public_key()),
    };
    let issuer_sk = ed25519_dalek::SigningKey::from_bytes(&issuer_bytes);
    let device_pub = device.public_key();

    let v2 = GroupManifest::new(
        group_id,
        2,
        vec![member_issuer.clone(), member_device.clone()],
        &issuer_sk,
    );
    let v1 = GroupManifest::new(group_id, 1, vec![member_issuer, member_device], &issuer_sk);

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_m, _a, _s| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(v2.clone());
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));
    let joined: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
    let joined_cb = joined.clone();
    session.set_on_member_joined(move |id, name| joined_cb.lock().unwrap().push((id, name)));

    // Replays: the CURRENT manifest again, and an OLDER one.
    for (blob_id, m) in [(1u64, v2), (2, v1)] {
        relay.deliver(
            blob_id,
            &Message::GroupManifest { manifest: m },
            device_pub,
            &signing_keypair(&issuer_bytes),
            20 + blob_id,
        );
    }

    wait_for(|| relay.deliver_acks().len() == 2, Duration::from_secs(3));
    // Stale copies must not churn state or report anything.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        issues.lock().unwrap().is_empty(),
        "benign stale manifests raise no Delivery Issue, got {:?}",
        issues.lock().unwrap()
    );
    assert!(
        joined.lock().unwrap().is_empty(),
        "replays fire no member events"
    );
    assert_eq!(session.members().len(), 1, "membership unchanged");
}

/// An authenticated-but-unacceptable manifest — here: issued by a key that
/// is not a member of the current manifest — raises `unauthorized`
/// (ADR-0034 §3 keeps it separate from `unreadable`).
#[test]
fn manifest_from_unknown_issuer_raises_unauthorized() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let issuer_bytes: [u8; 32] = rand::random();
    let outsider_bytes: [u8; 32] = rand::random();
    let group_id = new_group_id();

    let member_device = ManifestMember {
        noise_pub: device.public_key(),
        signing_pub: device.signing_public_key(),
        name: member_name(&device.signing_public_key()),
    };
    let device_pub = device.public_key();
    let issuer_sk = ed25519_dalek::SigningKey::from_bytes(&issuer_bytes);
    let v1 = GroupManifest::new(
        group_id,
        1,
        vec![signing_member(&issuer_bytes, [1u8; 32]), member_device],
        &issuer_sk,
    );
    // v2 signed by the OUTSIDER's key — issued_by is not in v1's members.
    let outsider_sk = ed25519_dalek::SigningKey::from_bytes(&outsider_bytes);
    let v2 = GroupManifest::new(
        group_id,
        2,
        vec![
            signing_member(&issuer_bytes, [1u8; 32]),
            signing_member(&outsider_bytes, [9u8; 32]),
        ],
        &outsider_sk,
    );

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_m, _a, _s| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(v1);
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    // Delivered as an Envelope from the issuer (a member) CARRYING the
    // outsider-signed manifest — the envelope authenticates, the manifest
    // cannot be authorised.
    relay.deliver(
        1,
        &Message::GroupManifest { manifest: v2 },
        device_pub,
        &signing_keypair(&issuer_bytes),
        30,
    );

    wait_for(
        || {
            issues
                .lock()
                .unwrap()
                .iter()
                .any(|i| matches!(i, DeliveryIssue::Unauthorized))
        },
        Duration::from_secs(3),
    );
    assert_eq!(
        relay.deliver_acks(),
        vec![1],
        "the unacceptable manifest is acked and dropped"
    );
    assert_eq!(session.members().len(), 1, "membership unchanged");
}

/// Member events are buffered until their handlers exist (ADR-0026 step 1):
/// a Pair that arrives before `set_on_member_request` still fires the event
/// when the handler registers — and the pending request stays admissible.
#[test]
fn member_request_arriving_before_registration_flushes_on_registration() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let joiner = DeviceKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device_pub = device.public_key();
    let joiner_noise = joiner.public_key().0;
    let joiner_signing = joiner.signing_public_key().0;
    let joiner_kp = joiner.signing_keypair();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_m, _a, _s| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let token = session.pairing_token(); // open the window
    let (_, _, secret, _) = crate::message::decode_pairing_token(&token).expect("token decodes");

    // The Pair arrives BEFORE any member-request handler is registered.
    relay.deliver(
        1,
        &Message::Pair {
            noise_pub: joiner_noise,
            signing_pub: joiner_signing,
            secret,
        },
        device_pub,
        &joiner_kp,
        1,
    );
    std::thread::sleep(Duration::from_millis(300)); // arrived, buffered

    let events: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
    let events_cb = events.clone();
    session.set_on_member_request(move |token, name| events_cb.lock().unwrap().push((token, name)));

    wait_for(
        || !events.lock().unwrap().is_empty(),
        Duration::from_secs(3),
    );
    let (token, _name) = events.lock().unwrap()[0].clone();
    assert!(
        session.accept_member(&token).expect("accept"),
        "the buffered request stays admissible after the flush"
    );
}

/// The Delivery Issue stream is one channel (ADR-0026): receive-path
/// rejections raised inside the RelayClient reach SESSION subscribers.
#[test]
fn receive_path_issues_reach_session_subscribers() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_m, _a, _s| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    // Undecodable envelope bytes — rejected at the RelayClient layer.
    relay.deliver_raw(1, b"\x00\x01\x02garbage".to_vec());

    wait_for(
        || {
            issues
                .lock()
                .unwrap()
                .iter()
                .any(|i| matches!(i, DeliveryIssue::Unreadable(_)))
        },
        Duration::from_secs(3),
    );
}

/// Per-sender ordering (ADR-0026): messages from one Device reach the
/// handler in the order that Device sent them. Dispatch is serial, so the
/// relay's arrival order is the handler's order.
#[test]
fn per_sender_order_is_preserved() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device_pub = device.public_key();
    let manifest = membership(&device, &sender);
    let received: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(vec![]));
    let received_cb = received.clone();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |_msg, _author, seq| {
            received_cb.lock().unwrap().push(seq);
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(manifest);

    for (blob_id, seq) in [(1u64, 1u64), (2, 2), (3, 3)] {
        relay.deliver(
            blob_id,
            &Message::Sync {
                body: format!("m{seq}").into_bytes(),
            },
            device_pub,
            &sender,
            seq,
        );
    }

    wait_for(
        || received.lock().unwrap().len() == 3,
        Duration::from_secs(3),
    );
    assert_eq!(
        *received.lock().unwrap(),
        vec![1, 2, 3],
        "the handler sees one sender's messages in send order"
    );
}
