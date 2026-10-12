//! SYNC-8 (#100): the Protocol Size Limit is 61,440 bytes of `Sync` body,
//! checked synchronously in `send()` (ADR-0025).
//!
//! The defect: an oversize send was accepted by the library, appended to the
//! outbox, and then replayed on every reconnect forever — the relay refuses
//! it permanently, but the client never noticed. The first two tests assert
//! the defect is gone; both fail against the pre-fix code.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;

use crate::delivery_issue::{DeliveryIssue, SendFailedReason};
use crate::device::DeviceKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::limits::{NOISE_FRAME_PLAINTEXT_MAX, PROTOCOL_SIZE_LIMIT};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::message::{message_id, Message};
use crate::operation_log::{MemLog, OperationLog};
use crate::relay::build_push_blob;

use super::super::test_helpers::*;
use super::super::{drop_oversize_outbox_entries, IssueSink, SessionError, TruesealSession};
use super::make_two_member_manifest;

fn offline_session_with_manifest() -> TruesealSession<MemPipeSimple> {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let remote = DeviceKeypair::generate();

    let session = TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in size-limit tests".into()),
        None,
        None,
    )
    .expect("offline session");

    let manifest = make_two_member_manifest(
        noise,
        signing,
        &sk,
        remote.public_key(),
        remote.signing_public_key(),
    );
    session.set_manifest(manifest);
    session
}

/// A body of 61,441 bytes is refused synchronously and never enters the
/// Outbox (ADR-0025: "`send()` checks the limit synchronously, before
/// anything is written to the Operation Log"). RED on the pre-fix code:
/// it returned `Ok(())` and queued the entry.
#[test]
fn oversize_send_is_refused_and_never_enters_outbox() {
    let session = offline_session_with_manifest();

    let result = session.push_sync(vec![0xABu8; 61_441]);

    assert!(
        result.is_err(),
        "61,441-byte body must be refused, got {result:?}"
    );
    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert!(
        undelivered.is_empty(),
        "an oversize body must never enter the Outbox, found {} entries",
        undelivered.len()
    );
}

/// An oversize entry persisted in an outbox from before this fix (only
/// possible in development stores) is dropped on load, so it can never be
/// replayed forever (ADR-0025). RED on the pre-fix code: the entry survived.
#[test]
fn oversize_outbox_entry_is_dropped_on_load() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let remote = DeviceKeypair::generate();

    // An outbox entry written by a pre-fix build: over the Protocol Size
    // Limit, undeliverable, and (pre-fix) replayed on every reconnect.
    let mut log = MemLog::new();
    log.append(&remote.public_key().0, 0, vec![0xCDu8; 61_441]);
    // A valid entry that must survive the drop.
    log.append(&remote.public_key().0, 1, b"within limit".to_vec());

    let session = TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in size-limit tests".into()),
        None,
        None,
    )
    .expect("offline session");

    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(
        undelivered.len(),
        1,
        "the oversize entry must be dropped on load, the valid one kept"
    );
    assert_eq!(undelivered[0].sequence, 1);
    assert_eq!(undelivered[0].blob, b"within limit");
}

/// A body of exactly 61,440 bytes — the Protocol Size Limit itself — is
/// accepted (boundary, passing side).
#[test]
fn send_at_exact_limit_is_accepted() {
    let session = offline_session_with_manifest();

    let result = session.push_sync(vec![0xEFu8; 61_440]);

    assert!(
        result.is_ok(),
        "61,440-byte body is exactly at the limit and must be accepted, got {result:?}"
    );
    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(
        undelivered.len(),
        1,
        "the accepted send is queued for the one remote member"
    );
}

/// The refusal is the typed `PayloadTooLarge { max }` of ADR-0025 /
/// ADR-0028's error list — not a stringly push failure.
#[test]
fn refusal_is_typed_and_carries_the_limit() {
    let session = offline_session_with_manifest();

    let result = session.push_sync(vec![0u8; PROTOCOL_SIZE_LIMIT + 1]);

    match result {
        Err(SessionError::PayloadTooLarge { max }) => assert_eq!(
            max, PROTOCOL_SIZE_LIMIT as u32,
            "the typed error carries the effective limit"
        ),
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}

/// A refused send consumes no Sequence — the next accepted send gets the
/// sequence the refused one would have used.
#[test]
fn refused_send_consumes_no_sequence() {
    let session = offline_session_with_manifest();

    let _ = session.push_sync(vec![0u8; PROTOCOL_SIZE_LIMIT + 1]);
    session
        .push_sync(b"valid".to_vec())
        .expect("valid send after refusal");

    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(undelivered.len(), 1);
    assert_eq!(
        undelivered[0].sequence, 0,
        "the refused send must not have consumed a sequence number"
    );
}

/// A caller may lower the payload limit (e.g. to match a stricter relay);
/// the lower limit is what `send()` enforces and reports (ADR-0025).
#[test]
fn lower_caller_limit_is_honoured() {
    let session = offline_session_with_manifest();

    let effective = session.set_max_payload_bytes(1_024);
    assert_eq!(effective, 1_024);
    assert_eq!(session.max_payload_bytes(), 1_024);

    match session.push_sync(vec![0u8; 1_025]) {
        Err(SessionError::PayloadTooLarge { max }) => {
            assert_eq!(max, 1_024, "the reported limit is the caller's")
        }
        other => panic!("expected PayloadTooLarge {{ max: 1024 }}, got {other:?}"),
    }
    assert!(
        session.push_sync(vec![0u8; 1_024]).is_ok(),
        "a body at the caller's limit is accepted"
    );
}

/// A caller can never raise the limit above the protocol ceiling — a higher
/// requested value is clamped (ADR-0025: "values above the Protocol Size
/// Limit are clamped to it").
#[test]
fn higher_caller_limit_is_clamped() {
    let session = offline_session_with_manifest();

    let effective = session.set_max_payload_bytes(usize::MAX);
    assert_eq!(effective, PROTOCOL_SIZE_LIMIT);
    assert_eq!(session.max_payload_bytes(), PROTOCOL_SIZE_LIMIT);

    assert!(
        matches!(
            session.push_sync(vec![0u8; PROTOCOL_SIZE_LIMIT + 1]),
            Err(SessionError::PayloadTooLarge { max }) if max == PROTOCOL_SIZE_LIMIT as u32
        ),
        "the protocol ceiling still applies after a higher request"
    );
}

/// Each oversize entry is reported exactly once as
/// `sendFailed(tooLarge)` carrying the Message ID the send would have had
/// (ADR-0034 §3) — the entry is removed permanently, so a second load has
/// nothing left to report.
#[test]
fn drop_reports_each_oversize_entry_once() {
    let device = DeviceKeypair::generate();
    let signing_pub = device.signing_public_key().0;
    let recipient = DeviceKeypair::generate();

    let mut log = MemLog::new();
    log.append(
        &recipient.public_key().0,
        3,
        vec![0u8; PROTOCOL_SIZE_LIMIT + 1],
    );
    log.append(
        &recipient.public_key().0,
        4,
        vec![0u8; PROTOCOL_SIZE_LIMIT + 100],
    );
    log.append(&recipient.public_key().0, 5, b"within limit".to_vec());
    let op_log: Arc<Mutex<Box<dyn OperationLog>>> = Arc::new(Mutex::new(Box::new(log)));

    let reports: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(Vec::new()));
    let reports_cb = reports.clone();
    let sink = Arc::new(Mutex::new(IssueSink::new()));
    sink.lock()
        .unwrap_or_else(|e| e.into_inner())
        .subscribe(Box::new(move |issue| {
            reports_cb
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(issue);
        }));

    drop_oversize_outbox_entries(&op_log, &signing_pub, &sink);
    // A second load (e.g. the next process start) reports nothing — the
    // entries are gone.
    drop_oversize_outbox_entries(&op_log, &signing_pub, &sink);

    let fired = reports.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        fired.len(),
        2,
        "exactly one report per oversize entry, none for the valid entry, none on re-load"
    );
    for (issue, seq) in fired.iter().zip([3u64, 4]) {
        match issue {
            DeliveryIssue::SendFailed {
                message_id: id,
                reason,
            } => {
                assert_eq!(*reason, SendFailedReason::TooLarge);
                assert_eq!(
                    *id,
                    message_id(&signing_pub, seq),
                    "the report carries the Message ID the send would have had"
                );
            }
            other => panic!("expected SendFailed, got {other:?}"),
        }
    }

    let remaining = op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].sequence, 5);
}

/// The load-time reports must reach an app that subscribes AFTER the
/// session is constructed — in real usage they fire during
/// `connect_background`, before `subscribe_delivery_issues` can be called,
/// so they are buffered and flushed to the first subscriber. Regression for
/// the review finding that the reports fired to zero subscribers and were
/// lost.
#[test]
fn drop_reports_reach_a_subscriber_after_construction() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let signing_pub = device.signing_public_key().0;
    let remote = DeviceKeypair::generate();

    let mut log = MemLog::new();
    log.append(
        &remote.public_key().0,
        7,
        vec![0u8; PROTOCOL_SIZE_LIMIT + 1],
    );

    let session = TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in size-limit tests".into()),
        None,
        None,
    )
    .expect("offline session");

    let reports: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(Vec::new()));
    let reports_cb = reports.clone();
    session.subscribe_delivery_issues(move |issue| {
        reports_cb
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(issue);
    });

    let fired = reports.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        fired.len(),
        1,
        "the buffered report is flushed to the first subscriber"
    );
    match &fired[0] {
        DeliveryIssue::SendFailed {
            message_id: id,
            reason,
        } => {
            assert_eq!(*reason, SendFailedReason::TooLarge);
            assert_eq!(*id, message_id(&signing_pub, 7));
        }
        other => panic!("expected SendFailed, got {other:?}"),
    }
}

/// The load-time drop works against the real SQLite-backed outbox, not only
/// the in-memory log (the defect lived in persisted dev stores).
#[test]
fn oversize_entry_dropped_from_persistent_log_on_load() {
    let dir = tempfile::TempDir::new().expect("tmp dir");
    let store = crate::store::Store::open(dir.path(), "size-limit").expect("store");
    let mut log = crate::store::PersistentLog::new(store);

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let remote = DeviceKeypair::generate();

    log.append(
        &remote.public_key().0,
        0,
        vec![0u8; PROTOCOL_SIZE_LIMIT + 1],
    );
    log.append(&remote.public_key().0, 1, b"within limit".to_vec());

    let session = TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in size-limit tests".into()),
        None,
        None,
    )
    .expect("offline session");

    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(
        undelivered.len(),
        1,
        "the oversize entry is deleted from the SQLite outbox on load"
    );
    assert_eq!(undelivered[0].sequence, 1);
}

/// ADR-0025: every Message type must fit in one Noise frame. A `Sync` body
/// at exactly the Protocol Size Limit, the largest allowed Group Manifest
/// (Maximum Group Size 32, ADR-0027), a Pair and a Revoke all serialise
/// under the frame ceiling.
#[test]
fn every_message_type_fits_one_frame_at_the_limit() {
    let sender = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let signing = sender.signing_keypair();

    let framed_len = |msg: Message| -> usize {
        build_push_blob(&msg, recipient.public_key(), 1, vec![], &signing)
            .expect("message must fit in one frame")
            .len()
    };

    let sync_framed = build_push_blob(
        &Message::Sync {
            body: vec![0x42u8; PROTOCOL_SIZE_LIMIT],
        },
        recipient.public_key(),
        1,
        vec![],
        &signing,
    )
    .expect("Sync at the Protocol Size Limit must fit one frame");
    assert!(
        sync_framed.len() <= NOISE_FRAME_PLAINTEXT_MAX,
        "Sync at the Protocol Size Limit must fit one frame: {} > {NOISE_FRAME_PLAINTEXT_MAX}",
        sync_framed.len()
    );

    // The restated 65,519 ceiling is only a claim until the real transport
    // agrees: push the frame through an actual trueseal-noise XX session,
    // so a noise-side change to the frame ceiling fails this test.
    let relay_kp = make_relay_kp();
    let relay_kp2 = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    let (client_end, relay_end) = mem_pipe_pair();
    let relay_thread = std::thread::spawn(move || {
        let sess = crate::version::testutil::xx_accept_after_prefix(relay_end, relay_kp2)
            .expect("relay accept");
        sess.receive().expect("receive the framed push")
    });
    let mut transport = client_end;
    let prologue =
        crate::version::exchange_transport_version(&mut transport).expect("prefix exchange");
    let sess = trueseal_noise::session_xx::dial(
        transport,
        trueseal_noise::keypair::Keypair::new(sender.noise.private(), sender.noise.public_key),
        &prologue,
    )
    .expect("dial");
    sess.send(&sync_framed)
        .expect("a Sync at the Protocol Size Limit must fit a real Noise frame");
    let got = relay_thread.join().expect("relay thread panicked");
    assert_eq!(
        got, sync_framed,
        "the frame survives the real session round-trip byte-for-byte"
    );

    // The largest allowed Group Manifest: 32 members (ADR-0027) with
    // realistic derived names.
    let members: Vec<ManifestMember> = (0..32u8)
        .map(|i| ManifestMember {
            noise_pub: NoisePublicKey([i; 32]),
            signing_pub: SigningPublicKey([i.wrapping_mul(7); 32]),
            name: format!("Quiet Ember Device {i:02}"),
        })
        .collect();
    let sk = SigningKey::from_bytes(&sender.signing.to_bytes());
    let manifest = GroupManifest::new(new_group_id(), 1, members, &sk);
    let manifest_len = framed_len(Message::GroupManifest { manifest });
    assert!(
        manifest_len <= NOISE_FRAME_PLAINTEXT_MAX,
        "32-member GroupManifest must fit one frame: {manifest_len} > {NOISE_FRAME_PLAINTEXT_MAX}"
    );

    let pair = framed_len(Message::Pair {
        noise_pub: sender.public_key().0,
        signing_pub: sender.signing_public_key().0,
    });
    assert!(pair <= NOISE_FRAME_PLAINTEXT_MAX, "Pair must fit one frame");

    let revoke = framed_len(Message::Revoke);
    assert!(
        revoke <= NOISE_FRAME_PLAINTEXT_MAX,
        "Revoke must fit one frame"
    );
}
