//! SYNC-13 (#105, ADR-0032 + ADR-0034 §1): the End-to-End bump re-seal at
//! the session seam.
//!
//! The store tests prove the migration transaction rewrites queued
//! manifests and leaves `Sync`/`Pair`/`Revoke` rows byte-identical. This
//! test proves the headline criterion end to end: a `Sync` entry queued
//! before a simulated End-to-End bump is delivered after the upgrade —
//! exactly once, with its original Message ID and Sender Timestamp.
//!
//! The bump is simulated at the store layer (`Store::open_inner` with the
//! next End-to-End Version): production has only one End-to-End Version (1,
//! ADR-0022), and the envelope-level re-seal is structural — this build
//! seals at push time from the stored body, stamped at `created_at`
//! (ADR-0034 §2), so the first push after the migration IS the re-seal.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::message::{message_id, Message};
use crate::operation_log::{LogEntry, OperationLog, OutboxKind};
use crate::relay::{frame, parse, MsgType};
use crate::store::{OpenOutcome, PersistentLog, Store};
use crate::version::testutil::xx_accept_after_prefix;
use trueseal_noise::keypair::Keypair;

use super::super::test_helpers::*;
use super::super::TruesealSession;

fn member_of(kp: &DeviceKeypair) -> ManifestMember {
    let sp = kp.signing_public_key();
    ManifestMember {
        noise_pub: kp.public_key(),
        signing_pub: sp,
        name: member_name(&sp),
    }
}

#[test]
fn sync_queued_before_e2e_bump_is_delivered_once_with_original_id_and_stamp() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise_priv = device_b.noise.private();
    let b_noise = device_b.public_key();
    let a_signing_pub = device_a.signing_public_key();

    let a_sk = ed25519_dalek::SigningKey::from_bytes(&device_a.signing.to_bytes());
    let manifest = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&device_a), member_of(&device_b)],
        &a_sk,
    );

    // ── A queues a Sync offline (the exact row send() writes), pre-bump ─────
    let dir_a = tempfile::TempDir::new().unwrap();
    let queued_created_at = {
        let s = Store::open(dir_a.path(), "a").expect("store A");
        s.save_keypair(&device_a).expect("save keypair");
        s.save_group_manifest(&manifest).expect("save manifest");
        let mut log = PersistentLog::new(s);
        log.append_entry(LogEntry {
            object_id: b_noise.0,
            sequence: 1,
            kind: OutboxKind::Sync,
            created_at: crate::operation_log::now_secs(),
            blob: b"queued before the upgrade".to_vec(),
        });
        // Read the stamped queue time back for the timestamp assertion.
        let s2 = Store::open(dir_a.path(), "a").expect("reopen");
        PersistentLog::new(s2).undelivered_entries()[0].created_at
    };

    // ── The simulated End-to-End bump: migrate the store to e2e v2 ──────────
    {
        let (_s, outcome) = Store::open_inner(
            dir_a.path(),
            "a",
            crate::version::STORE_VERSION,
            crate::version::END_TO_END_VERSION + 1,
            &[],
        )
        .expect("migration open");
        assert_eq!(
            outcome.resealed_from_e2e,
            Some(crate::version::END_TO_END_VERSION),
            "the re-seal ran"
        );
        let _ = outcome;
    }

    // ── Relay: bidirectional A↔B with an NK router, capturing pushed bytes ──
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![]));
    {
        let captured = captured.clone();
        let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_priv = relay_kp.private();
        let relay_pub_key = relay_kp.public_key;
        std::thread::spawn(move || {
            let sess_a = xx_accept_after_prefix(pipe_a_relay, relay_kp_a).unwrap();
            let sess_b = xx_accept_after_prefix(pipe_b_relay, relay_kp_b).unwrap();
            let a_noise = sess_a.remote_public_key();
            let b_noise = sess_b.remote_public_key();
            let sess_a = Arc::new(sess_a);
            let sess_b = Arc::new(sess_b);
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let sa = sess_a.clone();
                let sb = sess_b.clone();
                let captured = captured.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp)
                    {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                if body.len() < 32 {
                                    return;
                                }
                                captured.lock().unwrap().push(body[32..].to_vec());
                                let recipient_pub = &body[0..32];
                                let mut d = 0u64.to_be_bytes().to_vec();
                                d.extend_from_slice(&body[32..]);
                                let framed = frame(MsgType::Deliver, &d);
                                if recipient_pub == a_noise {
                                    let _ = sa.send(&framed);
                                } else if recipient_pub == b_noise {
                                    let _ = sb.send(&framed);
                                }
                                let _ = sess.send(&frame(MsgType::Ack, &[]));
                            }
                        }
                    }
                });
            }
        });
    }

    // ── B: seeded manifest, records deliveries ───────────────────────────────
    let received: Arc<Mutex<Vec<(Vec<u8>, String)>>> = Arc::new(Mutex::new(vec![]));
    let rc = received.clone();
    let _session_b = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_b,
        move |msg, author_signing_pub, sequence| {
            if let Message::Sync { body } = msg {
                rc.lock()
                    .unwrap()
                    .push((body, message_id(&author_signing_pub, sequence)));
            }
        },
        Box::new(crate::operation_log::MemLog::new()),
        Arc::new(Mutex::new(Some(manifest.clone()))),
        || {},
        |_| {},
        || {},
        {
            let pipe: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_b_client)));
            move || {
                pipe.lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            }
        },
        nk.factory(),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session B");

    // ── A restarts post-upgrade: same keys, same store, pump re-seals ───────
    let a_noise_priv = device_a.noise.private();
    let a_signing_priv = device_a.signing.to_bytes();
    let device_a2 = DeviceKeypair::from_bytes(a_noise_priv, a_signing_priv).expect("same keys");
    let _session_a = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_a2,
        |_, _, _| {},
        Box::new(PersistentLog::new(
            Store::open(dir_a.path(), "a").expect("A's store, post-migration"),
        )),
        Arc::new(Mutex::new(Some(manifest))),
        || {},
        |_| {},
        || {},
        {
            let pipe: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_a_client)));
            move || {
                pipe.lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            }
        },
        nk.factory(),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session A");

    // ── Exactly once, with the original Message ID ───────────────────────────
    let expected_id = message_id(&a_signing_pub.0, 1);
    wait_for(
        || !received.lock().unwrap().is_empty(),
        Duration::from_secs(10),
    );
    {
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1, "delivered exactly once");
        assert_eq!(got[0].0, b"queued before the upgrade");
        assert_eq!(got[0].1, expected_id, "original Message ID");
    }
    // No duplicate arrives from a re-seal or a retry.
    let dup_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < dup_deadline {
        assert!(
            received.lock().unwrap().len() == 1,
            "no second delivery of the migrated entry"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // ── The pushed copy kept the send()-time Sender Timestamp ────────────────
    wait_for(
        || !captured.lock().unwrap().is_empty(),
        Duration::from_secs(10),
    );
    let envelope_bytes = &captured.lock().unwrap()[0];
    let envelope = crate::envelope::Envelope::decode(envelope_bytes).expect("envelope decodes");
    assert_eq!(
        envelope.version,
        crate::version::END_TO_END_VERSION,
        "sealed under the current version at push (structural re-seal)"
    );
    let sealed = envelope
        .open_sealed(b_noise_priv)
        .expect("B opens the sealed content");
    assert_eq!(
        sealed.sender_timestamp_ms,
        queued_created_at.saturating_mul(1000),
        "ADR-0034 §2: the Sync entry kept its send() stamp through the upgrade"
    );

    // ── The queued entry is gone after acceptance (nothing to re-deliver) ────
    wait_for(
        || {
            PersistentLog::new(Store::open(dir_a.path(), "a").expect("check"))
                .undelivered_entries()
                .is_empty()
        },
        Duration::from_secs(10),
    );
}

/// A store reset mid-flight empties the outbox: after the automatic reset a
/// fresh identity is in place and nothing queued by the old identity leaks
/// into the new group's outbox (ADR-0032).
#[test]
fn store_reset_clears_everything_and_reopen_is_clean() {
    let dir = tempfile::TempDir::new().unwrap();
    {
        let s = Store::open(dir.path(), "ns").expect("open");
        let kp = DeviceKeypair::generate();
        s.save_keypair(&kp).expect("save");
        let mut log = PersistentLog::new(s);
        log.append(&[9u8; 32], 1, b"queued".to_vec());
        // Lose the version keys → unversioned (a dev-build store).
        let conn = rusqlite::Connection::open(dir.path().join("trueseal_ns.db")).unwrap();
        conn.execute(
            "DELETE FROM meta WHERE key IN ('store_version', 'e2e_version')",
            [],
        )
        .unwrap();
    }
    let (s, outcome) = Store::open_with_outcome(dir.path(), "ns").expect("reset open");
    assert!(outcome.reset);
    assert_eq!(outcome.migrated_from, None);
    assert_eq!(outcome.resealed_from_e2e, None);
    assert!(s.load_keypair().expect("load").is_none());
    assert!(PersistentLog::new(s).undelivered_entries().is_empty());
    // Reopen is a clean, current store.
    let (_s2, outcome2) = Store::open_with_outcome(dir.path(), "ns").expect("reopen");
    assert_eq!(outcome2, OpenOutcome::default());
}
