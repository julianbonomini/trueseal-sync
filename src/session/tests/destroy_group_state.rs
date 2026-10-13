//! SYNC-11 (#103): Destroy Group state machine — ADR-0029's unit-test list
//! and the issue's completion criteria:
//!
//! - Destroying persists and holds with the Relay unreachable, then
//!   delivers and wipes after reconnect (no timeout) — the replay test
//!   lives in `destroy_group.rs`.
//! - Crashes: before commit (nothing changed), after commit / mid-push
//!   (resumes Destroying), mid-wipe (restarts, never double-wipes).
//! - A Revoke from a past member is honoured after that member removed the
//!   initiator; one from a never-held key is ignored.
//! - A concurrently admitted device receives the forwarded Revoke and
//!   wipes; each device forwards at most once (32-member bounds).
//! - Leave then Destroy and Destroy then Leave both end in `notJoined`.
//! - Revoke is ignored in `pendingJoin`, `notJoined` and `destroying`;
//!   replaying a Revoke changes no state (ADR-0034).
//! - No `Sync` is sent and no handler runs while Destroying.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::keys::NoisePublicKey;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::message::Message;
use crate::operation_log::{LogEntry, MemLog, OperationLog, OutboxKind};
use crate::store::{PersistentLog, Store};

use super::super::test_helpers::*;
use super::super::{GroupStatus, SessionError, TruesealSession};

fn member_of(kp: &DeviceKeypair) -> ManifestMember {
    ManifestMember {
        noise_pub: kp.public_key(),
        signing_pub: kp.signing_public_key(),
        name: "m".to_string(),
    }
}

fn sk_of(kp: &DeviceKeypair) -> SigningKey {
    SigningKey::from_bytes(&kp.signing.to_bytes())
}

fn clone_kp(kp: &DeviceKeypair) -> DeviceKeypair {
    DeviceKeypair::from_bytes(kp.noise.private(), kp.signing.to_bytes()).expect("clone keypair")
}

/// A session connected over a ScriptedRelay (scripted inbound delivery)
/// whose NK pushes are accepted and Acked. Returns the destroy-event count
/// alongside.
fn destroy_test_session(
    device: &DeviceKeypair,
) -> (
    TruesealSession<MemPipeSimple>,
    ScriptedRelay,
    Arc<Mutex<u32>>,
) {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let (nk_rx, nk) = nk_push_channel();
    let drain_kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        while let Ok(pipe) = nk_rx.recv() {
            let kp = trueseal_noise::keypair::Keypair::new(drain_kp.private(), drain_kp.public_key);
            std::thread::spawn(move || {
                if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(pipe, kp) {
                    if sess.receive().is_ok() {
                        let _ = sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                    }
                }
            });
        }
    });
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let session = TruesealSession::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        clone_kp(device),
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        nk.factory(),
    )
    .expect("session");
    (session, relay, destroyed)
}

/// Like `destroy_test_session`, but the NK push factory is GATED: closed
/// (pushes fail) until `open()` is called. Intermediate Destroying
/// assertions need determinism — with an immediately-Acking drain the
/// forward can complete and wipe before the assertion reads the state.
fn gated_destroy_session(
    device: &DeviceKeypair,
) -> (
    TruesealSession<MemPipeSimple>,
    ScriptedRelay,
    Arc<Mutex<u32>>,
    Arc<AtomicBool>,
) {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let (nk_rx, nk) = nk_push_channel();
    let drain_kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        while let Ok(pipe) = nk_rx.recv() {
            let kp = trueseal_noise::keypair::Keypair::new(drain_kp.private(), drain_kp.public_key);
            std::thread::spawn(move || {
                if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(pipe, kp) {
                    if sess.receive().is_ok() {
                        let _ = sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                    }
                }
            });
        }
    });
    let gate = Arc::new(AtomicBool::new(false));
    let g = gate.clone();
    let nk_factory = nk.factory();
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let session = TruesealSession::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        clone_kp(device),
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        move || {
            if g.load(Ordering::Acquire) {
                nk_factory()
            } else {
                Err("pushes gated off".to_string())
            }
        },
    )
    .expect("session");
    (session, relay, destroyed, gate)
}

/// Deliver a Revoke from `author` to `recipient` over the scripted relay.
fn deliver_revoke(
    relay: &ScriptedRelay,
    blob_id: u64,
    author: &DeviceKeypair,
    recipient: &DeviceKeypair,
    seq: u64,
) {
    relay.deliver(
        blob_id,
        &Message::Revoke,
        recipient.public_key(),
        &signing_keypair(&author.signing.to_bytes()),
        seq,
    );
}

/// ADR-0029: destroyGroup() persists Destroying and queues one Revoke per
/// member in one transaction; no Sync survives; the state survives a
/// restart while the Relay is unreachable.
#[test]
fn destroy_group_persists_destroying_and_queues_revokes() {
    let dir = tempfile::TempDir::new().unwrap();
    let me = DeviceKeypair::generate();
    let m2 = DeviceKeypair::generate();
    let m3 = DeviceKeypair::generate();
    let my_signing = me.signing_public_key();

    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&me), member_of(&m2), member_of(&m3)],
        &sk_of(&me),
    );

    let relay_kp = make_relay_kp();
    let store = Store::open(dir.path(), "ns").expect("store");
    let log = PersistentLog::new(store);
    let session = TruesealSession::connect_background(
        relay_pub(&relay_kp),
        clone_kp(&me),
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");
    session.set_manifest(v1);

    // A pending Sync send exists and must drop unreported.
    session.push_sync(b"queued".to_vec()).expect("queued");

    session.destroy_group().expect("member can destroy");

    assert_eq!(session.group_status(), GroupStatus::Destroying);
    assert_eq!(
        session.signing_pub(),
        my_signing,
        "no wipe while the Relay is unreachable"
    );
    {
        let log = session.op_log.lock().unwrap();
        assert!(log.destroying().is_some(), "Destroying record persisted");
        let entries = log.undelivered_entries();
        assert_eq!(
            entries.len(),
            2,
            "one Revoke per other member, Sync dropped"
        );
        assert!(entries.iter().all(|e| e.kind == OutboxKind::Control));
        let mut recipients: Vec<[u8; 32]> = entries.iter().map(|e| e.object_id).collect();
        recipients.sort();
        let mut expected = vec![m2.public_key().0, m3.public_key().0];
        expected.sort();
        assert_eq!(recipients, expected);
    }

    // Restart over the same store, still offline: Destroying resumes.
    drop(session);
    let store = Store::open(dir.path(), "ns").expect("store reopen");
    let seeded = store
        .load_group_manifest()
        .expect("load")
        .expect("manifest");
    let log = PersistentLog::new(store);
    let session2 = TruesealSession::connect_background(
        relay_pub(&relay_kp),
        clone_kp(&me),
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(Some(seeded))),
        || {},
        |_| {},
        || {},
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session 2");
    assert_eq!(
        session2.group_status(),
        GroupStatus::Destroying,
        "a crash after the commit resumes Destroying"
    );
    let log = session2.op_log.lock().unwrap();
    assert_eq!(log.undelivered_entries().len(), 2, "Revokes still queued");
}

/// Crash before the commit: a store failure on the Destroying commit is a
/// typed error and changes NOTHING — no in-memory Destroying, no queued
/// Revokes, manifest intact.
#[test]
fn destroy_group_commit_failure_changes_nothing() {
    struct FailingCommitLog {
        inner: MemLog,
    }
    impl OperationLog for FailingCommitLog {
        fn append_entry(&mut self, entry: LogEntry) {
            self.inner.append_entry(entry);
        }
        fn mark_delivered(&mut self, object_id: &[u8; 32], sequence: u64) {
            self.inner.mark_delivered(object_id, sequence);
        }
        fn remove(&mut self, object_id: &[u8; 32], sequence: u64) {
            self.inner.remove(object_id, sequence);
        }
        fn undelivered_entries(&self) -> Vec<LogEntry> {
            self.inner.undelivered_entries()
        }
        fn entries_from(&self, object_id: &[u8; 32], since: u64) -> Vec<LogEntry> {
            self.inner.entries_from(object_id, since)
        }
        fn record_handled(&mut self, message_id: &str, at: u64) {
            self.inner.record_handled(message_id, at);
        }
        fn is_handled(&self, message_id: &str) -> bool {
            self.inner.is_handled(message_id)
        }
        fn handled_at(&self, message_id: &str) -> Option<u64> {
            self.inner.handled_at(message_id)
        }
        fn record_sequence(&mut self, sequence: u64) {
            self.inner.record_sequence(sequence);
        }
        fn max_sequence(&self) -> Option<u64> {
            self.inner.max_sequence()
        }
        fn begin_pending_join(
            &mut self,
            pending: &[u8],
            recipient: &[u8; 32],
            sequence: u64,
            encoded_pair: Vec<u8>,
        ) -> Result<(), String> {
            self.inner
                .begin_pending_join(pending, recipient, sequence, encoded_pair)
        }
        fn pending_join(&self) -> Option<Vec<u8>> {
            self.inner.pending_join()
        }
        fn clear_pending_join(&mut self) {
            self.inner.clear_pending_join();
        }
        fn commit_membership(
            &mut self,
            _commit: crate::operation_log::MembershipCommit,
        ) -> Result<(), String> {
            Err("disk full".to_string())
        }
        fn pending_membership_changes(&self) -> Option<Vec<u8>> {
            self.inner.pending_membership_changes()
        }
        fn is_held_including_self(&self, hash: &[u8; 32]) -> bool {
            self.inner.is_held_including_self(hash)
        }
        fn leaving(&self) -> Option<Vec<u8>> {
            self.inner.leaving()
        }
        fn destroying(&self) -> Option<Vec<u8>> {
            self.inner.destroying()
        }
        fn is_held_signer(&self, signing_pub: &[u8; 32]) -> bool {
            self.inner.is_held_signer(signing_pub)
        }
        fn wipe_group_state(&mut self) {
            self.inner.wipe_group_state();
        }
    }

    let me = DeviceKeypair::generate();
    let other = DeviceKeypair::generate();
    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&me), member_of(&other)],
        &sk_of(&me),
    );
    let relay_kp = make_relay_kp();
    let session = TruesealSession::connect_background(
        relay_pub(&relay_kp),
        clone_kp(&me),
        |_, _, _| {},
        Box::new(FailingCommitLog {
            inner: MemLog::new(),
        }),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");
    // Seed the manifest directly in memory (the store commit fails by
    // design; the state table is about destroyGroup's own commit).
    *session.manifest.lock().unwrap() = Some(v1);

    let result = session.destroy_group();
    assert!(
        matches!(result, Err(SessionError::Store(_))),
        "a failed Destroying commit is a typed Store error, got: {result:?}"
    );
    assert_eq!(
        session.group_status(),
        GroupStatus::Member,
        "nothing changed: still a member"
    );
    let log = session.op_log.lock().unwrap();
    assert!(log.destroying().is_none());
    assert!(log.undelivered_entries().is_empty(), "no Revoke queued");
}

/// Crash mid-wipe / completion at construction: a Destroying record whose
/// Revoke refs already drained completes during session construction —
/// wipe, rotate, one event — and a second restart finds nothing to redo.
#[test]
fn destroy_completes_at_construction_and_never_double_wipes() {
    let dir = tempfile::TempDir::new().unwrap();
    let me = DeviceKeypair::generate();
    let other = DeviceKeypair::generate();
    let my_noise = me.public_key();
    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&me), member_of(&other)],
        &sk_of(&me),
    );

    // Stage: manifest persisted, Destroying record references outbox
    // entries that were never written = already delivered (drained).
    {
        let store = Store::open(dir.path(), "ns").expect("store");
        let mut log = PersistentLog::new(store);
        let record = super::super::DestroyingRecord {
            refs: vec![(other.public_key().0, 7)],
        };
        log.commit_membership(crate::operation_log::MembershipCommit {
            manifest: v1.encode(),
            held: vec![(v1.hash(), true)],
            pending_changes: Vec::new(),
            leaving: None,
            destroying: Some(record.encode()),
            drop_sync_outbox: false,
            outbox: Vec::new(),
        })
        .expect("stage destroying");
        // CRASH: process dies before the completion ran.
    }

    let relay_kp = make_relay_kp();
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let rotated_to: Arc<Mutex<Option<NoisePublicKey>>> = Arc::new(Mutex::new(None));
    let rt = rotated_to.clone();
    let store = Store::open(dir.path(), "ns").expect("store reopen");
    let seeded = store.load_group_manifest().expect("load");
    let log = PersistentLog::new(store);
    let session = TruesealSession::connect_background_rotating(
        relay_pub(&relay_kp),
        clone_kp(&me),
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(seeded)),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        move |fresh| *rt.lock().unwrap() = Some(fresh.public_key()),
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    assert_eq!(
        session.group_status(),
        GroupStatus::NotJoined,
        "a drained Destroying completes at construction"
    );
    assert_eq!(*destroyed.lock().unwrap(), 1, "one destroy event");
    assert_ne!(
        session.noise_pub(),
        my_noise,
        "identity rotated by the completing wipe"
    );
    assert_eq!(
        *rotated_to.lock().unwrap(),
        Some(session.noise_pub()),
        "rotation callback carried the fresh identity"
    );
    // The store is clean: no destroying record, no manifest, no held state.
    {
        let store = Store::open(dir.path(), "ns").expect("check store");
        let log = PersistentLog::new(store);
        assert!(log.destroying().is_none());
        assert!(log.undelivered_entries().is_empty());
        assert!(!log.is_held_signer(&me.signing_public_key().0));
    }

    // A second restart finds nothing to redo: no double wipe, no double
    // event.
    drop(session);
    let destroyed2: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc2 = destroyed2.clone();
    let store = Store::open(dir.path(), "ns").expect("store reopen 2");
    let log = PersistentLog::new(store);
    let session2 = TruesealSession::connect_background_rotating(
        relay_pub(&relay_kp),
        clone_kp(&me),
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        move || {
            *dc2.lock().unwrap() += 1;
        },
        |_| {},
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        || -> Result<MemPipeSimple, String> { Err("offline".into()) },
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session 2");
    assert_eq!(session2.group_status(), GroupStatus::NotJoined);
    assert_eq!(
        *destroyed2.lock().unwrap(),
        0,
        "no second destroy event — the wipe never runs twice"
    );
}

/// ADR-0029: the thief removes the owner first — a Revoke from a PAST
/// member is still honoured. C held v1 = {A, T, C}; the thief T issues v2
/// excluding the owner A; then A's Revoke arrives. C honours it (A is in
/// C's held history), forwards to its own view, and wipes.
#[test]
fn revoke_from_past_member_is_honoured_after_their_removal() {
    let owner = DeviceKeypair::generate();
    let thief = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let stranger = DeviceKeypair::generate();
    let c_signing_before = c.signing_public_key();

    let (session_c, relay_c, destroyed, gate) = gated_destroy_session(&c);

    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&owner), member_of(&thief), member_of(&c)],
        &sk_of(&owner),
    );
    session_c.set_manifest(v1.clone());

    // The thief removes the owner: v2 excludes A. C accepts it (the thief
    // is a fully-trusted member, ADR-0027).
    let v2 = GroupManifest::update(&v1, vec![member_of(&thief), member_of(&c)], &sk_of(&thief))
        .expect("v2");
    relay_c.deliver(
        1,
        &Message::GroupManifest {
            manifest: v2.clone(),
        },
        c.public_key(),
        &signing_keypair(&thief.signing.to_bytes()),
        500,
    );
    wait_for(
        || {
            session_c
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.hash())
                == Some(v2.hash())
        },
        Duration::from_secs(20),
    );

    // A Revoke from a key that never appeared in any held manifest is
    // ignored (no state change, nothing queued).
    deliver_revoke(&relay_c, 2, &stranger, &c, 900);
    wait_for(
        || relay_c.deliver_acks().contains(&2),
        Duration::from_secs(20),
    );
    assert_eq!(session_c.group_status(), GroupStatus::Member);
    assert!(
        session_c
            .op_log
            .lock()
            .unwrap()
            .undelivered_entries()
            .is_empty(),
        "a stranger's Revoke queues nothing"
    );

    // The removed owner's Revoke IS honoured: C enters Destroying and
    // forwards to its own view except the author (v2 = {T, C} → forward
    // to T). Pushes are gated off, so the intermediate state is stable.
    deliver_revoke(&relay_c, 3, &owner, &c, 901);
    wait_for(
        || session_c.group_status() == GroupStatus::Destroying,
        Duration::from_secs(20),
    );
    {
        let log = session_c.op_log.lock().unwrap();
        let entries = log.undelivered_entries();
        assert_eq!(entries.len(), 1, "one forward queued");
        assert_eq!(
            entries[0].object_id,
            thief.public_key().0,
            "the forward goes to the thief — the concurrently-changed member"
        );
    }
    // The Relay accepts the forward: completion wipes and rotates.
    gate.store(true, Ordering::Release);
    wait_for(|| *destroyed.lock().unwrap() == 1, Duration::from_secs(20));
    assert_eq!(session_c.group_status(), GroupStatus::NotJoined);
    assert_ne!(
        session_c.signing_pub(),
        c_signing_before,
        "the receiving device wipes and rotates"
    );
}

/// ADR-0029: forwarding reaches a concurrently admitted device missing from
/// the initiator's view. A's view is {A, B}; B admitted C (view {A, B, C})
/// concurrently. A destroys → B forwards → C wipes. Every device ends
/// notJoined with a fresh identity; each fires its event exactly once.
#[test]
fn forwarded_revoke_reaches_concurrently_admitted_device() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let c_signing_before = c.signing_public_key();

    let relay_kp = make_relay_kp();
    let (nk_rx, nk) = nk_push_channel();
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    spawn_mesh_relay(
        &relay_kp,
        vec![pipe_a_relay, pipe_b_relay, pipe_c_relay],
        nk_rx,
    );

    let events: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let mk_cb = |tag: &'static str| {
        let events = events.clone();
        move || events.lock().unwrap().push(tag)
    };

    let session_a = TruesealSession::connect_full(
        pipe_a_client,
        relay_pub(&relay_kp),
        clone_kp(&a),
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        mk_cb("a"),
        nk.factory(),
    )
    .expect("A");
    let session_b = TruesealSession::connect_full(
        pipe_b_client,
        relay_pub(&relay_kp),
        clone_kp(&b),
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        mk_cb("b"),
        nk.factory(),
    )
    .expect("B");
    let session_c = TruesealSession::connect_full(
        pipe_c_client,
        relay_pub(&relay_kp),
        clone_kp(&c),
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        mk_cb("c"),
        nk.factory(),
    )
    .expect("C");

    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&a), member_of(&b)],
        &sk_of(&a),
    );
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1.clone());

    // B admits C concurrently: B and C move to v2 = {A, B, C}; A's view
    // still lacks C.
    let v2 = GroupManifest::update(
        &v1,
        vec![member_of(&a), member_of(&b), member_of(&c)],
        &sk_of(&b),
    )
    .expect("v2");
    session_b.set_manifest(v2.clone());
    session_c.set_manifest(v2);

    session_a.destroy_group().expect("A destroys");

    // A's Revoke reaches only B; B forwards to C; C forwards to A (already
    // Destroying — ignored). All three wipe exactly once.
    wait_for(
        || {
            let ev = events.lock().unwrap();
            ev.contains(&"a") && ev.contains(&"b") && ev.contains(&"c")
        },
        Duration::from_secs(20),
    );
    for (name, session) in [("a", &session_a), ("b", &session_b), ("c", &session_c)] {
        assert_eq!(
            session.group_status(),
            GroupStatus::NotJoined,
            "{name} wiped to notJoined"
        );
    }
    assert_ne!(
        session_c.signing_pub(),
        c_signing_before,
        "the concurrently admitted device rotated its identity"
    );
    // Each device forwarded / fired at most once.
    std::thread::sleep(Duration::from_millis(300));
    let ev = events.lock().unwrap();
    assert_eq!(ev.len(), 3, "exactly one destroy event per device: {ev:?}");
}

/// ADR-0029 state table: a Revoke is ignored in `notJoined` and
/// `pendingJoin` (no manifest to check the author against).
#[test]
fn revoke_ignored_in_not_joined_and_pending_join() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let (session_a, _relay_a, _d_a) = destroy_test_session(&a);
    let (session_b, relay_b, destroyed_b, _gate_b) = gated_destroy_session(&b);

    // notJoined: no manifest at all.
    deliver_revoke(&relay_b, 1, &a, &b, 900);
    wait_for(
        || relay_b.deliver_acks().contains(&1),
        Duration::from_secs(20),
    );
    assert_eq!(session_b.group_status(), GroupStatus::NotJoined);
    assert!(session_b.op_log.lock().unwrap().destroying().is_none());

    // pendingJoin: B asked to join via A's token and is waiting.
    let token = session_a.pairing_token();
    session_b.join_group(&token).expect("join");
    assert_eq!(session_b.group_status(), GroupStatus::PendingJoin);
    let control_before = session_b.op_log.lock().unwrap().undelivered_entries().len();
    deliver_revoke(&relay_b, 2, &a, &b, 901);
    wait_for(
        || relay_b.deliver_acks().contains(&2),
        Duration::from_secs(20),
    );
    assert_eq!(
        session_b.group_status(),
        GroupStatus::PendingJoin,
        "a Revoke does not disturb a Pending Join"
    );
    assert_eq!(*destroyed_b.lock().unwrap(), 0);
    assert_eq!(
        session_b.op_log.lock().unwrap().undelivered_entries().len(),
        control_before,
        "nothing queued"
    );
}

/// ADR-0034 / ADR-0029: replaying a Revoke changes no state, and a second
/// valid Revoke while Destroying is ignored — each device forwards at most
/// once.
#[test]
fn replayed_revoke_forwards_at_most_once() {
    let a = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let d = DeviceKeypair::generate();
    let (session_c, relay_c, destroyed, gate) = gated_destroy_session(&c);

    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&a), member_of(&c), member_of(&d)],
        &sk_of(&a),
    );
    session_c.set_manifest(v1);

    deliver_revoke(&relay_c, 1, &a, &c, 900);
    wait_for(
        || session_c.group_status() == GroupStatus::Destroying,
        Duration::from_secs(20),
    );
    let forwards = || session_c.op_log.lock().unwrap().undelivered_entries().len();
    assert_eq!(forwards(), 1, "one forward queued (to D)");

    // The same Envelope re-delivered (new blob id), and a DIFFERENT held
    // member's Revoke: both ignored — no new forwards.
    deliver_revoke(&relay_c, 2, &a, &c, 900);
    deliver_revoke(&relay_c, 3, &d, &c, 700);
    wait_for(
        || relay_c.deliver_acks().contains(&2) && relay_c.deliver_acks().contains(&3),
        Duration::from_secs(20),
    );
    assert_eq!(forwards(), 1, "no second forward round");

    // Once pushes flow, completion happens exactly once.
    gate.store(true, Ordering::Release);
    wait_for(|| *destroyed.lock().unwrap() == 1, Duration::from_secs(20));
    assert_eq!(session_c.group_status(), GroupStatus::NotJoined);
    assert_eq!(*destroyed.lock().unwrap(), 1);
}

/// ADR-0029: at the Maximum Group Size the initiator queues one Revoke per
/// other member (31) and a receiver forwards one round to its view except
/// the author (30) — never a second round.
#[test]
fn group_of_32_forwards_one_round_per_device() {
    let members: Vec<DeviceKeypair> = (0..32).map(|_| DeviceKeypair::generate()).collect();
    let a = &members[0];
    let c = &members[31];
    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        members.iter().map(member_of).collect(),
        &sk_of(a),
    );

    // Initiator side: 31 Revokes queued. (Pushes gated: the count must be
    // read before any drain.)
    let (session_a, _relay_a, _d_a, _gate_a) = gated_destroy_session(a);
    session_a.set_manifest(v1.clone());
    session_a.destroy_group().expect("destroy");
    assert_eq!(
        session_a.op_log.lock().unwrap().undelivered_entries().len(),
        31,
        "initiator queues one Revoke per other member"
    );

    // Receiver side: 30 forwards (32 minus author, minus self), and a
    // replay adds none.
    let (session_c, relay_c, _d_c, _gate_c) = gated_destroy_session(c);
    session_c.set_manifest(v1);
    deliver_revoke(&relay_c, 1, a, c, 900);
    wait_for(
        || session_c.group_status() == GroupStatus::Destroying,
        Duration::from_secs(20),
    );
    let forwards = || session_c.op_log.lock().unwrap().undelivered_entries().len();
    assert_eq!(forwards(), 30, "one forward round to the receiver's view");
    deliver_revoke(&relay_c, 2, a, c, 900);
    wait_for(
        || relay_c.deliver_acks().contains(&2),
        Duration::from_secs(20),
    );
    assert_eq!(forwards(), 30, "a replay adds no forwards");
}

/// ADR-0029 state table: Leave then Destroy — the Leave is abandoned and
/// the Destroy completes to `notJoined`. Destroy then Leave — a typed
/// error; the Destroy completes to `notJoined`.
#[test]
fn leave_then_destroy_and_destroy_then_leave_end_in_not_joined() {
    let relay_kp = make_relay_kp();
    let me = DeviceKeypair::generate();
    let other = DeviceKeypair::generate();
    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&me), member_of(&other)],
        &sk_of(&me),
    );

    // ── Leave, then Destroy ──────────────────────────────────────────────
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_single_relay(&relay_kp, pipe_relay, nk_rx);
    let online = Arc::new(AtomicBool::new(false));
    let pipe_slot: Arc<Mutex<Option<MemPipeSimple>>> = Arc::new(Mutex::new(Some(pipe_client)));
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let on = online.clone();
    let on_push = online.clone();
    let slot = pipe_slot.clone();
    let nk_factory = nk.factory();
    let session = TruesealSession::connect_background(
        relay_pub(&relay_kp),
        clone_kp(&me),
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        move || {
            if on.load(Ordering::Acquire) {
                slot.lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| "exhausted".to_string())
            } else {
                Err("offline".to_string())
            }
        },
        move || {
            if on_push.load(Ordering::Acquire) {
                nk_factory()
            } else {
                Err("offline".to_string())
            }
        },
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");
    session.set_manifest(v1.clone());

    session.leave_group().expect("leave");
    assert_eq!(session.group_status(), GroupStatus::Leaving);
    assert!(session.op_log.lock().unwrap().leaving().is_some());

    session.destroy_group().expect("destroy while Leaving");
    assert_eq!(
        session.group_status(),
        GroupStatus::Destroying,
        "Destroy supersedes Leave"
    );
    assert!(
        session
            .op_log
            .lock()
            .unwrap()
            .leaving()
            .and_then(|b| super::super::LeavingRecord::decode(&b))
            .is_none(),
        "the Leave is abandoned (empty record decodes as absent)"
    );
    assert!(
        session.op_log.lock().unwrap().destroying().is_some(),
        "the Destroying record is persisted"
    );

    // Online: the pump pushes the queued control entries (the abandoned
    // Leave manifest pushes too — harmless), the Relay accepts everything,
    // the Destroy completes.
    online.store(true, Ordering::Release);
    wait_for(|| *destroyed.lock().unwrap() == 1, Duration::from_secs(20));
    assert_eq!(session.group_status(), GroupStatus::NotJoined);
    drop(session);

    // ── Destroy, then Leave ──────────────────────────────────────────────
    let (session2, _relay2, destroyed2) = destroy_test_session(&me);
    session2.set_manifest(v1);
    session2.destroy_group().expect("destroy");
    let result = session2.leave_group();
    assert!(
        matches!(result, Err(SessionError::GroupDestroyed)),
        "Leave while Destroying is a typed error, got: {result:?}"
    );
    wait_for(|| *destroyed2.lock().unwrap() == 1, Duration::from_secs(20));
    assert_eq!(session2.group_status(), GroupStatus::NotJoined);
}

/// ADR-0029 state table: a Leaving device that receives a valid Revoke
/// moves to Destroying and forwards (the Leave is abandoned).
#[test]
fn leaving_device_forwards_revoke_and_destroys() {
    let a = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let d = DeviceKeypair::generate();
    let (session_c, relay_c, destroyed, _gate) = gated_destroy_session(&c);

    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&a), member_of(&c), member_of(&d)],
        &sk_of(&a),
    );
    session_c.set_manifest(v1);

    // C leaves; pushes are gated off, so the Leave holds.
    session_c.leave_group().expect("leave");
    assert_eq!(session_c.group_status(), GroupStatus::Leaving);

    deliver_revoke(&relay_c, 1, &a, &c, 900);
    wait_for(
        || session_c.group_status() == GroupStatus::Destroying,
        Duration::from_secs(20),
    );
    {
        let log = session_c.op_log.lock().unwrap();
        assert!(
            log.leaving()
                .and_then(|b| super::super::LeavingRecord::decode(&b))
                .is_none(),
            "the Leave is abandoned"
        );
        assert!(log.destroying().is_some(), "Destroying record persisted");
        // The forward to D (view minus author A, minus self C) is queued
        // alongside the still-undelivered Leave pushes.
        let entries = log.undelivered_entries();
        assert!(
            entries.iter().any(|e| e.object_id == d.public_key().0),
            "the Revoke is forwarded to the rest of the view"
        );
    }
    // Pushes are gated: no completion, no event, Destroying holds.
    assert_eq!(*destroyed.lock().unwrap(), 0);
    assert_eq!(session_c.group_status(), GroupStatus::Destroying);
}

/// ADR-0029: no handler runs while Destroying — an inbound Sync is
/// dedup-recorded and acked, never delivered to the app.
#[test]
fn no_handler_runs_while_destroying() {
    let a = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let d = DeviceKeypair::generate();

    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let handled: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let h = handled.clone();
    let destroyed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let dc = destroyed.clone();
    let session_c = TruesealSession::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        clone_kp(&c),
        move |_, _, _| {
            *h.lock().unwrap() += 1;
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        move || {
            *dc.lock().unwrap() += 1;
        },
        // Pushes never drain: C stays Destroying (a third member keeps the
        // forward non-empty, so completion cannot fire before the Sync
        // arrives).
        || -> Result<MemPipeSimple, String> { Err("pushes offline".into()) },
    )
    .expect("C");
    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(&a), member_of(&c), member_of(&d)],
        &sk_of(&a),
    );
    session_c.set_manifest(v1);

    deliver_revoke(&relay, 1, &a, &c, 900);
    wait_for(
        || session_c.group_status() == GroupStatus::Destroying,
        Duration::from_secs(20),
    );

    // A Sync from a member arrives mid-Destroy: acked, never handled.
    relay.deliver(
        2,
        &Message::Sync {
            body: b"app data".to_vec(),
        },
        c.public_key(),
        &signing_keypair(&a.signing.to_bytes()),
        901,
    );
    wait_for(
        || relay.deliver_acks().contains(&2),
        Duration::from_secs(20),
    );
    assert_eq!(
        session_c.group_status(),
        GroupStatus::Destroying,
        "still Destroying when the Sync arrives"
    );
    assert_eq!(
        *handled.lock().unwrap(),
        0,
        "no handler runs while Destroying"
    );
}
