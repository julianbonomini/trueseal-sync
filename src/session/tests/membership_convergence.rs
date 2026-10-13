//! SYNC-9 (#101): session-level membership convergence tests — the ADR-0027
//! Consequences list:
//!
//! - concurrent admit and remove converge on every device;
//! - an equal-version tie resolves the same way everywhere (the tie rule
//!   itself is covered by manifest-level tests and
//!   `manifest_filter::concurrent_manifest_conflict_last_version_wins`);
//! - a concurrently overwritten change is re-applied after an issuer
//!   restart and after an offline period;
//! - a deliberate later removal is not undone;
//! - a joiner that loses a tie does not wipe itself (false removal);
//! - Leave resumes after a crash;
//! - a 32-member manifest fits in a frame and a 33rd admission is refused;
//! - a replayed old Group Manifest changes no state (ADR-0034 §2);
//! - Group Status includes `leaving`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::{member_id, member_name};
use crate::message::Message;
use crate::operation_log::{MemLog, OperationLog};
use crate::store::{PersistentLog, Store};

use super::super::test_helpers::*;
use super::super::{GroupStatus, PendingChange, PendingIntent, SessionError, TruesealSession};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn member_of(kp: &DeviceKeypair) -> ManifestMember {
    let sp = kp.signing_public_key();
    ManifestMember {
        noise_pub: kp.public_key(),
        signing_pub: sp,
        name: member_name(&sp),
    }
}

fn clone_kp(kp: &DeviceKeypair) -> DeviceKeypair {
    DeviceKeypair::from_bytes(kp.noise.private(), kp.signing.to_bytes()).expect("clone keypair")
}

/// A session behind a ScriptedRelay: envelopes are delivered on demand; NK
/// pushes are accepted and acked so the outbox drains.
fn scripted_session(
    device: &DeviceKeypair,
) -> (
    TruesealSession<MemPipeSimple>,
    ScriptedRelay,
    Arc<Mutex<Vec<crate::delivery_issue::DeliveryIssue>>>,
) {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let (nk_rx, nk) = nk_push_channel();
    let drain_kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        while let Ok(pipe) = nk_rx.recv() {
            let kp = Keypair::new(drain_kp.private(), drain_kp.public_key);
            std::thread::spawn(move || {
                if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(pipe, kp) {
                    if sess.receive().is_ok() {
                        let _ = sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                    }
                }
            });
        }
    });
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        clone_kp(device),
        |_, _, _| {},
        nk.factory(),
    )
    .expect("scripted session");
    let issues: Arc<Mutex<Vec<crate::delivery_issue::DeliveryIssue>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = issues.clone();
    session.subscribe_delivery_issues(move |issue| sink.lock().unwrap().push(issue));
    (session, relay, issues)
}

use trueseal_noise::keypair::Keypair;

/// Genesis of `{a, b}` signed by `a`.
fn genesis_ab(a: &DeviceKeypair, b: &DeviceKeypair) -> GroupManifest {
    GroupManifest::new(
        new_group_id(),
        1,
        vec![member_of(a), member_of(b)],
        &SigningKey::from_bytes(&a.signing.to_bytes()),
    )
}

fn manifest_of(session: &TruesealSession<MemPipeSimple>) -> GroupManifest {
    session
        .manifest
        .lock()
        .unwrap()
        .clone()
        .expect("session holds a manifest")
}

fn deliver_manifest(
    relay: &ScriptedRelay,
    blob_id: u64,
    manifest: &GroupManifest,
    recipient: &DeviceKeypair,
    issuer: &DeviceKeypair,
    seq: u64,
) {
    relay.deliver(
        blob_id,
        &Message::GroupManifest {
            manifest: manifest.clone(),
        },
        recipient.public_key(),
        &signing_keypair(&issuer.signing.to_bytes()),
        seq,
    );
}

// ── Convergence ─────────────────────────────────────────────────────────────

/// ADR-0027: two members admit concurrently; the loser's change is
/// re-applied on the winner and every member converges on one manifest —
/// no change is lost.
#[test]
fn concurrent_admissions_converge_on_every_member() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let d = DeviceKeypair::generate();

    let (session_a, relay_a, _ia) = scripted_session(&a);
    let (session_b, relay_b, _ib) = scripted_session(&b);
    let v1 = genesis_ab(&a, &b);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1.clone());

    // A admits C; B admits D — concurrently (neither has seen the other).
    session_a.pairing_token();
    assert!(session_a
        .accept_pair(c.public_key(), c.signing_public_key())
        .expect("A admits C"));
    session_b.pairing_token();
    assert!(session_b
        .accept_pair(d.public_key(), d.signing_public_key())
        .expect("B admits D"));

    let v2a = manifest_of(&session_a); // {A, B, C}
    let v2b = manifest_of(&session_b); // {A, B, D}
    assert_eq!(v2a.version, 2);
    assert_eq!(v2b.version, 2);
    assert!(v2a.contains_signing_pub(&c.signing_public_key().0));
    assert!(v2b.contains_signing_pub(&d.signing_public_key().0));

    // Cross-deliver the concurrent manifests. The lower hash wins the tie;
    // whoever holds the loser accepts the winner and re-applies.
    deliver_manifest(&relay_b, 1, &v2a, &b, &a, 1);
    deliver_manifest(&relay_a, 2, &v2b, &a, &b, 1);

    // The lower hash wins the tie. The loser's session accepted the
    // winner above and must now re-apply its admission as v3.
    let a_won = v2a.hash() < v2b.hash();
    let winner = if a_won { &v2a } else { &v2b };
    let (loser_session, loser_device) = if a_won {
        (&session_b, &b)
    } else {
        (&session_a, &a)
    };
    let (winner_session, winner_relay, winner_device) = if a_won {
        (&session_a, &relay_a, &a)
    } else {
        (&session_b, &relay_b, &b)
    };

    // The loser re-applies: its manifest becomes version 3 with both
    // admissions.
    wait_for(
        || {
            loser_session
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.version == 3)
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    let v3 = manifest_of(loser_session);
    assert!(
        v3.contains_signing_pub(&c.signing_public_key().0),
        "C survives"
    );
    assert!(
        v3.contains_signing_pub(&d.signing_public_key().0),
        "D re-applied"
    );
    assert_eq!(
        v3.parent,
        Some(winner.hash()),
        "re-application builds on the winner"
    );

    // The re-application is pushed; deliver it to the winner's session so
    // both converge on the identical manifest.
    deliver_manifest(winner_relay, 3, &v3, winner_device, loser_device, 2);
    wait_for(
        || {
            winner_session
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.hash() == v3.hash())
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );

    assert_eq!(
        manifest_of(&session_a).hash(),
        manifest_of(&session_b).hash(),
        "both members hold the identical manifest — the changes converged"
    );
}

/// ADR-0027: a Pending Membership Change survives an issuer restart (and
/// the offline period before it) and is re-applied when the concurrent
/// manifest finally arrives.
#[test]
fn overwritten_change_reapplied_after_issuer_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let d = DeviceKeypair::generate();
    let a_signing = a.signing_public_key();

    let v1 = genesis_ab(&a, &b);
    let v2a; // A's admission of C
    {
        let store = Store::open(dir.path(), "ns").expect("store");
        let log = PersistentLog::new(store);
        let (session_a, _relay_a, _i) = {
            let relay_kp = make_relay_kp();
            let (pipe_client, pipe_relay) = mem_pipe_pair();
            let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
            let (_nk_rx, nk) = nk_push_channel(); // pushes go nowhere: A is "offline"
            let s = TruesealSession::connect_with_log(
                pipe_client,
                relay_pub(&relay_kp),
                clone_kp(&a),
                |_, _, _| {},
                Box::new(log),
                nk.factory(),
            )
            .expect("A phase 1");
            (s, relay, ())
        };
        session_a.set_manifest(v1.clone());
        session_a.pairing_token();
        assert!(session_a
            .accept_pair(c.public_key(), c.signing_public_key())
            .expect("A admits C"));
        v2a = manifest_of(&session_a);
        // The pending change is persisted before the "crash".
        let stored = {
            let log = session_a.op_log.lock().unwrap();
            log.pending_membership_changes()
                .expect("pending change persisted")
        };
        let decoded = PendingChange::decode_set(&stored).expect("decodes");
        assert_eq!(decoded.len(), 1);
        assert!(matches!(decoded[0].intent, PendingIntent::Admit(_)));
        assert_eq!(decoded[0].carrier, v2a.hash());
        // CRASH: session_a drops here.
    }

    // Restart: a new session over the same store. The pending change is
    // loaded; the manifest slot is seeded (the FFI's SYNC-7 pattern).
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_a2 = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let (_nk_rx, nk) = nk_push_channel();
    let store = Store::open(dir.path(), "ns").expect("store reopen");
    let log = PersistentLog::new(store);
    let session_a2 = TruesealSession::connect_with_log(
        pipe_client,
        relay_pub(&relay_kp),
        clone_kp(&a),
        |_, _, _| {},
        Box::new(log),
        nk.factory(),
    )
    .expect("A phase 2");
    session_a2.set_manifest(v2a.clone());
    assert_eq!(
        session_a2.signing_pub(),
        a_signing,
        "same identity after restart"
    );

    // B's concurrent manifest wins the tie (regenerate D-side ordering
    // until it does — the test needs W to unseat A's v2).
    let b_sk = SigningKey::from_bytes(&b.signing.to_bytes());
    let mut w = GroupManifest::update(
        &v1,
        vec![member_of(&a), member_of(&b), member_of(&d)],
        &b_sk,
    )
    .expect("W");
    let mut attempts = 0;
    while w.hash() >= v2a.hash() {
        attempts += 1;
        let renamed = ManifestMember {
            name: format!("{}-{attempts}", member_of(&d).name),
            ..member_of(&d)
        };
        w = GroupManifest::update(&v1, vec![member_of(&a), member_of(&b), renamed], &b_sk)
            .expect("W retry");
        assert!(attempts < 100, "hash tie-break should resolve quickly");
    }

    deliver_manifest(&relay_a2, 1, &w, &a, &b, 1);

    // The restarted issuer re-applies its admission on top of W.
    wait_for(
        || {
            session_a2
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.version == 3)
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    let v3 = manifest_of(&session_a2);
    assert_eq!(v3.parent, Some(w.hash()), "re-application builds on W");
    assert!(
        v3.contains_signing_pub(&c.signing_public_key().0),
        "the admission survived the restart"
    );
    assert!(
        v3.contains_signing_pub(&d.signing_public_key().0),
        "W's change kept"
    );
}

/// ADR-0027: a later manifest built ON a change's carrier that undoes the
/// change is a deliberate supersession — the change is cleared, not
/// re-applied ("a deliberate later removal is not undone").
#[test]
fn deliberate_later_removal_is_not_undone() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();

    let (session_a, relay_a, _ia) = scripted_session(&a);
    let v1 = genesis_ab(&a, &b);
    session_a.set_manifest(v1.clone());

    // A admits C — the Pending Membership Change.
    session_a.pairing_token();
    assert!(session_a
        .accept_pair(c.public_key(), c.signing_public_key())
        .expect("A admits C"));
    let v2 = manifest_of(&session_a);
    let c_in = c.signing_public_key().0;
    assert!(v2.contains_signing_pub(&c_in));

    // B receives v2, then deliberately removes C: v3 is built ON v2.
    let b_sk = SigningKey::from_bytes(&b.signing.to_bytes());
    let v3 = GroupManifest::update(&v2, vec![member_of(&a), member_of(&b)], &b_sk)
        .expect("v3 removes C deliberately");
    assert_eq!(v3.parent, Some(v2.hash()));
    deliver_manifest(&relay_a, 1, &v3, &a, &b, 1);

    wait_for(
        || {
            session_a
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.version == 3)
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    // A accepts the removal and does NOT re-apply the admission — the
    // change was deliberately superseded. The manifest stays v3.
    std::thread::sleep(Duration::from_millis(300));
    let m = manifest_of(&session_a);
    assert_eq!(m.version, 3, "no v4 re-application of the undone admission");
    assert!(!m.contains_signing_pub(&c_in), "the removal stands");
    // And nothing was queued: no re-application push went out.
    assert!(
        session_a
            .op_log
            .lock()
            .unwrap()
            .undelivered_entries()
            .is_empty(),
        "no re-application push queued"
    );
}

/// ADR-0027 "False removal is not removal": a manifest that excludes the
/// device but was NOT built on a manifest that included it is stored as the
/// current view — the device stays alive, does not wipe, and rejoins when
/// its admitter re-applies the admission.
#[test]
fn losing_joiner_does_not_wipe_itself() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let e = DeviceKeypair::generate();
    let joiner = DeviceKeypair::generate();

    let (session_d, relay_d, _id) = scripted_session(&joiner);
    let removed_fired = Arc::new(Mutex::new(0u32));
    let rf = removed_fired.clone();
    session_d.set_on_member_left(move |_, _| {
        *rf.lock().unwrap() += 1;
    });
    let d_signing_before = session_d.signing_pub();

    // D's first manifest: A admitted D (v2 = {A, B, D}). D never held v1.
    let v1 = genesis_ab(&a, &b);
    let a_sk = SigningKey::from_bytes(&a.signing.to_bytes());
    let b_sk = SigningKey::from_bytes(&b.signing.to_bytes());
    let v2 = GroupManifest::update(
        &v1,
        vec![member_of(&a), member_of(&b), member_of(&joiner)],
        &a_sk,
    )
    .expect("v2 admits D");
    session_d.set_manifest(v2.clone());

    // Concurrently B's chain moved on without ever seeing D: v2'' admits E,
    // then W (v3) removes E again. W excludes D and its parent (v2'') was
    // never held by D — a FALSE removal.
    let v2b = GroupManifest::update(
        &v1,
        vec![member_of(&a), member_of(&b), member_of(&e)],
        &b_sk,
    )
    .expect("v2b");
    let w = GroupManifest::update(&v2b, vec![member_of(&a), member_of(&b)], &b_sk).expect("W");
    assert!(!w.contains_signing_pub(&d_signing_before.0));

    deliver_manifest(&relay_d, 1, &w, &joiner, &b, 1);

    // D stores W as its current view...
    wait_for(
        || {
            session_d
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.version == 3)
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    // ...but does NOT wipe: same identity, no removed event.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        session_d.signing_pub(),
        d_signing_before,
        "false removal must not rotate the identity"
    );
    assert!(
        session_d.manifest.lock().unwrap().is_some(),
        "false removal keeps the device alive"
    );

    // A re-applies D's admission on W: v4 includes D again.
    let v4 = GroupManifest::update(
        &w,
        vec![member_of(&a), member_of(&b), member_of(&joiner)],
        &a_sk,
    )
    .expect("v4 re-admits D");
    deliver_manifest(&relay_d, 2, &v4, &joiner, &a, 2);
    wait_for(
        || {
            session_d
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.version == 4 && m.contains_signing_pub(&d_signing_before.0))
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    assert_eq!(
        session_d.signing_pub(),
        d_signing_before,
        "identity stable across the whole flicker"
    );
}

// ── Removal: deliberate wipe ────────────────────────────────────────────────

/// A deliberate removal (parent-linked to a held manifest) fires the
/// removed event exactly once and the wiped device returns no memberLeft
/// flicker for itself — covered end to end in remove_member.rs; here we
/// pin the parent-less case: an excluding manifest whose parent is unknown
/// is NOT a removal (no wipe, no event).
#[test]
fn exclusion_with_unknown_parent_is_not_a_removal() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();

    let removed = Arc::new(Mutex::new(0u32));
    let r = removed.clone();
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let (_nk_rx, nk) = nk_push_channel();
    let session_b = TruesealSession::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        clone_kp(&b),
        |_, _, _| {},
        Box::new(MemLog::new()),
        move || *r.lock().unwrap() += 1,
        |_| {},
        || {},
        nk.factory(),
    )
    .expect("B");
    let v1 = genesis_ab(&a, &b);
    session_b.set_manifest(v1.clone());

    // A hostile or confused issuer: an excluding manifest with NO parent
    // (pre-SYNC-9 wire shape). Not deliberate — B must not wipe.
    let a_sk = SigningKey::from_bytes(&a.signing.to_bytes());
    let hostile = GroupManifest::new(v1.group_id, 2, vec![member_of(&a)], &a_sk);
    deliver_manifest(&relay, 1, &hostile, &b, &a, 1);
    wait_for(
        || {
            session_b
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.version == 2)
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        *removed.lock().unwrap(),
        0,
        "unknown-parent exclusion is not a removal"
    );
    assert!(
        session_b.manifest.lock().unwrap().is_some(),
        "B stays alive and waits for its admitter"
    );
}

/// A device whose current VIEW excludes it (a false removal) has no
/// membership authority: it cannot admit, remove or leave — it waits for
/// its admitter's re-apply (ADR-0027).
#[test]
fn falsely_removed_device_cannot_issue_membership_changes() {
    let a = DeviceKeypair::generate();
    let d = DeviceKeypair::generate();
    let (session_d, _relay, _i) = scripted_session(&d);

    // D's view: a manifest that excludes D (seeded directly — the false
    // removal itself is covered by losing_joiner_does_not_wipe_itself).
    let view = GroupManifest::new(
        new_group_id(),
        3,
        vec![member_of(&a)],
        &SigningKey::from_bytes(&a.signing.to_bytes()),
    );
    session_d.set_manifest(view);

    session_d.pairing_token();
    let joiner = DeviceKeypair::generate();
    assert!(
        matches!(
            session_d.accept_pair(joiner.public_key(), joiner.signing_public_key()),
            Ok(false)
        ),
        "a non-member admits no one"
    );
    assert!(matches!(
        session_d.remove_member(a.signing_public_key()),
        Err(SessionError::NotInGroup)
    ));
    assert!(matches!(
        session_d.leave_group(),
        Err(SessionError::NotInGroup)
    ));
    assert_eq!(
        session_d.group_status(),
        GroupStatus::Member,
        "still waiting for the admitter's re-apply"
    );
}

// ── Leave ───────────────────────────────────────────────────────────────────

/// ADR-0027: Leave enters the persisted Leaving state (no Sync sends),
/// survives a crash mid-Leave, and completes once the Relay has accepted
/// every Leave push — wipe, rotate, NotJoined.
#[test]
fn leave_resumes_after_crash_and_completes() {
    let dir = tempfile::TempDir::new().unwrap();
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let b_signing_before = b.signing_public_key();

    let v1 = genesis_ab(&a, &b);

    // Phase 1: B, fully offline (factories fail). Leave is queued durably.
    {
        let store = Store::open(dir.path(), "ns").expect("store");
        let log = PersistentLog::new(store);
        let manifest_slot: Arc<Mutex<Option<GroupManifest>>> = Arc::new(Mutex::new(None));
        let session_b = TruesealSession::connect_background(
            relay_pub(&make_relay_kp()),
            clone_kp(&b),
            |_, _, _| {},
            Box::new(log),
            manifest_slot,
            || {},
            |_| {},
            || {},
            || -> Result<MemPipeSimple, String> { Err("offline".into()) },
            || -> Result<MemPipeSimple, String> { Err("offline".into()) },
            Some(Duration::from_millis(50)),
            None,
        )
        .expect("B phase 1");
        session_b.set_manifest(v1.clone());
        session_b.leave_group().expect("leave");

        assert_eq!(
            session_b.group_status(),
            GroupStatus::Leaving,
            "Leave entered"
        );
        assert_eq!(
            session_b.signing_pub(),
            b_signing_before,
            "offline Leave does not wipe"
        );
        assert!(
            matches!(
                session_b.push_sync(b"x".to_vec()),
                Err(SessionError::NotInGroup)
            ),
            "a Leaving device does not send Sync"
        );
        // The Leaving record and the manifest pushes are durable.
        let store = Store::open(dir.path(), "ns").expect("check store");
        let log = PersistentLog::new(store);
        assert!(log.leaving().is_some(), "Leaving record persisted");
        assert!(
            !log.undelivered_entries().is_empty(),
            "Leave manifest pushes queued"
        );
        // CRASH: session drops mid-Leave.
    }

    // Phase 2: restart over the same store, now online. The pump pushes
    // the queued Leave manifest; once the Relay accepts every push, the
    // Leave completes: wipe, rotate, NotJoined.
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_single_relay(&relay_kp, pipe_relay, nk_rx);

    let store = Store::open(dir.path(), "ns").expect("store reopen");
    let seeded = store
        .load_group_manifest()
        .expect("load")
        .expect("leave manifest persisted");
    assert!(
        !seeded.contains_signing_pub(&b_signing_before.0),
        "the persisted manifest is the Leave manifest"
    );
    let log = PersistentLog::new(store);
    let manifest_slot: Arc<Mutex<Option<GroupManifest>>> = Arc::new(Mutex::new(Some(seeded)));
    let rotated_to: Arc<Mutex<Option<NoisePublicKey>>> = Arc::new(Mutex::new(None));
    let rt = rotated_to.clone();
    let transport_once: Arc<Mutex<Option<MemPipeSimple>>> = Arc::new(Mutex::new(Some(pipe_client)));
    let session_b2 = TruesealSession::connect_background_rotating(
        relay_pub(&relay_kp),
        clone_kp(&b),
        |_, _, _| {},
        Box::new(log),
        manifest_slot,
        || {},
        |_| {},
        || {},
        move |fresh| *rt.lock().unwrap() = Some(fresh.public_key()),
        move || {
            transport_once
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "no more transports".to_string())
        },
        nk.factory(),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("B phase 2");

    assert_eq!(
        session_b2.group_status(),
        GroupStatus::Leaving,
        "a crash in Leaving resumes Leaving"
    );

    wait_for(
        || session_b2.group_status() == GroupStatus::NotJoined,
        Duration::from_secs(10),
    );
    assert_ne!(
        session_b2.signing_pub(),
        b_signing_before,
        "completed Leave rotates the identity"
    );
    assert_eq!(
        *rotated_to.lock().unwrap(),
        Some(session_b2.noise_pub()),
        "the rotation callback carried the fresh identity"
    );
    assert!(session_b2.manifest.lock().unwrap().is_none(), "wiped");

    // The store's log-owned state is wiped too.
    let store = Store::open(dir.path(), "ns").expect("check store");
    let log = PersistentLog::new(store);
    assert!(log.leaving().is_none());
    assert!(log.undelivered_entries().is_empty());
    assert!(log.pending_membership_changes().is_none());
}

// ── Maximum Group Size ──────────────────────────────────────────────────────

/// ADR-0025/0027: a 32-member Group Manifest (the Maximum Group Size) fits
/// in one Noise frame.
#[test]
fn thirty_two_member_manifest_fits_one_frame() {
    let issuer = DeviceKeypair::generate();
    let mut members = vec![member_of(&issuer)];
    for _ in 1..32 {
        members.push(member_of(&DeviceKeypair::generate()));
    }
    let manifest = GroupManifest::new(
        new_group_id(),
        1,
        members,
        &SigningKey::from_bytes(&issuer.signing.to_bytes()),
    );
    let msg = Message::GroupManifest {
        manifest: manifest.clone(),
    };
    let framed = crate::relay::build_push_blob(
        &msg,
        NoisePublicKey([7u8; 32]),
        0,
        vec![],
        &issuer.signing_keypair(),
    )
    .expect("a 32-member manifest fits one frame");
    assert!(
        framed.len() <= crate::limits::MAX_ENVELOPE_BYTES + 2,
        "frame within the ceiling"
    );
}

/// ADR-0027: the 33rd admission is refused locally with the typed
/// groupFull error — and the Pairing Window is NOT consumed.
#[test]
fn thirty_third_admission_refused_with_group_full() {
    let a = DeviceKeypair::generate();
    let (session_a, _relay, _i) = scripted_session(&a);

    let mut members = vec![member_of(&a)];
    for _ in 1..32 {
        members.push(member_of(&DeviceKeypair::generate()));
    }
    let full = GroupManifest::new(
        new_group_id(),
        7,
        members,
        &SigningKey::from_bytes(&a.signing.to_bytes()),
    );
    session_a.set_manifest(full);

    session_a.pairing_token();
    let joiner = DeviceKeypair::generate();
    let result = session_a.accept_pair(joiner.public_key(), joiner.signing_public_key());
    assert!(
        matches!(result, Err(SessionError::GroupFull { max: 32 })),
        "33rd admission refused with groupFull{{max: 32}}, got {result:?}"
    );

    // The window was not consumed: after the group shrinks, the same
    // window admits.
    let two = genesis_ab(&a, &DeviceKeypair::generate());
    session_a.set_manifest(two);
    assert!(
        session_a
            .accept_pair(joiner.public_key(), joiner.signing_public_key())
            .expect("admission after shrink"),
        "the Pairing Window survives a groupFull refusal"
    );
}

/// ADR-0027: a Pending Membership Change re-application that would exceed
/// the Maximum Group Size is dropped with the typed admissionDropped
/// event; the joiner stays out.
#[test]
fn reapplied_admission_over_group_size_drops_with_typed_event() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let (session_a, relay_a, issues) = scripted_session(&a);

    // v1: self + 30 others = 31 members, so the admission of D is the 32nd.
    let mut others: Vec<DeviceKeypair> = (0..29).map(|_| DeviceKeypair::generate()).collect();
    others.push(clone_kp(&b));
    let mut members = vec![member_of(&a)];
    members.extend(others.iter().map(member_of));
    let v1 = GroupManifest::new(
        new_group_id(),
        1,
        members,
        &SigningKey::from_bytes(&a.signing.to_bytes()),
    );
    session_a.set_manifest(v1.clone());

    // A admits D — the 32nd member — with a Pending Membership Change.
    let d = DeviceKeypair::generate();
    session_a.pairing_token();
    assert!(session_a
        .accept_pair(d.public_key(), d.signing_public_key())
        .expect("32nd admission fits"));
    let v2 = manifest_of(&session_a);
    assert_eq!(v2.members.len(), 32);

    // A concurrent chain fills the group differently: v2'' swaps in E for
    // the 32nd slot; W (v3) bumps on top. W overwrites A's admission of D,
    // and re-applying it would make 33.
    let e = DeviceKeypair::generate();
    let b_sk = SigningKey::from_bytes(&b.signing.to_bytes());
    let mut w_members = vec![member_of(&a)];
    w_members.extend(others.iter().map(member_of));
    w_members.push(member_of(&e));
    let v2b = GroupManifest::update(&v1, w_members.clone(), &b_sk).expect("v2''");
    let w = GroupManifest::update(&v2b, w_members, &b_sk).expect("W");
    assert_eq!(w.version, 3);
    assert_eq!(w.members.len(), 32);

    deliver_manifest(&relay_a, 1, &w, &a, &b, 1);

    let d_id = member_id(&d.signing_public_key());
    wait_for(
        || {
            issues.lock().unwrap().iter().any(|i| {
                matches!(
                    i,
                    crate::delivery_issue::DeliveryIssue::AdmissionDropped { member_id, .. }
                    if *member_id == d_id
                )
            })
        },
        Duration::from_secs(5),
    );
    let m = manifest_of(&session_a);
    assert_eq!(
        m.members.len(),
        32,
        "the group stays at the Maximum Group Size"
    );
    assert!(
        !m.contains_signing_pub(&d.signing_public_key().0),
        "the dropped admission is not applied"
    );
}

// ── Replay safety ───────────────────────────────────────────────────────────

/// ADR-0034 §2: a replayed old Group Manifest changes no state — acked,
/// no events, no Delivery Issue.
#[test]
fn replayed_old_manifest_changes_no_state() {
    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();

    let changed = Arc::new(Mutex::new(0u32));
    let c = changed.clone();
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let (_nk_rx, nk) = nk_push_channel();
    let session_b = TruesealSession::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        clone_kp(&b),
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |_| *c.lock().unwrap() += 1,
        || {},
        nk.factory(),
    )
    .expect("B");
    let issues: Arc<Mutex<Vec<crate::delivery_issue::DeliveryIssue>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = issues.clone();
    session_b.subscribe_delivery_issues(move |i| sink.lock().unwrap().push(i));

    let v1 = genesis_ab(&a, &b);
    let a_sk = SigningKey::from_bytes(&a.signing.to_bytes());
    let v2 = GroupManifest::update(&v1, vec![member_of(&a), member_of(&b)], &a_sk).expect("v2");
    session_b.set_manifest(v2.clone());
    let before = manifest_of(&session_b).hash();

    // The relay re-delivers v1 AND the current v2 — both benign stale.
    deliver_manifest(&relay, 41, &v1, &b, &a, 1);
    deliver_manifest(&relay, 42, &v2, &b, &a, 2);

    wait_for(
        || relay.deliver_acks().contains(&41) && relay.deliver_acks().contains(&42),
        Duration::from_secs(5),
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(manifest_of(&session_b).hash(), before, "no state change");
    assert_eq!(*changed.lock().unwrap(), 0, "no manifest-changed events");
    assert!(issues.lock().unwrap().is_empty(), "replays are unreported");
}

// ── Encodings (fail closed) ─────────────────────────────────────────────────

/// The Pending Membership Change and Leaving record encodings round-trip,
/// and corrupt bytes fail closed (no changes / no record, never a panic).
#[test]
fn membership_record_encodings_round_trip_and_fail_closed() {
    use super::super::LeavingRecord;

    let changes = vec![
        PendingChange {
            intent: PendingIntent::Admit(ManifestMember {
                noise_pub: NoisePublicKey([1u8; 32]),
                signing_pub: SigningPublicKey([2u8; 32]),
                name: "AmberFalcon".into(),
            }),
            carrier: [3u8; 32],
        },
        PendingChange {
            intent: PendingIntent::Remove(SigningPublicKey([4u8; 32])),
            carrier: [5u8; 32],
        },
        PendingChange {
            intent: PendingIntent::Leave,
            carrier: [6u8; 32],
        },
    ];
    let encoded = PendingChange::encode_set(&changes);
    assert_eq!(PendingChange::decode_set(&encoded), Some(changes));
    assert_eq!(
        PendingChange::decode_set(&[]),
        None,
        "truncated fails closed"
    );
    assert_eq!(
        PendingChange::decode_set(&encoded[..encoded.len() - 3]),
        None
    );
    let mut garbage = encoded.clone();
    garbage[4] = 0xEE; // unknown kind
    assert_eq!(PendingChange::decode_set(&garbage), None);

    let record = LeavingRecord {
        refs: vec![([7u8; 32], 42), ([8u8; 32], 43)],
    };
    let encoded = record.encode();
    assert_eq!(LeavingRecord::decode(&encoded), Some(record));
    assert_eq!(LeavingRecord::decode(&[]), None);
    assert_eq!(LeavingRecord::decode(&encoded[..encoded.len() - 5]), None);
}
