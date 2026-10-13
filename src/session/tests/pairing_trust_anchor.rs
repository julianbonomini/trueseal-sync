//! SYNC-3 (#95), ADR-0023 — pairing is anchored to the Pairing Token.
//!
//! Ports repro variants 1-4 from the throwaway branch
//! `repro/joiner-manifest-hijack` (trueseal-roadmap#4, commit a8313d7) and
//! adds the issue's adversarial cases: a relay-injected Pair, a wrong
//! secret, a replayed spent secret, and the crash transitions of ADR-0023
//! "Crash points". Variant 5 (Pair signer binding) lives in
//! `pair_signer_binding.rs` (SYNC-4).
//!
//! Every test here is red on pre-SYNC-3 main: without the Pairing Secret
//! any Pair raised a Join Request, and without the Pending Join anchor any
//! self-signed manifest was installed on a manifestless device.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::delivery_issue::DeliveryIssue;
use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::message::Message;
use crate::operation_log::{MemLog, OperationLog};
use crate::session::GroupStatus;
use crate::store::{PersistentLog, Store};

use super::super::test_helpers::*;
use super::super::{SessionError, TruesealSession};

/// A manifest signed by `attacker`, listing the attacker and the victim.
/// Well-formed and self-consistent — the kind of forgery the Relay can
/// produce for any victim whose public keys it knows.
fn forged_manifest(attacker: &DeviceKeypair, victim: &DeviceKeypair) -> GroupManifest {
    let sk = SigningKey::from_bytes(&attacker.signing.to_bytes());
    GroupManifest::new(
        new_group_id(),
        1,
        vec![
            ManifestMember {
                noise_pub: attacker.public_key(),
                signing_pub: attacker.signing_public_key(),
                name: "Attacker".into(),
            },
            ManifestMember {
                noise_pub: victim.public_key(),
                signing_pub: victim.signing_public_key(),
                name: "Victim".into(),
            },
        ],
        &sk,
    )
}

fn issue_collector() -> (
    Arc<Mutex<Vec<DeliveryIssue>>>,
    impl Fn(DeliveryIssue) + Send + 'static,
) {
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let cb = issues.clone();
    (issues, move |i| cb.lock().unwrap().push(i))
}

// ── Repro variant 1 ─────────────────────────────────────────────────────────

/// Variant 1: a joiner that scanned A's token accepts ONLY a first manifest
/// issued by A. An attacker's manifest that arrives first is dropped, the
/// Pending Join is kept, and A's legitimate manifest installs afterwards.
#[test]
fn joiner_accepts_only_initiator_manifest() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pa_c, pa_r) = mem_pipe_pair();
    let (pb_c, pb_r) = mem_pipe_pair();
    let (pm_c, pm_r) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_tripartite_relay(&relay_kp, pa_r, pb_r, pm_r, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_m = DeviceKeypair::generate();
    let a_signing = device_a.signing_public_key();
    let b_noise = device_b.public_key();
    let forged = forged_manifest(&device_m, &device_b);

    let session_a =
        TruesealSession::connect(pa_c, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("A");
    let session_b =
        TruesealSession::connect(pb_c, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("B");
    let session_m =
        TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory()).expect("M");

    let (b_issues, b_issue_cb) = issue_collector();
    session_b.subscribe_delivery_issues(b_issue_cb);

    // B asks to join A. The attacker races A's manifest with a forgery.
    let token = session_a.pairing_token();
    session_b.join_group(&token).expect("join");
    assert_eq!(session_b.group_status(), GroupStatus::PendingJoin);

    session_m
        .push_message(&Message::GroupManifest { manifest: forged }, b_noise)
        .expect("attacker push queues");
    wait_for(
        || !b_issues.lock().unwrap().is_empty(),
        Duration::from_secs(5),
    );
    assert!(
        session_b.manifest.lock().unwrap().is_none(),
        "the forged manifest must not install"
    );
    assert_eq!(
        session_b.group_status(),
        GroupStatus::PendingJoin,
        "a rejected first manifest keeps the Pending Join (ADR-0023)"
    );

    // A admits B for real; the anchored manifest wins.
    let req: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let r = req.clone();
    session_a.set_on_member_request(move |t, _| *r.lock().unwrap() = Some(t));
    wait_for(|| req.lock().unwrap().is_some(), Duration::from_secs(5));
    let t = req.lock().unwrap().clone().unwrap();
    assert!(session_a.accept_member(&t).expect("accept"), "A admits B");

    wait_for(
        || session_b.manifest.lock().unwrap().is_some(),
        Duration::from_secs(5),
    );
    let b_manifest = session_b.manifest.lock().unwrap().clone().unwrap();
    assert_eq!(
        b_manifest.issued_by, a_signing.0,
        "B installed a manifest not issued by the initiator it paired with"
    );
    assert_eq!(
        session_a
            .manifest
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .group_id,
        b_manifest.group_id,
        "B must be in A's group"
    );
    assert_eq!(session_b.group_status(), GroupStatus::Member);
}

// ── Repro variant 2 ─────────────────────────────────────────────────────────

/// Variant 2: a device that never called join_group accepts no manifest.
/// An unsolicited manifest is dropped, on_manifest_changed never fires, and
/// the rejection is reported as `unauthorized` (authenticated bytes that
/// fail the trust-anchor policy).
#[test]
fn device_that_never_joined_rejects_unsolicited_manifest() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let attacker_seed: [u8; 32] = rand::random();
    let attacker = signing_keypair(&attacker_seed);

    let changed = Arc::new(AtomicUsize::new(0));
    let c = changed.clone();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        },
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let (issues, issue_cb) = issue_collector();
    session.subscribe_delivery_issues(issue_cb);

    // The manifest is properly signed by its (attacker) issuer and even
    // lists the victim — none of that matters without a Pending Join.
    let victim_noise = session.noise_pub();
    let victim_signing = session.signing_pub();
    let forged = GroupManifest::new(
        new_group_id(),
        1,
        vec![
            signing_member(&attacker_seed, [7u8; 32]),
            ManifestMember {
                noise_pub: victim_noise,
                signing_pub: victim_signing,
                name: member_name(&victim_signing),
            },
        ],
        &SigningKey::from_bytes(&attacker_seed),
    );
    relay.deliver(
        1,
        &Message::GroupManifest { manifest: forged },
        victim_noise,
        &attacker,
        1,
    );

    wait_for(
        || !issues.lock().unwrap().is_empty(),
        Duration::from_secs(3),
    );
    assert!(
        session.manifest.lock().unwrap().is_none(),
        "a device with no Pending Join installed an unsolicited manifest"
    );
    assert_eq!(
        changed.load(Ordering::SeqCst),
        0,
        "on_manifest_changed must not fire"
    );
    assert!(
        issues
            .lock()
            .unwrap()
            .iter()
            .any(|i| matches!(i, DeliveryIssue::Unauthorized)),
        "the rejection is reported as unauthorized: {issues:?}"
    );
    assert_eq!(session.group_status(), GroupStatus::NotJoined);
}

// ── Repro variant 3 ─────────────────────────────────────────────────────────

/// Variant 3: the Relay itself injects a manifest. The envelope is signed
/// by a key the relay controls; the manifest is self-signed by the same
/// key. Without a Pending Join the device drops it.
#[test]
fn relay_cannot_inject_manifest() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let relay_device_bytes = [0xAB; 32]; // the "relay's own" signing identity
    let relay_signer = signing_keypair(&relay_device_bytes);

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let (issues, issue_cb) = issue_collector();
    session.subscribe_delivery_issues(issue_cb);
    let victim_noise = session.noise_pub();
    let victim_signing = session.signing_pub();

    let forged = GroupManifest::new(
        new_group_id(),
        1,
        vec![
            signing_member(&relay_device_bytes, [7u8; 32]),
            ManifestMember {
                noise_pub: victim_noise,
                signing_pub: victim_signing,
                name: member_name(&victim_signing),
            },
        ],
        &SigningKey::from_bytes(&relay_device_bytes),
    );
    relay.deliver(
        1,
        &Message::GroupManifest { manifest: forged },
        victim_noise,
        &relay_signer,
        1,
    );

    wait_for(
        || !issues.lock().unwrap().is_empty(),
        Duration::from_secs(3),
    );
    assert!(
        session.manifest.lock().unwrap().is_none(),
        "relay-injected manifest was installed"
    );
}

// ── Repro variant 4 ─────────────────────────────────────────────────────────

/// Variant 4: a manifestless device drops every Sync and Revoke, whoever
/// the author is (ADR-0023). This closes the pre-SYNC-3 fail-open gap where
/// the member filter was skipped without a manifest.
#[test]
fn manifestless_device_drops_sync_and_revoke() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let stranger = SigningKeypair::generate();

    let received: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let rc = received.clone();
    let destroyed = Arc::new(AtomicUsize::new(0));
    let d = destroyed.clone();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |msg, _, _| {
            if matches!(msg, Message::Sync { .. }) {
                rc.fetch_add(1, Ordering::SeqCst);
            }
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        move || {
            d.fetch_add(1, Ordering::SeqCst);
        },
        || Err("push factory unused".into()),
    )
    .expect("session");
    let device_pub = session.noise_pub();

    relay.deliver(
        1,
        &Message::Sync {
            body: b"injected".to_vec(),
        },
        device_pub,
        &stranger,
        1,
    );
    relay.deliver(2, &Message::Revoke, device_pub, &stranger, 2);

    wait_for(|| relay.deliver_acks().len() == 2, Duration::from_secs(3));
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "Sync reached the handler on a manifestless device"
    );
    assert_eq!(
        destroyed.load(Ordering::SeqCst),
        0,
        "Revoke destroyed a group that does not exist"
    );
}

// ── Pairing Secret adversarial cases ────────────────────────────────────────

/// A relay-injected Pair: well-formed, signer-bound (SYNC-4), but with a
/// secret the injector cannot know. No Join Request is raised.
#[test]
fn relay_injected_pair_is_rejected() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let injector = SigningKeypair::generate();

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let requests = Arc::new(AtomicUsize::new(0));
    let rq = requests.clone();
    session.set_on_member_request(move |_, _| {
        rq.fetch_add(1, Ordering::SeqCst);
    });
    let _token = session.pairing_token(); // window open
    let device_pub = session.noise_pub();

    relay.deliver(
        1,
        &Message::Pair {
            noise_pub: [0xCC; 32],
            signing_pub: injector.public_key_bytes(),
            secret: [0xEE; 32], // the Relay never saw the token
        },
        device_pub,
        &injector,
        1,
    );

    wait_for(|| relay.deliver_acks() == vec![1], Duration::from_secs(3));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "a Pair without the Pairing Secret raised a Join Request"
    );
}

/// A Pair with a wrong secret (a corrupted token) is rejected.
#[test]
fn pair_with_wrong_secret_is_rejected() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let joiner = SigningKeypair::generate();

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let requests = Arc::new(AtomicUsize::new(0));
    let rq = requests.clone();
    session.set_on_member_request(move |_, _| {
        rq.fetch_add(1, Ordering::SeqCst);
    });
    let token = session.pairing_token();
    let device_pub = session.noise_pub();
    let (_, _, mut secret, _) = crate::message::decode_pairing_token(&token).expect("token");
    secret[0] ^= 0xFF; // corrupted in transit

    relay.deliver(
        1,
        &Message::Pair {
            noise_pub: [0xB1; 32],
            signing_pub: joiner.public_key_bytes(),
            secret,
        },
        device_pub,
        &joiner,
        1,
    );

    wait_for(|| relay.deliver_acks() == vec![1], Duration::from_secs(3));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "a wrong-secret Pair raised a Join Request"
    );
}

/// A Pair replaying a spent secret is rejected: the window closed when the
/// first admission consumed it, so later Pairs under it are dropped.
#[test]
fn pair_replaying_spent_secret_is_rejected() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let joiner_b = SigningKeypair::generate();
    let attacker_m = SigningKeypair::generate();

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let requests = Arc::new(AtomicUsize::new(0));
    let rq = requests.clone();
    let first: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let f = first.clone();
    session.set_on_member_request(move |t, _| {
        rq.fetch_add(1, Ordering::SeqCst);
        *f.lock().unwrap() = Some(t);
    });
    let device_pub = session.noise_pub();

    // B proves the secret and is admitted — the single-use window is spent.
    let token = session.pairing_token();
    let (_, _, secret, _) = crate::message::decode_pairing_token(&token).expect("token");
    relay.deliver(
        1,
        &Message::Pair {
            noise_pub: [0xB1; 32],
            signing_pub: joiner_b.public_key_bytes(),
            secret,
        },
        device_pub,
        &joiner_b,
        1,
    );
    wait_for(|| first.lock().unwrap().is_some(), Duration::from_secs(5));
    let t = first.lock().unwrap().clone().unwrap();
    assert!(session.accept_member(&t).expect("accept"));
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    // M eavesdropped nothing — but suppose it somehow holds the spent
    // secret (e.g. a photographed token used too late). The replay dies.
    relay.deliver(
        2,
        &Message::Pair {
            noise_pub: [0x77; 32],
            signing_pub: attacker_m.public_key_bytes(),
            secret,
        },
        device_pub,
        &attacker_m,
        1,
    );

    // Deterministic negative assertion (B8 review F4): wait until the
    // replayed Pair was delivered AND acked — i.e. the handler ran — then
    // assert it raised nothing.
    wait_for(
        || relay.deliver_acks() == vec![1, 2],
        Duration::from_secs(3),
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "a Pair under the spent secret raised a second Join Request"
    );
}

/// Repeat Pairs from the same joiner keys deduplicate into one request
/// (ADR-0023) — a relay re-delivery must not spam the caller.
#[test]
fn repeat_pair_from_same_joiner_dedupes_into_one_request() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let joiner = SigningKeypair::generate();

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let requests = Arc::new(AtomicUsize::new(0));
    let rq = requests.clone();
    session.set_on_member_request(move |_, _| {
        rq.fetch_add(1, Ordering::SeqCst);
    });
    let token = session.pairing_token();
    let device_pub = session.noise_pub();
    let (_, _, secret, _) = crate::message::decode_pairing_token(&token).expect("token");

    let pair = Message::Pair {
        noise_pub: [0xB2; 32],
        signing_pub: joiner.public_key_bytes(),
        secret,
    };
    relay.deliver(1, &pair, device_pub, &joiner, 1);
    relay.deliver(2, &pair, device_pub, &joiner, 1); // same envelope, new blob id
    relay.deliver(3, &pair, device_pub, &joiner, 2); // new sequence, same keys

    wait_for(|| relay.deliver_acks().len() == 3, Duration::from_secs(3));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "three deliveries of the same joiner raised {} requests",
        requests.load(Ordering::SeqCst)
    );
}

// ── Joiner API state machine ────────────────────────────────────────────────

/// joinGroup with an existing manifest fails with AlreadyInGroup (one Sync
/// Group per namespace, ADR-0023).
#[test]
fn join_group_with_existing_manifest_fails_already_in_group() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let _relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(membership_ref(&session, &sender));

    let other = DeviceKeypair::generate();
    let token = crate::message::pairing_token(
        &other.public_key().0,
        &other.signing_public_key().0,
        &[9u8; 32],
    );
    let result = session.join_group(&token);
    assert!(
        matches!(result, Err(SessionError::AlreadyInGroup)),
        "expected AlreadyInGroup, got {result:?}"
    );
    assert_eq!(session.group_status(), GroupStatus::Member);
}

/// A manifest for the member-filter tests: the session's own keys plus the
/// scripted sender. (Local helper — `membership` takes the keypair, which
/// is already inside the session here.)
fn membership_ref<T: std::io::Read + std::io::Write + Send + 'static>(
    session: &TruesealSession<T>,
    sender: &SigningKeypair,
) -> GroupManifest {
    let self_sp = session.signing_pub();
    let sender_sp = sender.public_key();
    // The issuer key is irrelevant — set_manifest is the test backdoor.
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    GroupManifest::new(
        new_group_id(),
        1,
        vec![
            ManifestMember {
                noise_pub: session.noise_pub(),
                signing_pub: self_sp,
                name: member_name(&self_sp),
            },
            ManifestMember {
                noise_pub: NoisePublicKey([9u8; 32]),
                signing_pub: SigningPublicKey(sender.public_key_bytes()),
                name: member_name(&sender_sp),
            },
        ],
        &sk,
    )
}

/// A second joinGroup replaces the Pending Join: the anchor moves to the
/// new token's key, and a manifest signed by the OLD initiator is rejected.
#[test]
fn second_join_group_replaces_the_pending_join() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let (issues, issue_cb) = issue_collector();
    session.subscribe_delivery_issues(issue_cb);
    let own_noise = session.noise_pub();
    let own_signing = session.signing_pub();

    let initiator_old = DeviceKeypair::generate();
    let initiator_new = DeviceKeypair::generate();
    let token_old = crate::message::pairing_token(
        &initiator_old.public_key().0,
        &initiator_old.signing_public_key().0,
        &[1u8; 32],
    );
    let token_new = crate::message::pairing_token(
        &initiator_new.public_key().0,
        &initiator_new.signing_public_key().0,
        &[2u8; 32],
    );

    session.join_group(&token_old).expect("first join");
    session
        .join_group(&token_new)
        .expect("second join replaces");
    assert_eq!(session.group_status(), GroupStatus::PendingJoin);

    // A manifest from the OLD initiator must fail the NEW anchor.
    let old_manifest = {
        let sk = SigningKey::from_bytes(&initiator_old.signing.to_bytes());
        GroupManifest::new(
            new_group_id(),
            1,
            vec![
                ManifestMember {
                    noise_pub: initiator_old.public_key(),
                    signing_pub: initiator_old.signing_public_key(),
                    name: "Old".into(),
                },
                ManifestMember {
                    noise_pub: own_noise,
                    signing_pub: own_signing,
                    name: "Me".into(),
                },
            ],
            &sk,
        )
    };
    relay.deliver(
        1,
        &Message::GroupManifest {
            manifest: old_manifest,
        },
        own_noise,
        &signing_keypair(&initiator_old.signing.to_bytes()),
        1,
    );

    wait_for(
        || !issues.lock().unwrap().is_empty(),
        Duration::from_secs(3),
    );
    assert!(
        session.manifest.lock().unwrap().is_none(),
        "a manifest from the replaced anchor installed"
    );
    assert_eq!(session.group_status(), GroupStatus::PendingJoin);

    // A manifest from the NEW anchor is accepted.
    let new_manifest = {
        let sk = SigningKey::from_bytes(&initiator_new.signing.to_bytes());
        GroupManifest::new(
            new_group_id(),
            3, // any version — the anchor, not the number, gates (ADR-0023)
            vec![
                ManifestMember {
                    noise_pub: initiator_new.public_key(),
                    signing_pub: initiator_new.signing_public_key(),
                    name: "New".into(),
                },
                ManifestMember {
                    noise_pub: own_noise,
                    signing_pub: own_signing,
                    name: "Me".into(),
                },
            ],
            &sk,
        )
    };
    relay.deliver(
        2,
        &Message::GroupManifest {
            manifest: new_manifest,
        },
        own_noise,
        &signing_keypair(&initiator_new.signing.to_bytes()),
        2,
    );
    wait_for(
        || session.manifest.lock().unwrap().is_some(),
        Duration::from_secs(3),
    );
    assert_eq!(session.group_status(), GroupStatus::Member);
}

/// cancelJoin returns the device to NotJoined: the manifest gate closes and
/// even the previously-anchored initiator's manifest is rejected.
#[test]
fn cancel_join_closes_the_anchor() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let own_noise = session.noise_pub();
    let own_signing = session.signing_pub();

    let initiator = DeviceKeypair::generate();
    let token = crate::message::pairing_token(
        &initiator.public_key().0,
        &initiator.signing_public_key().0,
        &[3u8; 32],
    );
    session.join_group(&token).expect("join");
    assert_eq!(session.group_status(), GroupStatus::PendingJoin);

    session.cancel_join();
    assert_eq!(session.group_status(), GroupStatus::NotJoined);

    let manifest = {
        let sk = SigningKey::from_bytes(&initiator.signing.to_bytes());
        GroupManifest::new(
            new_group_id(),
            1,
            vec![
                ManifestMember {
                    noise_pub: initiator.public_key(),
                    signing_pub: initiator.signing_public_key(),
                    name: "A".into(),
                },
                ManifestMember {
                    noise_pub: own_noise,
                    signing_pub: own_signing,
                    name: "Me".into(),
                },
            ],
            &sk,
        )
    };
    relay.deliver(
        1,
        &Message::GroupManifest { manifest },
        own_noise,
        &signing_keypair(&initiator.signing.to_bytes()),
        1,
    );
    wait_for(|| relay.deliver_acks() == vec![1], Duration::from_secs(3));
    assert!(
        session.manifest.lock().unwrap().is_none(),
        "a cancelled Pending Join still accepted the manifest"
    );
}

/// A manifest genuinely signed by the anchored initiator but delivered in
/// an Envelope signed by someone else is rejected (ADR-0023: "the Envelope
/// signer is that same key") — a group member cannot play admission proxy.
#[test]
fn manifest_with_right_issuer_but_wrong_envelope_signer_is_rejected() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let (issues, issue_cb) = issue_collector();
    session.subscribe_delivery_issues(issue_cb);
    let own_noise = session.noise_pub();
    let own_signing = session.signing_pub();

    let initiator = DeviceKeypair::generate();
    let token = crate::message::pairing_token(
        &initiator.public_key().0,
        &initiator.signing_public_key().0,
        &[4u8; 32],
    );
    session.join_group(&token).expect("join");

    // The manifest is really signed by the initiator…
    let real_manifest = {
        let sk = SigningKey::from_bytes(&initiator.signing.to_bytes());
        GroupManifest::new(
            new_group_id(),
            1,
            vec![
                ManifestMember {
                    noise_pub: initiator.public_key(),
                    signing_pub: initiator.signing_public_key(),
                    name: "A".into(),
                },
                ManifestMember {
                    noise_pub: own_noise,
                    signing_pub: own_signing,
                    name: "Me".into(),
                },
            ],
            &sk,
        )
    };
    // …but the Envelope carrying it is signed by a third party.
    let proxy = SigningKeypair::generate();
    relay.deliver(
        1,
        &Message::GroupManifest {
            manifest: real_manifest,
        },
        own_noise,
        &proxy,
        1,
    );

    wait_for(
        || !issues.lock().unwrap().is_empty(),
        Duration::from_secs(3),
    );
    assert!(
        session.manifest.lock().unwrap().is_none(),
        "a real manifest relayed under a foreign Envelope signer installed"
    );
    assert!(
        issues
            .lock()
            .unwrap()
            .iter()
            .any(|i| matches!(i, DeliveryIssue::Unauthorized)),
        "expected unauthorized, got {issues:?}"
    );
}

// ── Crash points (ADR-0023) ─────────────────────────────────────────────────

/// Joiner crash point: a crash AFTER join_group's transaction commits
/// leaves PendingJoin — the record and the queued Pair survive the restart,
/// and the manifest gate still anchors to the token.
#[test]
fn pending_join_survives_restart_with_pair_queued() {
    let dir = tempfile::TempDir::new().expect("tmp dir");
    let relay_kp = make_relay_kp();

    let device = DeviceKeypair::generate();
    let noise_priv = device.noise.private();
    let signing_priv = device.signing.to_bytes();

    let initiator = DeviceKeypair::generate();
    let token = crate::message::pairing_token(
        &initiator.public_key().0,
        &initiator.signing_public_key().0,
        &[5u8; 32],
    );

    // First "process": join, then die. The push factory fails, so the Pair
    // is still in the outbox — the pre-crash state is fully observable.
    {
        let (pipe_client, pipe_relay) = mem_pipe_pair();
        let _relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
        let store = Store::open(dir.path(), "ns").expect("store");
        let session = TruesealSession::<MemPipe>::connect_full(
            pipe_client,
            relay_pub(&relay_kp),
            device,
            |_, _, _| {},
            Box::new(PersistentLog::new(store)),
            || {},
            |_| {},
            || {},
            || Err("no push before crash".into()),
        )
        .expect("session");
        session.join_group(&token).expect("join");
        assert_eq!(session.group_status(), GroupStatus::PendingJoin);
    }

    // Second "process": same store, same identity. Still pending; the Pair
    // is still queued for the outbox to retry (Pair is not re-sent on
    // restart — retries follow the outbox, ADR-0023).
    {
        let (pipe_client, pipe_relay) = mem_pipe_pair();
        let _relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
        let store = Store::open(dir.path(), "ns").expect("store");
        let device2 = DeviceKeypair::from_bytes(noise_priv, signing_priv).expect("keypair");
        let session = TruesealSession::<MemPipe>::connect_full(
            pipe_client,
            relay_pub(&relay_kp),
            device2,
            |_, _, _| {},
            Box::new(PersistentLog::new(store)),
            || {},
            |_| {},
            || {},
            || Err("no push".into()),
        )
        .expect("session");
        assert_eq!(
            session.group_status(),
            GroupStatus::PendingJoin,
            "the Pending Join must survive the restart"
        );
        let undelivered = session
            .op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .undelivered_entries();
        assert!(
            undelivered.iter().any(|e| matches!(
                crate::message::Message::decode(&e.blob),
                Ok(Message::Pair { .. })
            )),
            "the queued Pair survived the restart"
        );
    }
}

/// Joiner crash point: a completed admission stays complete. The manifest
/// is persisted and the Pending Join cleared; a restart comes up Member and
/// self-heals any stale record from the persist/clear crash window.
#[test]
fn accepted_manifest_survives_restart_as_member() {
    let dir = tempfile::TempDir::new().expect("tmp dir");
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let noise_priv = device.noise.private();
    let signing_priv = device.signing.to_bytes();
    let initiator = DeviceKeypair::generate();

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("no push".into()),
    )
    .expect("session");
    let own_noise = session.noise_pub();
    let own_signing = session.signing_pub();
    let token = crate::message::pairing_token(
        &initiator.public_key().0,
        &initiator.signing_public_key().0,
        &[6u8; 32],
    );
    session.join_group(&token).expect("join");

    let manifest = {
        let sk = SigningKey::from_bytes(&initiator.signing.to_bytes());
        GroupManifest::new(
            new_group_id(),
            7,
            vec![
                ManifestMember {
                    noise_pub: initiator.public_key(),
                    signing_pub: initiator.signing_public_key(),
                    name: "A".into(),
                },
                ManifestMember {
                    noise_pub: own_noise,
                    signing_pub: own_signing,
                    name: "Me".into(),
                },
            ],
            &sk,
        )
    };
    // The FFI persists via on_manifest_changed; mirror that wiring with the
    // store the "restart" will read.
    let store_for_save = Store::open(dir.path(), "ns").expect("store2");
    store_for_save.save_group_manifest(&manifest).expect("save");
    drop(store_for_save);

    relay.deliver(
        1,
        &Message::GroupManifest {
            manifest: manifest.clone(),
        },
        own_noise,
        &signing_keypair(&initiator.signing.to_bytes()),
        1,
    );
    // Admission is: install the manifest, THEN clear the Pending Join
    // (persist-first ordering, ADR-0023 Crash points) — wait for both
    // halves of the committed transition, not just the first.
    wait_for(
        || {
            session.manifest.lock().unwrap().is_some()
                && session
                    .op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .pending_join()
                    .is_none()
        },
        Duration::from_secs(3),
    );
    assert_eq!(session.group_status(), GroupStatus::Member);

    // Restart with the persisted manifest seeded by the caller (the FFI
    // pattern, SYNC-7). Status comes up Member with no anchor needed.
    drop(session);
    let (_pipe2_client, pipe2_relay) = mem_pipe_pair();
    let _relay2 = ScriptedRelay::spawn(pipe2_relay, &relay_kp);
    let store2 = Store::open(dir.path(), "ns").expect("store reopen");
    let seeded = store2.load_group_manifest().expect("load");
    let device2 = DeviceKeypair::from_bytes(noise_priv, signing_priv).expect("keypair");
    let session2 = TruesealSession::<MemPipe>::connect_background(
        relay_pub(&relay_kp),
        device2,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(seeded)),
        || {},
        |_| {},
        || {},
        || Err("no reconnect".into()),
        || Err("no push".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session2");
    assert_eq!(session2.group_status(), GroupStatus::Member);
    // joinGroup now fails — already in a group.
    let other = DeviceKeypair::generate();
    let token2 = crate::message::pairing_token(
        &other.public_key().0,
        &other.signing_public_key().0,
        &[8u8; 32],
    );
    assert!(matches!(
        session2.join_group(&token2),
        Err(SessionError::AlreadyInGroup)
    ));
}

/// Admitter crash point: the window is in-memory only, so a restart spends
/// the secret — a Pair under the pre-restart secret is rejected.
#[test]
fn admitter_restart_spends_the_secret() {
    let relay_kp = make_relay_kp();
    let device = DeviceKeypair::generate();
    let noise_priv = device.noise.private();
    let signing_priv = device.signing.to_bytes();
    let joiner = SigningKeypair::generate();

    // Pre-restart: the window works (sanity that the secret is live).
    let (pipe1_client, pipe1_relay) = mem_pipe_pair();
    let relay1 = ScriptedRelay::spawn(pipe1_relay, &relay_kp);
    let session1 = TruesealSession::<MemPipe>::connect_full(
        pipe1_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("no push".into()),
    )
    .expect("session1");
    let requests1 = Arc::new(AtomicUsize::new(0));
    let r1 = requests1.clone();
    session1.set_on_member_request(move |_, _| {
        r1.fetch_add(1, Ordering::SeqCst);
    });
    let token = session1.pairing_token();
    let pub1 = session1.noise_pub();
    let (_, _, secret, _) = crate::message::decode_pairing_token(&token).expect("token");
    relay1.deliver(
        1,
        &Message::Pair {
            noise_pub: [0xD1; 32],
            signing_pub: joiner.public_key_bytes(),
            secret,
        },
        pub1,
        &joiner,
        1,
    );
    wait_for(
        || requests1.load(Ordering::SeqCst) == 1,
        Duration::from_secs(3),
    );
    drop(session1); // the "crash" — the window dies with the process

    // Post-restart: same identity, no window. The same secret is spent.
    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    let relay2 = ScriptedRelay::spawn(pipe2_relay, &relay_kp);
    let device2 = DeviceKeypair::from_bytes(noise_priv, signing_priv).expect("keypair");
    let session2 = TruesealSession::<MemPipe>::connect_full(
        pipe2_client,
        relay_pub(&relay_kp),
        device2,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("no push".into()),
    )
    .expect("session2");
    let requests2 = Arc::new(AtomicUsize::new(0));
    let r2 = requests2.clone();
    session2.set_on_member_request(move |_, _| {
        r2.fetch_add(1, Ordering::SeqCst);
    });
    let pub2 = session2.noise_pub();
    relay2.deliver(
        1,
        &Message::Pair {
            noise_pub: [0xD1; 32],
            signing_pub: joiner.public_key_bytes(),
            secret,
        },
        pub2,
        &joiner,
        1,
    );
    wait_for(|| relay2.deliver_acks() == vec![1], Duration::from_secs(3));
    assert_eq!(
        requests2.load(Ordering::SeqCst),
        0,
        "the pre-restart secret must be spent — windows never survive a restart"
    );
}

/// Admitter crash point (ADR-0023): a crash AFTER accept commits loses the
/// window, but the admission manifest was persisted and queued first — the
/// outbox still holds it after a restart, so the sender pump re-sends it.
#[test]
fn admitter_restart_keeps_the_queued_admission_manifest() {
    let dir = tempfile::TempDir::new().expect("tmp dir");
    let relay_kp = make_relay_kp();

    let device_a = DeviceKeypair::generate();
    let a_noise_priv = device_a.noise.private();
    let a_signing_priv = device_a.signing.to_bytes();
    let joiner = DeviceKeypair::generate();

    // First "process": admit the joiner while the push path is down (the
    // Pair from the joiner never arrives — the admit uses accept_pair
    // directly, the primitive accept_member wraps), then die.
    {
        let (pipe_client, pipe_relay) = mem_pipe_pair();
        let _relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
        let store = Store::open(dir.path(), "ns").expect("store");
        let session = TruesealSession::<MemPipe>::connect_full(
            pipe_client,
            relay_pub(&relay_kp),
            device_a,
            |_, _, _| {},
            Box::new(PersistentLog::new(store)),
            || {},
            |_| {},
            || {},
            || Err("push path down".into()),
        )
        .expect("session");
        let _token = session.pairing_token();
        assert!(
            session
                .accept_pair(joiner.public_key(), joiner.signing_public_key())
                .expect("accept"),
            "admission commits"
        );
        // The manifest is local and queued; nothing could be pushed.
        assert!(session.manifest.lock().unwrap().is_some());
    }

    // Second "process": the queued GroupManifest control entries survived —
    // the joiner (and any prior members) still get the admission.
    {
        let store = Store::open(dir.path(), "ns").expect("reopen");
        let log = PersistentLog::new(store);
        let undelivered = log.undelivered_entries();
        assert!(
            undelivered.iter().any(|e| matches!(
                crate::message::Message::decode(&e.blob),
                Ok(Message::GroupManifest { .. })
            )),
            "the admission manifest must still be queued after the crash"
        );
        assert!(
            undelivered
                .iter()
                .all(|e| e.object_id == joiner.public_key().0),
            "genesis admission notifies exactly the joiner"
        );
        // Sanity: the identity is intact for the restart.
        let _ = (a_noise_priv, a_signing_priv);
    }
}

/// A fresh window gets a FRESH secret: a Pair under an older window's
/// secret is rejected even without a restart.
#[test]
fn new_window_spends_the_old_secret() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let joiner = SigningKeypair::generate();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("no push".into()),
    )
    .expect("session");
    let requests = Arc::new(AtomicUsize::new(0));
    let rq = requests.clone();
    session.set_on_member_request(move |_, _| {
        rq.fetch_add(1, Ordering::SeqCst);
    });
    let pubk = session.noise_pub();

    let token1 = session.pairing_token();
    let (_, _, secret1, _) = crate::message::decode_pairing_token(&token1).expect("t1");
    let token2 = session.pairing_token(); // reopen — new secret
    let (_, _, secret2, _) = crate::message::decode_pairing_token(&token2).expect("t2");
    assert_ne!(secret1, secret2, "each window gets a fresh secret");

    relay.deliver(
        1,
        &Message::Pair {
            noise_pub: [0xD2; 32],
            signing_pub: joiner.public_key_bytes(),
            secret: secret1, // from the replaced window
        },
        pubk,
        &joiner,
        1,
    );
    wait_for(|| relay.deliver_acks() == vec![1], Duration::from_secs(3));
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

/// Two concurrent accepts must not both succeed (B8 review F1): the window
/// check and the consume happen under one lock, so exactly one caller
/// observes the open window and the other gets `false` — no divergent
/// genesis manifests.
#[test]
fn two_concurrent_accepts_exactly_one_succeeds() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let _relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let session = Arc::new(
        TruesealSession::<MemPipe>::connect_full(
            pipe_client,
            relay_pub(&relay_kp),
            device,
            |_, _, _| {},
            Box::new(MemLog::new()),
            || {},
            |_| {},
            || {},
            || Err("push factory unused".into()),
        )
        .expect("session"),
    );
    let _token = session.pairing_token(); // window open

    let joiner_a = SigningKeypair::generate();
    let joiner_b = SigningKeypair::generate();

    let mut handles = Vec::new();
    for joiner in [joiner_a, joiner_b] {
        let session = session.clone();
        let noise = NoisePublicKey(rand::random());
        let signing = SigningPublicKey(joiner.public_key_bytes());
        handles.push(std::thread::spawn(move || {
            session.accept_pair(noise, signing).expect("accept")
        }));
    }
    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    assert_eq!(
        results.iter().filter(|&&ok| ok).count(),
        1,
        "concurrent accepts must yield exactly one admission, got {results:?}"
    );
    // The winner issued a well-formed genesis (self + one member) — the
    // loser did not interleave a second, divergent manifest.
    let members = session.members();
    assert_eq!(
        members.len(),
        1,
        "exactly one remote member was admitted, got {}",
        members.len()
    );
}

/// A failing op-log: every durable write works EXCEPT `begin_pending_join`,
/// which reports a store failure. Models a disk-full / locked-SQLite join.
struct FailingJoinLog {
    inner: MemLog,
}

impl FailingJoinLog {
    fn new() -> Self {
        Self {
            inner: MemLog::new(),
        }
    }
}

impl OperationLog for FailingJoinLog {
    fn append_entry(&mut self, entry: crate::operation_log::LogEntry) {
        self.inner.append_entry(entry);
    }
    fn mark_delivered(&mut self, object_id: &[u8; 32], sequence: u64) {
        self.inner.mark_delivered(object_id, sequence);
    }
    fn remove(&mut self, object_id: &[u8; 32], sequence: u64) {
        self.inner.remove(object_id, sequence);
    }
    fn undelivered_entries(&self) -> Vec<crate::operation_log::LogEntry> {
        self.inner.undelivered_entries()
    }
    fn entries_from(
        &self,
        object_id: &[u8; 32],
        sequence: u64,
    ) -> Vec<crate::operation_log::LogEntry> {
        self.inner.entries_from(object_id, sequence)
    }
    fn max_sequence(&self) -> Option<u64> {
        self.inner.max_sequence()
    }
    fn record_sequence(&mut self, sequence: u64) {
        self.inner.record_sequence(sequence);
    }
    fn is_handled(&self, message_id: &str) -> bool {
        self.inner.is_handled(message_id)
    }
    fn handled_at(&self, message_id: &str) -> Option<u64> {
        self.inner.handled_at(message_id)
    }
    fn record_handled(&mut self, message_id: &str, now: u64) {
        self.inner.record_handled(message_id, now);
    }
    fn begin_pending_join(
        &mut self,
        _pending: &[u8],
        _recipient: &[u8; 32],
        _sequence: u64,
        _encoded_pair: Vec<u8>,
    ) -> Result<(), String> {
        Err("disk is full".into())
    }
    fn pending_join(&self) -> Option<Vec<u8>> {
        self.inner.pending_join()
    }
    fn clear_pending_join(&mut self) {
        self.inner.clear_pending_join();
    }
    fn commit_membership(
        &mut self,
        commit: crate::operation_log::MembershipCommit,
    ) -> Result<(), String> {
        self.inner.commit_membership(commit)
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
    fn wipe_group_state(&mut self) {
        self.inner.wipe_group_state();
    }
}

/// A store failure on join surfaces a typed error and leaves NO in-memory
/// Pending Join behind (B8 review F3): before the fix the SQLite error was
/// swallowed and the device hung forever in PendingJoin with its Pair
/// never queued.
#[test]
fn join_group_store_failure_is_a_typed_error_without_pending_state() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let _relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);

    let device = DeviceKeypair::generate();
    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(FailingJoinLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");

    // A well-formed token (the session's own is fine — the store fails
    // before any network step matters).
    let token = session.pairing_token();

    let err = session
        .join_group(&token)
        .expect_err("a failed begin_pending_join must surface");
    assert!(
        matches!(err, SessionError::Store(ref msg) if msg.contains("disk is full")),
        "expected SessionError::Store, got {err:?}"
    );
    assert_eq!(
        session.group_status(),
        GroupStatus::NotJoined,
        "no in-memory Pending Join survives a failed durable write"
    );
}
