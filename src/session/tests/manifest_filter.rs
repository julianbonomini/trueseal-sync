use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::message::Message;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::TruesealSession;
use super::{make_one_member_manifest, make_two_member_manifest};

/// A message from a signing key NOT in the manifest is silently discarded.
#[test]
fn message_from_non_member_is_discarded() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_stranger_client, pipe_stranger_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_stranger_relay, pipe_a_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_stranger = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    // Relay accepts src (stranger) first, then dst (a) — connect in same order.
    let session_stranger =
        TruesealSession::connect(pipe_stranger_client, relay_pub, device_stranger, |_, _, _| {}, nk.factory())
            .expect("stranger");
    let session_a = TruesealSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _, _seq| {
        rx.lock().unwrap().push(msg);
    }, nk.factory())
    .expect("session A");
    session_a.set_manifest(make_one_member_manifest(a_noise, a_signing, &a_sk));

    session_stranger
        .push_message(
            &crate::message::Message::Sync {
                body: b"should be dropped".to_vec(),
            },
            a_noise,
        )
        .expect("push");

    std::thread::sleep(Duration::from_millis(100));
    assert!(
        received.lock().unwrap().is_empty(),
        "non-member message must be discarded"
    );
}

/// A message from a signing key IN the manifest is delivered to on_message.
#[test]
fn message_from_member_is_delivered() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    // Relay accepts src (b) first — connect b before a.
    let session_b =
        TruesealSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("session B");
    let session_a = TruesealSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _, _seq| {
        rx.lock().unwrap().push(msg);
    }, nk.factory())
    .expect("session A");
    session_a.set_manifest(make_two_member_manifest(
        a_noise, a_signing, &a_sk, b_noise, b_signing,
    ));

    session_b
        .push_message(
            &crate::message::Message::Sync {
                body: b"hello from B".to_vec(),
            },
            a_noise,
        )
        .expect("push");

    wait_for(|| !received.lock().unwrap().is_empty(), Duration::from_secs(5));
    let got = received.lock().unwrap();
    assert_eq!(got.len(), 1, "member message must be delivered");
    assert_eq!(
        got[0],
        Message::Sync {
            body: b"hello from B".to_vec()
        }
    );
}

/// Inbound GroupManifest with valid sig and higher version replaces current manifest.
#[test]
fn inbound_group_manifest_replaces_current() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    let group_id = v1.group_id;

    // Relay accepts src (b) first — connect b before a.
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
        &b_sk,
    );
    let session_b =
        TruesealSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("session B");
    let session_a =
        TruesealSession::connect(pipe_a_client, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("session A");
    session_a.set_manifest(v1);
    session_b
        .push_message(&Message::GroupManifest { manifest: v2 }, a_noise)
        .expect("push manifest");

    wait_for(|| session_a.manifest.lock().unwrap().as_ref().map(|m| m.version) == Some(2), Duration::from_secs(5));

    let stored = session_a.manifest.lock().unwrap();
    assert_eq!(
        stored.as_ref().map(|m| m.version),
        Some(2),
        "manifest should update to v2"
    );
}

/// Inbound GroupManifest with stale version is silently ignored.
#[test]
fn inbound_stale_manifest_is_ignored() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());

    let v3 = GroupManifest::new(
        new_group_id(),
        3,
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
    let group_id = v3.group_id;

    // Relay accepts src (b) first — connect b before a.
    let v1 = GroupManifest::new(
        group_id,
        1,
        vec![ManifestMember {
            noise_pub: b_noise,
            signing_pub: b_signing,
            name: "B".into(),
        }],
        &b_sk,
    );
    let session_b =
        TruesealSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("session B");
    let session_a =
        TruesealSession::connect(pipe_a_client, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("session A");
    session_a.set_manifest(v3);
    session_b
        .push_message(&Message::GroupManifest { manifest: v1 }, a_noise)
        .expect("push stale manifest");

    // Stale manifest (v1 < v3 current) must be ignored — wait a fixed time to confirm.
    std::thread::sleep(Duration::from_millis(200));

    let stored = session_a.manifest.lock().unwrap();
    assert_eq!(
        stored.as_ref().map(|m| m.version),
        Some(3),
        "manifest must stay at v3"
    );
}

/// on_removed_from_group fires when a valid incoming manifest excludes the local device.
#[test]
fn on_removed_from_group_fires_when_excluded_from_manifest() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    let group_id = v1.group_id;

    let removed_fired: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let rf = removed_fired.clone();

    // Relay accepts src (b) first — connect b before a.
    let v2_excl_a = GroupManifest::new(
        group_id,
        2,
        vec![ManifestMember {
            noise_pub: b_noise,
            signing_pub: b_signing,
            name: "B".into(),
        }],
        &b_sk,
    );
    let session_b =
        TruesealSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("session B");
    let session_a = TruesealSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        move || {
            *rf.lock().unwrap() += 1;
        },
        |_| {},
        || {},
        nk.factory(),
    )
    .expect("session A");
    session_a.set_manifest(v1);
    session_b
        .push_message(
            &Message::GroupManifest {
                manifest: v2_excl_a,
            },
            a_noise,
        )
        .expect("push excluding manifest");

    wait_for(|| *removed_fired.lock().unwrap() >= 1, Duration::from_secs(5));

    assert_eq!(
        *removed_fired.lock().unwrap(),
        1,
        "on_removed_from_group should fire once"
    );
}

/// A GroupManifest with a zeroed (invalid) signature is silently rejected.
/// A's manifest version must not change; no callbacks fire.
///
/// Zero-trust property: a rogue relay or MITM cannot inject a manifest to
/// hijack group membership.
#[test]
fn tampered_group_manifest_is_rejected() {
    use crate::message::Message;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    // A→B only; B will push to A.
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());

    let manifest_changed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let mc = manifest_changed.clone();
    let removed_fired: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let rf = removed_fired.clone();
    use crate::operation_log::MemLog;
    // B connects first — relay accepts pipe_b_relay first.
    let session_b =
        TruesealSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("session B");
    let session_a = TruesealSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        move || {
            *rf.lock().unwrap() += 1;
        },
        move |_| {
            *mc.lock().unwrap() += 1;
        },
        || {},
        nk.factory(),
    )
    .expect("session A");

    let group_id = crate::manifest::new_group_id();
    let v1 = GroupManifest::new(
        group_id,
        1,
        vec![
            ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
            ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ],
        &a_sk,
    );
    session_a.set_manifest(v1.clone());
    // on_manifest_changed fires once for set_manifest; reset counter.
    std::thread::sleep(Duration::from_millis(20));
    *manifest_changed.lock().unwrap() = 0;

    // Build a valid v2 manifest (signed by B, a known member)…
    let mut tampered = GroupManifest::new(
        group_id,
        2,
        vec![
            ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
            ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ],
        &b_sk,
    );
    // …then zero out the signature to make it invalid.
    tampered.signature = [0u8; 64];

    session_b
        .push_message(
            &Message::GroupManifest { manifest: tampered },
            a_noise,
        )
        .expect("push tampered manifest");

    std::thread::sleep(Duration::from_millis(200));

    // A's manifest must still be version 1.
    let a_manifest = session_a.manifest.lock().unwrap();
    let m = a_manifest.as_ref().expect("A has a manifest");
    assert_eq!(m.version, 1, "A's manifest version must not change");
    drop(a_manifest);

    assert_eq!(
        *manifest_changed.lock().unwrap(),
        0,
        "on_manifest_changed must not fire"
    );
    assert_eq!(
        *removed_fired.lock().unwrap(),
        0,
        "on_removed_from_group must not fire"
    );
}

/// Concurrent v2 manifests (A and B both issue v2 for the same group):
/// C must accept exactly one and end up with a valid v2 manifest.
/// on_manifest_changed fires exactly once (for whichever is delivered first).
/// No panic or deadlock.
#[test]
fn concurrent_manifest_conflict_last_version_wins() {
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use ed25519_dalek::SigningKey;
    use crate::operation_log::MemLog;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_tripartite_relay(&relay_kp, pipe_a_relay, pipe_b_relay, pipe_c_relay, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_c = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();
    let c_sk = SigningKey::from_bytes(&device_c.signing.to_bytes());

    let group_id = new_group_id();
    let v1_members = vec![
        ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
        ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ManifestMember { noise_pub: c_noise, signing_pub: c_signing, name: "C".into() },
    ];
    let v1_a = GroupManifest::new(group_id, 1, v1_members.clone(), &a_sk);
    let v1_b = GroupManifest::new(group_id, 1, v1_members.clone(), &b_sk);
    let v1_c = GroupManifest::new(group_id, 1, v1_members.clone(), &c_sk);

    // C counts manifest_changed events.
    let c_manifest_changed: Arc<(Mutex<u32>, Condvar)> = Arc::new((Mutex::new(0), Condvar::new()));
    let cmc = c_manifest_changed.clone();

    let session_a =
        TruesealSession::connect(pipe_a_client, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("A");
    let session_b =
        TruesealSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("B");
    let session_c = TruesealSession::connect_full(
        pipe_c_client, relay_pub, device_c,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |_| {
            let (lock, cvar) = &*cmc;
            *lock.lock().unwrap() += 1;
            cvar.notify_all();
        },
        || {},
        nk.factory(),
    ).expect("C");

    session_a.set_manifest(v1_a);
    session_b.set_manifest(v1_b);
    session_c.set_manifest(v1_c);
    // Reset counter after set_manifest calls (on_manifest_changed not called by set_manifest).

    // A and B each produce a v2 manifest simultaneously.
    // A's v2 adds a dummy extra member; B's v2 is a simple bump.
    let device_d = DeviceKeypair::generate();
    let d_noise = device_d.public_key();
    let d_signing = device_d.signing_public_key();
    let v2_a = GroupManifest::new(group_id, 2, vec![
        ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
        ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ManifestMember { noise_pub: c_noise, signing_pub: c_signing, name: "C".into() },
        ManifestMember { noise_pub: d_noise, signing_pub: d_signing, name: "D".into() },
    ], &a_sk);
    let v2_b = GroupManifest::new(group_id, 2, vec![
        ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
        ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ManifestMember { noise_pub: c_noise, signing_pub: c_signing, name: "C".into() },
    ], &b_sk);

    // Push both v2 manifests to C simultaneously.
    session_a
        .push_message(&crate::message::Message::GroupManifest { manifest: v2_a }, c_noise)
        .expect("A push v2");
    session_b
        .push_message(&crate::message::Message::GroupManifest { manifest: v2_b }, c_noise)
        .expect("B push v2");

    // Wait for C to process at least one manifest update.
    let (lock, cvar) = &*c_manifest_changed;
    let result = cvar
        .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |n| *n == 0)
        .unwrap();
    assert!(!result.1.timed_out(), "C must receive at least one v2 manifest");
    let fires = *result.0;
    drop(result);

    // Short additional wait to ensure the second manifest (if any) is processed.
    std::thread::sleep(Duration::from_millis(100));
    let final_fires = *c_manifest_changed.0.lock().unwrap();

    // C's manifest must be version 2 (whichever arrived first or last wins).
    let c_m = session_c.manifest.lock().unwrap();
    let m = c_m.as_ref().expect("C has a manifest");
    assert_eq!(m.version, 2, "C's manifest is version 2");
    assert_eq!(m.group_id, group_id, "same group_id");
    // on_manifest_changed fired exactly once (second v2 is same version — rejected as not higher).
    assert_eq!(final_fires, 1, "on_manifest_changed fires exactly once (same-version duplicate rejected)");
}
