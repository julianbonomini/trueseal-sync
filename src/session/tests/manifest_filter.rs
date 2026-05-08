use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::message::Message;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::HushSession;
use super::{make_one_member_manifest, make_two_member_manifest};

/// A message from a signing key NOT in the manifest is silently discarded.
#[test]
fn message_from_non_member_is_discarded() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_stranger_client, pipe_stranger_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_stranger_relay, pipe_a_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_stranger = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    // Relay accepts src (stranger) first, then dst (a) — connect in same order.
    let session_stranger =
        HushSession::connect(pipe_stranger_client, relay_pub, device_stranger, |_, _| {})
            .expect("stranger");
    let session_a = HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _| {
        rx.lock().unwrap().push(msg);
    })
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
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, true);

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
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");
    let session_a = HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _| {
        rx.lock().unwrap().push(msg);
    })
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

    std::thread::sleep(Duration::from_millis(100));
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
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, true);

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
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");
    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    session_a.set_manifest(v1);
    session_b
        .push_message(&Message::GroupManifest { manifest: v2 }, a_noise)
        .expect("push manifest");

    std::thread::sleep(Duration::from_millis(100));

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
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, true);

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
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");
    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    session_a.set_manifest(v3);
    session_b
        .push_message(&Message::GroupManifest { manifest: v1 }, a_noise)
        .expect("push stale manifest");

    std::thread::sleep(Duration::from_millis(100));

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
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, true);

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
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");
    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        |_| {},
        move || {
            *rf.lock().unwrap() += 1;
        },
        |_| {},
        || {},
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

    std::thread::sleep(Duration::from_millis(300));

    assert_eq!(
        *removed_fired.lock().unwrap(),
        1,
        "on_removed_from_group should fire once"
    );
}
