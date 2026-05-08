use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::member::member_id;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::HushSession;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};

use super::make_two_member_manifest;

/// onMemberJoined fires on the admitting device (A) when accept_member succeeds.
#[test]
fn on_member_joined_fires_on_admitting_device() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_id = member_id(&device_b.signing_public_key());

    let joined: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
    let jc = joined.clone();
    let token_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let ts = token_slot.clone();

    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session A");

    session_a.set_on_member_joined(move |id, name| {
        jc.lock().unwrap().push((id, name));
    });

    session_a.set_on_member_request(move |token, _name| {
        *ts.lock().unwrap() = Some(token);
    });

    let pairing_token = session_a.pairing_token();

    let _session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session B");

    _session_b.join_group(&pairing_token).expect("join");
    wait_for(|| token_slot.lock().unwrap().is_some(), Duration::from_secs(5));

    let req_token = token_slot.lock().unwrap().clone().expect("request token");
    session_a.accept_member(&req_token);

    let calls = joined.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "onMemberJoined fires once for B");
    assert_eq!(calls[0].0, b_id, "joined id matches B");
}

/// onMemberJoined fires on all existing members when they receive the new manifest.
#[test]
fn on_member_joined_fires_on_existing_members_via_manifest() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let device_c = DeviceKeypair::generate();
    let c_id = member_id(&device_c.signing_public_key());

    let b_joined: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let bjc = b_joined.clone();

    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session A");

    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session B");

    session_b.set_on_member_joined(move |id, _name| {
        bjc.lock().unwrap().push(id);
    });

    // Set up A and B in a group.
    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    // A issues a new manifest adding C.
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();
    let v2 = crate::manifest::GroupManifest::new(
        session_a
            .manifest
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .group_id,
        2,
        vec![
            crate::manifest::ManifestMember {
                noise_pub: a_noise,
                signing_pub: a_signing,
                name: "A".into(),
            },
            crate::manifest::ManifestMember {
                noise_pub: b_noise,
                signing_pub: b_signing,
                name: "B".into(),
            },
            crate::manifest::ManifestMember {
                noise_pub: c_noise,
                signing_pub: c_signing,
                name: "C".into(),
            },
        ],
        &a_sk,
    );
    // Push manifest to B directly via push_message (simulating A issuing manifest).
    use crate::message::Message;
    let msg = Message::GroupManifest { manifest: v2 };
    session_a.push_message(&msg, b_noise).ok();

    wait_for(|| !b_joined.lock().unwrap().is_empty(), Duration::from_secs(5));

    let calls = b_joined.lock().unwrap().clone();
    assert!(calls.contains(&c_id), "B fires onMemberJoined for C");
}

/// onMemberLeft fires on remaining members when a member is removed.
#[test]
fn on_member_left_fires_when_member_removed() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let device_c = DeviceKeypair::generate();
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();
    let c_id = member_id(&c_signing);

    let b_left: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let blc = b_left.clone();

    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session A");

    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session B");

    session_b.set_on_member_left(move |id, _name| {
        blc.lock().unwrap().push(id);
    });

    // A, B, C in a group.
    let v1 = crate::manifest::GroupManifest::new(
        crate::manifest::new_group_id(),
        1,
        vec![
            crate::manifest::ManifestMember {
                noise_pub: a_noise,
                signing_pub: a_signing,
                name: "A".into(),
            },
            crate::manifest::ManifestMember {
                noise_pub: b_noise,
                signing_pub: b_signing,
                name: "B".into(),
            },
            crate::manifest::ManifestMember {
                noise_pub: c_noise,
                signing_pub: c_signing,
                name: "C".into(),
            },
        ],
        &a_sk,
    );
    let group_id = v1.group_id;
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    // A issues manifest removing C (same group_id, version 2).
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
    let msg = crate::message::Message::GroupManifest { manifest: v2 };
    session_a.push_message(&msg, b_noise).ok();

    wait_for(|| !b_left.lock().unwrap().is_empty(), Duration::from_secs(5));

    let calls = b_left.lock().unwrap().clone();
    assert!(calls.contains(&c_id), "B fires onMemberLeft for C");
}

/// onMemberLeft does NOT fire for the local device (that's onRemovedFromGroup).
#[test]
fn on_member_left_does_not_fire_for_local_device() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_bidirectional_relay(&relay_kp, pipe_a_relay, pipe_b_relay);

    let device_a = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let b_left: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let blc = b_left.clone();
    let b_removed: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let brc = b_removed.clone();

    let session_a = HushSession::connect_full(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session A");

    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        move || {
            *brc.lock().unwrap() += 1;
        }, // on_removed_from_group
        |_| {},
        || {},
    )
    .expect("session B");

    session_b.set_on_member_left(move |id, _name| {
        blc.lock().unwrap().push(id);
    });

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    // A removes B — B should get onRemovedFromGroup, NOT onMemberLeft.
    session_a.remove_member(b_signing).expect("remove B");
    wait_for(|| *b_removed.lock().unwrap() >= 1, Duration::from_secs(5));
    // Short fixed wait to ensure on_member_left does NOT fire.
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(*b_removed.lock().unwrap(), 1, "onRemovedFromGroup fires for B");
    assert!(b_left.lock().unwrap().is_empty(), "onMemberLeft must NOT fire when local device is removed");
}
