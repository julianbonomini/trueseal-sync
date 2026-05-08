use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::{HushSession, SessionError};
use super::{make_one_member_manifest, make_two_member_manifest};

/// remove_member returns MemberNotFound when target signing pub is not in manifest.
#[test]
fn remove_member_unknown_returns_member_not_found() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session::accept(pipe_relay, kp);
        });
    }
    let device = DeviceKeypair::generate();
    let signing = device.signing_public_key();
    let noise = device.public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());

    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");
    let dummy_peer = DeviceKeypair::generate();
    let v1 = make_two_member_manifest(
        noise,
        signing,
        &sk,
        dummy_peer.public_key(),
        dummy_peer.signing_public_key(),
    );
    session.set_manifest(v1);

    let unknown = DeviceKeypair::generate().signing_public_key();
    let result = session.remove_member(unknown);
    assert!(
        matches!(result, Err(SessionError::MemberNotFound)),
        "should return MemberNotFound"
    );
}

/// remove_member returns NotInGroup when no manifest is set.
#[test]
fn remove_member_no_manifest_returns_not_in_group() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session::accept(pipe_relay, kp);
        });
    }
    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

    let target = DeviceKeypair::generate().signing_public_key();
    let result = session.remove_member(target);
    assert!(
        matches!(result, Err(SessionError::NotInGroup)),
        "should return NotInGroup"
    );
}

/// {A, B, C}: A removes C → B and C both receive updated manifest; C's manifest excludes C.
#[test]
fn remove_member_issues_new_manifest_excluding_target() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    spawn_tripartite_relay(&relay_kp, pipe_a_relay, pipe_b_relay, pipe_c_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_c = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();

    // Build a 3-member manifest.
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

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    let session_b =
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");
    let session_c =
        HushSession::connect(pipe_c_client, relay_pub, device_c, |_, _| {}).expect("session C");

    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1.clone());
    session_c.set_manifest(v1.clone());

    // A removes C.
    session_a.remove_member(c_signing).expect("remove_member");

    std::thread::sleep(Duration::from_millis(200));

    // A's manifest: 2 members.
    let a_m = session_a.manifest.lock().unwrap();
    assert_eq!(
        a_m.as_ref().unwrap().members.len(),
        2,
        "A: 2 members after remove"
    );
    assert_eq!(a_m.as_ref().unwrap().version, 2, "A: version incremented");
    drop(a_m);

    // B's manifest: updated to 2 members.
    let b_m = session_b.manifest.lock().unwrap();
    assert_eq!(
        b_m.as_ref().unwrap().members.len(),
        2,
        "B: updated to 2 members"
    );
    assert_eq!(b_m.as_ref().unwrap().version, 2, "B: version 2");
    drop(b_m);

    // C's manifest: should receive the new manifest (which excludes C).
    let c_m = session_c.manifest.lock().unwrap();
    assert!(c_m.is_some(), "C: received updated manifest");
    assert_eq!(c_m.as_ref().unwrap().version, 2, "C: version 2");
    assert_eq!(
        c_m.as_ref().unwrap().members.len(),
        2,
        "C: sees 2-member manifest"
    );
}

/// After remove_member, the removed device's subsequent messages are discarded by remaining members.
#[test]
fn removed_member_messages_are_discarded() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    spawn_tripartite_relay(&relay_kp, pipe_a_relay, pipe_b_relay, pipe_c_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_c = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();

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

    let a_received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![]));
    let ar = a_received.clone();
    let session_a = HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _| {
        if let crate::message::Message::Sync { body } = msg {
            ar.lock().unwrap().push(body);
        }
    })
    .expect("session A");

    let session_b =
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _| {}).expect("session B");
    let session_c =
        HushSession::connect(pipe_c_client, relay_pub, device_c, |_, _| {}).expect("session C");

    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1.clone());
    session_c.set_manifest(v1.clone());

    // A removes C.
    session_a.remove_member(c_signing).expect("remove_member");
    std::thread::sleep(Duration::from_millis(150));

    // C received the new manifest which excludes C.
    // C's push_sync fans out to A and B using C's (updated) manifest,
    // but A and B will discard the message because C's signing key is no longer
    // in their manifest — the inbound filter drops it.
    let _ = session_c.push_sync(b"should be dropped".to_vec());

    std::thread::sleep(Duration::from_millis(100));
    assert!(
        a_received.lock().unwrap().is_empty(),
        "A receives nothing from C after removal"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        a_received.lock().unwrap().is_empty(),
        "A receives nothing from C after removal"
    );
}

/// #30: A removes B; B's on_removed_from_group fires exactly once.
#[test]
fn on_removed_from_group_fires_on_remove_member() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let removed_count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let rc = removed_count.clone();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        move || {
            *rc.lock().unwrap() += 1;
        },
        |_| {},
        || {},
    )
    .expect("session B");

    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1);

    session_a.remove_member(b_signing).expect("remove_member");
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(
        *removed_count.lock().unwrap(),
        1,
        "B's on_removed_from_group must fire exactly once"
    );
}

/// #30: A removes C (not B); B's on_removed_from_group does NOT fire.
#[test]
fn on_removed_from_group_does_not_fire_for_unaffected_member() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    spawn_tripartite_relay(&relay_kp, pipe_a_relay, pipe_b_relay, pipe_c_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_c = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();

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

    let b_removed_count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let brc = b_removed_count.clone();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    let session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        move || {
            *brc.lock().unwrap() += 1;
        },
        |_| {},
        || {},
    )
    .expect("session B");
    let session_c =
        HushSession::connect(pipe_c_client, relay_pub, device_c, |_, _| {}).expect("session C");

    session_a.set_manifest(v1.clone());
    session_b.set_manifest(v1.clone());
    session_c.set_manifest(v1);

    // A removes C — B should NOT fire on_removed_from_group.
    session_a.remove_member(c_signing).expect("remove_member");
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(
        *b_removed_count.lock().unwrap(),
        0,
        "B's on_removed_from_group must NOT fire when C is removed"
    );
}
