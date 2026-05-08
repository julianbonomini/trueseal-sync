use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::member::{member_id, member_name};
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::HushSession;
use super::make_two_member_manifest;

/// members() returns an empty list when there is no manifest.
#[test]
fn members_empty_when_no_manifest() {
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
    let session = HushSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("connect");

    assert!(session.members().is_empty(), "no manifest → empty members");
}

/// members() returns remote members only — excludes the local device.
#[test]
fn members_excludes_local_device() {
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
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let remote = DeviceKeypair::generate();

    let session = HushSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("connect");

    let manifest = make_two_member_manifest(
        noise,
        signing,
        &sk,
        remote.public_key(),
        remote.signing_public_key(),
    );
    session.set_manifest(manifest);

    let members = session.members();
    assert_eq!(members.len(), 1, "only remote device in members");
    // The returned member should correspond to the remote device.
    let expected_id = member_id(&remote.signing_public_key());
    assert_eq!(members[0].id, expected_id);
    let expected_name = member_name(&remote.signing_public_key());
    assert_eq!(members[0].name, expected_name);
}

/// members() id and name are deterministic — same manifest, same result.
#[test]
fn members_id_and_name_are_stable() {
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
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let remote = DeviceKeypair::generate();

    let session = HushSession::connect_full(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("connect");

    let manifest = make_two_member_manifest(
        noise,
        signing,
        &sk,
        remote.public_key(),
        remote.signing_public_key(),
    );
    session.set_manifest(manifest);

    let m1 = session.members();
    let m2 = session.members();
    assert_eq!(m1[0].id, m2[0].id);
    assert_eq!(m1[0].name, m2[0].name);
}
