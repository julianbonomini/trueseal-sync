use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::member::member_id;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::{HushSession, SessionError};
use super::make_two_member_manifest;

/// remove_member_by_id with a valid id removes that member.
#[test]
fn remove_member_by_id_removes_the_member() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session_xx::accept(pipe_relay, kp);
        });
    }

    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let remote = DeviceKeypair::generate();
    let remote_id = member_id(&remote.signing_public_key());

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

    session
        .remove_member_by_id(&remote_id)
        .expect("remove by id");

    // Remote should no longer appear in members().
    assert!(
        session.members().is_empty(),
        "remote device should be removed"
    );
}

/// remove_member_by_id with unknown id returns MemberNotFound.
#[test]
fn remove_member_by_id_unknown_returns_member_not_found() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session_xx::accept(pipe_relay, kp);
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

    let result = session.remove_member_by_id("doesnotexist");
    assert!(
        matches!(result, Err(SessionError::MemberNotFound)),
        "unknown id must return MemberNotFound"
    );
}

/// remove_member_by_id with no manifest returns NotInGroup.
#[test]
fn remove_member_by_id_no_manifest_returns_not_in_group() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session_xx::accept(pipe_relay, kp);
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

    let result = session.remove_member_by_id("anyid");
    assert!(
        matches!(result, Err(SessionError::NotInGroup)),
        "no manifest must return NotInGroup"
    );
}
