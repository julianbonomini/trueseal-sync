use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::{HushSession, SessionError};

/// create_offline() succeeds with an unreachable relay — returns a session immediately.
#[test]
fn create_offline_returns_session_immediately() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();

    // Use a factory that always fails (unreachable relay).
    let session = HushSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in offline test".into()),
        None,
        None,
    );

    assert!(
        session.is_ok(),
        "connect_background must succeed even with unreachable relay"
    );
}

/// An offline session returns NotInGroup for push (no manifest), not a connectivity error.
#[test]
fn offline_session_send_returns_not_in_group() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();

    let session = HushSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in offline test".into()),
        None,
        None,
    )
    .expect("offline session");

    let result = session.push_sync(b"hello".to_vec());
    // No manifest → NotInGroup (not a connectivity error).
    assert!(
        matches!(result, Err(SessionError::NotInGroup)),
        "offline with no manifest → NotInGroup, got {result:?}"
    );
}

/// An offline session queues send to outbox when manifest is set.
#[test]
fn offline_session_with_manifest_queues_to_outbox() {
    use super::make_two_member_manifest;
    use ed25519_dalek::SigningKey;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let remote = DeviceKeypair::generate();

    let session = HushSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in offline test".into()),
        None,
        None,
    )
    .expect("offline session");

    let manifest = make_two_member_manifest(
        noise,
        signing,
        &sk,
        remote.public_key(),
        remote.signing_public_key(),
    );
    session.set_manifest(manifest);

    // push_sync while offline returns Ok(()) and queues to outbox (ADR-0017).
    let result = session.push_sync(b"hello".to_vec());
    assert!(
        result.is_ok(),
        "offline with manifest → Ok(()) (queued to outbox), got {result:?}"
    );
    // Verify outbox has the entry.
    let undelivered = session.op_log.lock().unwrap().undelivered_entries();
    assert_eq!(undelivered.len(), 1, "outbox should have 1 queued message");
}
