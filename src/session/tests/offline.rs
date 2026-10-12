use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::{SessionError, TruesealSession};

/// create_offline() succeeds with an unreachable relay — returns a session immediately.
#[test]
fn create_offline_returns_session_immediately() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();

    // Use a factory that always fails (unreachable relay).
    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
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

    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
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

    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
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

/// A relay that refuses our Transport Version (ADR-0022) leaves every outbox
/// entry queued — nothing is delivered, nothing is lost, the session keeps
/// retrying in the background (the relay may be upgraded).
#[test]
fn unsupported_transport_version_leaves_outbox_queued() {
    use super::make_two_member_manifest;
    use ed25519_dalek::SigningKey;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let remote = DeviceKeypair::generate();

    // Every connection attempt gets a fresh pipe whose relay end refuses the
    // Transport Version.
    let transport_factory = || {
        let (client_end, mut relay_end) = mem_pipe_pair();
        std::thread::spawn(move || {
            let mut prefix = [0u8; crate::version::TRANSPORT_PREFIX_LEN];
            let mut filled = 0;
            while filled < prefix.len() {
                match relay_end.read(&mut prefix[filled..]) {
                    Ok(0) => return,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
            let _ = relay_end.write_all(b"unsupported 1..1\n");
        });
        Ok(client_end)
    };

    let connected_events: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cb = connected_events.clone();

    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        transport_factory,
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        Some(Box::new(move |connected| {
            events_cb.lock().unwrap().push(connected);
        })),
    )
    .expect("session");

    let manifest = make_two_member_manifest(
        noise,
        signing,
        &sk,
        remote.public_key(),
        remote.signing_public_key(),
    );
    session.set_manifest(manifest);

    session
        .push_sync(b"still queued".to_vec())
        .expect("queued while offline");

    // Let the reconnect loop bang on the refusing relay a few times.
    std::thread::sleep(Duration::from_millis(500));

    let undelivered = session.op_log.lock().unwrap().undelivered_entries();
    assert_eq!(
        undelivered.len(),
        1,
        "the outbox entry must stay queued against a version-refusing relay"
    );
    assert!(
        !connected_events.lock().unwrap().contains(&true),
        "never connected"
    );
}
