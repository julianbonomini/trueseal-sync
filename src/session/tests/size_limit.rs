//! SYNC-8 (#100): the Protocol Size Limit is 61,440 bytes of `Sync` body,
//! checked synchronously in `send()` (ADR-0025).
//!
//! The defect: an oversize send was accepted by the library, appended to the
//! outbox, and then replayed on every reconnect forever — the relay refuses
//! it permanently, but the client never noticed. The first two tests assert
//! the defect is gone; both fail against the pre-fix code.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::operation_log::{MemLog, OperationLog};

use super::super::test_helpers::*;
use super::super::TruesealSession;
use super::make_two_member_manifest;

fn offline_session_with_manifest() -> TruesealSession<MemPipeSimple> {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let remote = DeviceKeypair::generate();

    let session = TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in size-limit tests".into()),
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
    session
}

/// A body of 61,441 bytes is refused synchronously and never enters the
/// Outbox (ADR-0025: "`send()` checks the limit synchronously, before
/// anything is written to the Operation Log"). RED on the pre-fix code:
/// it returned `Ok(())` and queued the entry.
#[test]
fn oversize_send_is_refused_and_never_enters_outbox() {
    let session = offline_session_with_manifest();

    let result = session.push_sync(vec![0xABu8; 61_441]);

    assert!(
        result.is_err(),
        "61,441-byte body must be refused, got {result:?}"
    );
    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert!(
        undelivered.is_empty(),
        "an oversize body must never enter the Outbox, found {} entries",
        undelivered.len()
    );
}

/// An oversize entry persisted in an outbox from before this fix (only
/// possible in development stores) is dropped on load, so it can never be
/// replayed forever (ADR-0025). RED on the pre-fix code: the entry survived.
#[test]
fn oversize_outbox_entry_is_dropped_on_load() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let remote = DeviceKeypair::generate();

    // An outbox entry written by a pre-fix build: over the Protocol Size
    // Limit, undeliverable, and (pre-fix) replayed on every reconnect.
    let mut log = MemLog::new();
    log.append(&remote.public_key().0, 0, vec![0xCDu8; 61_441]);
    // A valid entry that must survive the drop.
    log.append(&remote.public_key().0, 1, b"within limit".to_vec());

    let session = TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(log),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        || Err("unreachable".into()),
        || Err("push factory unused in size-limit tests".into()),
        None,
        None,
    )
    .expect("offline session");

    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(
        undelivered.len(),
        1,
        "the oversize entry must be dropped on load, the valid one kept"
    );
    assert_eq!(undelivered[0].sequence, 1);
    assert_eq!(undelivered[0].blob, b"within limit");
}

/// A body of exactly 61,440 bytes — the Protocol Size Limit itself — is
/// accepted (boundary, passing side).
#[test]
fn send_at_exact_limit_is_accepted() {
    let session = offline_session_with_manifest();

    let result = session.push_sync(vec![0xEFu8; 61_440]);

    assert!(
        result.is_ok(),
        "61,440-byte body is exactly at the limit and must be accepted, got {result:?}"
    );
    let undelivered = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(
        undelivered.len(),
        1,
        "the accepted send is queued for the one remote member"
    );
}
