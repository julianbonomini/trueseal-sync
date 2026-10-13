//! `close()` (SYNC-15, #107; ADR-0028): stops the connection and the
//! handlers, keeps Session State, and every later call fails with
//! `SessionError::Closed`. The reconnect loop and the sender pump exit on
//! the shutdown flag; the receive client is severed through the Noise
//! session's closed flag.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;
use crate::session::SessionError;
use crate::session::TruesealSession;

use super::super::test_helpers::*;

/// A session over factories that never connect (receive factory fails,
/// push factory fails) with a fast reconnect cap.
fn offline_session(
    receive_attempts: Arc<AtomicUsize>,
) -> TruesealSession<super::super::test_helpers::MemPipeSimple> {
    TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub(&make_relay_kp()),
        DeviceKeypair::generate(),
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        move || {
            receive_attempts.fetch_add(1, Ordering::SeqCst);
            Err("no relay in this test".into())
        },
        || Err("no push in this test".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("connect_background")
}

/// close() ends the reconnect loop: dial attempts stop within one backoff
/// slice, they do not just slow down.
#[test]
fn close_stops_the_reconnect_loop() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let session = offline_session(attempts.clone());

    // Baseline: the loop is alive and retrying.
    wait_for(
        || attempts.load(Ordering::SeqCst) >= 2,
        Duration::from_secs(5),
    );
    session.close();

    // With the loop dead the counter never moves again. The window is six
    // times the 50 ms poll slice, so a live loop could not stay silent even
    // on a slow CI machine.
    let at_close = attempts.load(Ordering::SeqCst);
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "test clock"
    );
    drop(tx);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        at_close,
        "reconnect attempts continued after close()"
    );
}

/// Every state-changing call after close() fails with the typed `Closed`.
#[test]
fn calls_after_close_fail_typed() {
    let session = offline_session(Arc::new(AtomicUsize::new(0)));
    session.close();

    assert!(matches!(
        session.push_sync(b"blob".to_vec()),
        Err(SessionError::Closed)
    ));
    assert!(matches!(
        session.join_group("garbage"),
        Err(SessionError::Closed)
    ));
    assert!(matches!(
        session.pairing_token(),
        Err(SessionError::Closed)
    ));
    assert!(matches!(
        session.accept_member("unknown"),
        Err(SessionError::Closed)
    ));
    assert!(matches!(
        session.remove_member_by_id("unknown"),
        Err(SessionError::Closed)
    ));
    assert!(matches!(session.leave_group(), Err(SessionError::Closed)));
    assert!(matches!(session.destroy_group(), Err(SessionError::Closed)));

    // The no-return-value calls become no-ops (they cannot throw).
    session.cancel_join();
    session.cancel_pairing();

    assert!(session.is_closed());
}

/// close() is idempotent.
#[test]
fn close_is_idempotent() {
    let session = offline_session(Arc::new(AtomicUsize::new(0)));
    session.close();
    session.close();
    assert!(session.is_closed());
}

/// close() severs the live receive link: the run loop exits and the
/// connection drops — proof the receive thread's WouldBlock retry observed
/// the Noise session's closed flag instead of parking on the socket.
#[test]
fn close_severs_the_receive_link() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let relay_gone2 = relay_gone.clone();
    std::thread::spawn(move || {
        if let Ok(sess) = crate::version::testutil::xx_accept_after_prefix(pipe_relay, relay_kp2)
        {
            // Hold the session open like a real relay until the client's
            // close kills the link (receive errors) — then record it.
            while sess.receive().is_ok() {}
            relay_gone2.store(true, std::sync::atomic::Ordering::Release);
        }
    });

    let events: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
    let ec = events.clone();
    let pipe_slot: Arc<Mutex<Option<_>>> = Arc::new(Mutex::new(Some(pipe_client)));
    let pipe_slot2 = pipe_slot.clone();
    let session = TruesealSession::<MemPipeSimple>::connect_background(
        relay_pub(&relay_kp),
        DeviceKeypair::generate(),
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        move || {
            pipe_slot2
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "exhausted".into())
        },
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        Some(Box::new(move |connected| {
            ec.lock().unwrap().push(connected);
        })),
    )
    .expect("connect_background");

    // Connected baseline.
    wait_for(
        || events.lock().unwrap().contains(&true),
        Duration::from_secs(5),
    );

    session.close();

    // The relay's receive errors as soon as the client's session closes —
    // the link really dies, it is not just flagged down locally.
    wait_for(
        || relay_gone.load(std::sync::atomic::Ordering::Acquire),
        Duration::from_secs(5),
    );
}
