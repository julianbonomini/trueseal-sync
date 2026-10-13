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
    assert!(matches!(session.pairing_token(), Err(SessionError::Closed)));
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
/// connection drops — proof the sever-induced transport EOF interrupts a
/// receive parked in WouldBlock retry (the noise closed flag is only
/// checked at receive entry, so the EOF does the work) instead of the
/// thread parking on the socket.
#[test]
fn close_severs_the_receive_link() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let relay_gone2 = relay_gone.clone();
    std::thread::spawn(move || {
        if let Ok(sess) = crate::version::testutil::xx_accept_after_prefix(pipe_relay, relay_kp2) {
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
        Some(Box::new(move |change| {
            ec.lock().unwrap().push(matches!(
                change,
                crate::session::ConnectionChange::Connected
            ));
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

/// close() landing mid-dial must not resurrect a zombie connection
/// (SYNC-15 gate F1): the version exchange can hold a dial open for
/// seconds, so the reconnect loop re-checks the shutdown flag after the
/// handshake completes and drops a client it built for a closed session —
/// its threads exit and the relay's end dies instead of parking forever.
#[test]
fn close_during_dial_installs_no_live_client() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Condvar;

    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();

    // The relay holds the handshake open until the test releases it, then
    // completes the accept and reports when the link dies.
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let relay_eof = Arc::new(AtomicBool::new(false));
    let relay_done = Arc::new(AtomicBool::new(false));
    {
        let release = release.clone();
        let relay_eof = relay_eof.clone();
        let relay_done = relay_done.clone();
        let relay_kp2 =
            trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let (lock, cvar) = &*release;
            let mut go = lock.lock().unwrap();
            while !*go {
                go = cvar.wait(go).unwrap();
            }
            drop(go);
            // The client was closed while its dial waited on this. Complete
            // the handshake anyway — the client side must drop the result.
            if let Ok(sess) =
                crate::version::testutil::xx_accept_after_prefix(pipe_relay, relay_kp2)
            {
                relay_done.store(true, Ordering::SeqCst);
                while sess.receive().is_ok() {}
                relay_eof.store(true, Ordering::SeqCst);
            }
        });
    }

    let dial_attempts = Arc::new(AtomicUsize::new(0));
    let da = dial_attempts.clone();
    let pipe_slot: Arc<Mutex<Option<_>>> = Arc::new(Mutex::new(Some(pipe_client)));
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
            da.fetch_add(1, Ordering::SeqCst);
            pipe_slot
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "exhausted".into())
        },
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("connect_background");

    // The dial is in flight once the factory produced the pipe. Give the
    // exchange a bounded 200 ms of relay silence — far under its 10 s
    // deadline — so close() lands while the dial is parked in the version
    // exchange. (A channel recv_timeout as the clock, not a bare sleep.)
    let start = std::time::Instant::now();
    while dial_attempts.load(Ordering::SeqCst) == 0 {
        if start.elapsed() > Duration::from_secs(5) {
            panic!("factory never called");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let clock = std::sync::mpsc::channel::<()>().1;
    let _ = clock.recv_timeout(Duration::from_millis(200));

    session.close();

    // Now the relay completes the handshake. Pre-fix, the loop installed
    // the live client and exited — the relay's session would stay open.
    {
        let (lock, cvar) = &*release;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    wait_for(
        || relay_done.load(Ordering::SeqCst),
        Duration::from_secs(15),
    );
    wait_for(|| relay_eof.load(Ordering::SeqCst), Duration::from_secs(15));
    assert!(session.is_closed());
}
