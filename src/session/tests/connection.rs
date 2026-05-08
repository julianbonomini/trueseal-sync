use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::HushSession;

/// connect_background fires on_connection_changed(true) once the relay connects.
#[test]
fn connection_changed_fires_true_on_initial_connect() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // Relay will accept one connection.
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let relay_kp2 = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session::accept(pipe_relay, relay_kp2);
        });
    }

    let events: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
    let ec = events.clone();

    let pipe_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_client)));
    let pipe_slot2 = pipe_slot.clone();

    let _session = HushSession::<MemPipe>::connect_background(
        relay_pub,
        DeviceKeypair::generate(),
        |_, _| {},
        Box::new(MemLog::new()),
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
        Some(Duration::from_millis(50)), // short cap for fast reconnect
        Some(Box::new(move |connected| {
            ec.lock().unwrap().push(connected);
        })),
    )
    .expect("session");

    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        *events.lock().unwrap(),
        vec![true],
        "should fire true once relay connects"
    );
}

/// connect→disconnect→reconnect fires [true, false, true].
#[test]
fn connection_changed_fires_sequence_on_disconnect_and_reconnect() {
    use std::sync::atomic::Ordering;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // First connection: will be closed after session starts.
    let (pipe1_client, pipe1_relay, _close_relay1, close_client1) = mem_pipe_pair_with_close();
    {
        let relay_kp2 = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session::accept(pipe1_relay, relay_kp2);
        });
    }

    // Second connection for reconnect.
    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    {
        let relay_kp3 = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = hush_noise::session::accept(pipe2_relay, relay_kp3);
        });
    }

    // Factory: gives pipe1 first, then pipe2.
    let pipes: Arc<Mutex<Vec<MemPipe>>> = Arc::new(Mutex::new(vec![pipe1_client, pipe2_client]));
    let pipes2 = pipes.clone();

    let events: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![]));
    let ec = events.clone();

    let _session = HushSession::<MemPipe>::connect_background(
        relay_pub,
        DeviceKeypair::generate(),
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        move || {
            let mut v = pipes2.lock().unwrap();
            if v.is_empty() {
                Err("exhausted".into())
            } else {
                Ok(v.remove(0))
            }
        },
        Some(Duration::from_millis(50)), // short cap
        Some(Box::new(move |connected| {
            ec.lock().unwrap().push(connected);
        })),
    )
    .expect("session");

    // Wait for first connect → true.
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(*events.lock().unwrap(), vec![true], "should connect first");

    // Kill the first connection → run_loop detects EOF → is_connected = false.
    close_client1.store(true, Ordering::Release);

    // Wait for false + reconnect true.
    // Reconnect backoff is reset to 1s after success, so allow ~1.5s total.
    std::thread::sleep(Duration::from_millis(1800));
    let snapshot = events.lock().unwrap().clone();
    assert!(
        snapshot.contains(&false),
        "should fire false on disconnect, got {snapshot:?}"
    );
    assert!(
        snapshot.last() == Some(&true),
        "should fire true on reconnect, got {snapshot:?}"
    );
}
