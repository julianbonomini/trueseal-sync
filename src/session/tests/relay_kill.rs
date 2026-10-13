//! B23c — the D1 finding: killing the relay must be detected through the
//! FULL session stack (receive loop → liveness watchdog → reconnect loop →
//! connection-event callback) over REAL TCP, not just at the RelayClient
//! level. The D1 Swift task observed ≥150 s of silence after a relay kill
//! with no Disconnected. Every liveness test predating this file ran over
//! in-memory pipes; a real dead TCP socket behaves differently (FIN/RST on
//! a clean kill, nothing at all on a black-hole).

use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use trueseal_noise::keypair::Keypair;

use crate::device::DeviceKeypair;
use crate::operation_log::MemLog;
use crate::relay::{frame, parse, MsgType, SessionTimeouts};
use crate::session::{ConnectionChange, TruesealSession};
use crate::version::testutil::xx_accept_after_prefix;

use super::super::test_helpers::*;

/// How the relay stand-in dies once told.
enum KillMode {
    /// Drop the socket: the kernel delivers FIN (or RST with a heartbeat
    /// in flight) — a clean process kill.
    CleanKill,
    /// Leak the socket without closing: no FIN, no RST, silence — a
    /// killed container / pulled cable. Only the liveness watchdog can
    /// notice this one.
    BlackHole,
}

/// A real-TCP relay stand-in: version exchange + XX accept, then echo
/// heartbeats exactly like the real relay until killed, then die per
/// `mode`. Returns (receive_addr, kill switch).
fn spawn_tcp_relay(relay_kp: Keypair, mode: KillMode) -> (String, mpsc::Sender<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind relay");
    let addr = listener.local_addr().expect("addr").to_string();
    let (kill_tx, kill_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        // The relay side blocks; the client side is non-blocking (the
        // production shape — ConnectionFactory sets non-blocking).
        let session = xx_accept_after_prefix(stream, relay_kp).expect("accept handshake");
        loop {
            if kill_rx.try_recv().is_ok() {
                match mode {
                    KillMode::CleanKill => drop(session),
                    KillMode::BlackHole => std::mem::forget(session),
                }
                return;
            }
            match session.receive() {
                Ok(raw) => {
                    if let Some((MsgType::Heartbeat, _)) = parse(&raw) {
                        if session.send(&frame(MsgType::Heartbeat, &[])).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => return,
            }
        }
    });
    (addr, kill_tx)
}

fn test_timeouts() -> SessionTimeouts {
    SessionTimeouts {
        heartbeat: Duration::from_millis(500),
        liveness: Duration::from_millis(1_500),
        handshake: Duration::from_millis(2_000),
    }
}

/// A full session (receive loop + reconnect loop + connection events) over
/// the real production transport against the given relay address.
fn tcp_session(
    addr: &str,
    relay_kp: &Keypair,
    events: Arc<Mutex<Vec<ConnectionChange>>>,
) -> TruesealSession<TcpStream> {
    let receive_addr = addr.to_string();
    let events_cb = events.clone();
    TruesealSession::<TcpStream>::connect_background_with_timeouts(
        relay_pub(relay_kp),
        DeviceKeypair::generate(),
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        |_, _| {},
        move || crate::connection::ConnectionFactory::open(&receive_addr),
        || Err("no push in this test".into()),
        Some(Duration::from_millis(200)),
        Some(Box::new(move |change| {
            events_cb
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(change);
        })),
        test_timeouts(),
    )
    .expect("connect_background_with_timeouts")
}

fn saw(events: &Arc<Mutex<Vec<ConnectionChange>>>, want: ConnectionChange) -> bool {
    events
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&want)
}

/// Clean kill over real TCP: FIN/RST must surface as Disconnected through
/// the whole stack.
#[test]
fn relay_clean_kill_surfaces_disconnected_through_the_full_stack() {
    let relay_kp = make_relay_kp();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let (addr, kill) = spawn_tcp_relay(relay_kp2, KillMode::CleanKill);

    let events = Arc::new(Mutex::new(Vec::new()));
    let _session = tcp_session(&addr, &relay_kp, events.clone());
    wait_for(
        || saw(&events, ConnectionChange::Connected),
        Duration::from_secs(5),
    );

    kill.send(()).expect("kill");
    wait_for(
        || saw(&events, ConnectionChange::Disconnected),
        Duration::from_secs(10),
    );
}

/// Black-hole kill over real TCP: no FIN, no RST — only the liveness
/// watchdog can notice, and the Disconnected must still surface.
#[test]
fn relay_blackhole_kill_surfaces_disconnected_through_the_full_stack() {
    let relay_kp = make_relay_kp();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let (addr, kill) = spawn_tcp_relay(relay_kp2, KillMode::BlackHole);

    let events = Arc::new(Mutex::new(Vec::new()));
    let _session = tcp_session(&addr, &relay_kp, events.clone());
    wait_for(
        || saw(&events, ConnectionChange::Connected),
        Duration::from_secs(5),
    );

    kill.send(()).expect("kill");
    wait_for(
        || saw(&events, ConnectionChange::Disconnected),
        Duration::from_secs(10),
    );
}
