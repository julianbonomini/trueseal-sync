//! FFI-surface tests (SYNC-15, #107): the canonical TrueSeal API against a
//! real loopback TCP relay stub — the same wire the SDKs will drive.

// This file is compiled only under cfg(test) (see the `mod tests;` gate in
// src/ffi.rs); the attribute on the first item keeps
// scripts/check-no-unwrap.sh's line-number heuristic aware of that.
#[cfg(test)]
use super::*;
use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

use crate::relay::{frame, parse, MsgType};

fn wait_for(cond: impl Fn() -> bool, timeout: Duration, what: &str) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("wait_for ({what}): condition not met within {timeout:?}");
}

/// Observe a bounded window with no event (the "must NOT happen yet"
/// assertions): waits `window`, then asserts `cond` stayed false.
fn assert_quiet(cond: impl Fn() -> bool, window: Duration, what: &str) {
    let deadline = std::time::Instant::now() + window;
    while std::time::Instant::now() < deadline {
        assert!(!cond(), "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ── TCP relay stub ────────────────────────────────────────────────────────────

/// A minimal relay on loopback TCP: accepts ONE XX receive connection after
/// the version prefix, records every client frame, and delivers sealed
/// envelopes on demand. The NK push side is a bare listener whose accepted
/// sockets are just counted (the handshake is allowed to fail).
struct TcpRelay {
    relay_pub: crate::keys::NoisePublicKey,
    receive_port: u16,
    push_port: u16,
    client_frames: Arc<Mutex<Vec<(u8, Vec<u8>)>>>,
    push_connections: Arc<AtomicUsize>,
    deliver_tx: mpsc::Sender<(u64, Vec<u8>)>,
}

impl TcpRelay {
    fn spawn() -> Self {
        let relay_kp = trueseal_noise::keypair::generate_keypair();
        let relay_pub = crate::keys::NoisePublicKey(relay_kp.public_key);
        let receive_listener = TcpListener::bind("127.0.0.1:0").expect("bind receive");
        let push_listener = TcpListener::bind("127.0.0.1:0").expect("bind push");
        let receive_port = receive_listener.local_addr().unwrap().port();
        let push_port = push_listener.local_addr().unwrap().port();

        let push_connections = Arc::new(AtomicUsize::new(0));
        {
            let push_connections = push_connections.clone();
            std::thread::spawn(move || {
                while let Ok((stream, _)) = push_listener.accept() {
                    push_connections.fetch_add(1, Ordering::SeqCst);
                    // Hold the socket so the client's handshake bytes have
                    // somewhere to go; never answer — the push attempt
                    // times out on its own.
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 256];
                        let mut s = stream;
                        loop {
                            match std::io::Read::read(&mut s, &mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    });
                }
            });
        }

        let client_frames = Arc::new(Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
        let (deliver_tx, deliver_rx) = mpsc::channel::<(u64, Vec<u8>)>();
        {
            let client_frames = client_frames.clone();
            let relay_kp =
                trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
            std::thread::spawn(move || {
                let (stream, _) = receive_listener.accept().expect("accept receive");
                // Non-blocking, like every real peer (B1-fix): a blocking
                // receive would hold the noise conn mutex for the whole
                // read syscall and starve the deliver writer's send.
                stream.set_nonblocking(true).expect("nonblocking");
                let session = crate::version::testutil::xx_accept_after_prefix(stream, relay_kp)
                    .expect("relay accept");
                let session = Arc::new(session);
                let send_session = session.clone();
                std::thread::spawn(move || {
                    for (blob_id, env_bytes) in deliver_rx {
                        let mut body = blob_id.to_be_bytes().to_vec();
                        body.extend_from_slice(&env_bytes);
                        if send_session.send(&frame(MsgType::Deliver, &body)).is_err() {
                            break;
                        }
                    }
                });
                while let Ok(raw) = session.receive() {
                    if let Some((t, body)) = parse(&raw) {
                        client_frames.lock().unwrap().push((t as u8, body.to_vec()));
                    }
                }
            });
        }

        TcpRelay {
            relay_pub,
            receive_port,
            push_port,
            client_frames,
            push_connections,
            deliver_tx,
        }
    }

    fn address(&self) -> String {
        let key_hex: String = self
            .relay_pub
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "trueseal://{key_hex}@127.0.0.1:{}?push={}",
            self.receive_port, self.push_port
        )
    }

    fn deliver_from(
        &self,
        blob_id: u64,
        body: &[u8],
        recipient: crate::keys::NoisePublicKey,
        sender: &crate::envelope::SigningKeypair,
        seq: u64,
    ) {
        let msg = crate::message::Message::Sync {
            body: body.to_vec(),
        };
        let env = crate::envelope::Envelope::build_sealed(
            seq,
            vec![],
            recipient,
            sender,
            crate::operation_log::now_secs() * 1000,
            &msg.encode(),
        );
        self.deliver_tx
            .send((blob_id, env.encode()))
            .expect("relay alive");
    }

    fn deliver_acks(&self) -> Vec<u64> {
        self.client_frames
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t == MsgType::DeliverAck as u8)
            .filter_map(|(_, b)| b.as_slice().try_into().ok().map(u64::from_be_bytes))
            .collect()
    }
}

/// A fresh tempdir-backed open against `relay`.
fn open_test_session(dir: &tempfile::TempDir, relay_addr: &str, namespace: &str) -> Arc<TrueSeal> {
    TrueSeal::open(
        relay_addr.to_string(),
        dir.path().to_string_lossy().into_owned(),
        Some(namespace.to_string()),
        None,
    )
    .expect("open")
}

/// Build the two-member genesis manifest {device, sender} and persist it to
/// the namespace's store, so the next open() seeds it (SYNC-7).
fn persist_membership(
    dir: &tempfile::TempDir,
    namespace: &str,
    device: &DeviceKeypair,
    sender: &crate::envelope::SigningKeypair,
) {
    let self_sp = device.signing_public_key();
    let sender_sp = crate::keys::SigningPublicKey(sender.public_key_bytes());
    let manifest = crate::manifest::GroupManifest::new(
        crate::manifest::new_group_id(),
        1,
        vec![
            crate::manifest::ManifestMember {
                noise_pub: device.public_key(),
                signing_pub: self_sp,
                name: crate::member::member_name(&self_sp),
            },
            crate::manifest::ManifestMember {
                noise_pub: crate::keys::NoisePublicKey([9u8; 32]),
                signing_pub: sender_sp,
                name: crate::member::member_name(&sender_sp),
            },
        ],
        &ed25519_dalek::SigningKey::from_bytes(&device.signing.to_bytes()),
    );
    crate::store::Store::open(dir.path(), namespace)
        .expect("store")
        .save_group_manifest(&manifest)
        .expect("save manifest");
}

fn load_identity(dir: &tempfile::TempDir, namespace: &str) -> DeviceKeypair {
    crate::store::Store::open(dir.path(), namespace)
        .expect("store")
        .load_keypair()
        .expect("load")
        .expect("identity exists after first open")
}

fn fresh_sender() -> crate::envelope::SigningKeypair {
    crate::envelope::SigningKeypair::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
        &rand::random::<[u8; 32]>(),
    ))
}

// ── Relay Address ─────────────────────────────────────────────────────────────

#[test]
fn relay_address_parsing_surface() {
    let key = "aa".repeat(32);
    let parsed =
        trueseal_parse_relay_address(format!("trueseal://{key}@relay.example.com")).expect("valid");
    assert_eq!(parsed.host, "relay.example.com");
    assert_eq!(parsed.public_key, vec![0xaau8; 32]);
    assert_eq!(parsed.receive_port, 7700);
    assert_eq!(parsed.push_port, 7701);

    let parsed =
        trueseal_parse_relay_address(format!("trueseal://{key}@relay.example.com:1?push=2"))
            .expect("valid");
    assert_eq!(parsed.receive_port, 1);
    assert_eq!(parsed.push_port, 2);

    for bad in ["", "http://x@y", "trueseal://zz@host", "trueseal://aa@"] {
        assert!(
            matches!(
                trueseal_parse_relay_address(bad.to_string()),
                Err(TrueSealError::InvalidRelayAddress { .. })
            ),
            "should reject {:?}",
            bad
        );
    }
}

#[test]
fn open_rejects_malformed_relay_address_and_namespace() {
    let dir = tempfile::TempDir::new().unwrap();
    let base = dir.path().to_string_lossy().into_owned();
    assert!(matches!(
        TrueSeal::open("not an address".into(), base.clone(), None, None),
        Err(TrueSealError::InvalidRelayAddress { .. })
    ));
    let key = "aa".repeat(32);
    assert!(matches!(
        TrueSeal::open(
            format!("trueseal://{key}@127.0.0.1:9"),
            base.clone(),
            Some("bad namespace".into()),
            None,
        ),
        Err(TrueSealError::InvalidNamespace { .. })
    ));
}

/// The ports in the Relay Address are the ports dialed — never dropped
/// (SWIFT-1's root cause). Receive: the listener on the custom port sees
/// the session. Push: a queued outbox entry makes the pump dial the custom
/// push port.
#[test]
fn open_dials_the_ports_from_the_relay_address() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();

    // Phase 1: create the identity.
    let first = open_test_session(&dir, &relay.address(), "app");
    first.close();

    // Phase 2: membership persisted; the device can send.
    let device = load_identity(&dir, "app");
    let sender = fresh_sender();
    persist_membership(&dir, "app", &device, &sender);

    let session = open_test_session(&dir, &relay.address(), "app");

    // The receive connection lands on the receive port (the relay accepted
    // it in spawn — observe it via the connection event instead).
    let events = Arc::new(Mutex::new(Vec::<TrueSealEvent>::new()));
    let ev = events.clone();
    struct L(Arc<Mutex<Vec<TrueSealEvent>>>);
    impl TrueSealEventListener for L {
        fn on_event(&self, event: TrueSealEvent) {
            self.0.lock().unwrap().push(event);
        }
    }
    session.on_event(Box::new(L(ev))).expect("on_event");
    wait_for(
        || {
            events.lock().unwrap().iter().any(|e| {
                matches!(
                    e,
                    TrueSealEvent::ConnectionChanged {
                        connection: ConnectionState::Connected
                    }
                )
            })
        },
        Duration::from_secs(10),
        "connection event on the custom receive port",
    );

    // A queued entry makes the pump dial the custom push port.
    session.send(b"hello".to_vec()).expect("send queues");
    wait_for(
        || relay.push_connections.load(Ordering::SeqCst) >= 1,
        Duration::from_secs(10),
        "push dialed on the custom push port",
    );
    session.close();
}

// ── The awaited async handler ─────────────────────────────────────────────────

struct RecordingHandler {
    entered: Arc<AtomicUsize>,
    release: Arc<(Mutex<bool>, Condvar)>,
    received: Arc<Mutex<Vec<TrueSealMessage>>>,
}

#[async_trait::async_trait]
impl TrueSealMessageHandler for RecordingHandler {
    async fn on_message(&self, message: TrueSealMessage) -> Result<(), HandlerError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        // Block until the test releases — the ack must NOT leave the
        // device while the handler is still running (ADR-0026).
        let (lock, cvar) = &*self.release;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = cvar.wait(released).unwrap();
        }
        self.received.lock().unwrap().push(message);
        Ok(())
    }
}

/// ADR-0026/0028 at the FFI seam: nothing is delivered before a handler is
/// registered; once registered, the DeliverAck leaves only after the async
/// handler completes.
#[test]
fn ack_only_after_the_awaited_handler_completes() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();

    // Phase 1: create the identity, then close.
    let first = open_test_session(&dir, &relay.address(), "app");
    first.close();
    // The first session's receive connection died with close(); the relay
    // stub accepted exactly one. Respawn for the second session.
    let relay = TcpRelay::spawn();
    let device = load_identity(&dir, "app");
    let sender = fresh_sender();
    persist_membership(&dir, "app", &device, &sender);

    let session = open_test_session(&dir, &relay.address(), "app");
    // Wait until the receive link is up before delivering.
    let connected = Arc::new(AtomicBool::new(false));
    struct CL(Arc<AtomicBool>);
    impl TrueSealEventListener for CL {
        fn on_event(&self, event: TrueSealEvent) {
            if matches!(
                event,
                TrueSealEvent::ConnectionChanged {
                    connection: ConnectionState::Connected
                }
            ) {
                self.0.store(true, Ordering::Release);
            }
        }
    }
    session
        .on_event(Box::new(CL(connected.clone())))
        .expect("on_event");
    wait_for(
        || connected.load(Ordering::Acquire),
        Duration::from_secs(10),
        "connected",
    );

    // No handler registered: the Blob is delivered by the relay but NOT
    // acked and NOT dispatched — receiving starts at registration.
    relay.deliver_from(7, b"payload", device.public_key(), &sender, 0);
    assert_quiet(
        || !relay.deliver_acks().is_empty(),
        Duration::from_millis(400),
        "acked with no handler registered",
    );

    // Register a blocking handler: it is entered (registration starts
    // receiving) but the ack waits for completion.
    let entered = Arc::new(AtomicUsize::new(0));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let received: Arc<Mutex<Vec<TrueSealMessage>>> = Arc::new(Mutex::new(vec![]));
    let handler = RecordingHandler {
        entered: entered.clone(),
        release: release.clone(),
        received: received.clone(),
    };
    session
        .on_message(Box::new(handler))
        .expect("first registration");

    wait_for(
        || entered.load(Ordering::SeqCst) >= 1,
        Duration::from_secs(10),
        "handler entered after registration",
    );
    assert_quiet(
        || !relay.deliver_acks().is_empty(),
        Duration::from_millis(400),
        "acked while the handler was still running",
    );

    // Release: the handler completes and the ack goes out with the blob id.
    {
        let (lock, cvar) = &*release;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    wait_for(
        || relay.deliver_acks() == vec![7],
        Duration::from_secs(10),
        "DeliverAck after the handler completed",
    );

    // The message carries the stable Message ID and the member identity.
    let got = received.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].body, b"payload");
    let sender_pub = crate::keys::SigningPublicKey(sender.public_key_bytes());
    assert_eq!(got[0].from.id, member_id(&sender_pub));
    assert_eq!(got[0].from.name, member_name(&sender_pub));
    assert_eq!(
        got[0].id,
        crate::message::message_id(&sender.public_key_bytes(), 0)
    );
    session.close();
}

/// A second on_message registration fails with messageHandlerAlreadySet.
#[test]
fn second_handler_registration_fails_typed() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();
    let session = open_test_session(&dir, &relay.address(), "app");

    struct Noop;
    #[async_trait::async_trait]
    impl TrueSealMessageHandler for Noop {
        async fn on_message(&self, _message: TrueSealMessage) -> Result<(), HandlerError> {
            Ok(())
        }
    }
    session.on_message(Box::new(Noop)).expect("first");
    let second = session.on_message(Box::new(Noop));
    assert!(matches!(
        second,
        Err(TrueSealError::MessageHandlerAlreadySet)
    ));
    // And cancelling does not reopen registration (ADR-0028: ONE handler).
    assert!(matches!(
        session.on_message(Box::new(Noop)),
        Err(TrueSealError::MessageHandlerAlreadySet)
    ));
    session.close();
}

// ── Typed errors ──────────────────────────────────────────────────────────────

#[test]
fn typed_errors_match_the_canonical_taxonomy() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();
    let session = open_test_session(&dir, &relay.address(), "app");

    // notMember{status} while notJoined.
    assert!(matches!(
        session.send(b"x".to_vec()),
        Err(TrueSealError::NotMember {
            status: GroupStatus::NotJoined
        })
    ));
    assert!(matches!(
        session.destroy_group(),
        Err(TrueSealError::NotMember {
            status: GroupStatus::NotJoined
        })
    ));
    assert!(matches!(
        session.leave(),
        Err(TrueSealError::NotMember {
            status: GroupStatus::NotJoined
        })
    ));
    assert!(matches!(
        session.remove("nobody".into()),
        Err(TrueSealError::NotMember {
            status: GroupStatus::NotJoined
        })
    ));
    assert!(matches!(
        session.join("garbage".into()),
        Err(TrueSealError::InvalidPairingToken)
    ));
    assert!(matches!(
        session.accept("no-such-request".into()),
        Err(TrueSealError::PairingClosed)
    ));

    // close(): every call fails typed; close() itself is idempotent.
    session.close();
    session.close();
    assert!(matches!(
        session.send(b"x".to_vec()),
        Err(TrueSealError::Closed)
    ));
    assert!(matches!(session.status(), Err(TrueSealError::Closed)));
    assert!(matches!(session.members(), Err(TrueSealError::Closed)));
    assert!(matches!(session.me(), Err(TrueSealError::Closed)));
    assert!(matches!(session.connection(), Err(TrueSealError::Closed)));
    assert!(matches!(
        session.start_pairing(),
        Err(TrueSealError::Closed)
    ));
    assert!(matches!(
        session.cancel_pairing(),
        Err(TrueSealError::Closed)
    ));
    assert!(matches!(session.cancel_join(), Err(TrueSealError::Closed)));
    struct Noop;
    #[async_trait::async_trait]
    impl TrueSealMessageHandler for Noop {
        async fn on_message(&self, _message: TrueSealMessage) -> Result<(), HandlerError> {
            Ok(())
        }
    }
    assert!(matches!(
        session.on_message(Box::new(Noop)),
        Err(TrueSealError::Closed)
    ));
    struct NoopEv;
    impl TrueSealEventListener for NoopEv {
        fn on_event(&self, _event: TrueSealEvent) {}
    }
    assert!(matches!(
        session.on_event(Box::new(NoopEv)),
        Err(TrueSealError::Closed)
    ));
}

/// send() returns the Message ID — the same derivation the receiver sees
/// (ADR-0031) — and payloadTooLarge carries the limit.
#[test]
fn send_returns_the_message_id_and_checks_size() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();
    let first = open_test_session(&dir, &relay.address(), "app");
    first.close();
    let relay = TcpRelay::spawn();
    let device = load_identity(&dir, "app");
    let sender = fresh_sender();
    persist_membership(&dir, "app", &device, &sender);
    let session = open_test_session(&dir, &relay.address(), "app");

    let id = session.send(b"hello".to_vec()).expect("send");
    // Fresh namespace, first send: sequence 0.
    let expected = crate::message::message_id(&device.signing_public_key().0, 0);
    assert_eq!(id, expected);
    // A second send gets the next sequence's ID.
    let id2 = session.send(b"again".to_vec()).expect("send");
    assert_eq!(
        id2,
        crate::message::message_id(&device.signing_public_key().0, 1)
    );

    // The limit is enforced synchronously (ADR-0025).
    let oversize = vec![0u8; crate::limits::PROTOCOL_SIZE_LIMIT + 1];
    assert!(matches!(
        session.send(oversize),
        Err(TrueSealError::PayloadTooLarge { max: 61440 })
    ));

    // The creation-time option lowers it (and cannot raise it).
    session.close();
    let limited = TrueSeal::open(
        relay.address(),
        dir.path().to_string_lossy().into_owned(),
        Some("limited".into()),
        Some(100),
    )
    .expect("open limited");
    assert!(matches!(
        limited.send(vec![0u8; 101]),
        Err(TrueSealError::PayloadTooLarge { max: 100 })
    ));
    assert!(limited.send(vec![0u8; 100]).is_err()); // notMember, but NOT tooLarge
    let capped = TrueSeal::open(
        relay.address(),
        dir.path().to_string_lossy().into_owned(),
        Some("capped".into()),
        Some(999_999_999),
    )
    .expect("open capped");
    assert!(matches!(
        capped.send(vec![0u8; crate::limits::PROTOCOL_SIZE_LIMIT + 1]),
        Err(TrueSealError::PayloadTooLarge { max: 61440 })
    ));
    limited.close();
    capped.close();
    session.close();
}

// ── Store Reset / StoreTooNew ─────────────────────────────────────────────────

struct EventLog(Arc<Mutex<Vec<TrueSealEvent>>>);
impl TrueSealEventListener for EventLog {
    fn on_event(&self, event: TrueSealEvent) {
        self.0.lock().unwrap().push(event);
    }
}

/// ADR-0032 + ADR-0028: an unmigratable store resets automatically and the
/// `statusChanged(notJoined, storeReset)` event is BUFFERED — a listener
/// registered after open() still receives it.
#[test]
fn store_reset_is_buffered_until_the_first_listener() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();
    {
        let s = crate::store::Store::open(dir.path(), "app").expect("open");
        let kp = DeviceKeypair::generate();
        s.save_keypair(&kp).expect("save");
        let conn = rusqlite::Connection::open(dir.path().join("trueseal_app.db")).unwrap();
        conn.execute(
            "DELETE FROM meta WHERE key IN ('store_version', 'e2e_version')",
            [],
        )
        .unwrap();
    }
    let session = open_test_session(&dir, &relay.address(), "app");

    // The listener registers AFTER open() and still sees the reset.
    let events = Arc::new(Mutex::new(Vec::new()));
    session
        .on_event(Box::new(EventLog(events.clone())))
        .expect("on_event");
    assert!(events.lock().unwrap().iter().any(|e| matches!(
        e,
        TrueSealEvent::StatusChanged {
            status: GroupStatus::NotJoined,
            reason: StatusReason::StoreReset
        }
    )));
    // The object is usable: notJoined and pairable.
    assert_eq!(session.status().unwrap(), GroupStatus::NotJoined);
    assert!(!session.start_pairing().expect("window opens").is_empty());
    session.close();
}

/// ADR-0032: a store written by a newer release is refused with the typed
/// storeTooNew, bytes unchanged.
#[test]
fn newer_store_is_refused_with_store_too_new() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();
    {
        let _s = crate::store::Store::open(dir.path(), "app").expect("open");
        let conn = rusqlite::Connection::open(dir.path().join("trueseal_app.db")).unwrap();
        conn.execute("UPDATE meta SET value = 99 WHERE key = 'store_version'", [])
            .unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }
    let before = std::fs::read(dir.path().join("trueseal_app.db")).unwrap();
    let result = TrueSeal::open(
        relay.address(),
        dir.path().to_string_lossy().into_owned(),
        Some("app".into()),
        None,
    );
    match result {
        Err(TrueSealError::StoreTooNew { found, supported }) => {
            assert_eq!(found, 99);
            assert_eq!(supported, crate::version::STORE_VERSION);
        }
        other => panic!("expected StoreTooNew, got {}", other.is_ok()),
    }
    let after = std::fs::read(dir.path().join("trueseal_app.db")).unwrap();
    assert_eq!(before, after, "refused store: bytes unchanged");
}

// ── The machine-readable surface (G12) ────────────────────────────────────────

/// One canonical code per error variant — an exhaustive match, so the
/// compiler fails this test's helper when a 15th case appears.
fn error_code(e: &TrueSealError) -> &'static str {
    match e {
        TrueSealError::InvalidRelayAddress { .. } => "invalidRelayAddress",
        TrueSealError::InvalidNamespace { .. } => "invalidNamespace",
        TrueSealError::Storage { .. } => "storage",
        TrueSealError::Closed => "closed",
        TrueSealError::NotMember { .. } => "notMember",
        TrueSealError::AlreadyInGroup => "alreadyInGroup",
        TrueSealError::InvalidPairingToken => "invalidPairingToken",
        TrueSealError::PairingClosed => "pairingClosed",
        TrueSealError::GroupFull { .. } => "groupFull",
        TrueSealError::MemberNotFound => "memberNotFound",
        TrueSealError::PayloadTooLarge { .. } => "payloadTooLarge",
        TrueSealError::MessageHandlerAlreadySet => "messageHandlerAlreadySet",
        TrueSealError::StoreTooNew { .. } => "storeTooNew",
        TrueSealError::ManifestVersionExhausted => "manifestVersionExhausted",
    }
}

/// One instance of every error variant — 14, no more (ADR-0028 as amended
/// by ADR-0032 and SYNC-15).
fn every_error() -> Vec<TrueSealError> {
    vec![
        TrueSealError::InvalidRelayAddress { msg: String::new() },
        TrueSealError::InvalidNamespace { msg: String::new() },
        TrueSealError::Storage { msg: String::new() },
        TrueSealError::Closed,
        TrueSealError::NotMember {
            status: GroupStatus::NotJoined,
        },
        TrueSealError::AlreadyInGroup,
        TrueSealError::InvalidPairingToken,
        TrueSealError::PairingClosed,
        TrueSealError::GroupFull { max: 32 },
        TrueSealError::MemberNotFound,
        TrueSealError::PayloadTooLarge { max: 61440 },
        TrueSealError::MessageHandlerAlreadySet,
        TrueSealError::StoreTooNew {
            found: 2,
            supported: 1,
        },
        TrueSealError::ManifestVersionExhausted,
    ]
}

#[test]
fn the_error_enum_is_exactly_the_canonical_14() {
    let codes: Vec<&str> = every_error().iter().map(error_code).collect();
    assert_eq!(codes.len(), 14);
    let golden: serde_jsonless::Surface = serde_jsonless::load();
    assert_eq!(codes, golden.errors, "docs/api-surface.json drifted");
}

// Minimal JSON reader for docs/api-surface.json — no serde dependency in
// the crate; the file is flat and written by this module's own generator.
mod serde_jsonless {
    pub struct Surface {
        pub errors: Vec<&'static str>,
    }

    pub fn load() -> Surface {
        let raw = include_str!("../../docs/api-surface.json");
        let errors = extract_array(raw, "errors");
        Surface { errors }
    }

    fn extract_array(raw: &str, key: &str) -> Vec<&'static str> {
        let needle = format!("\"{key}\"");
        let start = raw.find(&needle).expect("key present");
        let rest = &raw[start..];
        let open = rest.find('[').expect("array opens");
        let close = rest.find(']').expect("array closes");
        rest[open + 1..close]
            .split(',')
            .map(|item| {
                let item = item.trim().trim_matches('"');
                // Leak is fine in tests: the strings are a static table.
                Box::leak(item.to_string().into_boxed_str()) as &'static str
            })
            .filter(|s| !s.is_empty())
            .collect()
    }
}
