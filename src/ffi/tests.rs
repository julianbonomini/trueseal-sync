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

/// A minimal relay on loopback TCP: accepts XX receive connections in a
/// loop (a reconnect or a reopened session gets a fresh accept), records
/// every client frame, delivers sealed envelopes on demand — and, like a
/// real relay, re-delivers every delivered-but-unacked Blob when a new
/// Receive Session comes up (peek-and-ack, ADR-0020). The NK push side is
/// a bare listener whose accepted sockets are just counted (the handshake
/// is allowed to fail).
struct TcpRelay {
    relay_pub: crate::keys::NoisePublicKey,
    receive_port: u16,
    push_port: u16,
    client_frames: Arc<Mutex<Vec<(u8, Vec<u8>)>>>,
    push_connections: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
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
        let accepts = Arc::new(AtomicUsize::new(0));
        // All sends are driven by ONE writer thread over a shared state:
        // every Blob is tracked as unacked until its DeliverAck, and the
        // writer (re)sends unacked Blobs whenever a new Receive Session is
        // accepted (a generation bump) or a new Blob arrives. The accept
        // thread only publishes + signals, so no delivery can fall between
        // "accepted" and "published" (the resend-before-publish race).
        struct Shared {
            current: Option<(u64, Arc<trueseal_noise::session_xx::Session<TcpStream>>)>,
            generation: u64,
            unacked: Vec<(u64, Vec<u8>)>,
            sent_on: std::collections::HashMap<u64, u64>,
        }
        let shared = Arc::new(Mutex::new(Shared {
            current: None,
            generation: 0,
            unacked: Vec::new(),
            sent_on: std::collections::HashMap::new(),
        }));
        let changed = Arc::new(Condvar::new());
        let (deliver_tx, deliver_rx) = mpsc::channel::<(u64, Vec<u8>)>();

        // Incoming deliveries queue as unacked and wake the writer.
        {
            let shared = shared.clone();
            let changed = changed.clone();
            std::thread::spawn(move || {
                for delivery in deliver_rx {
                    shared.lock().unwrap().unacked.push(delivery);
                    changed.notify_all();
                }
            });
        }
        // Writer: the only sender.
        {
            let shared = shared.clone();
            let changed = changed.clone();
            std::thread::spawn(move || loop {
                let st = shared.lock().unwrap();
                let (mut st, _) = changed.wait_timeout(st, Duration::from_millis(50)).unwrap();
                let Some((gen, sess)) = st.current.clone() else {
                    continue;
                };
                let due: Vec<(u64, Vec<u8>)> = st
                    .unacked
                    .iter()
                    .filter(|(id, _)| st.sent_on.get(id) != Some(&gen))
                    .cloned()
                    .collect();
                for (blob_id, env_bytes) in due {
                    let mut body = blob_id.to_be_bytes().to_vec();
                    body.extend_from_slice(&env_bytes);
                    if sess.send(&frame(MsgType::Deliver, &body)).is_ok() {
                        st.sent_on.insert(blob_id, gen);
                    } else {
                        break; // session dying; the EOF handler clears it
                    }
                }
            });
        }

        // Accept loop: publish the new session and signal the writer.
        {
            let relay_kp =
                trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
            let client_frames = client_frames.clone();
            let accepts = accepts.clone();
            std::thread::spawn(move || {
                while let Ok((stream, _)) = receive_listener.accept() {
                    // Non-blocking, like every real peer (B1-fix): a
                    // blocking receive would hold the noise conn mutex for
                    // the whole read syscall and starve the writer's send.
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let kp = trueseal_noise::keypair::Keypair::new(
                        relay_kp.private(),
                        relay_kp.public_key,
                    );
                    let session = match crate::version::testutil::xx_accept_after_prefix(stream, kp)
                    {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let session = Arc::new(session);
                    {
                        let mut st = shared.lock().unwrap();
                        st.generation += 1;
                        st.current = Some((st.generation, session.clone()));
                    }
                    accepts.fetch_add(1, Ordering::SeqCst);
                    changed.notify_all();
                    // Read frames until the link dies; DeliverAcks retire
                    // the Blob.
                    let client_frames = client_frames.clone();
                    let shared = shared.clone();
                    let changed = changed.clone();
                    let session_for_read = session.clone();
                    std::thread::spawn(move || {
                        while let Ok(raw) = session_for_read.receive() {
                            if let Some((t, body)) = parse(&raw) {
                                if t == MsgType::DeliverAck {
                                    if let Ok(id) = <[u8; 8]>::try_from(body) {
                                        let id = u64::from_be_bytes(id);
                                        let mut st = shared.lock().unwrap();
                                        st.unacked.retain(|(bid, _)| *bid != id);
                                    }
                                }
                                client_frames.lock().unwrap().push((t as u8, body.to_vec()));
                            }
                        }
                        // The link died: stop pointing sends at it.
                        let mut st = shared.lock().unwrap();
                        let is_current = st
                            .current
                            .as_ref()
                            .map(|(_, c)| Arc::ptr_eq(c, &session))
                            .unwrap_or(false);
                        if is_current {
                            st.current = None;
                        }
                        drop(st);
                        changed.notify_all();
                    });
                }
            });
        }

        TcpRelay {
            relay_pub,
            receive_port,
            push_port,
            client_frames,
            push_connections,
            accepts,
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

/// Build the two-member genesis manifest {device, sender} and commit it
/// the way a real accept does (manifest + held history, atomically —
/// ADR-0027), so the next open() seeds it (SYNC-7). Returns the manifest.
fn persist_membership(
    dir: &tempfile::TempDir,
    namespace: &str,
    device: &DeviceKeypair,
    sender: &crate::envelope::SigningKeypair,
) -> crate::manifest::GroupManifest {
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
    let mut log = crate::store::PersistentLog::new(
        crate::store::Store::open(dir.path(), namespace).expect("store"),
    );
    crate::operation_log::OperationLog::commit_membership(
        &mut log,
        crate::operation_log::MembershipCommit {
            manifest: manifest.encode(),
            held: vec![(manifest.hash(), true)],
            pending_changes: Vec::new(),
            leaving: None,
            destroying: None,
            drop_sync_outbox: false,
            outbox: Vec::new(),
        },
    )
    .expect("commit membership");
    manifest
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

    // notMember{pendingJoin} while a Pending Join is held (ADR-0023; B13
    // review): a device mid-join is not Idle, so it can neither open a
    // Pairing Window nor accept a member into a group it has not
    // finished joining.
    let initiator = crate::device::DeviceKeypair::generate();
    let token = crate::message::pairing_token(
        &initiator.public_key().0,
        &initiator.signing_public_key().0,
        &[9u8; 32],
    );
    session.join(token).expect("well-formed token joins");
    assert!(matches!(
        session.start_pairing(),
        Err(TrueSealError::NotMember {
            status: GroupStatus::PendingJoin
        })
    ));
    // accept() while PendingJoin reaches the same gate for a LIVE request
    // id — but no live request can exist here (a window cannot open in
    // this state, and this device opened none before joining), so an
    // unknown id is honestly `pairingClosed`. The accept-side gate is
    // pinned at the core level by
    // session::tests::pairing_trust_anchor::pending_join_device_cannot_open_window_or_accept.

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

// ── The machine-readable surface (G12, SYNC-21) ───────────────────────────────
//
// The code-side lists come from `crate::surface` — the single source that
// also feeds the generator (`cargo run --bin gen-shared-facts`), so this
// test, the shared-facts test and the emitted files can never disagree
// about what the code says. `surface`'s naming functions are exhaustive
// matches: adding a variant fails compilation until it is named there.

#[test]
fn the_ffi_surface_matches_api_surface_json() {
    use crate::surface;
    let golden: serde_jsonless::Surface = serde_jsonless::load();

    // Errors: 14 canonical cases (ADR-0028 as amended by ADR-0032 and the
    // SYNC-15 amendment).
    let codes: Vec<&str> = surface::errors();
    assert_eq!(codes.len(), 14);
    assert_eq!(codes, golden.errors, "api-surface.json: errors drifted");

    // Events.
    let events: Vec<&str> = surface::events();
    assert_eq!(events, golden.events, "api-surface.json: events drifted");

    // Group statuses, status reasons, connection states.
    let statuses: Vec<&str> = surface::statuses();
    assert_eq!(
        statuses, golden.statuses,
        "api-surface.json: statuses drifted"
    );
    let reasons: Vec<&str> = surface::status_reasons();
    assert_eq!(
        reasons, golden.status_reasons,
        "api-surface.json: statusReasons drifted"
    );
    let connections: Vec<&str> = surface::connection_states();
    assert_eq!(
        connections, golden.connection_states,
        "api-surface.json: connectionStates drifted"
    );

    // Delivery issues and their reason enums.
    let issues: Vec<&str> = surface::delivery_issues();
    assert_eq!(
        issues, golden.delivery_issues,
        "api-surface.json: deliveryIssues drifted"
    );
    let unreadable: Vec<&str> = surface::unreadable_reasons();
    assert_eq!(
        unreadable, golden.unreadable_reasons,
        "api-surface.json: unreadableReasons drifted"
    );
    let send_failed: Vec<&str> = surface::send_failed_reasons();
    assert_eq!(
        send_failed, golden.send_failed_reasons,
        "api-surface.json: sendFailedReasons drifted"
    );
    let drops: Vec<&str> = surface::admission_drop_reasons();
    assert_eq!(
        drops, golden.admission_drop_reasons,
        "api-surface.json: admissionDropReasons drifted"
    );

    // Limits come from the core constants — the single source of truth.
    assert_eq!(golden.max_payload_bytes, 61_440);
    assert_eq!(golden.max_payload_bytes, trueseal_max_payload_bytes());
    assert_eq!(golden.max_payload_bytes, surface::max_payload_bytes());
    assert_eq!(golden.max_group_size, 32);
    assert_eq!(golden.max_group_size, trueseal_max_group_size());
    assert_eq!(golden.max_group_size, surface::max_group_size());
}

/// Shared Facts (SYNC-21, docs ADR-0003): the checked-in
/// docs/shared-facts.json must carry every public error, event, limit,
/// protocol/Store Version and the Relay Address format — from the code,
/// not by hand. This test fails if a fact is missing or stale; CI's
/// `gen-shared-facts --check` gate fails if the file was not regenerated.
#[test]
fn shared_facts_json_matches_the_code() {
    use crate::surface;
    let raw = include_str!("../../docs/shared-facts.json");

    assert_eq!(
        serde_jsonless::extract_string(raw, "sdkVersion"),
        env!("CARGO_PKG_VERSION")
    );

    // Versions (ADR-0022, ADR-0032).
    assert_eq!(
        serde_jsonless::extract_number(raw, "transportVersion"),
        surface::transport_version()
    );
    assert_eq!(
        serde_jsonless::extract_number(raw, "endToEndVersion"),
        surface::end_to_end_version()
    );
    assert_eq!(
        serde_jsonless::extract_number(raw, "storeVersion"),
        surface::store_version()
    );
    assert_eq!(
        serde_jsonless::extract_number(raw, "storeMigrationFloor"),
        surface::store_migration_floor()
    );

    // Limits (ADR-0025, ADR-0027, ADR-0022).
    assert_eq!(
        serde_jsonless::extract_number(raw, "maxPayloadBytes"),
        surface::max_payload_bytes()
    );
    assert_eq!(
        serde_jsonless::extract_number(raw, "maxGroupSize"),
        surface::max_group_size()
    );
    assert_eq!(
        serde_jsonless::extract_number(raw, "maxHeldBlobs"),
        surface::max_held_blobs()
    );

    // Relay Address (ADR-0028).
    assert_eq!(
        serde_jsonless::extract_string(raw, "format"),
        surface::relay_address_format()
    );
    assert_eq!(
        serde_jsonless::extract_string(raw, "scheme"),
        surface::relay_address_scheme()
    );
    assert_eq!(
        serde_jsonless::extract_number(raw, "defaultReceivePort"),
        surface::relay_address_default_receive_port() as u32
    );
    assert_eq!(
        serde_jsonless::extract_number(raw, "defaultPushPort"),
        surface::relay_address_default_push_port() as u32
    );

    // The full enum surface — including the 14th error case
    // (manifestVersionExhausted, SYNC-15's ADR-0028 amendment).
    assert_eq!(
        serde_jsonless::extract_array(raw, "errors"),
        surface::errors()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "events"),
        surface::events()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "statuses"),
        surface::statuses()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "statusReasons"),
        surface::status_reasons()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "connectionStates"),
        surface::connection_states()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "deliveryIssues"),
        surface::delivery_issues()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "unreadableReasons"),
        surface::unreadable_reasons()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "sendFailedReasons"),
        surface::send_failed_reasons()
    );
    assert_eq!(
        serde_jsonless::extract_array(raw, "admissionDropReasons"),
        surface::admission_drop_reasons()
    );
}

// Minimal JSON reader for docs/api-surface.json — no serde dependency in
// the crate; the file is flat and written by this module's own generator.
mod serde_jsonless {
    pub struct Surface {
        pub errors: Vec<&'static str>,
        pub events: Vec<&'static str>,
        pub statuses: Vec<&'static str>,
        pub status_reasons: Vec<&'static str>,
        pub connection_states: Vec<&'static str>,
        pub delivery_issues: Vec<&'static str>,
        pub unreadable_reasons: Vec<&'static str>,
        pub send_failed_reasons: Vec<&'static str>,
        pub admission_drop_reasons: Vec<&'static str>,
        pub max_payload_bytes: u32,
        pub max_group_size: u32,
    }

    pub fn load() -> Surface {
        let raw = include_str!("../../docs/api-surface.json");
        Surface {
            errors: extract_array(raw, "errors"),
            events: extract_array(raw, "events"),
            statuses: extract_array(raw, "statuses"),
            status_reasons: extract_array(raw, "statusReasons"),
            connection_states: extract_array(raw, "connectionStates"),
            delivery_issues: extract_array(raw, "deliveryIssues"),
            unreadable_reasons: extract_array(raw, "unreadableReasons"),
            send_failed_reasons: extract_array(raw, "sendFailedReasons"),
            admission_drop_reasons: extract_array(raw, "admissionDropReasons"),
            max_payload_bytes: extract_number(raw, "maxPayloadBytes"),
            max_group_size: extract_number(raw, "maxGroupSize"),
        }
    }

    pub fn extract_array(raw: &str, key: &str) -> Vec<&'static str> {
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

    pub fn extract_number(raw: &str, key: &str) -> u32 {
        let needle = format!("\"{key}\"");
        let start = raw.find(&needle).expect("key present");
        let rest = &raw[start + needle.len()..];
        let colon = rest.find(':').expect("colon");
        let num: String = rest[colon + 1..]
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        num.parse().expect("number parses")
    }

    /// Extract a flat string value: `"key": "value"`. Unescapes the escape
    /// sequences the generator can emit.
    pub fn extract_string(raw: &str, key: &str) -> String {
        let needle = format!("\"{key}\"");
        let start = raw.find(&needle).expect("key present");
        let rest = &raw[start + needle.len()..];
        let colon = rest.find(':').expect("colon");
        let rest = rest[colon + 1..].trim_start();
        let rest = rest.strip_prefix('"').expect("string opens");
        let mut out = String::new();
        let mut chars = rest.chars();
        loop {
            match chars.next().expect("string closes") {
                '"' => break,
                '\\' => match chars.next().expect("escape char") {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'n' => out.push('\n'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        let code = u32::from_str_radix(&hex, 16).expect("unicode escape");
                        out.push(char::from_u32(code).expect("valid char"));
                    }
                    other => panic!("unsupported escape: \\{other}"),
                },
                c => out.push(c),
            }
        }
        out
    }
}

/// The pre-listener buffer is bounded (SYNC-15 gate F5): overflow drops
/// the oldest, so a listener-less app against a flapping relay does not
/// grow memory forever.
#[test]
fn event_buffer_is_bounded_and_drops_oldest() {
    let bus: ListenerBus<u64> = ListenerBus::new();
    for i in 0..1100u64 {
        bus.fire(i);
    }
    let got: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(vec![]));
    let g = got.clone();
    let _id = bus.subscribe(Arc::new(move |e| g.lock().unwrap().push(e)));
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1024, "buffered events capped");
    assert_eq!(got[0], 1100 - 1024, "the oldest were dropped");
    assert_eq!(got[1023], 1099, "the newest survived");
}

/// A handler that records and returns immediately.
struct SimpleHandler(Arc<Mutex<Vec<TrueSealMessage>>>);
#[async_trait::async_trait]
impl TrueSealMessageHandler for SimpleHandler {
    async fn on_message(&self, message: TrueSealMessage) -> Result<(), HandlerError> {
        self.0.lock().unwrap().push(message);
        Ok(())
    }
}

/// SYNC-15 gate F2 (at-least-once across close with no handler): a Blob
/// delivered while no handler is registered parks the dispatch; closing
/// there must NOT record the message as handled — the ack never leaves,
/// the relay re-delivers on the next open(), and the handler then
/// registered receives it. (Pre-fix, the parked wait returned "success",
/// the dedup record committed, and the re-delivery was a silent no-op.)
#[test]
fn close_during_pre_registration_wait_does_not_lose_the_message() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();

    // Phase 1: create the identity. Wait for the link so the close lands
    // on a live connection — the accept count below is then exact.
    let first = open_test_session(&dir, &relay.address(), "app");
    wait_for(
        || relay.accepts.load(Ordering::SeqCst) == 1,
        Duration::from_secs(10),
        "first session accepted",
    );
    first.close();
    let device = load_identity(&dir, "app");
    let sender = fresh_sender();
    persist_membership(&dir, "app", &device, &sender);

    // Phase 2: open, NO message handler — the delivered Blob parks the
    // dispatch (registration-gated receiving, ADR-0026).
    let session = open_test_session(&dir, &relay.address(), "app");
    wait_for(
        || relay.accepts.load(Ordering::SeqCst) == 2,
        Duration::from_secs(10),
        "second session accepted",
    );
    relay.deliver_from(7, b"do-not-lose-me", device.public_key(), &sender, 0);
    // It parks unacked (no handler) — then close() mid-wait.
    assert_quiet(
        || !relay.deliver_acks().is_empty(),
        Duration::from_millis(400),
        "acked with no handler registered",
    );
    session.close();

    // Phase 3: reopen the same namespace, register the handler — the relay
    // re-delivers the unacked Blob on the new session and the handler runs.
    let received: Arc<Mutex<Vec<TrueSealMessage>>> = Arc::new(Mutex::new(vec![]));
    let session3 = open_test_session(&dir, &relay.address(), "app");
    session3
        .on_message(Box::new(SimpleHandler(received.clone())))
        .expect("handler registers");
    wait_for(
        || relay.accepts.load(Ordering::SeqCst) == 3,
        Duration::from_secs(10),
        "third session accepted",
    );
    wait_for(
        || received.lock().unwrap().len() == 1,
        Duration::from_secs(10),
        "redelivered message reaches the handler after reopen",
    );
    assert_eq!(received.lock().unwrap()[0].body, b"do-not-lose-me");
    wait_for(
        || relay.deliver_acks() == vec![7],
        Duration::from_secs(10),
        "acked exactly once, on the final session",
    );
    session3.close();
}

// ── The lifecycle rule (ADR-0028) ─────────────────────────────────────────────

/// After a Soft Removal the SAME object reports `statusChanged(notJoined,
/// removed)`, an emptied member list, and can pair again — no rebuild.
#[test]
fn removal_reports_not_joined_and_the_same_object_pairs_again() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();

    let first = open_test_session(&dir, &relay.address(), "app");
    first.close();
    let relay = TcpRelay::spawn();

    let device = load_identity(&dir, "app");
    // The remover: member B, holding a raw Ed25519 key for manifest
    // signing plus the envelope wrapper for sealing.
    let b_signing_bytes: [u8; 32] = rand::random();
    let b_signing = ed25519_dalek::SigningKey::from_bytes(&b_signing_bytes);
    let sender = crate::envelope::SigningKeypair::from_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&b_signing_bytes),
    );
    let v1 = persist_membership(&dir, "app", &device, &sender);

    let session = open_test_session(&dir, &relay.address(), "app");
    let events = Arc::new(Mutex::new(Vec::<TrueSealEvent>::new()));
    session
        .on_event(Box::new(EventLog(events.clone())))
        .expect("on_event");

    let me_before = session.me().expect("me").id;
    assert_eq!(session.status().unwrap(), GroupStatus::Member);

    // B issues v2 excluding this device, parent-linked to the v1 it held
    // — a deliberate removal (ADR-0027).
    let b_member = crate::manifest::ManifestMember {
        noise_pub: crate::keys::NoisePublicKey([9u8; 32]),
        signing_pub: crate::keys::SigningPublicKey(b_signing.verifying_key().to_bytes()),
        name: "B".into(),
    };
    let v2 =
        crate::manifest::GroupManifest::update(&v1, vec![b_member], &b_signing).expect("v2 issues");
    let msg = crate::message::Message::GroupManifest { manifest: v2 };
    let env = crate::envelope::Envelope::build_sealed(
        42,
        vec![],
        device.public_key(),
        &sender,
        crate::operation_log::now_secs() * 1000,
        &msg.encode(),
    );
    relay
        .deliver_tx
        .send((9, env.encode()))
        .expect("relay alive");

    wait_for(
        || {
            events.lock().unwrap().iter().any(|e| {
                matches!(
                    e,
                    TrueSealEvent::StatusChanged {
                        status: GroupStatus::NotJoined,
                        reason: StatusReason::Removed
                    }
                )
            })
        },
        Duration::from_secs(15),
        "statusChanged(notJoined, removed)",
    );
    assert!(events.lock().unwrap().iter().any(|e| matches!(
        e,
        TrueSealEvent::MembersChanged { members } if members.is_empty()
    )));
    assert_eq!(session.status().unwrap(), GroupStatus::NotJoined);
    // Identity rotated — the same object, a fresh device.
    assert_ne!(session.me().unwrap().id, me_before);
    // And it can pair again.
    assert!(!session.start_pairing().expect("window opens").is_empty());
    session.close();
}

/// A Leaving device applies inbound manifests without a spurious
/// `statusChanged(member, joined)` (SYNC-15 gate): the member event fires
/// only on an ENTRY into membership (from notJoined or pendingJoin).
#[test]
fn leaving_device_applies_manifests_without_a_spurious_joined_event() {
    let relay = TcpRelay::spawn();
    let dir = tempfile::TempDir::new().unwrap();

    let first = open_test_session(&dir, &relay.address(), "app");
    first.close();
    let relay = TcpRelay::spawn();

    let device = load_identity(&dir, "app");
    let b_signing_bytes: [u8; 32] = rand::random();
    let b_signing = ed25519_dalek::SigningKey::from_bytes(&b_signing_bytes);
    let sender = crate::envelope::SigningKeypair::from_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&b_signing_bytes),
    );
    let v1 = persist_membership(&dir, "app", &device, &sender);

    let session = open_test_session(&dir, &relay.address(), "app");
    let events = Arc::new(Mutex::new(Vec::<TrueSealEvent>::new()));
    session
        .on_event(Box::new(EventLog(events.clone())))
        .expect("on_event");
    assert_eq!(session.status().unwrap(), GroupStatus::Member);

    // Leave: the Leave manifest rides the outbox, but the relay stub never
    // completes NK pushes — the device stays Leaving, which is exactly the
    // state under test.
    session.leave().expect("leave");
    assert_eq!(session.status().unwrap(), GroupStatus::Leaving);
    events.lock().unwrap().clear();

    // B issues a routine update while this device's Leave is in flight.
    // leave() installed the Leave manifest as the local v2, so a same-
    // version inbound would be a (version, hash) coin flip (ADR-0027) —
    // B steps to v3, which always wins the order. Members unchanged; the
    // device is still included, so this is the routine-update path, not a
    // removal. A Leaving device still applies it.
    let v2_b = crate::manifest::GroupManifest::update(&v1, v1.members.clone(), &b_signing)
        .expect("v2 issues");
    let v3_b = crate::manifest::GroupManifest::update(&v2_b, v1.members.clone(), &b_signing)
        .expect("v3 issues");
    let msg = crate::message::Message::GroupManifest { manifest: v3_b };
    let env = crate::envelope::Envelope::build_sealed(
        42,
        vec![],
        device.public_key(),
        &sender,
        crate::operation_log::now_secs() * 1000,
        &msg.encode(),
    );
    relay
        .deliver_tx
        .send((11, env.encode()))
        .expect("relay alive");

    // membersChanged proves the hook ran and applied the manifest; the
    // statusChanged decision happens in the same hook, before it — so once
    // membersChanged is observed, a spurious joined would already be in
    // the log (no timing window needed for the negative).
    wait_for(
        || {
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, TrueSealEvent::MembersChanged { .. }))
        },
        Duration::from_secs(10),
        "manifest applied while leaving",
    );
    let log = events.lock().unwrap();
    assert!(
        !log.iter()
            .any(|e| matches!(e, TrueSealEvent::StatusChanged { .. })),
        "no statusChanged while leaving: {log:?}"
    );
    drop(log);
    assert_eq!(session.status().unwrap(), GroupStatus::Leaving);
    session.close();
}
