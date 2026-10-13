use std::io;
use std::sync::{mpsc, Arc, Mutex};

use trueseal_noise::keypair::{generate_keypair, Keypair};

use crate::version::testutil::xx_accept_after_prefix;

use crate::keys::NoisePublicKey;
use crate::relay::{frame, parse, MsgType};

/// Type alias so test files can name the pipe type without knowing internals.
pub(super) type MemPipeSimple = MemPipe;

/// Like `mem_pipe_pair` but with a shorter name for NK-push tests.
pub(super) fn mem_pipe_pair_simple() -> (MemPipeSimple, MemPipeSimple) {
    mem_pipe_pair()
}

/// Sender side of an NK push channel.
/// Clone to give the same relay-side channel to multiple sessions.
#[derive(Clone)]
pub(super) struct NkSender(Arc<Mutex<mpsc::Sender<MemPipe>>>);

impl NkSender {
    /// Return a push factory suitable for a session constructor.
    /// Each call creates an independent factory closure sharing the same channel.
    pub fn factory(&self) -> impl Fn() -> Result<MemPipe, String> + Send + Sync + 'static {
        let tx = self.0.clone();
        move || {
            let (client, relay) = mem_pipe_pair();
            tx.lock()
                .unwrap()
                .send(relay)
                .map_err(|_| "nk channel closed".to_string())?;
            Ok(client)
        }
    }
}

/// Create an NK push channel.
///
/// Returns `(relay_rx, nk_sender)` where:
/// - `relay_rx` is passed to a relay helper that accepts NK push connections
/// - `nk_sender.factory()` is passed to a session constructor; each push opens
///   a fresh in-memory pipe and sends the relay-side end through the channel.
/// - Multiple sessions can share a channel by cloning `nk_sender`.
pub(super) fn nk_push_channel() -> (mpsc::Receiver<MemPipe>, NkSender) {
    let (tx, rx) = mpsc::channel::<MemPipe>();
    (rx, NkSender(Arc::new(Mutex::new(tx))))
}

// ── In-memory bidirectional pipe ─────────────────────────────────────────────

pub(super) struct MemPipe {
    pub read_buf: Arc<Mutex<Vec<u8>>>,
    pub write_buf: Arc<Mutex<Vec<u8>>>,
    /// Set by the peer when IT drops — this end then reads EOF.
    pub closed: Arc<std::sync::atomic::AtomicBool>,
    /// Set when this end drops — the peer then reads EOF. `None` for pipes
    /// from `mem_pipe_pair_with_close`, whose close is driven only by the
    /// explicit close handles.
    peer_closed: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl Drop for MemPipe {
    fn drop(&mut self) {
        // Signal EOF to the PEER: set the flag the other end observes, like
        // closing a real socket does. (This previously set the flag this pipe
        // observes about itself, so a dropped end never EOFed its peer.)
        if let Some(peer_closed) = &self.peer_closed {
            peer_closed.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

impl io::Read for MemPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rb = self.read_buf.lock().unwrap();
        if !rb.is_empty() {
            let n = buf.len().min(rb.len());
            buf[..n].copy_from_slice(&rb[..n]);
            rb.drain(..n);
            return Ok(n);
        }
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(0); // EOF
        }
        Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer empty"))
    }
}

impl crate::relay::Severable for MemPipe {
    /// Severing a MemPipe makes THIS end read EOF, like a socket shutdown.
    fn sever_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        let closed = self.closed.clone();
        Arc::new(move || closed.store(true, std::sync::atomic::Ordering::Release))
    }
}

impl io::Write for MemPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn mem_pipe_pair() -> (MemPipe, MemPipe) {
    let ab = Arc::new(Mutex::new(Vec::new()));
    let ba = Arc::new(Mutex::new(Vec::new()));
    let a_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let b_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        MemPipe {
            read_buf: ba.clone(),
            write_buf: ab.clone(),
            closed: b_closed.clone(),
            peer_closed: Some(a_closed.clone()),
        },
        MemPipe {
            read_buf: ab.clone(),
            write_buf: ba.clone(),
            closed: a_closed.clone(),
            peer_closed: Some(b_closed),
        },
    )
}

/// Returns pipes + explicit close handles.
/// `close_a` set to true → pipe_b sees EOF; `close_b` set to true → pipe_a sees EOF.
pub(super) fn mem_pipe_pair_with_close() -> (
    MemPipe,
    MemPipe,
    Arc<std::sync::atomic::AtomicBool>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let ab = Arc::new(Mutex::new(Vec::new()));
    let ba = Arc::new(Mutex::new(Vec::new()));
    let a_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let b_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        MemPipe {
            read_buf: ba.clone(),
            write_buf: ab.clone(),
            closed: b_closed.clone(),
            peer_closed: None, // close is driven only by the returned handles
        },
        MemPipe {
            read_buf: ab.clone(),
            write_buf: ba.clone(),
            closed: a_closed.clone(),
            peer_closed: None,
        },
        a_closed,
        b_closed,
    )
}

// ── Pipe close semantics ─────────────────────────────────────────────────

/// A dropped pipe end EOFs its peer, like a real socket close: the peer
/// drains buffered data first, then reads EOF. Pre-fix `Drop` flipped the
/// flag the dropped pipe observes about itself, so the peer never saw EOF.
#[test]
fn dropped_pipe_end_eofs_its_peer() {
    use std::io::{Read, Write};
    let (mut a, mut b) = mem_pipe_pair();
    a.write_all(b"hello").unwrap();
    drop(a);

    let mut buf = [0u8; 5];
    b.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello", "buffered data drains before EOF");
    let mut byte = [0u8; 1];
    assert_eq!(
        b.read(&mut byte).unwrap(),
        0,
        "peer must see EOF after drop"
    );
    assert_eq!(b.read(&mut byte).unwrap(), 0, "EOF persists");
}

/// The same in the other direction (B drops, A reads EOF).
#[test]
fn dropped_pipe_end_eofs_its_peer_reverse() {
    use std::io::{Read, Write};
    let (mut a, mut b) = mem_pipe_pair();
    b.write_all(b"world").unwrap();
    drop(b);

    let mut buf = [0u8; 5];
    a.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"world");
    let mut byte = [0u8; 1];
    assert_eq!(
        a.read(&mut byte).unwrap(),
        0,
        "peer must see EOF after drop"
    );
}

// ── Routing relay helper ──────────────────────────────────────────────────────

/// Spawn a routing relay accepting two sessions; forwards Push from src→dst.
/// `a_is_src=true` means A→B, `false` means B→A.
pub(super) fn spawn_routing_relay(
    relay_kp: &Keypair,
    pipe_a: MemPipe,
    pipe_b: MemPipe,
    nk_rx: mpsc::Receiver<MemPipe>,
    a_is_src: bool,
) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;
    std::thread::spawn(move || {
        let sess_a = xx_accept_after_prefix(pipe_a, relay_kp_a).unwrap();
        let sess_b = xx_accept_after_prefix(pipe_b, relay_kp_b).unwrap();
        let (src, dst) = if a_is_src {
            (Arc::new(sess_a), Arc::new(sess_b))
        } else {
            (Arc::new(sess_b), Arc::new(sess_a))
        };
        // NK push accept loop: every push from the pushing device arrives here.
        let dst_nk = dst.clone();
        std::thread::spawn(move || {
            // Hold the source session OPEN for the life of the relay, like a
            // real relay does: dropping it EOFs the pushing device's Receive
            // Session, and since SYNC-5 the sender pump (correctly) only
            // sends while connected — a dropped src session silently wedged
            // the outbox in every test using this relay.
            let _keep_src_alive = src;
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let dst2 = dst_nk.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp)
                    {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                if body.len() >= 32 {
                                    let _ = dst2.send(&{
                                        let mut d = 0u64.to_be_bytes().to_vec();
                                        d.extend_from_slice(&body[32..]);
                                        frame(MsgType::Deliver, &d)
                                    });
                                }
                                let _ = sess.send(&frame(MsgType::Ack, &[]));
                            }
                        }
                    }
                });
            }
        });
    });
}

/// Spawn a bidirectional relay (A↔B).
/// Spawns a minimal relay that accepts exactly one client connection and
/// discards all messages. Used in tests that only need a live session
/// without any fanout (single-device panic-safety tests, etc.).
pub(super) fn spawn_single_relay(
    relay_kp: &Keypair,
    pipe: MemPipe,
    nk_rx: mpsc::Receiver<MemPipe>,
) {
    let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;
    // NK accept loop: accept and discard NK connections (tests using this relay
    // may trigger push_message internally; the NK session must be accepted so
    // the push does not block). There is no routing destination here.
    std::thread::spawn(move || {
        while let Ok(nk_pipe) = nk_rx.recv() {
            let kp = Keypair::new(relay_priv, relay_pub_key);
            std::thread::spawn(move || {
                if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp) {
                    if sess.receive().is_ok() {
                        let _ = sess.send(&frame(MsgType::Ack, &[]));
                    }
                }
            });
        }
    });
    std::thread::spawn(move || {
        let sess = match xx_accept_after_prefix(pipe, kp) {
            Ok(s) => s,
            Err(_) => return,
        };
        while sess.receive().is_ok() {}
    });
}

pub(super) fn spawn_bidirectional_relay(
    relay_kp: &Keypair,
    pipe_a: MemPipe,
    pipe_b: MemPipe,
    nk_rx: mpsc::Receiver<MemPipe>,
) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;
    std::thread::spawn(move || {
        let sess_a = xx_accept_after_prefix(pipe_a, relay_kp_a).unwrap();
        let sess_b = xx_accept_after_prefix(pipe_b, relay_kp_b).unwrap();
        // Build routing table: noise_pub → deliver channel
        let a_noise = sess_a.remote_public_key();
        let b_noise = sess_b.remote_public_key();
        let sess_a = Arc::new(sess_a);
        let sess_b = Arc::new(sess_b);
        // NK router: accept NK connections, parse recipient_pub, deliver to matching session.
        let sa_nk = sess_a.clone();
        let sb_nk = sess_b.clone();
        std::thread::spawn(move || {
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let sa2 = sa_nk.clone();
                let sb2 = sb_nk.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp)
                    {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                if body.len() < 32 {
                                    return;
                                }
                                let recipient_pub = &body[0..32];
                                let framed = {
                                    let mut d = 0u64.to_be_bytes().to_vec();
                                    d.extend_from_slice(&body[32..]);
                                    frame(MsgType::Deliver, &d)
                                };
                                if true {
                                    if recipient_pub == a_noise {
                                        let _ = sa2.send(&framed);
                                    } else if recipient_pub == b_noise {
                                        let _ = sb2.send(&framed);
                                    }
                                }
                                let _ = sess.send(&frame(MsgType::Ack, &[]));
                            }
                        }
                    }
                });
            }
        });
    });
}

/// An N-device mesh relay: accepts every XX Receive Session, routes each NK
/// push to the session whose noise_pub matches the Envelope recipient, and
/// Acks the push. The Destroy Group forwarding tests (ADR-0029) need a real
/// mesh: the initiator's Revoke and each device's forward must reach
/// different members.
pub(super) fn spawn_mesh_relay(
    relay_kp: &Keypair,
    pipes: Vec<MemPipe>,
    nk_rx: mpsc::Receiver<MemPipe>,
) {
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;
    std::thread::spawn(move || {
        let mut sessions: Vec<([u8; 32], Arc<_>)> = Vec::new();
        for (i, pipe) in pipes.into_iter().enumerate() {
            let kp = Keypair::new(relay_priv, relay_pub_key);
            let sess = xx_accept_after_prefix(pipe, kp)
                .unwrap_or_else(|_| panic!("mesh relay: XX accept {i} failed"));
            let noise = sess.remote_public_key();
            sessions.push((noise, Arc::new(sess)));
        }
        let sessions = Arc::new(sessions);
        while let Ok(nk_pipe) = nk_rx.recv() {
            let kp = Keypair::new(relay_priv, relay_pub_key);
            let sessions = sessions.clone();
            std::thread::spawn(move || {
                if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp) {
                    if let Ok(raw) = sess.receive() {
                        if let Some((MsgType::Push, body)) = parse(&raw) {
                            if body.len() >= 32 {
                                let recipient_pub = &body[0..32];
                                let framed = {
                                    let mut d = 0u64.to_be_bytes().to_vec();
                                    d.extend_from_slice(&body[32..]);
                                    frame(MsgType::Deliver, &d)
                                };
                                for (noise, target) in sessions.iter() {
                                    if noise.as_slice() == recipient_pub {
                                        let _ = target.send(&framed);
                                    }
                                }
                            }
                            let _ = sess.send(&frame(MsgType::Ack, &[]));
                        }
                    }
                }
            });
        }
    });
}

/// Spawn a bidirectional relay where each side connects in its own thread,
/// then routes once both are connected.  Safe to use when A and B connect at
/// unpredictable times (e.g. reconnect tests).
pub(super) fn spawn_bidirectional_relay_parallel(
    relay_kp: &Keypair,
    pipe_a: MemPipe,
    pipe_b: MemPipe,
    nk_rx: mpsc::Receiver<MemPipe>,
) {
    use std::sync::mpsc as std_mpsc;
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;

    let (tx_a, rx_a) = std_mpsc::channel();
    let (tx_b, rx_b) = std_mpsc::channel();

    std::thread::spawn(move || {
        let sess = xx_accept_after_prefix(pipe_a, relay_kp_a).unwrap();
        tx_a.send(sess).unwrap();
    });
    std::thread::spawn(move || {
        let sess = xx_accept_after_prefix(pipe_b, relay_kp_b).unwrap();
        tx_b.send(sess).unwrap();
    });

    std::thread::spawn(move || {
        let sess_a = rx_a.recv().unwrap();
        let sess_b = rx_b.recv().unwrap();
        let a_noise = sess_a.remote_public_key();
        let b_noise = sess_b.remote_public_key();
        let sess_a = Arc::new(sess_a);
        let sess_b = Arc::new(sess_b);
        // NK router
        let sa_nk = sess_a.clone();
        let sb_nk = sess_b.clone();
        std::thread::spawn(move || {
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let sa2 = sa_nk.clone();
                let sb2 = sb_nk.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp)
                    {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                if body.len() < 32 {
                                    return;
                                }
                                let recipient_pub = &body[0..32];
                                let framed = {
                                    let mut d = 0u64.to_be_bytes().to_vec();
                                    d.extend_from_slice(&body[32..]);
                                    frame(MsgType::Deliver, &d)
                                };
                                if true {
                                    if recipient_pub == a_noise {
                                        let _ = sa2.send(&framed);
                                    } else if recipient_pub == b_noise {
                                        let _ = sb2.send(&framed);
                                    }
                                }
                                let _ = sess.send(&frame(MsgType::Ack, &[]));
                            }
                        }
                    }
                });
            }
        });
    });
}

/// Run the ADR-0023 pairing ceremony end to end: the admitter opens a
/// Pairing Window, the joiner calls `join_group` with the token (Pairing
/// Secret included), the admitter accepts the resulting Join Request.
/// Returns once the admitter has admitted; the joiner's first-manifest
/// acceptance is asynchronous (the manifest rides the outbox).
pub(super) fn run_pairing_ceremony<T, U>(
    admitter: &super::TruesealSession<T>,
    joiner: &super::TruesealSession<U>,
) where
    T: crate::relay::Severable,
    U: crate::relay::Severable,
{
    let req: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let r = req.clone();
    admitter.set_on_member_request(move |token, _| *r.lock().unwrap() = Some(token));
    let token = admitter.pairing_token().expect("pairing window opens");
    joiner
        .join_group(&token)
        .expect("join_group durably queues the Pair");
    wait_for(
        || req.lock().unwrap().is_some(),
        std::time::Duration::from_secs(5),
    );
    let t = req.lock().unwrap().clone().expect("a Join Request arrived");
    assert!(
        admitter.accept_member(&t).expect("accept"),
        "accept_member admits the waiting joiner"
    );
}

// ── Scripted relay + membership helpers (shared by contract and adversarial
// tests) ─────────────────────────────────────────────────────────────────

/// A scripted relay for recipient-contract tests: accepts the XX session,
/// records every frame the client sends, and delivers envelopes on demand.
pub(super) struct ScriptedRelay {
    client_frames: Arc<Mutex<Vec<(u8, Vec<u8>)>>>,
    deliver_tx: mpsc::Sender<(u64, Vec<u8>)>,
}

impl ScriptedRelay {
    pub(super) fn spawn(pipe: MemPipe, relay_kp: &Keypair) -> Self {
        let client_frames = Arc::new(Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
        let (deliver_tx, deliver_rx) = mpsc::channel::<(u64, Vec<u8>)>();
        let frames_clone = client_frames.clone();
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let session = xx_accept_after_prefix(pipe, relay_kp2).expect("relay accept");
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
                    frames_clone.lock().unwrap().push((t as u8, body.to_vec()));
                }
            }
        });
        ScriptedRelay {
            client_frames,
            deliver_tx,
        }
    }

    /// Deliver an envelope sealed from `msg`, addressed to `recipient` and
    /// signed by `sender` with Envelope sequence `seq` and a fresh Sender
    /// Timestamp (ADR-0031).
    pub(super) fn deliver(
        &self,
        blob_id: u64,
        msg: &crate::message::Message,
        recipient: NoisePublicKey,
        sender: &crate::envelope::SigningKeypair,
        seq: u64,
    ) {
        self.deliver_at(
            blob_id,
            msg,
            recipient,
            sender,
            seq,
            crate::operation_log::now_secs() * 1000,
        );
    }

    /// Like `deliver`, but the sealed Sender Timestamp is chosen by the
    /// test — Replay Window cases stamp messages days in the past or future.
    pub(super) fn deliver_at(
        &self,
        blob_id: u64,
        msg: &crate::message::Message,
        recipient: NoisePublicKey,
        sender: &crate::envelope::SigningKeypair,
        seq: u64,
        sender_timestamp_ms: u64,
    ) {
        let env = crate::envelope::Envelope::build_sealed(
            seq,
            vec![],
            recipient,
            sender,
            sender_timestamp_ms,
            &msg.encode(),
        );
        self.deliver_raw(blob_id, env.encode());
    }

    pub(super) fn deliver_raw(&self, blob_id: u64, envelope_bytes: Vec<u8>) {
        self.deliver_tx
            .send((blob_id, envelope_bytes))
            .expect("relay alive");
    }

    /// Blob ids the client acked, in order.
    pub(super) fn deliver_acks(&self) -> Vec<u64> {
        self.client_frames
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t == MsgType::DeliverAck as u8)
            .filter_map(|(_, b)| b.as_slice().try_into().ok().map(u64::from_be_bytes))
            .collect()
    }
}

/// Rebuild a SigningKeypair from raw bytes (SigningKeypair is not Clone).
pub(super) fn signing_keypair(bytes: &[u8; 32]) -> crate::envelope::SigningKeypair {
    crate::envelope::SigningKeypair::from_signing_key(ed25519_dalek::SigningKey::from_bytes(bytes))
}

pub(super) fn pub_of(bytes: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(bytes)
        .verifying_key()
        .to_bytes()
}

pub(super) fn signing_member(
    signing_bytes: &[u8; 32],
    noise: [u8; 32],
) -> crate::manifest::ManifestMember {
    let sp = crate::keys::SigningPublicKey(pub_of(signing_bytes));
    crate::manifest::ManifestMember {
        noise_pub: NoisePublicKey(noise),
        signing_pub: sp,
        name: crate::member::member_name(&sp),
    }
}

/// ADR-0023: a manifestless device drops every Sync. Build the two-member
/// genesis (device + scripted sender) so plumbing tests can run as group
/// members. `set_manifest` bypasses the first-manifest gate on purpose —
/// these tests are not about pairing.
pub(super) fn membership(
    device: &crate::device::DeviceKeypair,
    sender: &crate::envelope::SigningKeypair,
) -> crate::manifest::GroupManifest {
    let sk = ed25519_dalek::SigningKey::from_bytes(&device.signing.to_bytes());
    let self_sp = device.signing_public_key();
    let sender_sp = sender.public_key();
    crate::manifest::GroupManifest::new(
        crate::manifest::new_group_id(),
        1,
        vec![
            crate::manifest::ManifestMember {
                noise_pub: device.public_key(),
                signing_pub: self_sp,
                name: crate::member::member_name(&self_sp),
            },
            crate::manifest::ManifestMember {
                noise_pub: NoisePublicKey([9u8; 32]),
                signing_pub: crate::keys::SigningPublicKey(sender.public_key_bytes()),
                name: crate::member::member_name(&sender_sp),
            },
        ],
        &sk,
    )
}

/// Spin-polls `cond` until it returns `true` or `timeout` elapses.
/// Replaces `sleep + assert` patterns — reacts to the actual event, not a fixed delay.
/// Panics with a descriptive message on timeout.
pub(super) fn wait_for(cond: impl Fn() -> bool, timeout: std::time::Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("wait_for: condition not met within {:?}", timeout);
}

pub(super) fn relay_pub(relay_kp: &Keypair) -> NoisePublicKey {
    NoisePublicKey(relay_kp.public_key)
}

pub(super) fn make_relay_kp() -> Keypair {
    generate_keypair()
}

/// Spawn a fully-connected 3-way relay (A↔B↔C).
/// Any Push from any device is delivered to both of the other two.
/// Uses channels to fan out from one reader to multiple writers, avoiding concurrent send() races.
pub(super) fn spawn_tripartite_relay(
    relay_kp: &Keypair,
    pipe_a: MemPipe,
    pipe_b: MemPipe,
    pipe_c: MemPipe,
    nk_rx: mpsc::Receiver<MemPipe>,
) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_c = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;
    std::thread::spawn(move || {
        let sess_a = Arc::new(xx_accept_after_prefix(pipe_a, relay_kp_a).unwrap());
        let sess_b = Arc::new(xx_accept_after_prefix(pipe_b, relay_kp_b).unwrap());
        let sess_c = Arc::new(xx_accept_after_prefix(pipe_c, relay_kp_c).unwrap());

        // Three channels — one per session destination.
        let (tx_a, rx_a) = mpsc::channel::<Vec<u8>>();
        let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>();
        let (tx_c, rx_c) = mpsc::channel::<Vec<u8>>();

        // Writer threads: one per session, drains the channel.
        let sa_w = sess_a.clone();
        std::thread::spawn(move || {
            for msg in rx_a {
                let _ = sa_w.send(&msg);
            }
        });
        let sb_w = sess_b.clone();
        std::thread::spawn(move || {
            for msg in rx_b {
                let _ = sb_w.send(&msg);
            }
        });
        let sc_w = sess_c.clone();
        std::thread::spawn(move || {
            for msg in rx_c {
                let _ = sc_w.send(&msg);
            }
        });

        // NK router: route each NK push to the intended recipient.
        let a_noise = sess_a.remote_public_key();
        let b_noise = sess_b.remote_public_key();
        let c_noise = sess_c.remote_public_key();
        let txa2 = tx_a.clone();
        let txb2 = tx_b.clone();
        let txc2 = tx_c.clone();
        std::thread::spawn(move || {
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let ta = txa2.clone();
                let tb = txb2.clone();
                let tc = txc2.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp)
                    {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                if body.len() < 32 {
                                    return;
                                }
                                let recipient_pub = &body[0..32];
                                let framed = {
                                    let mut d = 0u64.to_be_bytes().to_vec();
                                    d.extend_from_slice(&body[32..]);
                                    frame(MsgType::Deliver, &d)
                                };
                                if true {
                                    if recipient_pub == a_noise {
                                        let _ = ta.send(framed);
                                    } else if recipient_pub == b_noise {
                                        let _ = tb.send(framed);
                                    } else if recipient_pub == c_noise {
                                        let _ = tc.send(framed);
                                    }
                                }
                                let _ = sess.send(&frame(MsgType::Ack, &[]));
                            }
                        }
                    }
                });
            }
        });
    });
}

/// Spawn a fully-connected 4-way relay (A↔B↔C↔D).
/// Any Push from any device is delivered to the intended recipient.
pub(super) fn spawn_quadpartite_relay(
    relay_kp: &Keypair,
    pipe_a: MemPipe,
    pipe_b: MemPipe,
    pipe_c: MemPipe,
    pipe_d: MemPipe,
    nk_rx: mpsc::Receiver<MemPipe>,
) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_c = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_d = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;
    std::thread::spawn(move || {
        let sess_a = Arc::new(xx_accept_after_prefix(pipe_a, relay_kp_a).unwrap());
        let sess_b = Arc::new(xx_accept_after_prefix(pipe_b, relay_kp_b).unwrap());
        let sess_c = Arc::new(xx_accept_after_prefix(pipe_c, relay_kp_c).unwrap());
        let sess_d = Arc::new(xx_accept_after_prefix(pipe_d, relay_kp_d).unwrap());

        let (tx_a, rx_a) = mpsc::channel::<Vec<u8>>();
        let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>();
        let (tx_c, rx_c) = mpsc::channel::<Vec<u8>>();
        let (tx_d, rx_d) = mpsc::channel::<Vec<u8>>();

        // Writer threads.
        for (sess, rx) in [
            (sess_a.clone(), rx_a),
            (sess_b.clone(), rx_b),
            (sess_c.clone(), rx_c),
            (sess_d.clone(), rx_d),
        ] {
            std::thread::spawn(move || {
                for msg in rx {
                    let _ = sess.send(&msg);
                }
            });
        }

        // NK router: route each NK push to the intended recipient.
        let a_noise = sess_a.remote_public_key();
        let b_noise = sess_b.remote_public_key();
        let c_noise = sess_c.remote_public_key();
        let d_noise = sess_d.remote_public_key();
        let txa2 = tx_a.clone();
        let txb2 = tx_b.clone();
        let txc2 = tx_c.clone();
        let txd2 = tx_d.clone();
        std::thread::spawn(move || {
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let ta = txa2.clone();
                let tb = txb2.clone();
                let tc = txc2.clone();
                let td = txd2.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp)
                    {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                if body.len() < 32 {
                                    return;
                                }
                                let recipient_pub = &body[0..32];
                                let framed = {
                                    let mut d = 0u64.to_be_bytes().to_vec();
                                    d.extend_from_slice(&body[32..]);
                                    frame(MsgType::Deliver, &d)
                                };
                                if true {
                                    if recipient_pub == a_noise {
                                        let _ = ta.send(framed);
                                    } else if recipient_pub == b_noise {
                                        let _ = tb.send(framed);
                                    } else if recipient_pub == c_noise {
                                        let _ = tc.send(framed);
                                    } else if recipient_pub == d_noise {
                                        let _ = td.send(framed);
                                    }
                                }
                                let _ = sess.send(&frame(MsgType::Ack, &[]));
                            }
                        }
                    }
                });
            }
        });
    });
}
