use std::io;
use std::sync::{mpsc, Arc, Mutex};

use hush_noise::{
    keypair::{generate_keypair, Keypair},
    session_nk,
    session_xx::accept,
};

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
    pub closed: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for MemPipe {
    fn drop(&mut self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
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
        },
        MemPipe {
            read_buf: ab.clone(),
            write_buf: ba.clone(),
            closed: a_closed.clone(),
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
        },
        MemPipe {
            read_buf: ab.clone(),
            write_buf: ba.clone(),
            closed: a_closed.clone(),
        },
        a_closed,
        b_closed,
    )
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
        let sess_a = accept(pipe_a, relay_kp_a).unwrap();
        let sess_b = accept(pipe_b, relay_kp_b).unwrap();
        let (_src, dst) = if a_is_src {
            (Arc::new(sess_a), Arc::new(sess_b))
        } else {
            (Arc::new(sess_b), Arc::new(sess_a))
        };
        // NK push accept loop: every push from the pushing device arrives here.
        let dst_nk = dst.clone();
        std::thread::spawn(move || {
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let dst2 = dst_nk.clone();
                std::thread::spawn(move || {
                    if let Ok(sess) = hush_noise::session_nk::accept(nk_pipe, kp) {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                let _ = dst2.send(&frame(MsgType::Deliver, body));
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
pub(super) fn spawn_single_relay(relay_kp: &Keypair, pipe: MemPipe, nk_rx: mpsc::Receiver<MemPipe>) {
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
                if let Ok(sess) = hush_noise::session_nk::accept(nk_pipe, kp) {
                    let _ = sess.receive();
                }
            });
        }
    });
    std::thread::spawn(move || {
        let sess = match accept(pipe, kp) {
            Ok(s) => s,
            Err(_) => return,
        };
        loop {
            match sess.receive() {
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
}

pub(super) fn spawn_bidirectional_relay(relay_kp: &Keypair, pipe_a: MemPipe, pipe_b: MemPipe, nk_rx: mpsc::Receiver<MemPipe>) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_priv = relay_kp.private();
    let relay_pub_key = relay_kp.public_key;
    std::thread::spawn(move || {
        let sess_a = accept(pipe_a, relay_kp_a).unwrap();
        let sess_b = accept(pipe_b, relay_kp_b).unwrap();
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
                    if let Ok(sess) = hush_noise::session_nk::accept(nk_pipe, kp) {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                let framed = frame(MsgType::Deliver, body.clone());
                                if let Ok(env) = crate::envelope::Envelope::decode(&body) {
                                    if env.recipient_pub == a_noise {
                                        let _ = sa2.send(&framed);
                                    } else if env.recipient_pub == b_noise {
                                        let _ = sb2.send(&framed);
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });
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
        let sess = accept(pipe_a, relay_kp_a).unwrap();
        tx_a.send(sess).unwrap();
    });
    std::thread::spawn(move || {
        let sess = accept(pipe_b, relay_kp_b).unwrap();
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
                    if let Ok(sess) = hush_noise::session_nk::accept(nk_pipe, kp) {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                let framed = frame(MsgType::Deliver, body.clone());
                                if let Ok(env) = crate::envelope::Envelope::decode(&body) {
                                    if env.recipient_pub == a_noise {
                                        let _ = sa2.send(&framed);
                                    } else if env.recipient_pub == b_noise {
                                        let _ = sb2.send(&framed);
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });
    });
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
        let sess_a = Arc::new(accept(pipe_a, relay_kp_a).unwrap());
        let sess_b = Arc::new(accept(pipe_b, relay_kp_b).unwrap());
        let sess_c = Arc::new(accept(pipe_c, relay_kp_c).unwrap());

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
                    if let Ok(sess) = hush_noise::session_nk::accept(nk_pipe, kp) {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                let framed = frame(MsgType::Deliver, body.clone());
                                if let Ok(env) = crate::envelope::Envelope::decode(&body) {
                                    if env.recipient_pub == a_noise { let _ = ta.send(framed); }
                                    else if env.recipient_pub == b_noise { let _ = tb.send(framed); }
                                    else if env.recipient_pub == c_noise { let _ = tc.send(framed); }
                                }
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
        let sess_a = Arc::new(accept(pipe_a, relay_kp_a).unwrap());
        let sess_b = Arc::new(accept(pipe_b, relay_kp_b).unwrap());
        let sess_c = Arc::new(accept(pipe_c, relay_kp_c).unwrap());
        let sess_d = Arc::new(accept(pipe_d, relay_kp_d).unwrap());

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
                for msg in rx { let _ = sess.send(&msg); }
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
                    if let Ok(sess) = hush_noise::session_nk::accept(nk_pipe, kp) {
                        if let Ok(raw) = sess.receive() {
                            if let Some((MsgType::Push, body)) = parse(&raw) {
                                let framed = frame(MsgType::Deliver, body.clone());
                                if let Ok(env) = crate::envelope::Envelope::decode(&body) {
                                    if env.recipient_pub == a_noise { let _ = ta.send(framed); }
                                    else if env.recipient_pub == b_noise { let _ = tb.send(framed); }
                                    else if env.recipient_pub == c_noise { let _ = tc.send(framed); }
                                    else if env.recipient_pub == d_noise { let _ = td.send(framed); }
                                }
                            }
                        }
                    }
                });
            }
        });
    });
}
