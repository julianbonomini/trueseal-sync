use std::io;
use std::sync::{mpsc, Arc, Mutex};

use hush_noise::{
    keypair::{generate_keypair, Keypair},
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
    a_is_src: bool,
) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let sess_a = accept(pipe_a, relay_kp_a).unwrap();
        let sess_b = accept(pipe_b, relay_kp_b).unwrap();
        let (src, dst) = if a_is_src {
            (sess_a, sess_b)
        } else {
            (sess_b, sess_a)
        };
        loop {
            let raw = match src.receive() {
                Ok(r) => r,
                Err(_) => break,
            };
            if let Some((MsgType::Push, body)) = parse(&raw) {
                let _ = dst.send(&frame(MsgType::Deliver, body));
            }
        }
    });
}

/// Spawn a bidirectional relay (A↔B).
/// Spawns a minimal relay that accepts exactly one client connection and
/// discards all messages. Used in tests that only need a live session
/// without any fanout (single-device panic-safety tests, etc.).
pub(super) fn spawn_single_relay(relay_kp: &Keypair, pipe: MemPipe) {
    let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
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

pub(super) fn spawn_bidirectional_relay(relay_kp: &Keypair, pipe_a: MemPipe, pipe_b: MemPipe) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let sess_a = accept(pipe_a, relay_kp_a).unwrap();
        let sess_b = accept(pipe_b, relay_kp_b).unwrap();
        let sess_a = Arc::new(sess_a);
        let sess_b = Arc::new(sess_b);
        // A→B
        let sa2 = sess_a.clone();
        let sb2 = sess_b.clone();
        std::thread::spawn(move || loop {
            let raw = match sa2.receive() {
                Ok(r) => r,
                Err(_) => break,
            };
            if let Some((MsgType::Push, body)) = parse(&raw) {
                let _ = sb2.send(&frame(MsgType::Deliver, body));
            }
        });
        // B→A
        loop {
            let raw = match sess_b.receive() {
                Ok(r) => r,
                Err(_) => break,
            };
            if let Some((MsgType::Push, body)) = parse(&raw) {
                let _ = sess_a.send(&frame(MsgType::Deliver, body));
            }
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
) {
    use std::sync::mpsc;
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);

    let (tx_a, rx_a) = mpsc::channel();
    let (tx_b, rx_b) = mpsc::channel();

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
        let sess_a = Arc::new(sess_a);
        let sess_b = Arc::new(sess_b);
        let sa2 = sess_a.clone();
        let sb2 = sess_b.clone();
        // A → B
        std::thread::spawn(move || loop {
            let raw = match sa2.receive() {
                Ok(r) => r,
                Err(_) => break,
            };
            if let Some((MsgType::Push, body)) = parse(&raw) {
                let _ = sb2.send(&frame(MsgType::Deliver, body));
            }
        });
        // B → A
        loop {
            let raw = match sess_b.receive() {
                Ok(r) => r,
                Err(_) => break,
            };
            if let Some((MsgType::Push, body)) = parse(&raw) {
                let _ = sess_a.send(&frame(MsgType::Deliver, body));
            }
        }
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
) {
    use std::sync::mpsc;
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_c = Keypair::new(relay_kp.private(), relay_kp.public_key);
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

        // Reader threads: one per session, routes to the other two channels.
        let make_reader = |src: Arc<hush_noise::session_xx::Session<MemPipe>>,
                           out1: mpsc::Sender<Vec<u8>>,
                           out2: mpsc::Sender<Vec<u8>>| {
            std::thread::spawn(move || loop {
                let raw = match src.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    let framed = frame(MsgType::Deliver, body);
                    let _ = out1.send(framed.clone());
                    let _ = out2.send(framed);
                }
            })
        };

        make_reader(sess_a, tx_b.clone(), tx_c.clone());
        make_reader(sess_b, tx_a.clone(), tx_c.clone());
        make_reader(sess_c, tx_a.clone(), tx_b.clone());
    });
}

/// Spawn a fully-connected 4-way relay (A↔B↔C↔D).
/// Any Push from any device is delivered to the other three.
pub(super) fn spawn_quadpartite_relay(
    relay_kp: &Keypair,
    pipe_a: MemPipe,
    pipe_b: MemPipe,
    pipe_c: MemPipe,
    pipe_d: MemPipe,
) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_c = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_d = Keypair::new(relay_kp.private(), relay_kp.public_key);
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

        // Reader threads: each device's push goes to the other three.
        let make_reader = |src: Arc<hush_noise::session_xx::Session<MemPipe>>,
                           out1: mpsc::Sender<Vec<u8>>,
                           out2: mpsc::Sender<Vec<u8>>,
                           out3: mpsc::Sender<Vec<u8>>| {
            std::thread::spawn(move || loop {
                let raw = match src.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    let framed = frame(MsgType::Deliver, body);
                    let _ = out1.send(framed.clone());
                    let _ = out2.send(framed.clone());
                    let _ = out3.send(framed);
                }
            })
        };

        make_reader(sess_a, tx_b.clone(), tx_c.clone(), tx_d.clone());
        make_reader(sess_b, tx_a.clone(), tx_c.clone(), tx_d.clone());
        make_reader(sess_c, tx_a.clone(), tx_b.clone(), tx_d.clone());
        make_reader(sess_d, tx_a.clone(), tx_b.clone(), tx_c.clone());
    });
}
