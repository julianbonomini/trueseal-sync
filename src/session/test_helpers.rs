use std::io;
use std::sync::{Arc, Mutex};

use hush_noise::{
    keypair::{generate_keypair, Keypair},
    session::accept,
};

use crate::keys::NoisePublicKey;
use crate::relay::{frame, parse, MsgType};

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

pub(super) fn relay_pub(relay_kp: &Keypair) -> NoisePublicKey {
    NoisePublicKey(relay_kp.public_key)
}

pub(super) fn make_relay_kp() -> Keypair {
    generate_keypair()
}

/// Spawn a fully-connected 3-way relay (A↔B↔C).
/// Any Push from any device is delivered to both of the other two.
pub(super) fn spawn_tripartite_relay(
    relay_kp: &Keypair,
    pipe_a: MemPipe,
    pipe_b: MemPipe,
    pipe_c: MemPipe,
) {
    let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_c = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let sess_a = Arc::new(accept(pipe_a, relay_kp_a).unwrap());
        let sess_b = Arc::new(accept(pipe_b, relay_kp_b).unwrap());
        let sess_c = Arc::new(accept(pipe_c, relay_kp_c).unwrap());

        let make_fwd = |src: Arc<hush_noise::session::Session<MemPipe>>,
                        dst1: Arc<hush_noise::session::Session<MemPipe>>,
                        dst2: Arc<hush_noise::session::Session<MemPipe>>| {
            std::thread::spawn(move || loop {
                let raw = match src.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    let _ = dst1.send(&frame(MsgType::Deliver, body.clone()));
                    let _ = dst2.send(&frame(MsgType::Deliver, body));
                }
            })
        };

        let sa = sess_a.clone();
        let sb = sess_b.clone();
        let sc = sess_c.clone();
        make_fwd(sa.clone(), sb.clone(), sc.clone());
        make_fwd(sb.clone(), sa.clone(), sc.clone());
        make_fwd(sc, sa, sb);
    });
}
