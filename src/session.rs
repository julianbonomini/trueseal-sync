use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hush_noise::keypair::Keypair as NoiseKeypair;
use thiserror::Error;

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::NoisePublicKey;
use crate::message::{pairing_payload, Message};
use crate::relay::RelayClient;

/// Default pairing window duration (60 seconds, per ADR-0002).
const DEFAULT_PAIRING_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid keypair bytes")]
    InvalidKeypairBytes,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("push failed: {0}")]
    PushFailed(String),
}

/// An open pairing window. Exists only between `start_pairing()` and its close
/// (timeout, `cancel_pairing()`, or successful `accept_pair()`).
struct PairingWindow {
    deadline: Instant,
    on_paired: Box<dyn Fn(NoisePublicKey) + Send + 'static>,
}

impl PairingWindow {
    fn is_open(&self) -> bool {
        Instant::now() < self.deadline
    }
}

/// The opinionated session facade (ADR-0010).
///
/// Owns the relay connection, sequence counter, signing keypair, and pairing state.
/// Callers never see sequence numbers, parent hashes, or envelope construction.
///
/// Transport-generic so tests can inject in-memory pipes.
pub struct HushSession<T: Read + Write + Send + 'static> {
    client: RelayClient<T>,
    signing: SigningKeypair,
    noise_pub: NoisePublicKey,
    signing_pub: crate::keys::SigningPublicKey,
    sequence: Arc<Mutex<u64>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
}

impl<T: Read + Write + Send + 'static> HushSession<T> {
    /// Connect to a relay over `transport` and start the session.
    ///
    /// `on_message` fires for every decrypted, verified Message delivered to this device.
    /// When a `Message::Pair` arrives, call `accept_pair(noise_pub)` to admit the device
    /// (only valid inside an open pairing window opened by `start_pairing()`).
    pub fn connect(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message) + Send + 'static,
    ) -> Result<Self, SessionError> {
        let signing = keypair.signing_keypair();
        let noise_pub = keypair.public_key();
        let signing_pub = keypair.signing_public_key();
        let noise_kp = NoiseKeypair::new(keypair.noise.private(), keypair.noise.public_key);
        let client = RelayClient::connect(transport, relay_pub, noise_kp)
            .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;

        client.subscribe(on_message);

        Ok(Self {
            client,
            signing,
            noise_pub,
            signing_pub,
            sequence: Arc::new(Mutex::new(0)),
            pairing: Arc::new(Mutex::new(None)),
        })
    }

    /// Encrypt `blob` and push it to `recipient_pub` as a Sync message.
    /// Sequence counter increments monotonically per push.
    pub fn push_sync(
        &self,
        recipient_pub: NoisePublicKey,
        blob: Vec<u8>,
    ) -> Result<(), SessionError> {
        let msg = Message::Sync { body: blob };
        self.push_message(&msg, recipient_pub)
    }

    fn push_message(
        &self,
        msg: &Message,
        recipient_pub: NoisePublicKey,
    ) -> Result<(), SessionError> {
        let seq = {
            let mut s = self.sequence.lock().unwrap();
            let current = *s;
            *s += 1;
            current
        };
        self.client
            .push(msg, recipient_pub, seq, vec![], &self.signing)
            .map_err(|e| SessionError::PushFailed(e.to_string()))
    }

    // ── Pairing window ─────────────────────────────────────────────────────────

    /// Returns a 64-byte Pairing Payload (for QR encoding) and opens a pairing window.
    ///
    /// While the window is open (up to 60s), the caller may call `accept_pair(noise_pub)`
    /// after receiving a `Message::Pair` to admit a new device. The window is closed
    /// automatically after `duration` (default 60s), by `cancel_pairing()`, or by a
    /// successful `accept_pair()`.
    ///
    /// `on_paired` fires (with the admitted device's `NoisePublicKey`) after a successful
    /// `accept_pair()`.
    pub fn start_pairing(&self, on_paired: impl Fn(NoisePublicKey) + Send + 'static) -> Vec<u8> {
        self.start_pairing_with_duration(DEFAULT_PAIRING_WINDOW, on_paired)
    }

    /// Like `start_pairing` but with a caller-specified window duration (for tests).
    pub fn start_pairing_with_duration(
        &self,
        duration: Duration,
        on_paired: impl Fn(NoisePublicKey) + Send + 'static,
    ) -> Vec<u8> {
        let window = PairingWindow {
            deadline: Instant::now() + duration,
            on_paired: Box::new(on_paired),
        };
        *self.pairing.lock().unwrap() = Some(window);
        pairing_payload(&self.noise_pub.0, &self.signing_pub.0)
    }

    /// Admit a device into the paired list if the pairing window is still open.
    ///
    /// Fires `on_paired(noise_pub)` and closes the pairing window on success.
    /// Silent no-op if the window is closed or timed out.
    pub fn accept_pair(&self, noise_pub: NoisePublicKey) {
        let mut guard = self.pairing.lock().unwrap();
        if let Some(ref window) = *guard {
            if window.is_open() {
                (window.on_paired)(noise_pub);
                *guard = None; // close window after successful pair
                return;
            }
        }
        // Window is closed or timed out — no-op.
        *guard = None;
    }

    /// Close the pairing window immediately without pairing any device.
    pub fn cancel_pairing(&self) {
        *self.pairing.lock().unwrap() = None;
    }
}

// ── Concrete TCP constructor ──────────────────────────────────────────────────

impl HushSession<TcpStream> {
    /// Connect to a relay over TCP.
    pub fn connect_tcp(
        addr: &str,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message) + Send + 'static,
    ) -> Result<Self, SessionError> {
        let stream =
            TcpStream::connect(addr).map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;
        Self::connect(stream, relay_pub, keypair, on_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceKeypair;
    use crate::envelope::Envelope;
    use crate::keys::NoisePublicKey;
    use crate::message::Message;
    use crate::relay::{frame, parse, MsgType};
    use hush_noise::{
        keypair::{generate_keypair, Keypair},
        session::accept,
    };
    use std::io;
    use std::sync::{Arc, Mutex};

    // ── In-memory bidirectional pipe ─────────────────────────────────────────

    struct MemPipe {
        read_buf: Arc<Mutex<Vec<u8>>>,
        write_buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for MemPipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut rb = self.read_buf.lock().unwrap();
            if rb.is_empty() {
                // Return WouldBlock so Session releases conn mutex before retrying.
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer empty"));
            }
            let n = buf.len().min(rb.len());
            buf[..n].copy_from_slice(&rb[..n]);
            rb.drain(..n);
            Ok(n)
        }
    }

    impl Write for MemPipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn mem_pipe_pair() -> (MemPipe, MemPipe) {
        let ab = Arc::new(Mutex::new(Vec::new()));
        let ba = Arc::new(Mutex::new(Vec::new()));
        (
            MemPipe {
                read_buf: ba.clone(),
                write_buf: ab.clone(),
            },
            MemPipe {
                read_buf: ab.clone(),
                write_buf: ba.clone(),
            },
        )
    }

    // ── Routing relay helper ─────────────────────────────────────────────────

    /// Spawn a routing relay that accepts two sessions in order (pipe_a first, then pipe_b)
    /// and forwards Push from src to dst where src/dst are identified by `a_is_src`.
    fn spawn_routing_relay(
        relay_kp: &hush_noise::keypair::Keypair,
        pipe_a: MemPipe,
        pipe_b: MemPipe,
        a_is_src: bool, // if true, forwards A→B; if false, forwards B→A
    ) {
        let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            // Accept in order — must match the order clients connect.
            let sess_a = accept(pipe_a, relay_kp_a).unwrap();
            let sess_b = accept(pipe_b, relay_kp_b).unwrap();
            let (src_sess, dst_sess) = if a_is_src {
                (sess_a, sess_b)
            } else {
                (sess_b, sess_a)
            };
            loop {
                let raw = match src_sess.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    let deliver = frame(MsgType::Deliver, body);
                    let _ = dst_sess.send(&deliver);
                }
            }
        });
    }

    /// Tracer bullet: Session A pushes a Sync message through a fake relay;
    /// Session B's on_message callback receives the correct body.
    #[test]
    fn two_sessions_can_exchange_sync_message() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);

        let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
        let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();

        // Routing relay: accepts A and B; forwards Push from A as Deliver to B.
        spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

        let device_a = DeviceKeypair::generate();
        let device_b = DeviceKeypair::generate();
        let b_pub = device_b.public_key();

        let session_a = HushSession::connect(pipe_a_client, relay_pub, device_a, |_| {})
            .expect("session A should connect");

        let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();
        let _session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg| {
            received_clone.lock().unwrap().push(msg);
        })
        .expect("session B should connect");

        session_a
            .push_sync(b_pub, b"hello from A".to_vec())
            .expect("push_sync should succeed");

        std::thread::sleep(std::time::Duration::from_millis(100));

        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1, "B should have received exactly one message");
        assert_eq!(
            got[0],
            Message::Sync {
                body: b"hello from A".to_vec()
            }
        );
    }

    /// Two consecutive push_sync calls use incrementing sequence numbers.
    #[test]
    fn push_sync_increments_sequence() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);

        let (pipe_client, pipe_relay) = mem_pipe_pair();

        // Simple recording relay: records received envelopes
        let received_envs: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received_envs.clone();
        {
            let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
            std::thread::spawn(move || {
                let session = accept(pipe_relay, relay_kp2).unwrap();
                loop {
                    let raw = match session.receive() {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    if let Some((MsgType::Push, body)) = parse(&raw) {
                        if let Ok(env) = Envelope::decode(body) {
                            received_clone.lock().unwrap().push(env);
                        }
                    }
                }
            });
        }

        let device = DeviceKeypair::generate();
        let recipient = DeviceKeypair::generate();
        let session =
            HushSession::connect(pipe_client, relay_pub, device, |_| {}).expect("should connect");

        session
            .push_sync(recipient.public_key(), b"first".to_vec())
            .expect("first push should succeed");
        session
            .push_sync(recipient.public_key(), b"second".to_vec())
            .expect("second push should succeed");

        std::thread::sleep(std::time::Duration::from_millis(50));

        let envs = received_envs.lock().unwrap();
        assert_eq!(envs.len(), 2, "relay should have received two envelopes");
        assert_eq!(envs[0].sequence, 0, "first envelope sequence should be 0");
        assert_eq!(envs[1].sequence, 1, "second envelope sequence should be 1");
    }

    /// Full pairing ceremony: A opens a pairing window, B pushes a Pair message,
    /// A's on_message fires, A calls accept_pair, on_paired fires with B's key.
    #[test]
    fn pairing_ceremony_on_paired_fires_with_correct_key() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);

        let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
        let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();

        // Routing relay: accepts A first, B second; routes B→A (a_is_src=false).
        spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, false);

        let device_a = DeviceKeypair::generate();
        let device_b = DeviceKeypair::generate();

        // A will receive inbound Pair messages and stash them for accept_pair.
        let pair_msgs: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let pair_msgs_clone = pair_msgs.clone();

        let session_a = Arc::new(
            HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg| {
                pair_msgs_clone.lock().unwrap().push(msg);
            })
            .expect("session A should connect"),
        );

        // A starts pairing — get payload bytes (B would scan the QR).
        let on_paired_fired: Arc<Mutex<Vec<NoisePublicKey>>> = Arc::new(Mutex::new(Vec::new()));
        let on_paired_clone = on_paired_fired.clone();
        let _payload = session_a.start_pairing(move |noise_pub| {
            on_paired_clone.lock().unwrap().push(noise_pub);
        });

        // B connects and pushes a Pair message addressed to A.
        let device_b_noise_pub = device_b.public_key();
        let device_b_signing_pub = device_b.signing_public_key();
        let session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, |_| {})
            .expect("session B should connect");
        let pair_msg = Message::Pair {
            noise_pub: device_b_noise_pub.0,
            signing_pub: device_b_signing_pub.0,
        };
        // B pushes its Pair message to A's noise public key.
        session_b
            .push_message(&pair_msg, session_a.noise_pub)
            .expect("B should push Pair message");

        // Wait for A to receive B's Pair message via the relay.
        std::thread::sleep(std::time::Duration::from_millis(100));

        // A's on_message fired — extract B's noise_pub and call accept_pair.
        let msgs = pair_msgs.lock().unwrap();
        assert_eq!(
            msgs.len(),
            1,
            "A should have received exactly one Pair message"
        );
        if let Message::Pair { noise_pub, .. } = msgs[0] {
            drop(msgs);
            session_a.accept_pair(NoisePublicKey(noise_pub));
        } else {
            panic!("expected Pair message");
        }

        // on_paired should have fired with B's noise public key.
        let paired = on_paired_fired.lock().unwrap();
        assert_eq!(paired.len(), 1, "on_paired should have fired once");
        assert_eq!(
            paired[0].0, device_b_noise_pub.0,
            "on_paired should fire with B's noise public key"
        );
    }

    /// accept_pair called outside a pairing window is a no-op.
    #[test]
    fn accept_pair_outside_window_is_noop() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let (pipe_client, pipe_relay) = mem_pipe_pair();

        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = accept(pipe_relay, relay_kp2);
        });

        let device = DeviceKeypair::generate();
        let session =
            HushSession::connect(pipe_client, relay_pub, device, |_| {}).expect("should connect");

        let on_paired_fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let fired_clone = on_paired_fired.clone();

        // No window open — accept_pair should be a no-op.
        let dummy_key = NoisePublicKey(generate_keypair().public_key);
        session.accept_pair(dummy_key); // should not panic or fire callback

        assert!(
            !*on_paired_fired.lock().unwrap(),
            "on_paired must not fire outside a pairing window"
        );

        // Start pairing then immediately cancel — accept_pair should also be a no-op.
        let _payload = session.start_pairing(move |_| {
            *fired_clone.lock().unwrap() = true;
        });
        session.cancel_pairing();
        session.accept_pair(dummy_key);

        assert!(
            !*on_paired_fired.lock().unwrap(),
            "on_paired must not fire after cancel_pairing"
        );
    }

    /// accept_pair after the pairing window times out is a no-op.
    #[test]
    fn accept_pair_after_timeout_is_noop() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let (pipe_client, pipe_relay) = mem_pipe_pair();

        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = accept(pipe_relay, relay_kp2);
        });

        let device = DeviceKeypair::generate();
        let session =
            HushSession::connect(pipe_client, relay_pub, device, |_| {}).expect("should connect");

        let on_paired_fired: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let fired_clone = on_paired_fired.clone();

        // Start pairing with a 1ms window — it will expire immediately.
        let _payload = session.start_pairing_with_duration(Duration::from_millis(1), move |_| {
            *fired_clone.lock().unwrap() = true;
        });

        std::thread::sleep(Duration::from_millis(10)); // let window expire

        let dummy_key = NoisePublicKey(generate_keypair().public_key);
        session.accept_pair(dummy_key);

        assert!(
            !*on_paired_fired.lock().unwrap(),
            "on_paired must not fire after window timeout"
        );
    }
}
