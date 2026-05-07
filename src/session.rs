use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use hush_noise::keypair::Keypair as NoiseKeypair;
use thiserror::Error;

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::NoisePublicKey;
use crate::message::Message;
use crate::relay::RelayClient;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid keypair bytes")]
    InvalidKeypairBytes,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("push failed: {0}")]
    PushFailed(String),
}

/// The opinionated session facade (ADR-0010).
///
/// Owns the relay connection, sequence counter, signing keypair, and message
/// dispatch. Callers never see sequence numbers, parent hashes, or envelope
/// construction — those are hidden inside.
///
/// Transport-generic so tests can inject in-memory pipes.
pub struct HushSession<T: Read + Write + Send + 'static> {
    client: RelayClient<T>,
    signing: SigningKeypair,
    sequence: Arc<Mutex<u64>>,
}

impl<T: Read + Write + Send + 'static> HushSession<T> {
    /// Connect to a relay over `transport` and start the session.
    /// `on_message` fires for every decrypted, verified Message delivered to this device.
    pub fn connect(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message) + Send + 'static,
    ) -> Result<Self, SessionError> {
        let signing = keypair.signing_keypair();
        let noise_kp = NoiseKeypair::new(keypair.noise.private(), keypair.noise.public_key);
        let client = RelayClient::connect(transport, relay_pub, noise_kp)
            .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;

        client.subscribe(on_message);

        Ok(Self {
            client,
            signing,
            sequence: Arc::new(Mutex::new(0)),
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
        let seq = {
            let mut s = self.sequence.lock().unwrap();
            let current = *s;
            *s += 1;
            current
        };
        self.client
            .push(&msg, recipient_pub, seq, vec![], &self.signing)
            .map_err(|e| SessionError::PushFailed(e.to_string()))
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

    // ── In-memory bidirectional pipe (same simple spin-loop as relay tests) ───

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

    /// Tracer bullet: Session A pushes a Sync message through a fake relay;
    /// Session B's on_message callback receives the correct body.
    #[test]
    fn two_sessions_can_exchange_sync_message() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);

        let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
        let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();

        // Routing relay: accepts A and B; forwards Push from A as Deliver to B.
        // relay accepts pipe_a_relay first, then pipe_b_relay.
        {
            let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
            let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
            std::thread::spawn(move || {
                let sess_a = accept(pipe_a_relay, relay_kp_a).unwrap();
                let sess_b = accept(pipe_b_relay, relay_kp_b).unwrap();
                loop {
                    let raw = match sess_a.receive() {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    if let Some((MsgType::Push, body)) = parse(&raw) {
                        let deliver = frame(MsgType::Deliver, body);
                        let _ = sess_b.send(&deliver);
                    }
                }
            });
        }

        let device_a = DeviceKeypair::generate();
        let device_b = DeviceKeypair::generate();
        let b_pub = device_b.public_key();

        // Session A connects first — matches relay's first accept(pipe_a_relay)
        let session_a = HushSession::connect(pipe_a_client, relay_pub, device_a, |_| {})
            .expect("session A should connect");

        // Session B connects second — matches relay's second accept(pipe_b_relay)
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
}
