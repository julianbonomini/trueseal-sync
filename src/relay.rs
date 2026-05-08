use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use hush_noise::{
    keypair::Keypair as NoiseKeypair,
    session_xx::{dial, Session},
};
use thiserror::Error;

use crate::crypto;
use crate::envelope::Envelope;
use crate::keys::NoisePublicKey;
use crate::message::Message;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("push failed: {0}")]
    PushFailed(String),
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Wire protocol framing over the Noise session.
/// Each message: [msg_type: u8][len: u32 BE][body: bytes]
#[repr(u8)]
#[derive(PartialEq)]
pub(crate) enum MsgType {
    Push = 0x01,
    Deliver = 0x02,
}

impl MsgType {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Push),
            0x02 => Some(Self::Deliver),
            _ => None,
        }
    }
}

/// Frame a typed message into bytes for sending over a Noise session.
pub(crate) fn frame(msg_type: MsgType, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(5 + body.len());
    msg.push(msg_type as u8);
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(body);
    msg
}

/// Parse a framed message received from a Noise session.
pub(crate) fn parse(raw: &[u8]) -> Option<(MsgType, &[u8])> {
    if raw.len() < 5 {
        return None;
    }
    let msg_type = MsgType::from_u8(raw[0])?;
    let len = u32::from_be_bytes(raw[1..5].try_into().ok()?) as usize;
    if raw.len() < 5 + len {
        return None;
    }
    Some((msg_type, &raw[5..5 + len]))
}

/// A pre-encoded framed push message, ready to send over the Noise session.
type PushBytes = Vec<u8>;

/// Client-side connection to a hush-relay server.
/// Transport-generic: uses any Read+Write+Send stream (TCP in production,
/// in-memory pipes in tests).
///
/// Push operations are sent via a channel to the run() thread, which owns
/// the Session exclusively. This prevents the send/receive deadlock that
/// would occur if both operations shared the same Noise session mutex.
pub struct RelayClient<T: Read + Write + Send + 'static> {
    /// Channel for sending pre-encoded push frames to the run thread.
    push_tx: mpsc::SyncSender<PushBytes>,
    /// Callbacks receive the decoded Message and the sender's signing public key ([u8;32]).
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32]) + Send + 'static>>>>,
    /// True while the background run loop is alive; set to false when relay disconnects.
    is_connected: Arc<AtomicBool>,
    _transport: PhantomData<T>,
}

impl<T: Read + Write + Send + 'static> RelayClient<T> {
    /// Perform a Noise XX handshake over `transport` and verify the relay's identity.
    pub fn connect(
        transport: T,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        let my_noise_priv = my_keypair.private();
        let session = dial(transport, my_keypair).map_err(RelayError::HandshakeFailed)?;

        if session.remote_public_key() != relay_pub.0 {
            return Err(RelayError::HandshakeFailed(
                "relay public key mismatch".into(),
            ));
        }

        // Bounded channel: backpressure if the run thread falls behind.
        let (push_tx, push_rx) = mpsc::sync_channel::<PushBytes>(64);

        let callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32]) + Send + 'static>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let callbacks_clone = callbacks.clone();

        let is_connected = Arc::new(AtomicBool::new(true));
        let is_connected_clone = is_connected.clone();

        // run() thread owns the Session exclusively — no shared lock needed.
        std::thread::spawn(move || {
            run_loop(
                session,
                push_rx,
                callbacks_clone,
                my_noise_priv,
                is_connected_clone,
            );
        });

        Ok(Self {
            push_tx,
            callbacks,
            is_connected,
            _transport: PhantomData,
        })
    }

    /// Encrypt a Message for `recipient_pub` and push the resulting Envelope to the relay.
    pub fn push(
        &self,
        message: &Message,
        recipient_pub: NoisePublicKey,
        sequence: u64,
        parents: Vec<[u8; 32]>,
        author_signing: &crate::envelope::SigningKeypair,
    ) -> Result<(), RelayError> {
        let plaintext = message.encode();
        let author_pub = author_signing.public_key_bytes();
        let payload = crypto::encrypt(recipient_pub, author_pub, &plaintext);
        let envelope = Envelope::build(sequence, parents, recipient_pub, author_signing, payload);
        let body = envelope.encode();
        let framed = frame(MsgType::Push, &body);
        self.push_tx
            .send(framed)
            .map_err(|_| RelayError::PushFailed("relay run loop exited".into()))
    }

    /// Register a callback invoked when the relay delivers a Message to this device.
    /// Decryption and type parsing happen inside — callers receive a clean `Message`
    /// and the sender's signing public key (`author_pub` from the Envelope).
    pub fn subscribe(&self, callback: impl Fn(Message, [u8; 32]) + Send + 'static) {
        self.callbacks.lock().unwrap_or_else(|e| e.into_inner()).push(Box::new(callback));
    }

    /// Returns true while the background run loop is alive (relay connected).
    /// Becomes false when the relay disconnects or the transport fails.
    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Acquire)
    }

    /// Create a stub client in a permanently-disconnected state.
    ///
    /// Used by `connect_background` to start a session without any relay transport.
    /// `is_connected()` returns `false` immediately; `push()` returns an error.
    /// The reconnect loop will replace this client once the relay is reachable.
    pub(crate) fn disconnected() -> Self {
        // Create a channel and immediately drop the receiver so push_tx.send() fails.
        let (push_tx, _rx) = mpsc::sync_channel::<PushBytes>(0);
        Self {
            push_tx,
            callbacks: Arc::new(Mutex::new(Vec::new())),
            is_connected: Arc::new(AtomicBool::new(false)),
            _transport: PhantomData,
        }
    }

    /// Blocking receive loop — now a no-op since run() is started automatically in connect().
    /// Kept for API compatibility; returns immediately.
    ///
    /// Note: the actual receive loop runs in the background thread started by connect().
    pub fn run(&self) -> Result<(), RelayError> {
        // The real loop is in the background thread. This stub exists so callers
        // that previously called run() in a background thread continue to compile.
        // They can drop the spawned thread handle — the work happens automatically.
        Ok(())
    }
}

/// The actual event loop: runs in a dedicated thread that owns the Session.
/// Interleaves push sends (from the channel) with receive processing.
fn run_loop<T: Read + Write + Send + 'static>(
    session: Session<T>,
    push_rx: mpsc::Receiver<PushBytes>,
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32]) + Send + 'static>>>>,
    my_noise_priv: [u8; 32],
    is_connected: Arc<AtomicBool>,
) {
    // We need to interleave: check for pending pushes, then do one receive.
    // Since receive() blocks until a message arrives, we wrap the session in a
    // thread pair: one blocking-receive thread + one push-sender thread, both
    // sharing the session via Arc.
    //
    // Strategy: spawn a dedicated receive thread that blocks on session.receive(),
    // and handle pushes in this thread before blocking on channel recv.
    // This works because Session locks conn per-call; sends/receives interleave.
    //
    // HOWEVER: hush-noise Session holds conn:Arc<Mutex<T>>. Both send() and
    // receive() lock conn. If receive() is blocking, send() blocks too.
    // To truly decouple, we use a thread that only does receive(), and this
    // thread handles push sends when receive() is not holding the lock.
    //
    // Simplest correct approach: alternate between draining push_rx and calling
    // receive() with a non-blocking receive attempt. Since hush-noise doesn't
    // support non-blocking receives, we use a dedicated send thread.

    let session = Arc::new(session);
    let session_for_recv = session.clone();
    let session_for_send = session.clone();

    // Receive thread: blocks on session.receive() and forwards results.
    let (recv_tx, recv_rx) = mpsc::channel::<Result<Vec<u8>, String>>();
    std::thread::spawn(move || loop {
        let result = session_for_recv.receive();
        let done = result.is_err();
        if recv_tx.send(result).is_err() {
            break;
        }
        if done {
            break;
        }
    });

    // Send thread: receives push frames from push_rx and sends them.
    std::thread::spawn(move || {
        for framed in push_rx {
            if session_for_send.send(&framed).is_err() {
                break;
            }
        }
    });

    // This thread: dispatches received messages to callbacks.
    for result in recv_rx {
        match result {
            Err(_) => break,
            Ok(raw) => {
                if let Some((MsgType::Deliver, body)) = parse(&raw) {
                    if let Ok(env) = Envelope::decode(body) {
                        // New flow (ADR-0018 / #49): decrypt first to extract
                        // author_pub from the payload, then verify the signature
                        // using that key. author_pub is no longer in the clear header.
                        if let Ok((author_pub, plaintext)) = crypto::decrypt(my_noise_priv, &env.payload) {
                            if env.verify_with(author_pub).is_ok() {
                                if let Ok(msg) = Message::decode(&plaintext) {
                                    let cbs = callbacks.lock().unwrap_or_else(|e| e.into_inner());
                                    for cb in cbs.iter() {
                                        cb(msg.clone(), author_pub);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Signal that the relay connection has been lost.
    is_connected.store(false, Ordering::Release);
}

// ── Convenience constructor for TCP connections ──────────────────────────────

use std::net::TcpStream;

impl RelayClient<TcpStream> {
    /// Connect to a relay over TCP at `addr`.
    pub fn connect_tcp(
        addr: &str,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        let stream =
            TcpStream::connect(addr).map_err(|e| RelayError::ConnectionFailed(e.to_string()))?;
        Self::connect(stream, relay_pub, my_keypair)
    }
}

/// Opens a fresh Noise NK push session, sends `blob` as a framed Push message,
/// closes the session immediately, and returns the ephemeral public key used.
///
/// The relay sees this ephemeral key but cannot link it to the device's stable
/// noise identity — a fresh keypair is generated on every call (ADR-0018 / #51).
pub fn push_send<T: Read + Write + Send>(
    transport: T,
    relay_pub: [u8; 32],
    blob: Vec<u8>,
) -> Result<[u8; 32], RelayError> {
    use hush_noise::keypair::generate_keypair;
    let fresh_kp = generate_keypair();
    let eph_pub = fresh_kp.public_key;
    let session = hush_noise::session_nk::dial(transport, fresh_kp, relay_pub)
        .map_err(|e| RelayError::HandshakeFailed(e))?;
    session
        .send(&blob)
        .map_err(|e| RelayError::PushFailed(e))?;
    session.close().ok();
    Ok(eph_pub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceKeypair;
    use crate::envelope::SigningKeypair;
    use crate::keys::NoisePublicKey;
    use crate::message::Message;
    use hush_noise::{
        keypair::{generate_keypair, Keypair},
        session_xx::accept,
    };
    use std::io;
    use std::sync::{Arc, Mutex};

    // ── In-memory bidirectional pipe ──────────────────────────────────────────

    struct MemPipe {
        read_buf: Arc<Mutex<Vec<u8>>>,
        write_buf: Arc<Mutex<Vec<u8>>>,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for MemPipe {
        fn drop(&mut self) {
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    impl Read for MemPipe {
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

    // ── Minimal fake relay ────────────────────────────────────────────────────

    /// Spawns a fake relay. Receives Push messages and records raw envelope bytes.
    fn spawn_fake_relay(relay_pipe: MemPipe, relay_keypair: Keypair) -> Arc<Mutex<Vec<Envelope>>> {
        let received = Arc::new(Mutex::new(Vec::<Envelope>::new()));
        let received_clone = received.clone();
        std::thread::spawn(move || {
            let session = accept(relay_pipe, relay_keypair).unwrap();
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
        received
    }

    /// Helper: connect a device client to a fake relay, return (client, received_envelopes)
    fn connect_device(
        device: &DeviceKeypair,
        relay_pub: NoisePublicKey,
        client_pipe: MemPipe,
    ) -> RelayClient<MemPipe> {
        RelayClient::connect(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        )
        .expect("connect should succeed")
    }

    /// Tracer bullet: a device pushes a Sync message; the fake relay receives the envelope.
    #[test]
    fn device_can_push_sync_message_to_relay() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let received = spawn_fake_relay(relay_pipe, relay_kp2);

        let sender = DeviceKeypair::generate();
        let recipient = DeviceKeypair::generate();
        let client = connect_device(&sender, relay_pub, client_pipe);

        let msg = Message::Sync {
            body: b"clipboard entry".to_vec(),
        };
        client
            .push(
                &msg,
                recipient.public_key(),
                1,
                vec![],
                &sender.signing_keypair(),
            )
            .expect("push should succeed");

        // Spin-wait: react to actual delivery rather than a fixed delay.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !received.lock().unwrap().is_empty() { break; }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let stored = received.lock().unwrap();
        assert_eq!(stored.len(), 1, "relay should have received one envelope");
    }

    /// Connecting with the wrong relay public key is rejected.
    #[test]
    fn wrong_relay_key_is_rejected() {
        let relay_kp = generate_keypair();
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let wrong_pub = NoisePublicKey(generate_keypair().public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();
        std::thread::spawn(move || {
            let _ = accept(relay_pipe, relay_kp2);
        });

        let device = DeviceKeypair::generate();
        let result = RelayClient::connect(
            client_pipe,
            wrong_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        );

        assert!(result.is_err(), "wrong relay key should be rejected");
        assert!(matches!(
            result.err().unwrap(),
            RelayError::HandshakeFailed(_)
        ));
    }

    /// Subscribe callback receives a decoded Message when the relay delivers an envelope.
    #[test]
    fn subscribe_callback_receives_decoded_message() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();

        let recipient = DeviceKeypair::generate();
        let sender_signing = SigningKeypair::generate();
        let msg_to_deliver = Message::Sync {
            body: b"hello!".to_vec(),
        };

        // Fake relay: deliver one envelope to the client after handshake
        {
            let recipient_pub = recipient.public_key();
            let plaintext = msg_to_deliver.encode();
            let payload = crate::crypto::encrypt(recipient_pub, sender_signing.public_key_bytes(), &plaintext);
            let env = Envelope::build(1, vec![], recipient_pub, &sender_signing, payload);
            let env_bytes = env.encode();

            std::thread::spawn(move || {
                let session = accept(relay_pipe, relay_kp2).unwrap();
                let msg = frame(MsgType::Deliver, &env_bytes);
                session.send(&msg).unwrap();
            });
        }

        let delivered: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_clone = delivered.clone();

        // Connect and subscribe — run loop starts automatically in connect()
        let client = connect_device(&recipient, relay_pub, client_pipe);
        client.subscribe(move |msg, _author_pub| {
            delivered_clone.lock().unwrap().push(msg);
        });

        // Spin-wait for callback.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !delivered.lock().unwrap().is_empty() { break; }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let got = delivered.lock().unwrap();
        assert_eq!(got.len(), 1, "callback should have fired once");
        assert_eq!(got[0], msg_to_deliver);
    }

    /// Full pairing ceremony: A generates a pairing payload, B decodes it, pushes
    /// a Pair message addressed to A. A's subscribe callback receives B's public keys.
    ///
    /// This is an end-to-end integration test: message → crypto → envelope → relay
    /// → relay routes Push as Deliver → relay → crypto → envelope → message.
    #[test]
    fn pairing_ceremony_delivers_pair_message_to_initiator() {
        use crate::message::{decode_pairing_payload, pairing_payload};

        // ── Relay setup: two pipes (A↔relay, B↔relay) ──────────────────────
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);

        // Two pipe pairs — one per device
        let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
        let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();

        // Routing relay: accepts A then B, receives Push from B, delivers to A.
        // Uses raw Noise sessions directly (no RelayClient).
        {
            let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
            let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
            std::thread::spawn(move || {
                let sess_a = accept(pipe_a_relay, relay_kp_a).unwrap();
                let sess_b = accept(pipe_b_relay, relay_kp_b).unwrap();
                // Receive Push from B, route as Deliver to A
                loop {
                    let raw = match sess_b.receive() {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    if let Some((MsgType::Push, body)) = parse(&raw) {
                        let deliver = frame(MsgType::Deliver, body);
                        let _ = sess_a.send(&deliver);
                    }
                }
            });
        }

        // ── Devices ─────────────────────────────────────────────────────────
        let device_a = DeviceKeypair::generate();
        let device_b = DeviceKeypair::generate();

        // A generates its pairing payload (would be encoded as QR in real life)
        let payload_bytes =
            pairing_payload(&device_a.public_key().0, &device_a.signing_public_key().0);

        // B decodes A's pairing payload and obtains A's public keys
        let (a_noise_pub, _a_signing_pub) =
            decode_pairing_payload(&payload_bytes).expect("should decode pairing payload");

        // A connects to the relay and subscribes
        let client_a = connect_device(&device_a, relay_pub, pipe_a_client);
        let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();
        client_a.subscribe(move |msg, _author_pub| {
            received_clone.lock().unwrap().push(msg);
        });
        // run loop starts automatically in connect()

        // B connects and pushes a Pair message addressed to A
        let client_b = connect_device(&device_b, relay_pub, pipe_b_client);
        let pair_msg = Message::Pair {
            noise_pub: device_b.public_key().0,
            signing_pub: device_b.signing_public_key().0,
        };
        client_b
            .push(
                &pair_msg,
                NoisePublicKey(a_noise_pub),
                1,
                vec![],
                &device_b.signing_keypair(),
            )
            .expect("push should succeed");

        // Spin-wait for A's callback to fire.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !received.lock().unwrap().is_empty() { break; }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        // A's callback should have received B's Pair message
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1, "A should have received exactly one message");
        assert_eq!(
            got[0],
            Message::Pair {
                noise_pub: device_b.public_key().0,
                signing_pub: device_b.signing_public_key().0,
            },
            "A should receive B's Pair message with B's public keys"
        );
    }
}
