use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use trueseal_noise::{
    keypair::Keypair as NoiseKeypair,
    session_xx::{dial, Session},
};

use crate::crypto;
use crate::delivery_issue::{DeliveryIssue, UnreadableReason};
use crate::envelope::Envelope;
use crate::keys::NoisePublicKey;
use crate::message::Message;
use crate::version::{self, TransportVersionError};

/// Maximum serialised envelope size the client will attempt to push (1 MiB).
/// trueseal-sync is the protocol authority — this constant must match the relay's
/// configurable default (`relay.max_envelope_bytes`).
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;

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
    /// The serialised envelope exceeds MAX_ENVELOPE_BYTES.
    /// Non-retryable — the outbox must not replay this blob.
    #[error("envelope too large")]
    EnvelopeTooLarge,
    /// The relay permanently rejected the blob (e.g. oversized, malformed).
    /// Non-retryable — the outbox must not replay this blob indefinitely.
    #[error("push rejected by relay")]
    PushRejected,
    /// The relay refused our Transport Version and reported the range it
    /// supports (ADR-0022). Not a per-blob rejection — outbox entries stay
    /// queued; the relay (or this client) must be upgraded.
    #[error("relay supports Transport Version {min}..={max}")]
    RelayVersionUnsupported { min: u32, max: u32 },
}

impl From<TransportVersionError> for RelayError {
    fn from(e: TransportVersionError) -> Self {
        match e {
            TransportVersionError::Unsupported { min, max } => {
                RelayError::RelayVersionUnsupported { min, max }
            }
            TransportVersionError::Exchange(msg) => RelayError::HandshakeFailed(msg),
        }
    }
}

/// Wire protocol framing over the Noise session.
/// Each message: [msg_type: u8][len: u32 BE][body: bytes]
#[repr(u8)]
#[derive(PartialEq)]
pub(crate) enum MsgType {
    Push = 0x01,
    Deliver = 0x02,
    Heartbeat = 0x03,
    /// Relay → client. Body: empty (0 bytes).
    /// Semantic: "persisted to InboxStore" — not "received bytes" (ADR-0008).
    /// An earlier draft proposed an 8-byte u64 BE sequence in the body —
    /// rejected: relay never uses sequence numbers; dedup impossible on NK sessions;
    /// NK already authenticates the relay so a well-formed Ack is sufficient proof.
    /// trueseal-sync accepts any body length defensively but the relay always sends 0 bytes.
    Ack = 0x04,
    /// Relay → client. Body: empty (0 bytes).
    /// Semantic: the relay permanently rejected the blob (e.g. oversized envelope).
    /// The sender must NOT retry — `push_send` returns `RelayError::PushRejected`.
    Error = 0x05,
    DeliverAck = 0x06,
}

impl MsgType {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Push),
            0x02 => Some(Self::Deliver),
            0x03 => Some(Self::Heartbeat),
            0x04 => Some(Self::Ack),
            0x05 => Some(Self::Error),
            0x06 => Some(Self::DeliverAck),
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

/// Client-side connection to a trueseal-relay server.
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
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32], u64) + Send + 'static>>>>,
    /// Callbacks receive typed Delivery Issues (ADR-0034). Never sent to the
    /// relay or the sender.
    issue_callbacks: Arc<Mutex<Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>>>,
    /// True while the background run loop is alive; set to false when relay disconnects.
    is_connected: Arc<AtomicBool>,
    _transport: PhantomData<T>,
}

impl<T: Read + Write + Send + 'static> RelayClient<T> {
    /// Perform the Transport Version exchange, then a Noise XX handshake over
    /// `transport`, and verify the relay's identity.
    ///
    /// The version prefix is sent in plaintext first and becomes the Noise
    /// prologue (ADR-0022): a relay that refuses it answers
    /// `unsupported min..max`, surfaced as `RelayError::RelayVersionUnsupported`.
    ///
    /// The transport must be non-blocking (reads return `WouldBlock` when no
    /// data is ready) or carry its own read/write deadlines: the version
    /// exchange and the session loops enforce their timeouts through
    /// `WouldBlock` retries. A blocking transport with no deadline can hang
    /// forever against a silent (pre-version) relay. `connect_tcp` sets
    /// non-blocking mode for you.
    ///
    /// Connect with no message handler registered.
    ///
    /// The receive loop starts reading immediately, so a Blob delivered
    /// before `subscribe()` is called is processed with no handler attached
    /// and lost (SYNC-6, #98). Callers that must not miss early Delivers —
    /// every Session path — use [`Self::connect_subscribed`] instead.
    pub fn connect(
        transport: T,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        Self::connect_inner(transport, relay_pub, my_keypair, None)
    }

    /// Connect with the message handler registered up front, closing the
    /// connect/subscribe race (SYNC-6, #98): the handler is attached before
    /// the receive loop starts reading, so no Deliver is processed — or
    /// acked — before a handler exists (ADR-0026 recipient step 1).
    pub fn connect_subscribed(
        transport: T,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
    ) -> Result<Self, RelayError> {
        Self::connect_inner(transport, relay_pub, my_keypair, Some(Box::new(on_message)))
    }

    fn connect_inner(
        transport: T,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
        first_callback: Option<Box<dyn Fn(Message, [u8; 32], u64) + Send + 'static>>,
    ) -> Result<Self, RelayError> {
        let my_noise_priv = my_keypair.private();
        let mut transport = transport;
        let prologue = version::exchange_transport_version(&mut transport)?;
        let session =
            dial(transport, my_keypair, &prologue).map_err(RelayError::HandshakeFailed)?;

        if session.remote_public_key() != relay_pub.0 {
            return Err(RelayError::HandshakeFailed(
                "relay public key mismatch".into(),
            ));
        }

        // Bounded channel: backpressure if the run thread falls behind.
        let (push_tx, push_rx) = mpsc::sync_channel::<PushBytes>(64);

        // The first callback is registered before the run thread spawns, so
        // no Deliver can be processed before a handler exists (SYNC-6).
        let callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32], u64) + Send + 'static>>>> =
            Arc::new(Mutex::new(first_callback.into_iter().collect()));
        let callbacks_clone = callbacks.clone();

        let issue_callbacks: Arc<Mutex<Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let issue_callbacks_clone = issue_callbacks.clone();

        let is_connected = Arc::new(AtomicBool::new(true));
        let is_connected_clone = is_connected.clone();

        // run() thread owns the Session exclusively — no shared lock needed.
        std::thread::spawn(move || {
            run_loop(
                session,
                push_rx,
                callbacks_clone,
                issue_callbacks_clone,
                my_noise_priv,
                is_connected_clone,
            );
        });

        Ok(Self {
            push_tx,
            callbacks,
            issue_callbacks,
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
        let framed = build_push_blob(message, recipient_pub, sequence, parents, author_signing)?;
        self.push_tx
            .send(framed)
            .map_err(|_| RelayError::PushFailed("relay run loop exited".into()))
    }

    /// Register a callback invoked when the relay delivers a Message to this device.
    /// Decryption and type parsing happen inside — callers receive a clean `Message`
    /// and the sender's signing public key (`author_pub` from the Envelope).
    pub fn subscribe(&self, callback: impl Fn(Message, [u8; 32], u64) + Send + 'static) {
        self.callbacks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Box::new(callback));
    }

    /// Register a callback invoked with typed Delivery Issues: incoming Blobs
    /// the library rejected or is holding for an upgrade (ADR-0034).
    /// Device-local only — never sent to the relay or the sender.
    pub fn subscribe_delivery_issues(&self, callback: impl Fn(DeliveryIssue) + Send + 'static) {
        self.issue_callbacks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Box::new(callback));
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
            issue_callbacks: Arc::new(Mutex::new(Vec::new())),
            is_connected: Arc::new(AtomicBool::new(false)),
            _transport: PhantomData,
        }
    }
}

/// Build and frame a Push blob without sending it.
///
/// Encrypts `message` to `recipient_pub`, wraps it in a signed Envelope, and
/// returns the wire-framed bytes ready to hand to `push_send` (ADR-0018).
/// Returns `Err(RelayError::EnvelopeTooLarge)` if the serialised envelope
/// exceeds `MAX_ENVELOPE_BYTES` — checked after serialisation, before framing.
pub fn build_push_blob(
    message: &Message,
    recipient_pub: NoisePublicKey,
    sequence: u64,
    parents: Vec<[u8; 32]>,
    author_signing: &crate::envelope::SigningKeypair,
) -> Result<Vec<u8>, RelayError> {
    let plaintext = message.encode();
    let author_pub = author_signing.public_key_bytes();
    let payload = crypto::encrypt(recipient_pub, author_pub, &plaintext);
    let envelope = Envelope::build(sequence, parents, recipient_pub, author_signing, payload);
    let envelope_bytes = envelope.encode();
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(RelayError::EnvelopeTooLarge);
    }
    // Push body layout (ADR-0019): [recipient_pub: 32 bytes][envelope_proto: variable].
    // Relay reads body[0..32] as inbox routing key without proto decode.
    let mut body = Vec::with_capacity(32 + envelope_bytes.len());
    body.extend_from_slice(&recipient_pub.0);
    body.extend_from_slice(&envelope_bytes);
    Ok(frame(MsgType::Push, &body))
}

/// The actual event loop: runs in a dedicated thread that owns the Session.
/// Interleaves push sends (from the channel) with receive processing.
fn run_loop<T: Read + Write + Send + 'static>(
    session: Session<T>,
    push_rx: mpsc::Receiver<PushBytes>,
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32], u64) + Send + 'static>>>>,
    issue_callbacks: Arc<Mutex<Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>>>,
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
    // HOWEVER: trueseal-noise Session holds conn:Arc<Mutex<T>>. Both send() and
    // receive() lock conn. If receive() is blocking, send() blocks too.
    // To truly decouple, we use a thread that only does receive(), and this
    // thread handles push sends when receive() is not holding the lock.
    //
    // Simplest correct approach: alternate between draining push_rx and calling
    // receive() with a non-blocking receive attempt. Since trueseal-noise doesn't
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
    //
    // Newer-End-to-End-Version Blobs held unacked (blob ids, in arrival order),
    // awaiting a library upgrade (ADR-0022). In-memory per Receive Session: if
    // the session drops, the relay re-delivers and they are held again.
    let mut held: std::collections::VecDeque<[u8; 8]> = std::collections::VecDeque::new();
    let mut held_set: std::collections::HashSet<[u8; 8]> = std::collections::HashSet::new();

    let fire_issue =
        |issue_callbacks: &Arc<Mutex<Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>>>,
         issue: DeliveryIssue| {
            let cbs = issue_callbacks.lock().unwrap_or_else(|e| e.into_inner());
            for cb in cbs.iter() {
                cb(issue.clone());
            }
        };

    for result in recv_rx {
        match result {
            Err(_) => break,
            Ok(raw) => {
                if let Some((MsgType::Deliver, body)) = parse(&raw) {
                    // ADR-0020: Deliver body = [blob_id: 8 bytes][proto Envelope].
                    let blob_id: [u8; 8] = match body.get(0..8).and_then(|b| b.try_into().ok()) {
                        Some(id) => id,
                        None => {
                            // A Deliver frame with no blob id is malformed;
                            // there is nothing to ack.
                            fire_issue(
                                &issue_callbacks,
                                DeliveryIssue::Unreadable(UnreadableReason::Malformed),
                            );
                            continue;
                        }
                    };
                    let envelope_bytes = &body[8..];

                    // ADR-0022: the End-to-End Version is checked BEFORE any
                    // DeliverAck. Nothing but the DeliverAck (to the relay)
                    // ever leaves this device on a rejection path.
                    let env = match Envelope::decode(envelope_bytes) {
                        Ok(env) => env,
                        Err(_) => {
                            // Undecodable envelope: ack and drop (malformed).
                            let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
                            fire_issue(
                                &issue_callbacks,
                                DeliveryIssue::Unreadable(UnreadableReason::Malformed),
                            );
                            continue;
                        }
                    };

                    if env.version > version::END_TO_END_VERSION {
                        // Newer version: hold unacked so an upgrade recovers it.
                        if held_set.insert(blob_id) {
                            held.push_back(blob_id);
                            fire_issue(
                                &issue_callbacks,
                                DeliveryIssue::HeldForUpgrade(env.version),
                            );
                            if held.len() > version::MAX_HELD_BLOBS {
                                // Cap overflow: ack and drop the oldest held blob.
                                if let Some(oldest) = held.pop_front() {
                                    held_set.remove(&oldest);
                                    let _ = session.send(&frame(MsgType::DeliverAck, &oldest));
                                    fire_issue(
                                        &issue_callbacks,
                                        DeliveryIssue::Unreadable(
                                            UnreadableReason::DroppedWhileHeld,
                                        ),
                                    );
                                }
                            }
                        }
                        // A duplicate delivery of an already-held blob changes
                        // nothing and stays unacked.
                        continue;
                    }

                    if env.version < version::END_TO_END_VERSION {
                        // Older version — including 0, the refused pre-version
                        // format: ack and drop, never reaches a handler.
                        let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
                        fire_issue(
                            &issue_callbacks,
                            DeliveryIssue::Unreadable(UnreadableReason::SenderOutdated),
                        );
                        continue;
                    }

                    // Supported version: ack immediately — before decryption —
                    // so the relay learns nothing about the decryption outcome
                    // (zero trust, ADR-0020). Decrypt/verify failures are then
                    // reported as malformed; the blob is already acked and gone.
                    let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
                    let decoded = crypto::decrypt(my_noise_priv, &env.payload).and_then(
                        |(author_pub, plaintext)| {
                            if env.verify_with(author_pub).is_ok() {
                                Message::decode(&plaintext)
                                    .map(|msg| (author_pub, msg))
                                    .map_err(|_| crate::crypto::CryptoError::DecryptionFailed)
                            } else {
                                Err(crate::crypto::CryptoError::DecryptionFailed)
                            }
                        },
                    );
                    match decoded {
                        Ok((author_pub, msg)) => {
                            let cbs = callbacks.lock().unwrap_or_else(|e| e.into_inner());
                            for cb in cbs.iter() {
                                cb(msg.clone(), author_pub, env.sequence);
                            }
                        }
                        Err(_) => {
                            fire_issue(
                                &issue_callbacks,
                                DeliveryIssue::Unreadable(UnreadableReason::Malformed),
                            );
                        }
                    }
                } else if let Some((MsgType::Heartbeat, _)) = parse(&raw) {
                    // Echo Heartbeat back to keep the Receive Session alive (ADR-0019).
                    let _ = session.send(&frame(MsgType::Heartbeat, &[]));
                } else if parse(&raw).is_none() {
                    // An unknown frame type or unparseable bytes (ADR-0034: malformed).
                    fire_issue(
                        &issue_callbacks,
                        DeliveryIssue::Unreadable(UnreadableReason::Malformed),
                    );
                }
                // MsgType::Ack on XX session: silently drop (defensive).
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
    ///
    /// The stream is put in non-blocking mode before the Transport Version
    /// exchange, so a silent (pre-version) relay surfaces as a typed timeout
    /// (within the exchange deadline, 10 s) instead of hanging a blocking
    /// `read()` forever. Non-blocking is also the mode the FFI and CLI run
    /// every session in: a blocking receive would hold the session lock for
    /// the whole `read()` syscall and starve concurrent sends.
    pub fn connect_tcp(
        addr: &str,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        let stream =
            TcpStream::connect(addr).map_err(|e| RelayError::ConnectionFailed(e.to_string()))?;
        stream
            .set_nonblocking(true)
            .map_err(|e| RelayError::ConnectionFailed(e.to_string()))?;
        Self::connect(stream, relay_pub, my_keypair)
    }
}

/// Opens a fresh Noise NK push session, sends `blob` as a framed Push message,
/// waits for an Ack from the relay (ADR-0008), then closes the session.
///
/// The relay sends `Ack` (empty body) after persisting the Envelope to the
/// InboxStore — "bytes written" is not sufficient; we block until persistence
/// is confirmed. Ack body is ignored defensively.
///
/// The relay is authenticated via NK (client verified relay static key), so a
/// well-formed Ack is accepted without sequence validation.
///
/// The relay sees only the ephemeral key — a fresh keypair is generated on
/// every call and discarded after the session (ADR-0002 / #51).
///
/// Like `RelayClient::connect`, the transport must be non-blocking or carry
/// its own deadlines — otherwise a silent (pre-version) relay hangs the
/// version exchange on a blocking `read()` forever.
pub fn push_send<T: Read + Write + Send>(
    transport: T,
    relay_pub: [u8; 32],
    blob: Vec<u8>,
) -> Result<(), RelayError> {
    use trueseal_noise::keypair::generate_keypair;
    let fresh_kp = generate_keypair();
    let mut transport = transport;
    // Transport Version exchange first (ADR-0022); the prefix becomes the
    // Noise prologue. A refusal surfaces as RelayVersionUnsupported and the
    // outbox entry stays queued.
    let prologue = version::exchange_transport_version(&mut transport)?;
    let session = trueseal_noise::session_nk::dial(transport, fresh_kp, relay_pub, &prologue)
        .map_err(RelayError::HandshakeFailed)?;
    session.send(&blob).map_err(RelayError::PushFailed)?;
    // Block until the relay confirms persistence (ADR-0019).
    let raw = session
        .receive()
        .map_err(|_| RelayError::PushFailed("expected Ack, connection closed".into()))?;
    match parse(&raw) {
        Some((MsgType::Ack, _)) => {}
        Some((MsgType::Error, _)) => return Err(RelayError::PushRejected),
        _ => return Err(RelayError::PushFailed("expected Ack".into())),
    }
    session.close().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceKeypair;
    use crate::envelope::SigningKeypair;
    use crate::keys::NoisePublicKey;
    use crate::message::Message;
    use crate::version::testutil::xx_accept_after_prefix;
    use std::io;
    use std::sync::{Arc, Mutex};
    use trueseal_noise::keypair::{generate_keypair, Keypair};

    // ── In-memory bidirectional pipe ──────────────────────────────────────────

    struct MemPipe {
        read_buf: Arc<Mutex<Vec<u8>>>,
        write_buf: Arc<Mutex<Vec<u8>>>,
        /// Set by the peer when IT drops — this end then reads EOF.
        closed: Arc<std::sync::atomic::AtomicBool>,
        /// Set when this end drops — the peer then reads EOF.
        peer_closed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for MemPipe {
        fn drop(&mut self) {
            // Signal EOF to the PEER: set the flag the other end observes,
            // like closing a real socket does. (This previously set the flag
            // this pipe observes about itself, so a dropped relay never EOFed
            // the client.)
            self.peer_closed
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
                peer_closed: a_closed.clone(),
            },
            MemPipe {
                read_buf: ab.clone(),
                write_buf: ba.clone(),
                closed: a_closed.clone(),
                peer_closed: b_closed,
            },
        )
    }

    // ── Minimal fake relay ────────────────────────────────────────────────────

    /// Spawns a fake relay. Receives Push messages and records raw envelope bytes.
    fn spawn_fake_relay(relay_pipe: MemPipe, relay_keypair: Keypair) -> Arc<Mutex<Vec<Envelope>>> {
        let received = Arc::new(Mutex::new(Vec::<Envelope>::new()));
        let received_clone = received.clone();
        std::thread::spawn(move || {
            let session = xx_accept_after_prefix(relay_pipe, relay_keypair).unwrap();
            while let Ok(raw) = session.receive() {
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    // Push body layout (ADR-0019): [recipient_pub: 32][envelope_proto: ...]
                    if body.len() >= 32 {
                        if let Ok(env) = Envelope::decode(&body[32..]) {
                            received_clone.lock().unwrap().push(env);
                        }
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
            if !received.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let stored = received.lock().unwrap();
        assert_eq!(stored.len(), 1, "relay should have received one envelope");
    }

    /// build_push_blob returns EnvelopeTooLarge when envelope exceeds MAX_ENVELOPE_BYTES.
    #[test]
    fn build_push_blob_rejects_oversized_envelope() {
        let sender = DeviceKeypair::generate();
        let recipient = DeviceKeypair::generate();
        // Craft a message whose serialised envelope exceeds MAX_ENVELOPE_BYTES.
        let huge_body = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        let msg = Message::Sync { body: huge_body };
        let result = build_push_blob(
            &msg,
            recipient.public_key(),
            1,
            vec![],
            &sender.signing_keypair(),
        );
        assert!(
            matches!(result, Err(RelayError::EnvelopeTooLarge)),
            "expected EnvelopeTooLarge, got {:?}",
            result
        );
    }

    /// push_send returns PushRejected when relay sends an Error frame.
    #[test]
    fn push_send_returns_push_rejected_on_error_frame() {
        use crate::version::testutil::nk_accept_after_prefix as nk_accept;
        use trueseal_noise::keypair::generate_keypair;

        let relay_kp = generate_keypair();
        let relay_pub = relay_kp.public_key;

        let (client_pipe, relay_pipe) = mem_pipe_pair();

        // Stub relay: completes NK handshake, then immediately sends an Error frame.
        std::thread::spawn(move || {
            let relay_kp2 =
                trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
            let session = nk_accept(relay_pipe, relay_kp2).unwrap();
            let _ = session.receive(); // drain the Push
            let _ = session.send(&frame(MsgType::Error, &[]));
        });

        let sender = DeviceKeypair::generate();
        let recipient = DeviceKeypair::generate();
        let msg = Message::Sync {
            body: b"test".to_vec(),
        };
        let blob = build_push_blob(
            &msg,
            recipient.public_key(),
            1,
            vec![],
            &sender.signing_keypair(),
        )
        .expect("build_push_blob should succeed");

        let result = push_send(client_pipe, relay_pub, blob);
        assert!(
            matches!(result, Err(RelayError::PushRejected)),
            "expected PushRejected, got {:?}",
            result
        );
    }

    /// Connecting with the wrong relay public key is rejected.
    #[test]
    fn wrong_relay_key_is_rejected() {
        let relay_kp = generate_keypair();
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let wrong_pub = NoisePublicKey(generate_keypair().public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();
        std::thread::spawn(move || {
            let _ = xx_accept_after_prefix(relay_pipe, relay_kp2);
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
            let payload = crate::crypto::encrypt(
                recipient_pub,
                sender_signing.public_key_bytes(),
                &plaintext,
            );
            let env = Envelope::build(1, vec![], recipient_pub, &sender_signing, payload);
            let env_bytes = env.encode();

            std::thread::spawn(move || {
                let session = xx_accept_after_prefix(relay_pipe, relay_kp2).unwrap();
                // ADR-0020: Deliver body = [blob_id: 8 bytes][envelope_proto]
                let mut deliver_body = 0u64.to_be_bytes().to_vec();
                deliver_body.extend_from_slice(&env_bytes);
                let msg = frame(MsgType::Deliver, &deliver_body);
                session.send(&msg).unwrap();
            });
        }

        let delivered: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_clone = delivered.clone();

        // Connect and subscribe — run loop starts automatically in connect()
        let client = connect_device(&recipient, relay_pub, client_pipe);
        client.subscribe(move |msg, _author_pub, _seq| {
            delivered_clone.lock().unwrap().push(msg);
        });

        // Spin-wait for callback.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !delivered.lock().unwrap().is_empty() {
                break;
            }
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
                let sess_a = xx_accept_after_prefix(pipe_a_relay, relay_kp_a).unwrap();
                let sess_b = xx_accept_after_prefix(pipe_b_relay, relay_kp_b).unwrap();
                // Receive Push from B, route as Deliver to A
                while let Ok(raw) = sess_b.receive() {
                    if let Some((MsgType::Push, body)) = parse(&raw) {
                        if body.len() >= 32 {
                            // ADR-0020: Deliver body = [blob_id: 8 bytes][envelope_proto]
                            let mut deliver_body = 0u64.to_be_bytes().to_vec();
                            deliver_body.extend_from_slice(&body[32..]);
                            let deliver = frame(MsgType::Deliver, &deliver_body);
                            let _ = sess_a.send(&deliver);
                        }
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
        client_a.subscribe(move |msg, _author_pub, _seq| {
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
            if !received.lock().unwrap().is_empty() {
                break;
            }
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

    // ── SYNC-1: fixed protocol versions with typed rejection (ADR-0022) ──────

    use crate::delivery_issue::{DeliveryIssue, UnreadableReason};

    fn wait_until(cond: impl Fn() -> bool, millis: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(millis);
        while std::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        cond()
    }

    /// Build a validly-shaped envelope addressed to an arbitrary recipient,
    /// then stamp it with the given End-to-End Version. The version gate runs
    /// before decryption, so the payload need not decrypt for gate tests.
    fn envelope_bytes_with_version(version: u32) -> Vec<u8> {
        let author = SigningKeypair::generate();
        let recipient = DeviceKeypair::generate();
        let mut env = Envelope::build(
            1,
            vec![],
            recipient.public_key(),
            &author,
            b"irrelevant".to_vec(),
        );
        env.version = version;
        env.encode()
    }

    /// A fake relay that speaks the prefix exchange, records every frame the
    /// client sends, and delivers envelopes on demand.
    struct DeliverRelay {
        /// Every frame the client sent, as (msg_type_byte, body).
        client_frames: Arc<Mutex<Vec<(u8, Vec<u8>)>>>,
        deliver_tx: mpsc::Sender<(u64, Vec<u8>)>,
    }

    impl DeliverRelay {
        fn deliver(&self, blob_id: u64, envelope_bytes: Vec<u8>) {
            self.deliver_tx
                .send((blob_id, envelope_bytes))
                .expect("relay alive");
        }

        fn deliver_acks(&self) -> Vec<Vec<u8>> {
            self.client_frames
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, _)| *t == MsgType::DeliverAck as u8)
                .map(|(_, b)| b.clone())
                .collect()
        }

        /// Nothing but DeliverAck may leave the client on a rejection path —
        /// in particular nothing is ever sent back towards the sender.
        fn assert_only_deliver_acks(&self) {
            let frames = self.client_frames.lock().unwrap();
            assert!(
                frames.iter().all(|(t, _)| *t == MsgType::DeliverAck as u8),
                "client sent a non-DeliverAck frame: {:?}",
                frames.iter().map(|(t, _)| *t).collect::<Vec<_>>()
            );
        }
    }

    fn spawn_deliver_relay(relay_pipe: MemPipe, relay_keypair: Keypair) -> DeliverRelay {
        let client_frames = Arc::new(Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
        let (deliver_tx, deliver_rx) = mpsc::channel::<(u64, Vec<u8>)>();
        let frames_clone = client_frames.clone();
        std::thread::spawn(move || {
            let session =
                crate::version::testutil::xx_accept_after_prefix(relay_pipe, relay_keypair)
                    .expect("relay accept");
            let session = Arc::new(session);
            // Sender half: deliver envelopes the test asks for.
            let send_session = session.clone();
            std::thread::spawn(move || {
                // Give the client a moment to register its subscriptions
                // before the first deliver.
                std::thread::sleep(std::time::Duration::from_millis(50));
                for (blob_id, env_bytes) in deliver_rx {
                    let mut body = blob_id.to_be_bytes().to_vec();
                    body.extend_from_slice(&env_bytes);
                    if send_session.send(&frame(MsgType::Deliver, &body)).is_err() {
                        break;
                    }
                }
            });
            // Recorder half: every frame the client sends.
            while let Ok(raw) = session.receive() {
                if let Some((t, body)) = parse(&raw) {
                    frames_clone.lock().unwrap().push((t as u8, body.to_vec()));
                }
            }
        });
        DeliverRelay {
            client_frames,
            deliver_tx,
        }
    }

    /// Connect a client to a DeliverRelay, returning the client plus the
    /// recorded Delivery Issues and handled messages.
    #[allow(clippy::type_complexity)]
    fn connect_to_deliver_relay(
        relay_pub: NoisePublicKey,
        client_pipe: MemPipe,
    ) -> (
        RelayClient<MemPipe>,
        Arc<Mutex<Vec<DeliveryIssue>>>,
        Arc<Mutex<Vec<Message>>>,
    ) {
        let device = DeviceKeypair::generate();
        let client = RelayClient::connect(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        )
        .expect("connect");
        let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(Vec::new()));
        let issues_cb = issues.clone();
        client.subscribe_delivery_issues(move |issue| {
            issues_cb.lock().unwrap().push(issue);
        });
        let delivered: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_cb = delivered.clone();
        client.subscribe(move |msg, _author, _seq| {
            delivered_cb.lock().unwrap().push(msg);
        });
        (client, issues, delivered)
    }

    /// A relay that refuses the Transport Version replies `unsupported min..max`
    /// and the client surfaces RelayVersionUnsupported — before any handshake.
    #[test]
    fn connect_surfaces_relay_version_unsupported() {
        let (client_pipe, mut relay_pipe) = mem_pipe_pair();
        std::thread::spawn(move || {
            let mut prefix = [0u8; crate::version::TRANSPORT_PREFIX_LEN];
            use std::io::Read;
            // Read the client prefix, then refuse.
            let mut filled = 0;
            while filled < prefix.len() {
                match relay_pipe.read(&mut prefix[filled..]) {
                    Ok(0) => return,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
            use std::io::Write;
            let _ = relay_pipe.write_all(b"unsupported 1..1\n");
        });

        let device = DeviceKeypair::generate();
        let result = RelayClient::connect(
            client_pipe,
            NoisePublicKey(generate_keypair().public_key),
            Keypair::new(device.noise.private(), device.noise.public_key),
        );
        assert!(
            matches!(
                result,
                Err(RelayError::RelayVersionUnsupported { min: 1, max: 1 })
            ),
            "expected RelayVersionUnsupported{{1,1}}, got {:?}",
            result.err()
        );
    }

    /// A relay supporting only newer versions reports its own range verbatim.
    #[test]
    fn connect_reports_the_relays_supported_range() {
        let (client_pipe, mut relay_pipe) = mem_pipe_pair();
        std::thread::spawn(move || {
            let mut prefix = [0u8; crate::version::TRANSPORT_PREFIX_LEN];
            use std::io::Read;
            let mut filled = 0;
            while filled < prefix.len() {
                match relay_pipe.read(&mut prefix[filled..]) {
                    Ok(0) => return,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
            use std::io::Write;
            let _ = relay_pipe.write_all(b"unsupported 2..4\n");
        });

        let device = DeviceKeypair::generate();
        let result = RelayClient::connect(
            client_pipe,
            NoisePublicKey(generate_keypair().public_key),
            Keypair::new(device.noise.private(), device.noise.public_key),
        );
        assert!(matches!(
            result,
            Err(RelayError::RelayVersionUnsupported { min: 2, max: 4 })
        ));
    }

    /// NK push sessions get the same typed refusal.
    #[test]
    fn push_send_surfaces_relay_version_unsupported() {
        let (client_pipe, mut relay_pipe) = mem_pipe_pair();
        std::thread::spawn(move || {
            let mut prefix = [0u8; crate::version::TRANSPORT_PREFIX_LEN];
            use std::io::Read;
            let mut filled = 0;
            while filled < prefix.len() {
                match relay_pipe.read(&mut prefix[filled..]) {
                    Ok(0) => return,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
            use std::io::Write;
            let _ = relay_pipe.write_all(b"unsupported 1..1\n");
        });

        let result = push_send(client_pipe, [7u8; 32], frame(MsgType::Push, b"x"));
        assert!(matches!(
            result,
            Err(RelayError::RelayVersionUnsupported { min: 1, max: 1 })
        ));
    }

    /// The Transport Version is cryptographically bound: a relay that answers
    /// `supported` but handshakes with different prologue bytes fails.
    #[test]
    fn mismatched_prologue_breaks_the_handshake() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let (client_pipe, mut relay_pipe) = mem_pipe_pair();
        std::thread::spawn(move || {
            let _prefix = crate::version::fake_relay_accept_prefix(&mut relay_pipe);
            let kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
            // Handshake with a DIFFERENT prologue than the prefix bytes.
            let _ = trueseal_noise::session_xx::accept(relay_pipe, kp2, b"wrong prologue");
        });

        let device = DeviceKeypair::generate();
        let result = RelayClient::connect(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        );
        assert!(
            matches!(result, Err(RelayError::HandshakeFailed(_))),
            "mismatched prologue must fail the handshake, got {:?}",
            result.err()
        );
    }

    /// The NK push path gets the same prologue binding: a relay that answers
    /// `supported` but handshakes with different prologue bytes fails.
    #[test]
    fn nk_push_with_mismatched_prologue_breaks_the_handshake() {
        let relay_kp = generate_keypair();
        let relay_pub = relay_kp.public_key;
        let (client_pipe, mut relay_pipe) = mem_pipe_pair();
        std::thread::spawn(move || {
            let _prefix = crate::version::fake_relay_accept_prefix(&mut relay_pipe);
            let kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
            // Handshake with a DIFFERENT prologue than the prefix bytes.
            let _ = trueseal_noise::session_nk::accept(relay_pipe, kp2, b"wrong prologue");
        });

        let result = push_send(client_pipe, relay_pub, frame(MsgType::Push, b"x"));
        // The relay's accept fails on the prologue mismatch and it drops the
        // connection. Depending on scheduling the initiator sees that either
        // while dialing or while waiting for the Ack — never a successful push.
        assert!(
            matches!(
                result,
                Err(RelayError::HandshakeFailed(_)) | Err(RelayError::PushFailed(_))
            ),
            "mismatched prologue must fail the push, got {:?}",
            result.err()
        );
    }

    /// A silent pre-version relay (accepts TCP, never replies) must surface
    /// as a typed timeout, not hang a blocking read forever — the
    /// `connect_tcp` stream is non-blocking so the exchange deadline applies.
    /// Pre-fix this test never returns.
    #[test]
    fn silent_relay_surfaces_a_timeout_not_a_hang() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            // Accept and stay silent, holding the connection open.
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(std::time::Duration::from_secs(30));
                drop(stream);
            }
        });

        let device = DeviceKeypair::generate();
        let start = std::time::Instant::now();
        let result = RelayClient::connect_tcp(
            &addr.to_string(),
            NoisePublicKey(generate_keypair().public_key),
            Keypair::new(device.noise.private(), device.noise.public_key),
        );
        let elapsed = start.elapsed();

        match result {
            Err(RelayError::HandshakeFailed(msg)) => assert!(
                msg.contains("timed out"),
                "expected a typed timeout, got {msg:?}"
            ),
            Err(other) => panic!("expected a HandshakeFailed timeout, got {other:?}"),
            Ok(_) => panic!("a silent relay must not connect successfully"),
        }
        // The exchange deadline is 10 s; well clear of a hang, generous for CI.
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "took {elapsed:?} — deadline did not fire"
        );
    }

    /// A newer-version Blob is held UNACKED, raises heldForUpgrade, and never
    /// reaches the handler (ADR-0022).
    #[test]
    fn newer_version_blob_is_held_unacked() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        relay.deliver(
            42,
            envelope_bytes_with_version(crate::version::END_TO_END_VERSION + 1),
        );

        assert!(
            wait_until(
                || issues
                    .lock()
                    .unwrap()
                    .contains(&DeliveryIssue::HeldForUpgrade(
                        crate::version::END_TO_END_VERSION + 1
                    )),
                3000
            ),
            "heldForUpgrade should fire"
        );
        // Quiet period: no DeliverAck for a held blob.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            relay.deliver_acks().is_empty(),
            "a held blob must stay unacked"
        );
        assert!(
            delivered.lock().unwrap().is_empty(),
            "held blob never reaches the handler"
        );
    }

    /// Boundary: exactly MAX_HELD_BLOBS newer blobs are all held — no drops.
    #[test]
    fn held_cap_boundary_holds_exactly_max() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, _delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        let newer = envelope_bytes_with_version(crate::version::END_TO_END_VERSION + 1);
        for id in 0..crate::version::MAX_HELD_BLOBS as u64 {
            relay.deliver(id, newer.clone());
        }

        assert!(
            wait_until(
                || issues
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|i| matches!(i, DeliveryIssue::HeldForUpgrade(_)))
                    .count()
                    == crate::version::MAX_HELD_BLOBS,
                5000
            ),
            "all 100 blobs should be held"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            relay.deliver_acks().is_empty(),
            "nothing dropped at the cap boundary"
        );
        assert!(
            !issues.lock().unwrap().contains(&DeliveryIssue::Unreadable(
                UnreadableReason::DroppedWhileHeld
            )),
            "no droppedWhileHeld at exactly the cap"
        );
    }

    /// Cap overflow: the 101st newer blob acks and drops the oldest with
    /// droppedWhileHeld; the rest stay held (ADR-0022, ADR-0034).
    #[test]
    fn held_cap_overflow_acks_and_drops_the_oldest() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, _delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        let newer = envelope_bytes_with_version(crate::version::END_TO_END_VERSION + 1);
        for id in 0..=crate::version::MAX_HELD_BLOBS as u64 {
            relay.deliver(id, newer.clone());
        }

        assert!(
            wait_until(
                || issues.lock().unwrap().contains(&DeliveryIssue::Unreadable(
                    UnreadableReason::DroppedWhileHeld
                )),
                5000
            ),
            "overflow should drop the oldest"
        );
        assert!(
            wait_until(|| relay.deliver_acks().len() == 1, 2000),
            "exactly one ack"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
        let acks = relay.deliver_acks();
        assert_eq!(acks.len(), 1, "only the oldest blob is acked and dropped");
        assert_eq!(
            acks[0],
            0u64.to_be_bytes().to_vec(),
            "the acked blob is the OLDEST held one (blob 0)"
        );
        relay.assert_only_deliver_acks();
    }

    /// A duplicate delivery of an already-held blob changes nothing: no second
    /// issue, no ack.
    #[test]
    fn duplicate_delivery_of_held_blob_is_a_noop() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, _delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        let newer = envelope_bytes_with_version(crate::version::END_TO_END_VERSION + 1);
        relay.deliver(7, newer.clone());
        relay.deliver(7, newer);

        assert!(wait_until(|| !issues.lock().unwrap().is_empty(), 3000));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let held_count = issues
            .lock()
            .unwrap()
            .iter()
            .filter(|i| matches!(i, DeliveryIssue::HeldForUpgrade(_)))
            .count();
        assert_eq!(
            held_count, 1,
            "one heldForUpgrade despite duplicate delivery"
        );
        assert!(relay.deliver_acks().is_empty(), "still unacked");
    }

    /// An unversioned (pre-version-format) Blob decodes with version 0: it is
    /// acked and dropped with senderOutdated and never reaches a handler
    /// (ADR-0022: today's format is refused).
    #[test]
    fn unversioned_blob_is_acked_dropped_and_reported_sender_outdated() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        relay.deliver(9, envelope_bytes_with_version(0));

        assert!(
            wait_until(
                || issues
                    .lock()
                    .unwrap()
                    .contains(&DeliveryIssue::Unreadable(UnreadableReason::SenderOutdated)),
                3000
            ),
            "senderOutdated should fire"
        );
        assert!(
            wait_until(|| !relay.deliver_acks().is_empty(), 2000),
            "acked and dropped"
        );
        assert!(
            delivered.lock().unwrap().is_empty(),
            "never reaches the handler"
        );
        relay.assert_only_deliver_acks();
    }

    /// An older-version Blob is acked and dropped with senderOutdated.
    #[test]
    fn older_version_blob_is_acked_dropped_and_reported_sender_outdated() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        // Any version below END_TO_END_VERSION is "older" (0 is the only such
        // value today; the check is a comparison, not a special case).
        relay.deliver(
            10,
            envelope_bytes_with_version(crate::version::END_TO_END_VERSION - 1),
        );

        assert!(wait_until(
            || issues
                .lock()
                .unwrap()
                .contains(&DeliveryIssue::Unreadable(UnreadableReason::SenderOutdated)),
            3000
        ));
        assert!(wait_until(|| !relay.deliver_acks().is_empty(), 2000));
        assert!(delivered.lock().unwrap().is_empty());
        relay.assert_only_deliver_acks();
    }

    /// A malformed (undecodable) Blob is acked and dropped with malformed, and
    /// never reaches a handler (ADR-0034 §3).
    #[test]
    fn malformed_blob_is_acked_dropped_and_reported_malformed() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        relay.deliver(11, b"not a protobuf envelope".to_vec());

        assert!(
            wait_until(
                || issues
                    .lock()
                    .unwrap()
                    .contains(&DeliveryIssue::Unreadable(UnreadableReason::Malformed)),
                3000
            ),
            "malformed should fire"
        );
        assert!(wait_until(|| !relay.deliver_acks().is_empty(), 2000));
        assert!(delivered.lock().unwrap().is_empty());
        relay.assert_only_deliver_acks();
    }

    /// A supported-version Blob that fails authentication (garbage payload) is
    /// acked (zero-trust ack timing, ADR-0020) and reported malformed.
    #[test]
    fn undecryptable_blob_is_reported_malformed_and_never_handled() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);
        let (_client, issues, delivered) = connect_to_deliver_relay(relay_pub, client_pipe);

        relay.deliver(
            12,
            envelope_bytes_with_version(crate::version::END_TO_END_VERSION),
        );

        assert!(
            wait_until(
                || issues
                    .lock()
                    .unwrap()
                    .contains(&DeliveryIssue::Unreadable(UnreadableReason::Malformed)),
                3000
            ),
            "undecryptable payload should report malformed"
        );
        assert!(delivered.lock().unwrap().is_empty());
        relay.assert_only_deliver_acks();
    }

    // ── SYNC-6 (#98): the connect/subscribe race ────────────────────────────

    /// A Blob the relay delivers the moment the session comes up must reach
    /// the handler — it must not be acked into an empty callback list and
    /// lost (SYNC-6, ADR-0026 recipient step 1).
    ///
    /// `connect_subscribed` attaches the handler before the receive loop
    /// starts reading, so no Deliver is processed — or acked — before a
    /// handler exists. The relay delivers immediately after the handshake
    /// (the offline-inbox case); there is deliberately no grace period.
    #[test]
    fn deliver_before_subscribe_reaches_the_handler() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();

        let recipient = DeviceKeypair::generate();
        let sender_signing = SigningKeypair::generate();
        let msg_to_deliver = Message::Sync {
            body: b"waiting in the inbox".to_vec(),
        };

        let client_frames: Arc<Mutex<Vec<(u8, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let recipient_pub = recipient.public_key();
            let plaintext = msg_to_deliver.encode();
            let payload = crate::crypto::encrypt(
                recipient_pub,
                sender_signing.public_key_bytes(),
                &plaintext,
            );
            let env = Envelope::build(1, vec![], recipient_pub, &sender_signing, payload);
            let env_bytes = env.encode();
            let frames_clone = client_frames.clone();
            std::thread::spawn(move || {
                let session = xx_accept_after_prefix(relay_pipe, relay_kp2).unwrap();
                // Deliver immediately — no grace period for the client to
                // subscribe first. This is the SYNC-6 offline-inbox case.
                let mut body = 7u64.to_be_bytes().to_vec();
                body.extend_from_slice(&env_bytes);
                session.send(&frame(MsgType::Deliver, &body)).unwrap();
                while let Ok(raw) = session.receive() {
                    if let Some((t, b)) = parse(&raw) {
                        frames_clone.lock().unwrap().push((t as u8, b.to_vec()));
                    }
                }
            });
        }

        let delivered: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_cb = delivered.clone();
        let _client = RelayClient::connect_subscribed(
            client_pipe,
            relay_pub,
            Keypair::new(recipient.noise.private(), recipient.noise.public_key),
            move |msg, _author, _seq| {
                delivered_cb.lock().unwrap().push(msg);
            },
        )
        .expect("connect");

        assert!(
            wait_until(|| !delivered.lock().unwrap().is_empty(), 2000),
            "SYNC-6: a Blob delivered as the session comes up must reach the handler"
        );
        assert_eq!(delivered.lock().unwrap()[0], msg_to_deliver);
        // The Blob was processed — and therefore acked — only after the
        // handler was attached (registration precedes the receive loop).
        assert!(
            wait_until(
                || client_frames
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(t, _)| *t == MsgType::DeliverAck as u8),
                2000
            ),
            "the delivered blob should have been acked"
        );
    }
}
