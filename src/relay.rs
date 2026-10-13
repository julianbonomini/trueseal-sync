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

use crate::delivery_issue::{DeliveryIssue, UnreadableReason};
use crate::envelope::Envelope;
use crate::keys::NoisePublicKey;
use crate::limits::MAX_ENVELOPE_BYTES;
use crate::message::Message;
use crate::version::{self, TransportVersionError};

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
    /// The serialised envelope exceeds `limits::MAX_ENVELOPE_BYTES` — the
    /// largest envelope that still fits in one Noise frame (ADR-0025).
    /// Non-retryable — the outbox must not replay this blob.
    #[error("envelope too large")]
    EnvelopeTooLarge,
    /// The relay refused the blob with an Error frame, classified by the
    /// typed reason byte (relay ADR-0008, amended by RELAY-5). Permanent
    /// refusals are non-retryable — the outbox must not replay this blob
    /// indefinitely; temporary refusals back off and retry (ADR-0026).
    #[error("push refused by relay: {0:?}")]
    PushRejected(RelayRefusal),
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

/// The relay's typed refusal of a Push, classified from the Error frame's
/// one-byte reason code (relay ADR-0008, amended by RELAY-5; the ADR-0026
/// relay contract). Bit 7 set marks a TEMPORARY refusal — the blob may be
/// accepted on a later retry. Bit 7 clear is permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRefusal {
    /// 0x01 tooLarge — the blob exceeds the relay's size limit (ADR-0025:
    /// a size refusal is permanent and typed; a relay operator may only
    /// LOWER the limit, so a client-legal blob can still be refused).
    TooLarge,
    /// 0x02 malformed, an unknown bit-7-clear code, or a legacy reasonless
    /// Error body. Permanent: the blob will never be accepted. The legacy
    /// mapping is ADR-0026's documented rule — an untyped refusal reports
    /// `sendFailed(malformed)` — and pre-RELAY-5 relays only refused
    /// oversize pushes, which the client-side size check already prevents.
    Malformed { code: Option<u8> },
    /// Any reason byte with bit 7 set: 0x81 inboxFull, 0x82 rateLimited,
    /// 0x83 unavailable, 0x84 internal, or a future temporary code.
    /// Temporary — the outbox backs off and retries while connected.
    Temporary { code: u8 },
}

/// Classify a relay Error frame body (relay ADR-0008 amended). A
/// zero-length body remains well-formed for backward compatibility with
/// pre-typed relays and maps to the ADR-0026 legacy rule (permanent,
/// malformed). Unknown codes classify by bit 7 alone, so a future relay
/// taxonomy stays forward-compatible: unknown temporary codes retry,
/// unknown permanent codes fail typed.
fn classify_refusal(body: &[u8]) -> RelayRefusal {
    match body.first().copied() {
        Some(0x01) => RelayRefusal::TooLarge,
        Some(0x02) => RelayRefusal::Malformed { code: Some(0x02) },
        Some(code) if code & 0x80 != 0 => RelayRefusal::Temporary { code },
        other => RelayRefusal::Malformed { code: other },
    }
}

/// Wire protocol framing over the Noise session.
/// Each message: [msg_type: u8][len: u32 BE][body: bytes]
#[repr(u8)]
#[derive(PartialEq, Clone, Copy, Debug)]
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
    /// Relay → client. Body: one byte — the typed reason code (relay
    /// ADR-0008, amended by RELAY-5); a zero-length body stays well-formed
    /// for pre-typed relays. `push_send` classifies it into
    /// `RelayError::PushRejected(RelayRefusal)` — permanent codes must not
    /// be retried; temporary codes (bit 7 set) back off and retry.
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

/// Relay ADR-0012 deadlines, enforced at the client seams (SYNC-16):
/// trueseal-noise retries `WouldBlock` forever (RetryConn during the
/// handshake, `read_exact_interruptible` inside `receive`), so the bound
/// lives here. The Noise handshake gets 10 s (ADR-0012's handshake
/// deadline); a whole Push Session gets 30 s (ADR-0012's Push Session
/// deadline) — a hung Ack wait resolves typed and temporary instead of
/// wedging the outbox pump thread silently (B7 review note).
const HANDSHAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
const PUSH_SESSION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// A transport wrapper that fails reads and writes with `TimedOut` once
/// its deadline passes. trueseal-noise's retry loops pass every error
/// except `WouldBlock`/`Interrupted` straight through, so a `TimedOut`
/// terminates a stalled handshake or Ack wait instead of spinning
/// forever. Disarm once the bounded phase is over (after the XX
/// handshake) and the session runs passthrough.
struct DeadlineConn<T> {
    inner: T,
    deadline: Arc<Mutex<Option<std::time::Instant>>>,
}

/// Handle that disarms a `DeadlineConn`'s deadline (None = passthrough).
struct DeadlineHandle(Arc<Mutex<Option<std::time::Instant>>>);

impl DeadlineHandle {
    fn disarm(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl<T> DeadlineConn<T> {
    fn armed(inner: T, budget: std::time::Duration) -> (Self, DeadlineHandle) {
        let deadline = Arc::new(Mutex::new(Some(std::time::Instant::now() + budget)));
        (
            Self {
                inner,
                deadline: deadline.clone(),
            },
            DeadlineHandle(deadline),
        )
    }

    fn expired(&self) -> bool {
        self.deadline
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|d| std::time::Instant::now() >= d)
    }

    fn timed_out() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "relay deadline exceeded")
    }
}

impl<T: Read> Read for DeadlineConn<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.expired() {
            return Err(Self::timed_out());
        }
        self.inner.read(buf)
    }
}

impl<T: Write> Write for DeadlineConn<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.expired() {
            return Err(Self::timed_out());
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<T: Severable> Severable for DeadlineConn<T> {
    /// Severing delegates to the inner transport: a sever must interrupt
    /// a receive no matter what deadline state the wrapper is in.
    fn sever_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        self.inner.sever_handle()
    }
}

/// Wall-clock milliseconds for the liveness stamp. A clock step can only
/// cause a false-positive sever, which costs one reconnect — acceptable.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A transport that can be severed from outside a blocked read (SYNC-15,
/// ADR-0028 `close()`): after the sever handle runs, in-flight and future
/// reads return EOF or an error, so a receive thread parked in WouldBlock
/// retry exits instead of leaking for the process lifetime. Implemented by
/// `TcpStream` (shutdown) and by the in-memory test pipes.
pub trait Severable: Read + Write + Send + 'static {
    /// A handle that severs the transport. Safe to call from any thread,
    /// any number of times, and must not block.
    fn sever_handle(&self) -> Arc<dyn Fn() + Send + Sync>;
}

impl Severable for std::net::TcpStream {
    fn sever_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        match self.try_clone() {
            Ok(twin) => Arc::new(move || {
                let _ = twin.shutdown(std::net::Shutdown::Both);
            }),
            // A stream we cannot clone cannot be severed from outside; the
            // noise session's closed flag still gates new sends/receives.
            Err(_) => Arc::new(|| {}),
        }
    }
}

/// Receive Session timeout knobs (relay ADR-0012). The client sends a
/// Heartbeat every `heartbeat`; if NO inbound frame of any kind arrives
/// within `liveness`, the session is dead and is severed so the reconnect
/// loop engages. `handshake` bounds the post-0x01 Noise handshake
/// (trueseal-noise RetryConn retries WouldBlock with no deadline of its
/// own). Production defaults: 25 s / 75 s / 10 s.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTimeouts {
    pub heartbeat: std::time::Duration,
    pub liveness: std::time::Duration,
    pub handshake: std::time::Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            heartbeat: std::time::Duration::from_secs(25),
            liveness: std::time::Duration::from_secs(75),
            handshake: HANDSHAKE_DEADLINE,
        }
    }
}

/// Client-side connection to a trueseal-relay server.
/// Transport-generic: uses any Read+Write+Send stream (TCP in production,
/// in-memory pipes in tests).
///
/// Push operations are sent via a channel to the run() thread, which owns
/// the Session exclusively. This prevents the send/receive deadlock that
/// would occur if both operations shared the same Noise session mutex.
pub struct RelayClient<T: Severable> {
    /// Channel for sending pre-encoded push frames to the run thread.
    push_tx: mpsc::SyncSender<PushBytes>,
    /// Callbacks receive the decoded Message and the sender's signing public key ([u8;32]).
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32], u64, u64) + Send + 'static>>>>,
    /// Callbacks receive typed Delivery Issues (ADR-0034). Never sent to the
    /// relay or the sender.
    issue_callbacks: Arc<Mutex<Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>>>,
    /// True while the background run loop is alive; set to false when relay disconnects.
    is_connected: Arc<AtomicBool>,
    /// Handle to the receive-side Noise Session, so `close()` (and Drop) can
    /// fail NEW sends/receives fast. The closed flag is only checked at
    /// send/receive ENTRY — interrupting a receive parked in WouldBlock
    /// retry is the sever handle's job (below). `None` for the
    /// disconnected stub.
    session: Option<Arc<Session<DeadlineConn<T>>>>,
    /// Severs the transport under a receive parked in WouldBlock retry
    /// (SYNC-15): the noise closed flag alone is only checked at
    /// send/receive ENTRY, so without this a dropped client left its
    /// receive thread parked on the socket forever (B7b/B12b review
    /// notes). No-op for the disconnected stub.
    sever: Arc<dyn Fn() + Send + Sync>,
    _transport: PhantomData<T>,
}

impl<T: Severable> Drop for RelayClient<T> {
    /// Dropping the client severs the receive side: the transport EOF
    /// unblocks its receive thread (the noise closed flag is only checked
    /// at receive entry), and dropping `push_tx` ends the send thread.
    /// This is also what finally reaps the OLD client after an identity
    /// rotation swaps in the disconnected stub.
    fn drop(&mut self) {
        self.close();
    }
}

impl<T: Severable> RelayClient<T> {
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
        Self::connect_inner(
            transport,
            relay_pub,
            my_keypair,
            None,
            None,
            SessionTimeouts::default(),
        )
    }

    /// Connect with the message handler registered up front, closing the
    /// connect/subscribe race (SYNC-6, #98): the handler is attached before
    /// the receive loop starts reading, so no Deliver is processed — or
    /// acked — before a handler exists (ADR-0026 recipient step 1).
    ///
    /// `on_issue` is registered before the receive loop starts too
    /// (SYNC-5): the Delivery Issue stream is one channel from the very
    /// first frame, so an early rejection is never lost to a late
    /// `subscribe_delivery_issues`.
    pub fn connect_subscribed(
        transport: T,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
        on_message: impl Fn(Message, [u8; 32], u64, u64) + Send + 'static,
        on_issue: Option<Box<dyn Fn(DeliveryIssue) + Send + 'static>>,
    ) -> Result<Self, RelayError> {
        Self::connect_inner(
            transport,
            relay_pub,
            my_keypair,
            Some(Box::new(on_message)),
            on_issue,
            SessionTimeouts::default(),
        )
    }

    /// `connect_subscribed` with explicit heartbeat/liveness knobs —
    /// production callers pass the ADR-0012 defaults (25 s / 75 s) via
    /// `SessionTimeouts::default()`; tests pass scaled-down windows (B23c:
    /// relay-kill liveness must be exercisable without a 75 s test).
    pub(crate) fn connect_subscribed_with_timeouts(
        transport: T,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
        on_message: impl Fn(Message, [u8; 32], u64, u64) + Send + 'static,
        on_issue: Option<Box<dyn Fn(DeliveryIssue) + Send + 'static>>,
        timeouts: SessionTimeouts,
    ) -> Result<Self, RelayError> {
        Self::connect_inner(
            transport,
            relay_pub,
            my_keypair,
            Some(Box::new(on_message)),
            on_issue,
            timeouts,
        )
    }

    fn connect_inner(
        transport: T,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
        first_callback: Option<Box<dyn Fn(Message, [u8; 32], u64, u64) + Send + 'static>>,
        first_issue_callback: Option<Box<dyn Fn(DeliveryIssue) + Send + 'static>>,
        timeouts: SessionTimeouts,
    ) -> Result<Self, RelayError> {
        let my_noise_priv = my_keypair.private();
        let sever = transport.sever_handle();
        let mut transport = transport;
        let prologue = version::exchange_transport_version(&mut transport)?;
        // Bound the Noise handshake (relay ADR-0012: 10 s): a relay that
        // answers 0x01 and then goes silent must surface a typed failure,
        // not spin RetryConn forever. Disarmed on success — the session
        // then runs passthrough.
        let (transport, handshake_deadline) = DeadlineConn::armed(transport, timeouts.handshake);
        let session =
            dial(transport, my_keypair, &prologue).map_err(RelayError::HandshakeFailed)?;
        handshake_deadline.disarm();

        if session.remote_public_key() != relay_pub.0 {
            return Err(RelayError::HandshakeFailed(
                "relay public key mismatch".into(),
            ));
        }

        // Bounded channel: backpressure if the run thread falls behind.
        let (push_tx, push_rx) = mpsc::sync_channel::<PushBytes>(64);

        // The first callback is registered before the run thread spawns, so
        // no Deliver can be processed before a handler exists (SYNC-6).
        let callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32], u64, u64) + Send + 'static>>>> =
            Arc::new(Mutex::new(first_callback.into_iter().collect()));
        let callbacks_clone = callbacks.clone();

        // The first issue callback is registered before the run thread
        // spawns, alongside the first message callback (SYNC-5).
        let issue_callbacks: Arc<Mutex<Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>>> =
            Arc::new(Mutex::new(first_issue_callback.into_iter().collect()));
        let issue_callbacks_clone = issue_callbacks.clone();

        let is_connected = Arc::new(AtomicBool::new(true));
        let is_connected_clone = is_connected.clone();

        // run() thread owns the Session exclusively — no shared lock needed.
        // The client keeps an Arc handle so `close()` can interrupt the
        // receive thread from the outside.
        let session = Arc::new(session);
        let session_for_loop = session.clone();
        let sever_for_loop = sever.clone();
        std::thread::spawn(move || {
            run_loop(
                session_for_loop,
                push_rx,
                callbacks_clone,
                issue_callbacks_clone,
                my_noise_priv,
                is_connected_clone,
                timeouts,
                sever_for_loop,
            );
        });

        Ok(Self {
            push_tx,
            callbacks,
            issue_callbacks,
            is_connected,
            session: Some(session),
            sever,
            _transport: PhantomData,
        })
    }

    /// Seal a Message for `recipient_pub` and push the resulting Envelope to
    /// the relay. `sender_timestamp_ms` follows the ADR-0034 §2 rule (see
    /// [`build_push_blob`]).
    pub fn push(
        &self,
        message: &Message,
        recipient_pub: NoisePublicKey,
        sequence: u64,
        parents: Vec<[u8; 32]>,
        author_signing: &crate::envelope::SigningKeypair,
        sender_timestamp_ms: u64,
    ) -> Result<(), RelayError> {
        let framed = build_push_blob(
            message,
            recipient_pub,
            sequence,
            parents,
            author_signing,
            sender_timestamp_ms,
        )?;
        self.push_tx
            .send(framed)
            .map_err(|_| RelayError::PushFailed("relay run loop exited".into()))
    }

    /// Register a callback invoked when the relay delivers a Message to this device.
    /// Decryption and type parsing happen inside — callers receive a clean `Message`
    /// and the sender's signing public key (`author_pub` from the Envelope).
    pub fn subscribe(&self, callback: impl Fn(Message, [u8; 32], u64, u64) + Send + 'static) {
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
            session: None,
            sever: Arc::new(|| {}),
            _transport: PhantomData,
        }
    }

    /// Interrupt the receive side: severing the transport makes a receive
    /// parked in WouldBlock retry return EOF (the noise session's closed
    /// flag is only checked at send/receive ENTRY, so the flag alone would
    /// leave the thread parked). The run loop and its receive thread exit,
    /// and `is_connected` flips to false via the DisconnectGuard. The send thread ends when the client (and its
    /// `push_tx`) drops. Idempotent; a no-op on the disconnected stub.
    ///
    /// Does NOT wait for thread exit — the run loop winds down within one
    /// WouldBlock retry cycle of the transport.
    pub fn close(&self) {
        // Sever first: the parked receive EOFs and its thread exits, then
        // the run loop follows and the DisconnectGuard marks the link down.
        (self.sever)();
        if let Some(session) = &self.session {
            let _ = session.close();
        }
    }
}

/// Build and frame a Push blob without sending it.
///
/// Seals `message` to `recipient_pub` — the signature, sequence, parents and
/// Sender Timestamp all move inside the Addressed Encryption (ADR-0031) —
/// and returns the wire-framed bytes ready to hand to `push_send` (ADR-0018).
///
/// `sender_timestamp_ms` is the sealed Sender Timestamp in unix millis
/// (ADR-0034 §2): a `Sync` message passes its `send()` time (kept through
/// every re-seal); a control message passes the seal time.
///
/// Returns `Err(RelayError::EnvelopeTooLarge)` if the serialised envelope
/// exceeds `limits::MAX_ENVELOPE_BYTES` (the one-frame ceiling, ADR-0025) —
/// checked after serialisation, before framing. `Sync` bodies are refused
/// earlier, at the Protocol Size Limit in `send()`.
pub fn build_push_blob(
    message: &Message,
    recipient_pub: NoisePublicKey,
    sequence: u64,
    parents: Vec<[u8; 32]>,
    author_signing: &crate::envelope::SigningKeypair,
    sender_timestamp_ms: u64,
) -> Result<Vec<u8>, RelayError> {
    let envelope = Envelope::build_sealed(
        sequence,
        parents,
        recipient_pub,
        author_signing,
        sender_timestamp_ms,
        &message.encode(),
    );
    push_frame_for_envelope(&envelope)
}

/// Frame an already-sealed Envelope as a Push blob: the size backstop plus
/// the routing-prefix body assembly of [`build_push_blob`]. Shared with the
/// SYNC-2 test vectors so the wire bytes the vectors pin come from the same
/// code that production pushes use.
pub(crate) fn push_frame_for_envelope(envelope: &Envelope) -> Result<Vec<u8>, RelayError> {
    let envelope_bytes = envelope.encode();
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(RelayError::EnvelopeTooLarge);
    }
    // Push body layout (ADR-0019): [recipient_pub: 32 bytes][envelope_proto: variable].
    // Relay reads body[0..32] as inbox routing key without proto decode.
    let mut body = Vec::with_capacity(32 + envelope_bytes.len());
    body.extend_from_slice(&envelope.recipient_pub);
    body.extend_from_slice(&envelope_bytes);
    Ok(frame(MsgType::Push, &body))
}

/// Clears `is_connected` when the run thread exits by ANY path — a clean
/// receive error or a panic unwinding through an app callback. Only the
/// Sync handler is panic-wrapped (handler attempts, ADR-0026); a panic in a
/// control-plane callback (e.g. `on_manifest_changed` writing to the app's
/// database) unwinds this thread. Without the guard the `is_connected`
/// store would be skipped, and the reconnect loop — which polls it — would
/// never engage: delivery wedges silently, forever, with no signal.
struct DisconnectGuard(Arc<AtomicBool>);

impl Drop for DisconnectGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The actual event loop: runs in a dedicated thread that owns the Session.
/// Interleaves push sends (from the channel) with receive processing.
fn run_loop<T: Severable>(
    session: Arc<Session<DeadlineConn<T>>>,
    push_rx: mpsc::Receiver<PushBytes>,
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message, [u8; 32], u64, u64) + Send + 'static>>>>,
    issue_callbacks: Arc<Mutex<Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>>>,
    my_noise_priv: [u8; 32],
    is_connected: Arc<AtomicBool>,
    timeouts: SessionTimeouts,
    sever: Arc<dyn Fn() + Send + Sync>,
) {
    // On ANY exit — clean or unwinding — signal that the relay connection
    // has been lost.
    let _disconnect_guard = DisconnectGuard(is_connected);
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

    let session_for_recv = session.clone();
    let session_for_send = session.clone();
    let session_for_heartbeat = session.clone();

    // Liveness stamp (SYNC-16, relay ADR-0012): the RECEIVE thread stamps
    // EVERY inbound frame — not the dispatch thread (a slow handler must
    // not look like a dead connection) and not only heartbeat echoes (the
    // relay may legitimately drop echoes under Deliver saturation,
    // trueseal-relay #47 — any inbound frame proves the link is alive).
    let last_inbound = Arc::new(std::sync::atomic::AtomicU64::new(now_millis()));
    let last_inbound_recv = last_inbound.clone();

    // Receive thread: blocks on session.receive() and forwards results.
    let (recv_tx, recv_rx) = mpsc::channel::<Result<Vec<u8>, String>>();
    std::thread::spawn(move || loop {
        let result = session_for_recv.receive();
        let done = result.is_err();
        if result.is_ok() {
            last_inbound_recv.store(now_millis(), Ordering::Release);
        }
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

    // Heartbeat thread (SYNC-16, relay ADR-0012 — superseding ADR-0019's
    // relay-initiated keepalive): the client sends a Heartbeat every
    // `interval` while connected. The relay echoes it, but ANY inbound
    // frame counts as liveness; if no inbound frame arrives within
    // `liveness`, the link is dead. The watchdog then performs BOTH halves
    // of link-down signaling itself — flips is_connected AND severs —
    // because the DisconnectGuard at this run loop's scope only drops when
    // the dispatch loop below exits, and that loop runs APP CALLBACKS on
    // this thread: a PARKED handler (B7b covered panicking ones) would
    // otherwise wedge disconnect detection forever — socket severed,
    // receive thread dead, is_connected true, no Disconnected ever
    // surfacing (B23c, the structural shape of the D1 finding). The
    // guard's later store is idempotent, so the double signal is
    // harmless, and the parked loop still drains its queue in order when
    // the callback returns. A heartbeat SEND failure is the same verdict:
    // a healthy link does not refuse 19 bytes (a WouldBlock under relay
    // backpressure is a wedged link) — flip + sever, costing at most one
    // spurious reconnect, the false-positive price the liveness stamp
    // already accepts. The thread exits the moment this run loop does
    // (the stop channel's sender drops), so close() leaves no zombie.
    let (heartbeat_stop_tx, heartbeat_stop_rx) = mpsc::channel::<()>();
    let _heartbeat_stop_tx = heartbeat_stop_tx;
    let last_inbound_heartbeat = last_inbound.clone();
    // `while let` on the timeout arm: any other outcome (sender dropped
    // — the run loop is exiting — or a spurious send) ends the thread.
    std::thread::spawn(move || {
        while let Err(mpsc::RecvTimeoutError::Timeout) =
            heartbeat_stop_rx.recv_timeout(timeouts.heartbeat)
        {
            let age = now_millis().saturating_sub(last_inbound_heartbeat.load(Ordering::Acquire));
            if age > timeouts.liveness.as_millis() as u64 {
                (sever)();
                break;
            }
            if session_for_heartbeat
                .send(&frame(MsgType::Heartbeat, &[]))
                .is_err()
            {
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
                            // Undecodable envelope: the rejection is
                            // recorded BEFORE the ack (ADR-0031/0034 crash
                            // ordering), then ack and drop (malformed).
                            fire_issue(
                                &issue_callbacks,
                                DeliveryIssue::Unreadable(UnreadableReason::Malformed),
                            );
                            let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
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
                                    // Rejection recorded before the ack
                                    // (ADR-0031/0034 crash ordering).
                                    fire_issue(
                                        &issue_callbacks,
                                        DeliveryIssue::Unreadable(
                                            UnreadableReason::DroppedWhileHeld,
                                        ),
                                    );
                                    let _ = session.send(&frame(MsgType::DeliverAck, &oldest));
                                }
                            }
                        }
                        // A duplicate delivery of an already-held blob changes
                        // nothing and stays unacked.
                        continue;
                    }

                    if env.version < version::END_TO_END_VERSION {
                        // Older version — including 0, the refused pre-version
                        // format: the rejection is recorded BEFORE the ack
                        // (ADR-0031/0034 crash ordering), then ack and drop,
                        // never reaching a handler.
                        fire_issue(
                            &issue_callbacks,
                            DeliveryIssue::Unreadable(UnreadableReason::SenderOutdated),
                        );
                        let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
                        continue;
                    }

                    // Supported version. Open the seal: decrypt, parse the
                    // sealed content and verify the author's signature over
                    // the full binding (version, recipient, ephemeral key,
                    // every sealed field) in one step (ADR-0031). Every
                    // failure is malformed.
                    let opened = env.open_sealed(my_noise_priv).and_then(|sc| {
                        Message::decode(&sc.message)
                            .map(|msg| (sc, msg))
                            .map_err(|_| crate::envelope::EnvelopeError::OpenFailed)
                    });
                    match opened {
                        Ok((sealed, msg)) => {
                            // The Replay Window (ADR-0031): a message whose
                            // signed Sender Timestamp is more than 60 days
                            // behind this device's clock is acked and dropped
                            // as `unreadable(expired)` (ADR-0034 §3) — it
                            // never reaches a handler. Future stamps are
                            // accepted; the dedup record clamps forward
                            // (ADR-0034 §2). Control messages are stamped at
                            // each seal, so an honest control is always fresh.
                            let now_ms = crate::operation_log::now_secs() * 1000;
                            if crate::envelope::is_expired(sealed.sender_timestamp_ms, now_ms) {
                                // Rejection recorded BEFORE the ack
                                // (ADR-0031/0034 crash ordering).
                                fire_issue(
                                    &issue_callbacks,
                                    DeliveryIssue::Unreadable(UnreadableReason::Expired),
                                );
                                let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
                                continue;
                            }

                            // ADR-0026 (superseding ADR-0020's ack-on-receipt):
                            // the DeliverAck leaves this device only after
                            // every handler has FINISHED with the Blob. The
                            // dispatch loop is serial, so handlers run one at
                            // a time, in arrival order; a handler that never
                            // finishes stalls delivery for this session (an
                            // accepted, documented trade-off — apps that want
                            // a timeout put one in their handler). The relay
                            // can observe handling latency; that metadata
                            // cost is documented in ADR-0026.
                            let cbs = callbacks.lock().unwrap_or_else(|e| e.into_inner());
                            for cb in cbs.iter() {
                                cb(
                                    msg.clone(),
                                    sealed.author_pub,
                                    sealed.sequence,
                                    sealed.sender_timestamp_ms,
                                );
                            }
                            drop(cbs);
                            let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
                        }
                        Err(_) => {
                            // Undecodable or unauthenticated: the library
                            // decided the Blob is unusable — report it
                            // (BEFORE the ack: ADR-0031/0034 crash ordering),
                            // then ack and drop (ADR-0026 step 3). Nothing
                            // but the DeliverAck ever leaves this device.
                            fire_issue(
                                &issue_callbacks,
                                DeliveryIssue::Unreadable(UnreadableReason::Malformed),
                            );
                            let _ = session.send(&frame(MsgType::DeliverAck, &blob_id));
                        }
                    }
                } else if let Some((MsgType::Heartbeat, _)) = parse(&raw) {
                    // The relay's echo of our Heartbeat (SYNC-16, relay
                    // ADR-0012): a liveness signal only — the receive
                    // thread already stamped it. The client NEVER echoes:
                    // the relay does not initiate Heartbeats (relay #13
                    // wontfix), and echoing its echoes would ping-pong
                    // without bound.
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
    // The disconnect signal fires from the DisconnectGuard on every exit
    // path, including a panic unwinding through an app callback.
}

// ── Convenience constructor for TCP connections ──────────────────────────────

use std::net::TcpStream;

impl RelayClient<TcpStream> {
    /// Connect to a relay over TCP at `addr`.
    ///
    /// Thin convenience over the connection factory (SYNC-17): the socket is
    /// opened by [`crate::connection::ConnectionFactory::open`], the only
    /// socket-open in production code. The stream is non-blocking before the
    /// Transport Version exchange, so a silent (pre-version) relay surfaces
    /// as a typed timeout (within the exchange deadline, 10 s) instead of
    /// hanging a blocking `read()` forever. Non-blocking is also the mode the
    /// FFI and CLI run every session in: a blocking receive would hold the
    /// session lock for the whole `read()` syscall and starve concurrent
    /// sends.
    ///
    /// WARNING (SYNC-6): a client connected this way has NO message handler
    /// registered — an inbound Deliver frame processed before a handler
    /// exists is acked and dropped, losing the message. Production paths
    /// must register the handler before the receive loop starts (the
    /// `connect` variants that take the handler up front, as `connect_full`
    /// and `connect_background` do). This convenience exists for tests and
    /// push-only clients.
    pub fn connect_tcp(
        addr: &str,
        relay_pub: NoisePublicKey,
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        let stream = crate::connection::ConnectionFactory::open(addr)
            .map_err(RelayError::ConnectionFailed)?;
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
    push_send_with_deadline(transport, relay_pub, blob, PUSH_SESSION_DEADLINE)
}

/// `push_send` with an explicit Push Session deadline — the seam the
/// SYNC-16 tests use; production gets ADR-0012's 30 s.
fn push_send_with_deadline<T: Read + Write + Send>(
    transport: T,
    relay_pub: [u8; 32],
    blob: Vec<u8>,
    deadline: std::time::Duration,
) -> Result<(), RelayError> {
    use trueseal_noise::keypair::generate_keypair;
    let fresh_kp = generate_keypair();
    let mut transport = transport;
    // Transport Version exchange first (ADR-0022); the prefix becomes the
    // Noise prologue. A refusal surfaces as RelayVersionUnsupported and the
    // outbox entry stays queued.
    let prologue = version::exchange_transport_version(&mut transport)?;
    // Bound the whole Push Session (relay ADR-0012: 30 s): handshake, push
    // and the Ack wait. A relay that accepts the push but never Acks must
    // resolve typed — the pump classifies PushFailed as temporary, backs
    // off and retries — instead of wedging the pump thread forever (B7
    // review note). The deadline stays armed until the session closes.
    let (transport, _push_deadline) = DeadlineConn::armed(transport, deadline);
    let session = trueseal_noise::session_nk::dial(transport, fresh_kp, relay_pub, &prologue)
        .map_err(RelayError::HandshakeFailed)?;
    session.send(&blob).map_err(RelayError::PushFailed)?;
    // Block until the relay confirms persistence (ADR-0019), bounded by
    // the Push Session deadline above.
    let raw = session
        .receive()
        .map_err(|e| RelayError::PushFailed(format!("expected Ack: {e}")))?;
    match parse(&raw) {
        Some((MsgType::Ack, _)) => {}
        Some((MsgType::Error, body)) => {
            return Err(RelayError::PushRejected(classify_refusal(body)))
        }
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

    impl super::Severable for MemPipe {
        /// Severing a MemPipe makes THIS end read EOF, like a socket
        /// shutdown — a parked receive thread exits instead of leaking.
        fn sever_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
            let closed = self.closed.clone();
            Arc::new(move || closed.store(true, std::sync::atomic::Ordering::Release))
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
                crate::operation_log::now_secs() * 1000,
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

    /// build_push_blob returns EnvelopeTooLarge when the serialised envelope
    /// cannot fit in one Noise frame (limits::MAX_ENVELOPE_BYTES, ADR-0025).
    /// This is the internal backstop for control messages; `Sync` bodies are
    /// refused earlier at the Protocol Size Limit in `send()`.
    #[test]
    fn build_push_blob_rejects_oversized_envelope() {
        let sender = DeviceKeypair::generate();
        let recipient = DeviceKeypair::generate();
        // A body at the Envelope limit always serialises over it (message tag
        // and encryption overhead are added on top).
        let huge_body = vec![0u8; MAX_ENVELOPE_BYTES];
        let msg = Message::Sync { body: huge_body };
        let result = build_push_blob(
            &msg,
            recipient.public_key(),
            1,
            vec![],
            &sender.signing_keypair(),
            1_000,
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
            1_000,
        )
        .expect("build_push_blob should succeed");

        let result = push_send(client_pipe, relay_pub, blob);
        assert!(
            matches!(
                result,
                Err(RelayError::PushRejected(RelayRefusal::Malformed {
                    code: None
                }))
            ),
            "a legacy reasonless Error body maps to permanent Malformed, got {:?}",
            result
        );
    }

    /// The relay's typed Error reason byte classifies at the push seam
    /// (relay ADR-0008, amended by RELAY-5): permanent codes never retry,
    /// temporary codes (bit 7 set) back off, and the legacy reasonless
    /// body keeps ADR-0026's documented untyped mapping.
    #[test]
    fn error_reason_byte_classifies_at_the_push_seam() {
        use crate::version::testutil::nk_accept_after_prefix as nk_accept;
        use trueseal_noise::keypair::generate_keypair;

        let cases: &[(&[u8], RelayRefusal)] = &[
            (&[0x01], RelayRefusal::TooLarge),
            (&[0x02], RelayRefusal::Malformed { code: Some(0x02) }),
            (&[0x81], RelayRefusal::Temporary { code: 0x81 }),
            (&[0x82], RelayRefusal::Temporary { code: 0x82 }),
            (&[0x83], RelayRefusal::Temporary { code: 0x83 }),
            (&[0x84], RelayRefusal::Temporary { code: 0x84 }),
            // Unknown codes classify by bit 7 alone (forward-compatible).
            (&[0x03], RelayRefusal::Malformed { code: Some(0x03) }),
            (&[0x85], RelayRefusal::Temporary { code: 0x85 }),
            (&[0xFF], RelayRefusal::Temporary { code: 0xFF }),
            // The legacy pre-RELAY-5 reasonless body: permanent, ADR-0026.
            (&[], RelayRefusal::Malformed { code: None }),
        ];
        for (body, expected) in cases {
            let relay_kp = generate_keypair();
            let relay_pub = relay_kp.public_key;
            let (client_pipe, relay_pipe) = mem_pipe_pair();
            let body = body.to_vec();
            let body_dbg = format!("{body:02x?}");
            std::thread::spawn(move || {
                let relay_kp2 =
                    trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_pub);
                let session = nk_accept(relay_pipe, relay_kp2).unwrap();
                let _ = session.receive(); // drain the Push
                let _ = session.send(&frame(MsgType::Error, &body));
            });

            let result = push_send(client_pipe, relay_pub, b"blob".to_vec());
            match result {
                Err(RelayError::PushRejected(refusal)) => assert_eq!(
                    &refusal, expected,
                    "Error body {body_dbg} must classify as {expected:?}"
                ),
                other => panic!("expected a typed refusal, got {other:?}"),
            }
        }
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
            let env = Envelope::build_sealed(
                1,
                vec![],
                recipient_pub,
                &sender_signing,
                crate::operation_log::now_secs() * 1000,
                &msg_to_deliver.encode(),
            );
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
        client.subscribe(move |msg, _author_pub, _seq, _ts| {
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
        client_a.subscribe(move |msg, _author_pub, _seq, _ts| {
            received_clone.lock().unwrap().push(msg);
        });
        // run loop starts automatically in connect()

        // B connects and pushes a Pair message addressed to A
        let client_b = connect_device(&device_b, relay_pub, pipe_b_client);
        let pair_msg = Message::Pair {
            noise_pub: device_b.public_key().0,
            signing_pub: device_b.signing_public_key().0,
            secret: [0u8; 32],
        };
        client_b
            .push(
                &pair_msg,
                NoisePublicKey(a_noise_pub),
                1,
                vec![],
                &device_b.signing_keypair(),
                crate::operation_log::now_secs() * 1000,
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
                secret: [0u8; 32],
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
        let mut env = Envelope::build_sealed(
            1,
            vec![],
            recipient.public_key(),
            &author,
            crate::operation_log::now_secs() * 1000,
            b"irrelevant",
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
        client.subscribe(move |msg, _author, _seq, _ts| {
            delivered_cb.lock().unwrap().push(msg);
        });
        (client, issues, delivered)
    }

    /// ADR-0026: the DeliverAck leaves this device only AFTER every handler
    /// has finished with the Blob — never on receipt. A handler that is
    /// still running (here: blocked on a channel) must hold the ack; the
    /// relay keeps the Blob and would re-deliver on a new session.
    /// Red before SYNC-5: the ack went out before decryption.
    #[test]
    fn deliver_ack_waits_for_the_handler() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay = spawn_deliver_relay(relay_pipe, relay_kp2);

        let device = DeviceKeypair::generate();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let client = RelayClient::connect(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        )
        .expect("connect");
        client.subscribe(move |_msg, _author, _seq, _ts| {
            // The handler blocks until the test releases it.
            release_rx.recv().ok();
        });

        let sender_signing = SigningKeypair::generate();
        let env = Envelope::build_sealed(
            1,
            vec![],
            device.public_key(),
            &sender_signing,
            crate::operation_log::now_secs() * 1000,
            &Message::Sync {
                body: b"hi".to_vec(),
            }
            .encode(),
        );
        relay.deliver(7, env.encode());

        // While the handler is blocked the relay must see NO DeliverAck —
        // the Blob is not yet handled, so it is not yet acknowledged.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            relay.deliver_acks().is_empty(),
            "no DeliverAck may leave the device while the handler is still running"
        );

        // Once the handler finishes, the ack goes out with the right blob id.
        release_tx.send(()).unwrap();
        assert!(
            wait_until(|| relay.deliver_acks().len() == 1, 2_000),
            "the ack follows the handler's completion"
        );
        assert_eq!(relay.deliver_acks()[0], 7u64.to_be_bytes());
        relay.assert_only_deliver_acks();
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
            let env = Envelope::build_sealed(
                1,
                vec![],
                recipient_pub,
                &sender_signing,
                crate::operation_log::now_secs() * 1000,
                &msg_to_deliver.encode(),
            );
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
            move |msg, _author, _seq, _ts| {
                delivered_cb.lock().unwrap().push(msg);
            },
            None,
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

    // ── SYNC-16: client heartbeat, deadlines and liveness (relay ADR-0012) ──

    /// A fake relay that accepts the XX session, then records every inbound
    /// frame type with its arrival time. `echo_heartbeats` mirrors the real
    /// relay (echo each Heartbeat; never initiates one — trueseal-relay ADR-0012).
    fn spawn_frame_recording_relay(
        relay_pipe: MemPipe,
        relay_keypair: Keypair,
        echo_heartbeats: bool,
    ) -> Arc<Mutex<Vec<(MsgType, std::time::Instant)>>> {
        let frames = Arc::new(Mutex::new(Vec::<(MsgType, std::time::Instant)>::new()));
        let frames_clone = frames.clone();
        std::thread::spawn(move || {
            let session = xx_accept_after_prefix(relay_pipe, relay_keypair).unwrap();
            while let Ok(raw) = session.receive() {
                if let Some((typ, _)) = parse(&raw) {
                    frames_clone
                        .lock()
                        .unwrap()
                        .push((typ, std::time::Instant::now()));
                    if typ == MsgType::Heartbeat && echo_heartbeats {
                        let _ = session.send(&frame(MsgType::Heartbeat, &[]));
                    }
                }
            }
        });
        frames
    }

    fn test_timeouts(heartbeat_ms: u64, liveness_ms: u64) -> SessionTimeouts {
        SessionTimeouts {
            heartbeat: std::time::Duration::from_millis(heartbeat_ms),
            liveness: std::time::Duration::from_millis(liveness_ms),
            handshake: std::time::Duration::from_millis(400),
        }
    }

    fn connect_with_timeouts(
        client_pipe: MemPipe,
        relay_pub: NoisePublicKey,
        device: &DeviceKeypair,
        timeouts: SessionTimeouts,
    ) -> RelayClient<MemPipe> {
        RelayClient::connect_subscribed_with_timeouts(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
            |_, _, _, _| {},
            None,
            timeouts,
        )
        .expect("connect should succeed")
    }

    /// The client sends a Heartbeat every `interval` on an idle Receive
    /// Session (relay ADR-0012: every 25 s in production).
    #[test]
    fn heartbeat_frames_arrive_at_the_configured_interval_while_idle() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let frames = spawn_frame_recording_relay(relay_pipe, relay_kp2, true);

        let device = DeviceKeypair::generate();
        let _client =
            connect_with_timeouts(client_pipe, relay_pub, &device, test_timeouts(40, 5_000));

        // At least 3 heartbeats within one second on an idle session.
        let ok = wait_until(
            || {
                frames
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(t, _)| *t == MsgType::Heartbeat)
                    .count()
                    >= 3
            },
            1_000,
        );
        assert!(
            ok,
            "an idle session should heartbeat at the configured interval"
        );

        // Cadence: consecutive heartbeats arrive roughly an interval apart.
        let beats: Vec<std::time::Instant> = frames
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t == MsgType::Heartbeat)
            .map(|(_, at)| *at)
            .collect();
        for pair in beats.windows(2) {
            let gap = pair[1] - pair[0];
            assert!(
                gap < std::time::Duration::from_millis(500),
                "heartbeat cadence broke down: gap {gap:?}"
            );
        }
    }

    /// The client must NOT echo the relay's echoes: the real relay echoes
    /// every inbound Heartbeat, so echoing inbound Heartbeats would
    /// ping-pong without bound. The relay's echo is a liveness signal only.
    #[test]
    fn client_does_not_echo_the_relays_heartbeat_echoes() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let frames = spawn_frame_recording_relay(relay_pipe, relay_kp2, true);

        let device = DeviceKeypair::generate();
        let _client =
            connect_with_timeouts(client_pipe, relay_pub, &device, test_timeouts(40, 5_000));

        let beat_count =
            |frames: &std::sync::Arc<std::sync::Mutex<Vec<(MsgType, std::time::Instant)>>>| {
                frames
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(t, _)| *t == MsgType::Heartbeat)
                    .count()
            };
        // Lower bound WITHOUT a fixed sleep (SYNC-19 flake sweep): wait for
        // the first beats however long startup takes on a loaded runner.
        assert!(
            wait_until(|| beat_count(&frames) >= 2, 5_000),
            "the client should heartbeat at the configured interval"
        );
        // Upper bound: over one more sampling window the count grows by
        // roughly one beat per interval (~10 in 400 ms). A ping-pong storm
        // would produce hundreds.
        let before = beat_count(&frames);
        std::thread::sleep(std::time::Duration::from_millis(400));
        let delta = beat_count(&frames) - before;
        assert!(
            delta <= 40,
            "expected roughly one heartbeat per interval, got {delta} in 400 ms — ping-pong?"
        );
    }

    /// A session with NO inbound frames for the liveness window is dead:
    /// the client severs it so the reconnect loop engages. Any inbound frame
    /// — not just heartbeat echoes — counts as liveness (the relay may
    /// legitimately drop echoes under Deliver saturation, trueseal-relay #47).
    #[test]
    fn silent_session_is_detected_dead_and_severed() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        // Accept the session, then NEVER send anything back (no echoes).
        let frames = spawn_frame_recording_relay(relay_pipe, relay_kp2, false);

        let device = DeviceKeypair::generate();
        let client = connect_with_timeouts(client_pipe, relay_pub, &device, test_timeouts(40, 300));

        assert!(
            wait_until(|| !client.is_connected(), 3_000),
            "a session with no inbound frame inside the liveness window must be severed"
        );
        // The client kept heartbeating until it gave up (the silence was
        // one-directional: the relay heard the client fine).
        assert!(
            frames
                .lock()
                .unwrap()
                .iter()
                .any(|(t, _)| *t == MsgType::Heartbeat),
            "the silent relay should still have observed client heartbeats"
        );
    }

    /// Inbound Deliver traffic keeps the session alive even with zero
    /// heartbeat echoes (any-frame liveness).
    #[test]
    fn inbound_frames_reset_the_liveness_window() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();

        // Relay that accepts, never echoes heartbeats, but sends a Deliver
        // every 100 ms for a while (any inbound frame = liveness).
        let (deliver_tx, deliver_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let session = xx_accept_after_prefix(relay_pipe, relay_kp2).unwrap();
            // A Deliver body needs a blob id + an envelope; the client will
            // fail to open it (malformed → issue + ack) — but it still
            // counts as an inbound frame for liveness.
            let body = frame(MsgType::Deliver, &[7u8; 16]);
            for _ in 0..10 {
                if deliver_rx.try_recv().is_ok() {
                    break;
                }
                if session.send(&body).is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });

        let device = DeviceKeypair::generate();
        let client = connect_with_timeouts(client_pipe, relay_pub, &device, test_timeouts(40, 300));

        // 700 ms of regular inbound frames with a 300 ms liveness window:
        // the session must still be alive at the end of the burst.
        std::thread::sleep(std::time::Duration::from_millis(700));
        assert!(
            client.is_connected(),
            "regular inbound frames (no echoes) must keep the session alive"
        );
        drop(deliver_tx);
    }

    // ── B23c: relay kill over REAL TCP (the D1 finding) ─────────────────────
    //
    // Every liveness test above runs over MemPipe, whose sever EOFs cleanly.
    // The D1 Swift task found that killing a REAL relay is never detected
    // (≥150 s, no Disconnected): a real dead TCP socket behaves differently —
    // a clean kill delivers FIN/RST, but a killed container / cable pull can
    // black-hole the connection (no FIN at all). These tests run the real
    // production transport (ConnectionFactory::open — a non-blocking
    // TcpStream) against a real TCP relay stand-in and kill it both ways.

    /// How the relay stand-in dies once told.
    enum KillMode {
        /// Drop the socket: the kernel delivers FIN (or RST with a heartbeat
        /// in flight) — a clean process kill.
        CleanKill,
        /// Leak the socket without closing: no FIN, no RST, silence — a
        /// killed container / pulled cable. The worst case for liveness:
        /// only the watchdog can notice.
        BlackHole,
    }

    /// A real-TCP relay stand-in: version exchange + XX accept, then echo
    /// heartbeats exactly like the real relay until `kill_rx` fires, then die
    /// per `mode`. Returns (addr, kill switch).
    fn spawn_tcp_relay(
        relay_kp: Keypair,
        mode: KillMode,
    ) -> (String, std::sync::mpsc::Sender<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind relay");
        let addr = listener.local_addr().expect("addr").to_string();
        let (kill_tx, kill_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            // The relay side blocks; the client side is non-blocking (the
            // production shape — ConnectionFactory sets non-blocking).
            let session = xx_accept_after_prefix(stream, relay_kp).expect("accept handshake");
            loop {
                if kill_rx.try_recv().is_ok() {
                    match mode {
                        KillMode::CleanKill => drop(session),
                        KillMode::BlackHole => std::mem::forget(session),
                    }
                    return;
                }
                match session.receive() {
                    Ok(raw) => {
                        if let Some((MsgType::Heartbeat, _)) = parse(&raw) {
                            if session.send(&frame(MsgType::Heartbeat, &[])).is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        (addr, kill_tx)
    }

    /// A client on the REAL production transport for the given relay address.
    fn tcp_client(
        addr: &str,
        relay_pub: NoisePublicKey,
        device: &DeviceKeypair,
    ) -> RelayClient<std::net::TcpStream> {
        let stream = crate::connection::ConnectionFactory::open(addr).expect("open");
        RelayClient::connect_subscribed_with_timeouts(
            stream,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
            |_, _, _, _| {},
            None,
            test_timeouts(100, 300),
        )
        .expect("connect")
    }

    /// Clean kill: the kernel delivers FIN/RST — the receive thread must
    /// surface it and the session must go down.
    #[test]
    fn relay_clean_kill_is_detected_over_real_tcp() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (addr, kill) = spawn_tcp_relay(relay_kp2, KillMode::CleanKill);

        let device = DeviceKeypair::generate();
        let client = tcp_client(&addr, relay_pub, &device);
        assert!(client.is_connected(), "session should be up pre-kill");
        // Let a heartbeat or two flow so the liveness stamp has moved.
        std::thread::sleep(std::time::Duration::from_millis(250));

        kill.send(()).expect("kill");
        assert!(
            wait_until(|| !client.is_connected(), 3_000),
            "a cleanly killed relay (FIN/RST) must be detected over real TCP"
        );
    }

    /// Black-hole kill: no FIN, no RST — the socket just goes silent. Only
    /// the liveness watchdog can notice: it must sever within the window.
    #[test]
    fn relay_blackhole_kill_is_detected_over_real_tcp() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (addr, kill) = spawn_tcp_relay(relay_kp2, KillMode::BlackHole);

        let device = DeviceKeypair::generate();
        let client = tcp_client(&addr, relay_pub, &device);
        assert!(client.is_connected(), "session should be up pre-kill");
        std::thread::sleep(std::time::Duration::from_millis(250));

        kill.send(()).expect("kill");
        assert!(
            wait_until(|| !client.is_connected(), 3_000),
            "a black-holed relay (no FIN) must be severed by the liveness watchdog"
        );
    }

    /// After the relay answers `0x01` (supported), a silent relay must not
    /// spin dial() forever: the Noise handshake is deadline-bounded
    /// (trueseal-noise RetryConn retries WouldBlock with no deadline —
    /// the bound is the client's job; relay ADR-0012: 10 s).
    #[test]
    fn handshake_after_supported_byte_is_deadline_bounded() {
        let (client_pipe, mut relay_pipe) = mem_pipe_pair();
        // Fake relay: complete the version exchange, then go silent.
        let relay_handle = std::thread::spawn(move || {
            crate::version::fake_relay_accept_prefix(&mut relay_pipe);
            // Never answer the handshake; keep the pipe open.
            std::thread::sleep(std::time::Duration::from_secs(30));
            relay_pipe
        });

        let relay_kp = generate_keypair();
        let device = DeviceKeypair::generate();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = RelayClient::connect_subscribed_with_timeouts(
                client_pipe,
                NoisePublicKey(relay_kp.public_key),
                Keypair::new(device.noise.private(), device.noise.public_key),
                |_, _, _, _| {},
                None,
                test_timeouts(25_000, 75_000), // handshake: 400 ms
            );
            let _ = result_tx.send(result.is_err());
        });

        let answered = result_rx.recv_timeout(std::time::Duration::from_secs(5));
        // Unstick the fake relay either way.
        drop(relay_handle);
        assert!(
            answered.is_ok(),
            "a silent post-0x01 relay must surface a handshake error, not spin forever"
        );
        assert!(answered.unwrap(), "the bounded handshake must fail typed");
    }

    /// A relay that accepts a Push but never Acks must not wedge the caller
    /// (B7 review note: a hung push_send wedges the outbox pump thread
    /// silently). The wait is bounded (relay ADR-0012: 30 s Push Session
    /// deadline) and resolves as a TEMPORARY failure (not PushRejected), so
    /// the pump backs off and retries.
    #[test]
    fn push_ack_wait_is_deadline_bounded_and_temporary() {
        let relay_kp = generate_keypair();
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let relay_handle = std::thread::spawn(move || {
            let session =
                crate::version::testutil::nk_accept_after_prefix(relay_pipe, relay_kp2).unwrap();
            // Receive the Push, then never Ack; keep the pipe open.
            let _ = session.receive();
            std::thread::sleep(std::time::Duration::from_secs(60));
        });

        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = push_send_with_deadline(
                client_pipe,
                relay_kp.public_key,
                b"blob".to_vec(),
                std::time::Duration::from_millis(500),
            );
            let _ = result_tx.send(result);
        });

        let answered = result_rx.recv_timeout(std::time::Duration::from_secs(10));
        drop(relay_handle);
        let result = answered.expect("a hung Ack wait must resolve, not wedge the pump forever");
        match result {
            Err(RelayError::PushRejected(_)) => {
                panic!("a missing Ack is temporary (retry), never a permanent refusal")
            }
            Err(_) => {}
            Ok(()) => panic!("no Ack ever arrived; push_send must not report success"),
        }
    }

    /// close() with the heartbeat active shuts down promptly: no zombie
    /// heartbeat thread, and the relay observes the session end.
    #[test]
    fn close_with_active_heartbeat_is_clean() {
        let relay_kp = generate_keypair();
        let relay_pub = NoisePublicKey(relay_kp.public_key);
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let frames = spawn_frame_recording_relay(relay_pipe, relay_kp2, true);

        let device = DeviceKeypair::generate();
        let client =
            connect_with_timeouts(client_pipe, relay_pub, &device, test_timeouts(40, 5_000));
        assert!(wait_until(
            || frames
                .lock()
                .unwrap()
                .iter()
                .any(|(t, _)| *t == MsgType::Heartbeat),
            1_000
        ));

        client.close();
        assert!(
            wait_until(|| !client.is_connected(), 1_000),
            "close() severs promptly with the heartbeat thread active"
        );
        // After close, no further heartbeats leave this client.
        let count_at_close = frames
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t == MsgType::Heartbeat)
            .count();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let count_later = frames
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t == MsgType::Heartbeat)
            .count();
        assert_eq!(count_at_close, count_later, "no heartbeats after close()");
    }
}
