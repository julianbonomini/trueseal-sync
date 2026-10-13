// FFI surface for Swift and Kotlin via UniFFI (proc-macro mode).
//
// The canonical TrueSeal API (ADR-0028, amended by ADR-0032 and ADR-0034):
// one `TrueSeal` entry type, one awaited async message handler, one event
// listener, one delivery-issue listener, the 14 typed errors, `close()`,
// Relay Address parsing, and the version/limits constants. Every SDK is a
// thin wrapper over this surface — behaviour lives in the core, not here.

use std::net::TcpStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::member::{member_id, member_name};
use crate::message::Message;
use crate::relay_address::RelayAddress as ParsedRelayAddress;
use crate::session::{
    ConnectionChange, ExitReason, GroupStatus as CoreGroupStatus, SessionError as CoreSessionError,
    TruesealSession,
};
use crate::store::{PersistentLog, Store};

// ── Errors ─────────────────────────────────────────────────────────────────────

/// The canonical error set (ADR-0028 as amended by ADR-0032 and SYNC-15):
/// exactly these 14 cases cross the FFI. There is no catch-all; a store
/// failure is never reported as `invalidNamespace`.
///
/// All 14 cases are named in `docs/api-surface.json` for the G12 parity
/// check, with a test keeping that file in lockstep with this enum.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TrueSealError {
    /// The Relay Address string is malformed (ADR-0028). Nothing was dialed.
    #[error("invalid relay address: {msg}")]
    InvalidRelayAddress { msg: String },
    /// The namespace is empty or outside `[a-zA-Z0-9_-]+`.
    #[error("invalid namespace: {msg}")]
    InvalidNamespace { msg: String },
    /// A durable write failed — the operation did not commit and no
    /// in-memory state changed. The caller may retry.
    #[error("storage failure: {msg}")]
    Storage { msg: String },
    /// The object was closed (`close()`, ADR-0028). Every call after
    /// `close()` fails with this; Session State is kept on disk.
    #[error("closed")]
    Closed,
    /// The operation needs group membership the device does not currently
    /// hold — sending while `notJoined`, `pendingJoin`, `leaving` or
    /// `destroying`, for example (ADR-0026/0027/0029). Carries the status
    /// the call saw.
    #[error("not a member (status: {status:?})")]
    NotMember { status: GroupStatus },
    /// `join()` while this device already holds a Group Manifest — one
    /// Sync Group per namespace (ADR-0023).
    #[error("already in a group")]
    AlreadyInGroup,
    /// The Pairing Token is malformed or predates the Pairing Secret
    /// (ADR-0023).
    #[error("invalid pairing token")]
    InvalidPairingToken,
    /// The Pairing Window is closed, or the Join Request ID is unknown
    /// (an unaccepted request disappears when the window closes,
    /// ADR-0023). Also: admission attempted while `leaving` or from a
    /// view that excludes the local device.
    #[error("pairing window is closed")]
    PairingClosed,
    /// The admission would exceed the Maximum Group Size (ADR-0027).
    /// The Pairing Window stays open.
    #[error("group is full: maximum {max} members")]
    GroupFull { max: u32 },
    /// No member with that ID in the current manifest.
    #[error("member not found")]
    MemberNotFound,
    /// The `Sync` body exceeds the payload limit (ADR-0025). The body was
    /// never queued and no Sequence was consumed. Permanent — a retry
    /// with the same body fails the same way.
    #[error("payload too large: maximum {max} bytes")]
    PayloadTooLarge { max: u32 },
    /// A second `onMessage` registration (ADR-0026: one handler).
    #[error("message handler already set")]
    MessageHandlerAlreadySet,
    /// The store was written by a newer release (a rollback) and is
    /// refused, unmodified — upgrade the SDK (ADR-0032).
    #[error("store was written by a newer release (store version {found}; this build supports up to {supported})")]
    StoreTooNew { found: u32, supported: u32 },
    /// The group's manifest version space is exhausted (the next version
    /// could never be accepted — ADR-0027, SYNC-10). The group's Devices
    /// must pair again. (14th case, added by SYNC-15 with the ADR-0028
    /// amendment — the ADR's list predates SYNC-10.)
    #[error("manifest version exhausted: the group must re-pair")]
    ManifestVersionExhausted,
}

/// Map a core error onto the canonical taxonomy. `status` is the Group
/// Status the caller observed, for the `notMember{status}` cases.
fn map_core_error(e: CoreSessionError, status: GroupStatus) -> TrueSealError {
    match e {
        CoreSessionError::InvalidToken => TrueSealError::InvalidPairingToken,
        CoreSessionError::AlreadyInGroup => TrueSealError::AlreadyInGroup,
        CoreSessionError::MemberNotFound => TrueSealError::MemberNotFound,
        CoreSessionError::GroupFull { max } => TrueSealError::GroupFull { max },
        CoreSessionError::PayloadTooLarge { max } => TrueSealError::PayloadTooLarge { max },
        CoreSessionError::ManifestVersionExhausted => TrueSealError::ManifestVersionExhausted,
        CoreSessionError::Closed => TrueSealError::Closed,
        CoreSessionError::NotInGroup => TrueSealError::NotMember { status },
        CoreSessionError::GroupDestroyed => TrueSealError::NotMember { status },
        CoreSessionError::Store(msg) => TrueSealError::Storage { msg },
        // Unreachable from the canonical surface: keypair bytes never cross
        // the FFI, and since the delivery contract (SYNC-5) every send is a
        // durable queue write — the background pump owns dialing, so
        // connection/push failures and the Transport Version refusal reach
        // the app as connection events and delivery issues, never here.
        other => {
            log::error!("[trueseal-sync] unexpected core error on the FFI surface: {other}");
            TrueSealError::Storage {
                msg: format!("internal: {other}"),
            }
        }
    }
}

// ── State enums ───────────────────────────────────────────────────────────────

/// Where the local Device stands in its namespace's Sync Group (ADR-0023,
/// ADR-0027, ADR-0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum GroupStatus {
    /// No Group Manifest and no Pending Join.
    NotJoined,
    /// Asked to join via a Pairing Token; waiting to be admitted.
    PendingJoin,
    /// Holds a Group Manifest.
    Member,
    /// Issued a Leave; waiting for the Relay to accept every push of it
    /// (ADR-0027).
    Leaving,
    /// Started or received Destroy Group; waiting for the Relay to accept
    /// every queued Revoke (ADR-0029).
    Destroying,
}

impl From<CoreGroupStatus> for GroupStatus {
    fn from(s: CoreGroupStatus) -> Self {
        match s {
            CoreGroupStatus::NotJoined => GroupStatus::NotJoined,
            CoreGroupStatus::PendingJoin => GroupStatus::PendingJoin,
            CoreGroupStatus::Member => GroupStatus::Member,
            CoreGroupStatus::Leaving => GroupStatus::Leaving,
            CoreGroupStatus::Destroying => GroupStatus::Destroying,
        }
    }
}

/// Why the status changed (ADR-0028). `statusChanged` fires only for the
/// asynchronous transitions — the ones the caller could not otherwise
/// observe; the synchronous ones (`join` → `pendingJoin`, `leave` →
/// `leaving`, `destroyGroup` → `destroying`) are knowable from the call
/// itself and the `status` getter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum StatusReason {
    /// This device created the group (its admission produced the genesis
    /// manifest).
    Created,
    /// This device was admitted — its Pending Join's first manifest
    /// arrived (ADR-0023).
    Joined,
    /// The device's own Leave completed (ADR-0027).
    Left,
    /// Another member removed this device (ADR-0027).
    Removed,
    /// Destroy Group completed (ADR-0029).
    Destroyed,
    /// The store was unmigratable and automatically reset (ADR-0032).
    StoreReset,
}

/// The relay link state (ADR-0028 `connection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    /// Never connected since `open()`. The library connects in the
    /// background; this is the initial value of the `connection` getter,
    /// never an event.
    Connecting,
    /// The Receive Session is up.
    Connected,
    /// The Receive Session dropped; the library reconnects automatically.
    Disconnected,
    /// The Relay refused our Transport Version and reported the range it
    /// supports (ADR-0022). The outbox stays queued and the library keeps
    /// retrying in case the Relay is upgraded.
    RelayVersionUnsupported { min: u32, max: u32 },
}

impl From<ConnectionChange> for ConnectionState {
    fn from(c: ConnectionChange) -> Self {
        match c {
            ConnectionChange::Connected => ConnectionState::Connected,
            ConnectionChange::Disconnected => ConnectionState::Disconnected,
            ConnectionChange::RelayVersionUnsupported { min, max } => {
                ConnectionState::RelayVersionUnsupported { min, max }
            }
        }
    }
}

// ── Value types ───────────────────────────────────────────────────────────────

/// A group member (ADR-0028). `id` is stable and opaque, derived from the
/// member's signing public key; `name` is auto-generated from the key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Member {
    pub id: String,
    pub name: String,
}

/// A delivered `Sync` message (ADR-0026, ADR-0031).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TrueSealMessage {
    /// Stable, opaque, derived from the author's signing key and the
    /// Envelope Sequence. The same across relay re-delivery; a caller sees
    /// it twice only if it crashed while handling the message.
    pub id: String,
    /// The sending member. `from.id` is the same identifier as in
    /// `members` (ADR-0028).
    pub from: Member,
    /// The raw application payload.
    pub body: Vec<u8>,
}

/// The admitter's view of a Pair that proved knowledge of the Pairing
/// Secret (ADR-0023). Pass `id` back to `accept()` to admit the device.
/// An unaccepted request disappears when the Pairing Window closes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JoinRequest {
    pub id: String,
    pub name: String,
}

/// The typed form of a Relay Address (ADR-0028). `open()` accepts either
/// this or the string form.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RelayAddress {
    pub host: String,
    /// The relay's 32-byte X25519 public key.
    pub public_key: Vec<u8>,
    pub receive_port: u16,
    pub push_port: u16,
}

/// Version triple reported by every TrueSeal SDK (ADR-0022, ADR-0030).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TruesealInfo {
    pub sdk_version: String,
    pub transport_version: u32,
    pub end_to_end_version: u32,
}

// ── Events ────────────────────────────────────────────────────────────────────

/// Why an admission was dropped during membership convergence (ADR-0027).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AdmissionDropReason {
    /// Re-applying the admission would exceed the Maximum Group Size.
    GroupFull,
}

/// The single event sum type (ADR-0028, as amended by ADR-0032). Delivered
/// to every registered `onEvent` listener; events raised before the first
/// listener registers are buffered and flushed to it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TrueSealEvent {
    /// An asynchronous group-status transition (see [`StatusReason`] for
    /// why synchronous transitions raise no event).
    StatusChanged {
        status: GroupStatus,
        reason: StatusReason,
    },
    /// The whole current member list, not a delta (ADR-0027: membership
    /// events can flicker while concurrent changes settle).
    MembersChanged { members: Vec<Member> },
    /// A device requested to join inside the open Pairing Window
    /// (ADR-0023).
    JoinRequest { request: JoinRequest },
    /// The relay link transitioned.
    ConnectionChanged { connection: ConnectionState },
    /// A Pending Membership Change re-application was dropped
    /// (ADR-0027). The joiner stays in Pending Join.
    AdmissionDropped {
        name: String,
        reason: AdmissionDropReason,
    },
}

// ── Delivery issues ───────────────────────────────────────────────────────────

/// Why an incoming Blob was rejected as unreadable (ADR-0034 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UnreadableReason {
    /// Undecodable or unauthenticated bytes — including the refused
    /// pre-version format.
    Malformed,
    /// The Blob carries an older End-to-End Version than this build
    /// supports — the one reason an app can act on ("a device needs an
    /// update").
    SenderOutdated,
    /// The message is older than the Replay Window.
    Expired,
    /// The oldest held newer-version Blob, dropped when the hold cap
    /// overflowed (ADR-0022).
    DroppedWhileHeld,
}

/// Why the library gave up sending an outgoing message (ADR-0034 §3).
/// Every reason is permanent — the message is never retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SendFailedReason {
    /// The entry exceeds the Protocol Size Limit (ADR-0025).
    TooLarge,
    /// The Relay permanently refused the push (ADR-0026).
    Malformed,
    /// A `Sync` entry still undelivered 30 days after `send()`.
    Expired,
}

/// A typed, device-local report that the library could not deliver or
/// handle a message (ADR-0026/0034). Never sent to the other Device or the
/// Relay. Observing issues is optional; the library already does the right
/// thing. There is deliberately no `undeliverableAfterUpgrade` case
/// (withdrawn by ADR-0034 — an upgrade re-seals the outbox instead).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryIssue {
    /// An incoming Blob was rejected and will never reach a handler.
    Unreadable { reason: UnreadableReason },
    /// An authenticated-but-unacceptable control message (an over-bound
    /// manifest jump, an unknown issuer, ...). Acked and dropped
    /// (ADR-0034 §3).
    Unauthorized,
    /// A Blob carries a newer End-to-End Version than this build supports;
    /// it is held unacked on the Relay (up to the cap) so an upgrade
    /// recovers it (ADR-0022).
    HeldForUpgrade { version: u32 },
    /// The app's message handler failed on all 5 attempts; the Blob was
    /// acked and dropped (ADR-0026).
    HandlerGaveUp { message_id: String, error: String },
    /// An outgoing message was dropped without delivery. `message_id` is
    /// the ID `send()` returned.
    SendFailed {
        message_id: String,
        reason: SendFailedReason,
    },
}

impl DeliveryIssue {
    /// Route a core issue onto the canonical surface: `admissionDropped`
    /// is an EVENT in ADR-0028's list, so it never reaches this stream.
    fn from_core(issue: crate::delivery_issue::DeliveryIssue) -> Option<Self> {
        use crate::delivery_issue as core;
        match issue {
            core::DeliveryIssue::Unreadable(reason) => Some(DeliveryIssue::Unreadable {
                reason: match reason {
                    core::UnreadableReason::Malformed => UnreadableReason::Malformed,
                    core::UnreadableReason::SenderOutdated => UnreadableReason::SenderOutdated,
                    core::UnreadableReason::Expired => UnreadableReason::Expired,
                    core::UnreadableReason::DroppedWhileHeld => UnreadableReason::DroppedWhileHeld,
                },
            }),
            core::DeliveryIssue::Unauthorized => Some(DeliveryIssue::Unauthorized),
            core::DeliveryIssue::HeldForUpgrade(v) => {
                Some(DeliveryIssue::HeldForUpgrade { version: v })
            }
            core::DeliveryIssue::HandlerGaveUp { message_id, error } => {
                Some(DeliveryIssue::HandlerGaveUp { message_id, error })
            }
            core::DeliveryIssue::SendFailed { message_id, reason } => {
                Some(DeliveryIssue::SendFailed {
                    message_id,
                    reason: match reason {
                        core::SendFailedReason::TooLarge => SendFailedReason::TooLarge,
                        core::SendFailedReason::Malformed => SendFailedReason::Malformed,
                        core::SendFailedReason::Expired => SendFailedReason::Expired,
                    },
                })
            }
            // Routed to the event stream by the caller — never delivered here.
            core::DeliveryIssue::AdmissionDropped { .. } => None,
        }
    }
}

// ── Callback interfaces ───────────────────────────────────────────────────────

/// Thrown by the message handler to mark a delivery attempt failed
/// (ADR-0026): the library retries 5 times with backoff, then acks, drops
/// and reports `handlerGaveUp`. The Blob is acked only after the handler
/// completes successfully.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HandlerError {
    #[error("message handler failed: {msg}")]
    Failed { msg: String },
}

/// THE message handler (ADR-0026/0028): one per object; registering it
/// starts receiving. Async and awaited — the DeliverAck leaves the device
/// only after it completes.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait TrueSealMessageHandler: Send + Sync {
    async fn on_message(&self, message: TrueSealMessage) -> Result<(), HandlerError>;
}

/// Receives [`TrueSealEvent`]s (ADR-0028). Any number of listeners.
#[uniffi::export(callback_interface)]
pub trait TrueSealEventListener: Send + Sync {
    fn on_event(&self, event: TrueSealEvent);
}

/// Receives [`DeliveryIssue`]s (ADR-0026). Any number of listeners;
/// optional — the library already does the right thing.
#[uniffi::export(callback_interface)]
pub trait TrueSealIssueListener: Send + Sync {
    fn on_delivery_issue(&self, issue: DeliveryIssue);
}

// ── Subscription ──────────────────────────────────────────────────────────────

/// The cancel handle returned by every `on…` registration (ADR-0028).
/// `cancel()` unregisters the listener; idempotent.
#[derive(uniffi::Object)]
pub struct Subscription {
    cancel: Mutex<Option<Box<dyn Fn() + Send + Sync + 'static>>>,
}

#[uniffi::export]
impl Subscription {
    pub fn cancel(&self) {
        let f = self.cancel.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(f) = f {
            f();
        }
    }
}

// ── Listener bus ──────────────────────────────────────────────────────────────

/// A buffered multi-listener bus (ADR-0028: "Events raised before the
/// first listener is registered are buffered"). The buffer is one-shot: it
/// flushes to the FIRST listener, so a report reaches the app exactly once
/// even across reloads (same semantics as the core's issue sink, SYNC-5).
struct ListenerBus<T: Clone + Send + 'static> {
    state: Mutex<ListenerBusState<T>>,
}

/// Cap on buffered pre-listener events (SYNC-15 gate F5): a listener-less
/// app against a flapping relay would otherwise grow this buffer forever
/// (~2 connection events per minute, plus membership churn). Overflow drops
/// the OLDEST buffered events and warns with the running dropped count —
/// the buffer exists to deliver startup transitions, not to be a log.
const MAX_BUFFERED_EVENTS: usize = 1024;

struct ListenerBusState<T: Clone + Send + 'static> {
    pending: Vec<T>,
    listeners: Vec<(u64, Arc<dyn Fn(T) + Send + Sync + 'static>)>,
    next_id: u64,
    dropped: u64,
}

impl<T: Clone + Send + 'static> ListenerBus<T> {
    fn new() -> Self {
        Self {
            state: Mutex::new(ListenerBusState {
                pending: Vec::new(),
                listeners: Vec::new(),
                next_id: 0,
                dropped: 0,
            }),
        }
    }

    /// Fire an event: to every listener, or into the buffer when none are
    /// registered yet. Listeners fire under the lock and must not re-enter.
    fn fire(&self, event: T) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.listeners.is_empty() {
            if st.pending.len() >= MAX_BUFFERED_EVENTS {
                st.pending.remove(0);
                st.dropped += 1;
                log::warn!(
                    "[trueseal-sync] event buffer full ({MAX_BUFFERED_EVENTS}); dropped the oldest buffered event ({} dropped so far — register a listener to drain)",
                    st.dropped
                );
            }
            st.pending.push(event);
            return;
        }
        for (_, listener) in &st.listeners {
            listener(event.clone());
        }
    }

    /// Register a listener; buffered events flush to the first one.
    /// Returns the subscription id.
    fn subscribe(&self, listener: Arc<dyn Fn(T) + Send + Sync + 'static>) -> u64 {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.listeners.is_empty() {
            for event in st.pending.drain(..) {
                listener(event);
            }
        }
        let id = st.next_id;
        st.next_id += 1;
        st.listeners.push((id, listener));
        id
    }

    fn unsubscribe(&self, id: u64) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .listeners
            .retain(|(lid, _)| *lid != id);
    }
}

// ── Message handler gating ────────────────────────────────────────────────────

/// Registration-gated handler slot (ADR-0026: "receiving starts when a
/// handler is registered"). Until a handler exists, the receive-side
/// closure WAITS — the Blob is not acked, not dropped, and the relay
/// re-delivers on reconnect, exactly as with a hung handler (accepted and
/// documented in ADR-0026). The wait is interruptible by `close()`.
struct HandlerSlot {
    handler: Option<Arc<dyn TrueSealMessageHandler>>,
    registered_once: bool,
    closed: bool,
}

// ── TrueSeal ──────────────────────────────────────────────────────────────────

/// The canonical TrueSeal object (ADR-0028). One per namespace. Created
/// via `TrueSeal.open(...)`; connects in the background; `send()` works
/// immediately (durably queued, ADR-0026). The object outlives group
/// membership: after removal, leave or Destroy Group it reports
/// `notJoined` with the reason and can pair again.
#[derive(uniffi::Object)]
pub struct TrueSeal {
    inner: TruesealSession<TcpStream>,
    /// Mirrors `inner.is_closed()`; gates every FFI call with `closed` and
    /// releases a parked handler wait.
    closed: Arc<AtomicBool>,
    handler_slot: Arc<(Mutex<HandlerSlot>, Condvar)>,
    events: Arc<ListenerBus<TrueSealEvent>>,
    issues: Arc<ListenerBus<DeliveryIssue>>,
    /// The last status an event was reported for, so a manifest that
    /// arrives while already a member raises `membersChanged` only.
    last_status: Arc<Mutex<GroupStatus>>,
    /// Cached connection state for the `connection` getter (starts
    /// `connecting`; updated by the core's connection callback).
    connection: Arc<Mutex<ConnectionState>>,
}

#[uniffi::export]
impl TrueSeal {
    /// Open a session on `namespace` (default `"default"`) with state under
    /// `base_dir`, connecting to the relay named by `relay` — a Relay
    /// Address string, `trueseal://<relay public key hex>@host[:port][?push=port]`
    /// (ADR-0028; use [`TrueSeal::open_with_address`] for the typed form).
    ///
    /// Returns before the connection is up; the relay connects in the
    /// background and the outbox delivers as soon as it does. `send()`
    /// works immediately.
    ///
    /// `max_payload_bytes` lowers the payload limit (e.g. to match a
    /// stricter relay); it can never exceed the Protocol Size Limit
    /// (ADR-0025). The option is creation-time by design: the limit is a
    /// property of how the app deploys, not something to mutate mid-flight.
    #[uniffi::constructor]
    pub fn open(
        relay: String,
        base_dir: String,
        namespace: Option<String>,
        max_payload_bytes: Option<u32>,
    ) -> Result<Arc<Self>, TrueSealError> {
        let address = ParsedRelayAddress::parse(&relay)
            .map_err(|e| TrueSealError::InvalidRelayAddress { msg: e.0 })?;
        Self::open_parsed(address, base_dir, namespace, max_payload_bytes)
    }

    /// [`Self::open`] with the typed Relay Address form (ADR-0028).
    #[uniffi::constructor]
    pub fn open_with_address(
        relay: RelayAddress,
        base_dir: String,
        namespace: Option<String>,
        max_payload_bytes: Option<u32>,
    ) -> Result<Arc<Self>, TrueSealError> {
        let key: [u8; 32] = relay.public_key.as_slice().try_into().map_err(|_| {
            TrueSealError::InvalidRelayAddress {
                msg: format!(
                    "relay public key must be 32 bytes, got {}",
                    relay.public_key.len()
                ),
            }
        })?;
        let address = ParsedRelayAddress {
            host: relay.host,
            public_key: crate::keys::NoisePublicKey(key),
            receive_port: relay.receive_port,
            push_port: relay.push_port,
        };
        Self::open_parsed(address, base_dir, namespace, max_payload_bytes)
    }

    /// The group status (ADR-0028 `status`).
    pub fn status(&self) -> Result<GroupStatus, TrueSealError> {
        self.check_open()?;
        Ok(self.inner.group_status().into())
    }

    /// This device as a `Member` (ADR-0028 `me`) — the same `id` and
    /// `name` other members see.
    pub fn me(&self) -> Result<Member, TrueSealError> {
        self.check_open()?;
        let signing = self.inner.signing_pub();
        Ok(Member {
            id: member_id(&signing),
            name: member_name(&signing),
        })
    }

    /// Every other current member (ADR-0028 `members`). Empty when not in
    /// a group.
    pub fn members(&self) -> Result<Vec<Member>, TrueSealError> {
        self.check_open()?;
        Ok(self
            .inner
            .members()
            .into_iter()
            .map(|m| Member {
                id: m.id,
                name: m.name,
            })
            .collect())
    }

    /// The relay link state (ADR-0028 `connection`).
    pub fn connection(&self) -> Result<ConnectionState, TrueSealError> {
        self.check_open()?;
        Ok(*self.connection.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Register THE message handler; registration starts receiving
    /// (ADR-0026). The handler is async and awaited — a Blob is acked only
    /// after it completes. A second registration fails with
    /// `messageHandlerAlreadySet`; cancelling the returned Subscription
    /// unregisters the handler (receiving waits again).
    pub fn on_message(
        &self,
        handler: Box<dyn TrueSealMessageHandler>,
    ) -> Result<Arc<Subscription>, TrueSealError> {
        self.check_open()?;
        let (lock, cvar) = &*self.handler_slot;
        {
            let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            if slot.registered_once {
                return Err(TrueSealError::MessageHandlerAlreadySet);
            }
            slot.handler = Some(Arc::from(handler));
            slot.registered_once = true;
        }
        cvar.notify_all();
        let slot = self.handler_slot.clone();
        Ok(Arc::new(Subscription {
            cancel: Mutex::new(Some(Box::new(move || {
                let (lock, cvar) = &*slot;
                lock.lock().unwrap_or_else(|e| e.into_inner()).handler = None;
                // Wake the waiter so it re-parks on the empty slot instead
                // of holding a stale handler.
                cvar.notify_all();
            }))),
        }))
    }

    /// Queue `body` for fan-out to every group member (ADR-0026). Returns
    /// the Message ID once the message is durably in the outbox — delivery
    /// continues in the background; a permanent failure arrives as a
    /// `sendFailed` delivery issue carrying the same ID.
    ///
    /// Fails immediately with `payloadTooLarge{max}` (ADR-0025) or
    /// `notMember{status}`.
    pub fn send(&self, body: Vec<u8>) -> Result<String, TrueSealError> {
        self.check_open()?;
        self.inner
            .push_sync(body)
            .map_err(|e| map_core_error(e, self.status_now()))
    }

    /// Open a Pairing Window and return the Pairing Token (ADR-0023).
    /// Requests arrive as `joinRequest` events; the window closes on the
    /// first `accept()`, on `cancelPairing()`, or on process end. Fails
    /// `notMember{destroying}` while Destroying (ADR-0029) and
    /// `notMember{pendingJoin}` while a Pending Join is held (ADR-0023).
    pub fn start_pairing(&self) -> Result<String, TrueSealError> {
        self.check_open()?;
        self.inner
            .pairing_token()
            .map_err(|e| map_core_error(e, self.status_now()))
    }

    /// Admit the device behind a `joinRequest` event (ADR-0023). Fails
    /// with `pairingClosed` (window closed or unknown request),
    /// `groupFull{max}` (ADR-0027), `notMember{status}` while Leaving /
    /// Destroying / PendingJoin, or `manifestVersionExhausted` (SYNC-10).
    pub fn accept(&self, request_id: String) -> Result<(), TrueSealError> {
        self.check_open()?;
        let result = self.inner.accept_member(&request_id);
        match result {
            Ok(true) => {
                *self.last_status.lock().unwrap_or_else(|e| e.into_inner()) =
                    self.inner.group_status().into();
                Ok(())
            }
            // The request is gone (window closed, unknown id) or this
            // device's state admits no one (leaving; a view that excludes
            // it) — ADR-0023 sends no decline, so the typed answer is
            // `pairingClosed` for the former and `notMember` for the rest.
            Ok(false) => match self.inner.group_status() {
                CoreGroupStatus::Leaving | CoreGroupStatus::Destroying => {
                    Err(TrueSealError::NotMember {
                        status: self.status_now(),
                    })
                }
                _ => Err(TrueSealError::PairingClosed),
            },
            Err(e) => Err(map_core_error(e, self.status_now())),
        }
    }

    /// Close the Pairing Window without admitting anyone.
    pub fn cancel_pairing(&self) -> Result<(), TrueSealError> {
        self.check_open()?;
        self.inner.cancel_pairing();
        Ok(())
    }

    /// Join the group a Pairing Token names (ADR-0023): moves to
    /// `pendingJoin` and durably queues the Pair. Fails with
    /// `invalidPairingToken` or `alreadyInGroup`.
    pub fn join(&self, token: String) -> Result<(), TrueSealError> {
        self.check_open()?;
        self.inner
            .join_group(&token)
            .map_err(|e| map_core_error(e, self.status_now()))?;
        *self.last_status.lock().unwrap_or_else(|e| e.into_inner()) = GroupStatus::PendingJoin;
        Ok(())
    }

    /// Abandon a Pending Join (ADR-0023).
    pub fn cancel_join(&self) -> Result<(), TrueSealError> {
        self.check_open()?;
        self.inner.cancel_join();
        *self.last_status.lock().unwrap_or_else(|e| e.into_inner()) = GroupStatus::NotJoined;
        Ok(())
    }

    /// Remove a member by their `Member.id` (Soft Removal, ADR-0027).
    pub fn remove(&self, member_id: String) -> Result<(), TrueSealError> {
        self.check_open()?;
        self.inner
            .remove_member_by_id(&member_id)
            .map_err(|e| map_core_error(e, self.status_now()))
    }

    /// Leave the Sync Group (ADR-0027): moves to `leaving`; when the Relay
    /// has accepted every push of the excluding manifest, the device wipes
    /// and rotates and reports `statusChanged(notJoined, left)`.
    pub fn leave(&self) -> Result<(), TrueSealError> {
        self.check_open()?;
        self.inner
            .leave_group()
            .map_err(|e| map_core_error(e, self.status_now()))?;
        *self.last_status.lock().unwrap_or_else(|e| e.into_inner()) = GroupStatus::Leaving;
        Ok(())
    }

    /// Destroy the group (ADR-0029): durable, forwarded Revoke; the device
    /// stays `destroying` until the Relay has accepted every Revoke, then
    /// wipes, rotates and reports `statusChanged(notJoined, destroyed)`.
    /// No-op while already Destroying.
    pub fn destroy_group(&self) -> Result<(), TrueSealError> {
        self.check_open()?;
        self.inner
            .destroy_group()
            .map_err(|e| map_core_error(e, self.status_now()))?;
        *self.last_status.lock().unwrap_or_else(|e| e.into_inner()) = GroupStatus::Destroying;
        Ok(())
    }

    /// Register an event listener (ADR-0028). Any number; events raised
    /// before the first listener registers are buffered and flushed to it.
    /// Listeners fire under the bus lock (same rule as the core's sinks):
    /// they must not call back into this object synchronously.
    pub fn on_event(
        &self,
        listener: Box<dyn TrueSealEventListener>,
    ) -> Result<Arc<Subscription>, TrueSealError> {
        self.check_open()?;
        let listener: Arc<dyn TrueSealEventListener> = Arc::from(listener);
        let id = self
            .events
            .subscribe(Arc::new(move |e| listener.on_event(e)));
        let bus = self.events.clone();
        Ok(Arc::new(Subscription {
            cancel: Mutex::new(Some(Box::new(move || bus.unsubscribe(id)))),
        }))
    }

    /// Register a delivery-issue listener (ADR-0026). Optional. Listeners
    /// fire under the bus lock and must not call back into this object
    /// synchronously.
    pub fn on_delivery_issue(
        &self,
        listener: Box<dyn TrueSealIssueListener>,
    ) -> Result<Arc<Subscription>, TrueSealError> {
        self.check_open()?;
        let listener: Arc<dyn TrueSealIssueListener> = Arc::from(listener);
        let id = self
            .issues
            .subscribe(Arc::new(move |i| listener.on_delivery_issue(i)));
        let bus = self.issues.clone();
        Ok(Arc::new(Subscription {
            cancel: Mutex::new(Some(Box::new(move || bus.unsubscribe(id)))),
        }))
    }

    /// Stop the connection and the handlers; keep Session State
    /// (ADR-0028). After `close()`, every call fails with `closed` —
    /// except `close()` itself, which is idempotent. In-flight handlers
    /// run to completion; their Blobs stay unacked and are re-delivered on
    /// the next `open()` (at-least-once, ADR-0026).
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        // ORDER MATTERS (SYNC-15 gate, F2's happens-before): the core's
        // shutdown flag FIRST — it never blocks on the receive thread —
        // then release a handler wait parked on "no handler registered".
        // In the reverse order a woken waiter could reach the dispatch's
        // shutdown guard before the flag was set, and the dedup record
        // would commit for a delivery whose handler never ran.
        self.inner.close();
        {
            let (lock, cvar) = &*self.handler_slot;
            lock.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
            cvar.notify_all();
        }
    }
}

/// The internal constructor both `open` entry points share.
impl TrueSeal {
    fn open_parsed(
        address: ParsedRelayAddress,
        base_dir: String,
        namespace: Option<String>,
        max_payload_bytes: Option<u32>,
    ) -> Result<Arc<Self>, TrueSealError> {
        let namespace = namespace.unwrap_or_else(|| "default".to_string());
        if namespace.is_empty()
            || !namespace
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(TrueSealError::InvalidNamespace {
                msg: format!("namespace must match [a-zA-Z0-9_-]+ (got {namespace:?})"),
            });
        }

        let (store, open_outcome) =
            Store::open_with_outcome(Path::new(&base_dir), &namespace).map_err(map_store_error)?;
        let keypair = load_or_generate_keypair(&store)?;

        // SYNC-7 (#99): the manifest slot is created and seeded from the
        // store BEFORE the session (and its reconnect loop) starts, so the
        // receive path never observes a transient `None`.
        let manifest: Arc<Mutex<Option<crate::manifest::GroupManifest>>> =
            Arc::new(Mutex::new(store.load_group_manifest().ok().flatten()));

        let log_store = Store::open(Path::new(&base_dir), &namespace).map_err(map_store_error)?;
        let manifest_store = Arc::new(Mutex::new(
            Store::open(Path::new(&base_dir), &namespace).map_err(map_store_error)?,
        ));
        let rotate_store = Arc::new(Mutex::new(
            Store::open(Path::new(&base_dir), &namespace).map_err(map_store_error)?,
        ));

        let events: Arc<ListenerBus<TrueSealEvent>> = Arc::new(ListenerBus::new());
        let issues: Arc<ListenerBus<DeliveryIssue>> = Arc::new(ListenerBus::new());
        let last_status = Arc::new(Mutex::new(GroupStatus::NotJoined));
        let connection: Arc<Mutex<ConnectionState>> =
            Arc::new(Mutex::new(ConnectionState::Connecting));
        let handler_slot = Arc::new((
            Mutex::new(HandlerSlot {
                handler: None,
                registered_once: false,
                closed: false,
            }),
            Condvar::new(),
        ));
        let closed = Arc::new(AtomicBool::new(false));

        // The core message hook: control messages are handled inside the
        // core; only `Sync` bodies reach here. The closure WAITS for a
        // registered handler (ADR-0026: receiving starts on registration)
        // and converts a foreign-side failure into a failed handler
        // attempt (the core's 5-attempts-then-handlerGaveUp loop catches
        // the panic). The wait releases on close().
        let on_message = {
            let handler_slot = handler_slot.clone();
            move |msg: Message, author_signing_pub: [u8; 32], sequence: u64| {
                let Message::Sync { body } = msg else {
                    return;
                };

                let message = TrueSealMessage {
                    id: crate::message::message_id(&author_signing_pub, sequence),
                    from: Member {
                        id: member_id(&crate::keys::SigningPublicKey(author_signing_pub)),
                        name: member_name(&crate::keys::SigningPublicKey(author_signing_pub)),
                    },
                    body,
                };
                let (lock, cvar) = &*handler_slot;
                let handler = loop {
                    let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(h) = &slot.handler {
                        break h.clone();
                    }
                    if slot.closed {
                        // Closed while waiting: abandon the Blob unacked —
                        // the relay re-delivers on the next open (ADR-0026).
                        return;
                    }
                    let (guard, _timeout) = cvar
                        .wait_timeout(slot, Duration::from_millis(50))
                        .unwrap_or_else(|e| e.into_inner());
                    slot = guard;
                };
                if let Err(e) = futures::executor::block_on(handler.on_message(message)) {
                    // A failed handler attempt (ADR-0026 step 4): the core
                    // retries with backoff and eventually reports
                    // handlerGaveUp with this message.
                    panic!("message handler failed: {e}");
                }
            }
        };

        let on_removed_from_group = || {
            // The statusChanged(notJoined, removed) event is emitted by the
            // identity-rotation hook below, which carries the reason; this
            // hook stays a no-op on the canonical surface.
        };

        // The manifest's issuer tells Created from Joined with no flag and
        // no race: a genesis (or any manifest) this device issued carries
        // its own signing key (SYNC-15 gate F7).
        let self_signing_pub = keypair.signing_public_key();
        let on_manifest_changed = {
            let events = events.clone();
            let last_status = last_status.clone();
            move |m: &crate::manifest::GroupManifest| {
                // Persist first: the store is the crash-recovery record
                // (SYNC-7); a save failure is logged, not swallowed (B13
                // review note) — the in-memory manifest still advances.
                if let Err(e) = manifest_store
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .save_group_manifest(m)
                {
                    log::error!("[trueseal-sync] failed to persist the group manifest: {e}");
                }
                let members: Vec<Member> = m
                    .members
                    .iter()
                    .map(|mm| Member {
                        id: member_id(&mm.signing_pub),
                        name: member_name(&mm.signing_pub),
                    })
                    .collect();
                // A member-status event only makes sense on an ENTRY into
                // membership — from NotJoined (a local genesis: Created) or
                // PendingJoin (an admission: Joined). A Leaving or
                // Destroying device still applies inbound manifests (its
                // view must stay current until the wipe), but it is not
                // joining anything (SYNC-15 gate): no spurious `joined`.
                let mut last = last_status.lock().unwrap_or_else(|e| e.into_inner());
                if matches!(*last, GroupStatus::NotJoined | GroupStatus::PendingJoin) {
                    let reason = if m.issued_by == self_signing_pub.0 {
                        StatusReason::Created
                    } else {
                        StatusReason::Joined
                    };
                    *last = GroupStatus::Member;
                    events.fire(TrueSealEvent::StatusChanged {
                        status: GroupStatus::Member,
                        reason,
                    });
                }
                events.fire(TrueSealEvent::MembersChanged { members });
            }
        };

        let on_group_destroyed = || {
            // Covered by the identity-rotation hook (reason Destroyed).
        };

        let on_identity_rotated = {
            let events = events.clone();
            let last_status = last_status.clone();
            let manifest_slot = manifest.clone();
            move |fresh: DeviceKeypair, reason: ExitReason| {
                // The namespace's store is wiped (manifest, identity,
                // outbox, dedup, pending records) and the fresh keypair
                // persisted, so a restart opens as the rotated device.
                // This runs mid-wipe, inside the crash window — the durable
                // work is done here, inline, on purpose. Failures are
                // logged loudly, never swallowed (B13 review note): the
                // durable Leaving/Destroying record survives a failed wipe,
                // so the next open retries the completion.
                let store = rotate_store.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = store.wipe() {
                    log::error!("[trueseal-sync] store wipe during identity rotation failed: {e}");
                }
                if let Err(e) = store.save_keypair(&fresh) {
                    log::error!("[trueseal-sync] persisting the rotated identity failed: {e}");
                }
                // The events fire once the wipe has SETTLED (the manifest
                // slot clears right after this callback returns), so the
                // `status` getter never contradicts a `statusChanged` the
                // app already received. Bounded poll: if the settle never
                // comes the events fire anyway rather than being lost.
                let events = events.clone();
                let last_status = last_status.clone();
                let slot = manifest_slot.clone();
                std::thread::spawn(move || {
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while std::time::Instant::now() < deadline {
                        if slot.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    *last_status.lock().unwrap_or_else(|e| e.into_inner()) = GroupStatus::NotJoined;
                    events.fire(TrueSealEvent::MembersChanged { members: vec![] });
                    events.fire(TrueSealEvent::StatusChanged {
                        status: GroupStatus::NotJoined,
                        reason: match reason {
                            ExitReason::Removed => StatusReason::Removed,
                            ExitReason::Left => StatusReason::Left,
                            ExitReason::Destroyed => StatusReason::Destroyed,
                        },
                    });
                });
            }
        };

        // SYNC-17 (#109): sockets are opened only by the connection factory,
        // so a future IP-hiding transport (roadmap#26) is one local change.
        let (receive_factory, push_factory) =
            crate::connection::ConnectionFactory::new(
                address.receive_addr(),
                address.push_addr(),
            )
            .into_factories();

        let on_connection_changed = {
            let events = events.clone();
            let connection = connection.clone();
            move |change: ConnectionChange| {
                let state = ConnectionState::from(change);
                *connection.lock().unwrap_or_else(|e| e.into_inner()) = state;
                events.fire(TrueSealEvent::ConnectionChanged { connection: state });
            }
        };

        let inner = TruesealSession::connect_background_rotating(
            address.public_key,
            keypair,
            on_message,
            Box::new(PersistentLog::new(log_store)),
            manifest,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            on_identity_rotated,
            receive_factory,
            push_factory,
            None, // default 30-second reconnect cap
            Some(Box::new(on_connection_changed)),
        )
        .map_err(|e| map_core_error(e, GroupStatus::NotJoined))?;

        // Receive-path and session Delivery Issues forward into the FFI
        // issue bus — except `admissionDropped`, which ADR-0028 lists as an
        // EVENT, so it routes to the event bus here.
        {
            let issues = issues.clone();
            let events = events.clone();
            inner.subscribe_delivery_issues(move |issue| {
                if let crate::delivery_issue::DeliveryIssue::AdmissionDropped { name, .. } = &issue
                {
                    events.fire(TrueSealEvent::AdmissionDropped {
                        name: name.clone(),
                        reason: AdmissionDropReason::GroupFull,
                    });
                    return;
                }
                if let Some(mapped) = DeliveryIssue::from_core(issue) {
                    issues.fire(mapped);
                }
            });
        }
        // Join Requests arrive through the core's buffered member-request
        // sink; they are events on the canonical surface.
        {
            let events = events.clone();
            inner.set_on_member_request(move |token, name| {
                events.fire(TrueSealEvent::JoinRequest {
                    request: JoinRequest { id: token, name },
                });
            });
        }

        *last_status.lock().unwrap_or_else(|e| e.into_inner()) = inner.group_status().into();

        if let Some(max) = max_payload_bytes {
            // Clamped at the Protocol Size Limit inside the core (ADR-0025).
            inner.set_max_payload_bytes(max as usize);
        }

        let session = Arc::new(Self {
            inner,
            closed,
            handler_slot,
            events,
            issues,
            last_status,
            connection,
        });

        // ADR-0032: report the automatic Store Reset as
        // `statusChanged(notJoined, storeReset)` once the object exists.
        // Events are buffered until the first listener registers, so the
        // app cannot miss it by registering after open().
        if open_outcome.reset {
            session.events.fire(TrueSealEvent::StatusChanged {
                status: GroupStatus::NotJoined,
                reason: StatusReason::StoreReset,
            });
        }

        Ok(session)
    }

    fn check_open(&self) -> Result<(), TrueSealError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TrueSealError::Closed);
        }
        Ok(())
    }

    fn status_now(&self) -> GroupStatus {
        self.inner.group_status().into()
    }
}

// ── Module-level functions ────────────────────────────────────────────────────

/// The version triple for this build (ADR-0022 Reporting): the two
/// protocol versions come from the core constants — the single source of
/// truth. Package versions imply nothing about wire compatibility.
#[uniffi::export]
pub fn trueseal_info() -> TruesealInfo {
    TruesealInfo {
        sdk_version: env!("CARGO_PKG_VERSION").to_string(),
        transport_version: crate::version::TRANSPORT_VERSION,
        end_to_end_version: crate::version::END_TO_END_VERSION,
    }
}

/// The Protocol Size Limit (61,440 bytes, ADR-0025): the largest `Sync`
/// body any device may send. `maxPayloadBytes` in the canonical API.
#[uniffi::export]
pub fn trueseal_max_payload_bytes() -> u32 {
    crate::limits::PROTOCOL_SIZE_LIMIT as u32
}

/// The Maximum Group Size (32, ADR-0027). `maxGroupSize` in the canonical
/// API.
#[uniffi::export]
pub fn trueseal_max_group_size() -> u32 {
    crate::session::MAX_GROUP_SIZE as u32
}

/// Parse a Relay Address string into its typed form (ADR-0028), so SDKs
/// can validate or display one without opening a session.
#[uniffi::export]
pub fn trueseal_parse_relay_address(input: String) -> Result<RelayAddress, TrueSealError> {
    let parsed = ParsedRelayAddress::parse(&input)
        .map_err(|e| TrueSealError::InvalidRelayAddress { msg: e.0 })?;
    Ok(RelayAddress {
        host: parsed.host,
        public_key: parsed.public_key.0.to_vec(),
        receive_port: parsed.receive_port,
        push_port: parsed.push_port,
    })
}

// ── Storage helpers ───────────────────────────────────────────────────────────

/// Map a store failure to the typed taxonomy (ADR-0028): a newer store is
/// `storeTooNew`; anything else is the `storage` case — never
/// `invalidNamespace`.
fn map_store_error(e: crate::store::StoreError) -> TrueSealError {
    match e {
        crate::store::StoreError::StoreTooNew { found, supported } => {
            TrueSealError::StoreTooNew { found, supported }
        }
        other => TrueSealError::Storage {
            msg: format!("store: {other}"),
        },
    }
}

/// Load the identity keypair from `store`, or generate and persist a fresh one.
fn load_or_generate_keypair(store: &Store) -> Result<DeviceKeypair, TrueSealError> {
    match store.load_keypair() {
        Ok(Some(kp)) => Ok(kp),
        Ok(None) => {
            let kp = DeviceKeypair::generate();
            store.save_keypair(&kp).map_err(map_store_error)?;
            Ok(kp)
        }
        Err(e) => Err(map_store_error(e)),
    }
}

#[cfg(test)]
mod tests;
