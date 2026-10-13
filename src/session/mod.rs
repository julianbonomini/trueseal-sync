mod reconnect;
mod sender;
#[cfg(test)]
mod test_helpers;
#[cfg(test)]
mod tests;

use std::any::Any;
use std::collections::HashMap;
use std::net::TcpStream;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use log::warn;
use thiserror::Error;
use trueseal_noise::keypair::Keypair as NoiseKeypair;

use crate::delivery_issue::{DeliveryIssue, SendFailedReason, UnreadableReason};
use crate::device::DeviceKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::limits::PROTOCOL_SIZE_LIMIT;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::{member_id, member_name};
use crate::message::{device_name, message_id, Message};
use crate::operation_log::{now_secs, MemLog, OperationLog};
use crate::relay::RelayClient;

const DEFAULT_RECONNECT_CAP: Duration = Duration::from_secs(30);

// ── Public types ──────────────────────────────────────────────────────────────

/// A remote group member as seen by this session.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    /// Stable opaque identifier derived from the member's signing public key.
    pub id: String,
    /// Auto-generated human-readable name derived from the member's signing public key.
    pub name: String,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid keypair bytes")]
    InvalidKeypairBytes,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("push failed: {0}")]
    PushFailed(String),
    #[error("not in any group — set a manifest first")]
    NotInGroup,
    #[error("invalid pairing token")]
    InvalidToken,
    #[error("member not found in current manifest")]
    MemberNotFound,
    #[error("group has been destroyed")]
    GroupDestroyed,
    /// The relay refused our Transport Version (ADR-0022). Outbox entries
    /// stay queued; the relay (or this client) must be upgraded.
    #[error("relay supports Transport Version {min}..={max}")]
    RelayVersionUnsupported { min: u32, max: u32 },
    /// The `Sync` body exceeds this session's payload limit — at most the
    /// Protocol Size Limit of 61,440 bytes (ADR-0025). Checked
    /// synchronously in `send()`: the body never entered the Outbox and no
    /// Sequence was consumed. Permanent — a retry with the same body fails
    /// the same way.
    #[error("payload too large: maximum {max} bytes")]
    PayloadTooLarge { max: u32 },
    /// The current manifest's version cannot be incremented — issuing would
    /// produce `u64::MAX`, which receivers reject because it can never be
    /// incremented (SYNC-10, ADR-0027). Checked arithmetic: no panic, no
    /// wrap. Membership is exhausted; the group's Devices must pair again.
    #[error("manifest version exhausted: cannot issue a new version")]
    ManifestVersionExhausted,
    /// `join_group` while a manifest exists — one Sync Group per namespace
    /// (ADR-0023). (`alreadyInGroup` in ADR-0028's error list.)
    #[error("already in a group")]
    AlreadyInGroup,
    /// A durable write failed (B8 review F3). The operation did not commit:
    /// no in-memory state was changed, and the caller may retry. Without
    /// surfacing this, a failed `begin_pending_join` would leave a join
    /// hanging forever in PendingJoin with its Pair never queued.
    #[error("store write failed: {0}")]
    Store(String),
    /// The admission would exceed the Maximum Group Size (32, ADR-0027;
    /// `groupFull{max}` in ADR-0028's error list). Refused locally before
    /// anything is issued; the Pairing Window stays open.
    #[error("group is full: maximum {max} members")]
    GroupFull { max: u32 },
    /// The session was closed (`close()`, ADR-0028): the connection and
    /// the handlers are stopped, Session State is kept, and every later
    /// call fails with this. (`closed` in ADR-0028's error list.)
    #[error("session is closed")]
    Closed,
}

/// The Maximum Group Size: 32 members (ADR-0027; `maxGroupSize` in
/// ADR-0028). An admission beyond it is refused locally with
/// [`SessionError::GroupFull`], and a Pending Membership Change
/// re-application that would exceed it is dropped with
/// [`DeliveryIssue::AdmissionDropped`] — the joiner stays in Pending Join.
pub const MAX_GROUP_SIZE: usize = 32;

/// Where the local Device stands in its namespace's Sync Group (ADR-0023,
/// ADR-0027, ADR-0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupStatus {
    /// No Group Manifest and no Pending Join. No manifest is accepted and
    /// every `Sync`/`Revoke` is dropped.
    NotJoined,
    /// Asked to join via a Pairing Token; waiting to be admitted. Only a
    /// first manifest anchored to the token's signing key is accepted.
    PendingJoin,
    /// Holds a Group Manifest.
    Member,
    /// Issued a manifest excluding the local Device and waiting for the
    /// Relay to accept every push of it; then the device wipes its group
    /// state, rotates its identity and returns to `NotJoined` (ADR-0027).
    /// Survives restarts. A Leaving device does not send `Sync` and does
    /// not run handlers.
    Leaving,
    /// Started or received Destroy Group and waiting for the Relay to
    /// accept every queued Revoke; then the device wipes its group state,
    /// rotates its identity and returns to `notJoined` (ADR-0029).
    /// Survives restarts. A Destroying device sends no `Sync`, runs no
    /// handlers and stays connected.
    Destroying,
}

impl From<crate::relay::RelayError> for SessionError {
    fn from(e: crate::relay::RelayError) -> Self {
        match e {
            crate::relay::RelayError::RelayVersionUnsupported { min, max } => {
                SessionError::RelayVersionUnsupported { min, max }
            }
            other => SessionError::ConnectionFailed(other.to_string()),
        }
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

/// An open pairing window — present means open, absent means closed.
/// Lifetime is caller-controlled: open on `pairing_token()`, closed on
/// `accept_pair()` (single-use), explicit `cancel_pairing()`, or process
/// end (ADR-0021, ADR-0023).
///
/// Carries this window's single-use Pairing Secret: a `Pair` must prove
/// knowledge of it, so the Relay — which never sees the Pairing Token —
/// cannot raise a Join Request. In memory only: a restart spends the
/// secret (ADR-0023 rejected persisting the window).
pub(super) struct PairingWindow {
    secret: [u8; 32],
}

impl PairingWindow {
    fn is_open(&self) -> bool {
        true
    }
}

/// Constant-time equality for Pairing Secrets. The comparison result is
/// not observable to the Relay (the secret travels inside addressed
/// encryption), but pairing code should not grow a timing side channel.
fn secret_matches(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// The joiner's durable record that it asked to join via a specific
/// Pairing Token and is waiting to be admitted (ADR-0023). Persisted in
/// Session State alongside the queued `Pair`, in one transaction. Has no
/// timer; ends when a valid first manifest arrives or the caller cancels.
///
/// Encoding: `initiator_noise(32) || initiator_signing(32) || secret(32)`.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PendingJoin {
    pub initiator_noise_pub: NoisePublicKey,
    pub initiator_signing_pub: SigningPublicKey,
    pub secret: [u8; 32],
}

impl PendingJoin {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&self.initiator_noise_pub.0);
        out.extend_from_slice(&self.initiator_signing_pub.0);
        out.extend_from_slice(&self.secret);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }
        Some(Self {
            initiator_noise_pub: NoisePublicKey(bytes[0..32].try_into().ok()?),
            initiator_signing_pub: SigningPublicKey(bytes[32..64].try_into().ok()?),
            secret: bytes[64..96].try_into().ok()?,
        })
    }
}

/// A Pending Membership Change (ADR-0027): a membership change its issuer
/// keeps until the group's manifest reflects it (satisfied) or a deliberate
/// later change supersedes it. A concurrent manifest that overwrites it is
/// answered by re-applying the change on top, `W.version + 1`; that
/// manifest becomes the change's new `carrier`.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PendingChange {
    pub intent: PendingIntent,
    /// Hash of the manifest that currently carries this change.
    pub carrier: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum PendingIntent {
    /// "D is a member."
    Admit(ManifestMember),
    /// "X is not a member."
    Remove(SigningPublicKey),
    /// "The local Device is not a member" (a Leave in flight).
    Leave,
}

impl PendingChange {
    /// Is this change already reflected by manifest `m`?
    fn satisfied_by(&self, m: &GroupManifest, self_signing: &SigningPublicKey) -> bool {
        match &self.intent {
            PendingIntent::Admit(member) => m.contains_signing_pub(&member.signing_pub.0),
            PendingIntent::Remove(sp) => !m.contains_signing_pub(&sp.0),
            PendingIntent::Leave => !m.contains_signing_pub(&self_signing.0),
        }
    }

    /// Encoding: count(u32 LE) || per change: kind(u8) || signing_pub(32)
    /// || (admit only: noise_pub(32) || name_len(u16 LE) || name) ||
    /// carrier(32). Session-owned, versioned by the End-to-End clean break.
    fn encode_set(changes: &[PendingChange]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(changes.len() as u32).to_le_bytes());
        for c in changes {
            match &c.intent {
                PendingIntent::Admit(m) => {
                    out.push(0u8);
                    out.extend_from_slice(&m.signing_pub.0);
                    out.extend_from_slice(&m.noise_pub.0);
                    out.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
                    out.extend_from_slice(m.name.as_bytes());
                }
                PendingIntent::Remove(sp) => {
                    out.push(1u8);
                    out.extend_from_slice(&sp.0);
                }
                PendingIntent::Leave => {
                    out.push(2u8);
                    out.extend_from_slice(&[0u8; 32]);
                }
            }
            out.extend_from_slice(&c.carrier);
        }
        out
    }

    fn decode_set(bytes: &[u8]) -> Option<Vec<PendingChange>> {
        fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            if rest.len() < n {
                return None;
            }
            let (head, tail) = rest.split_at(n);
            *rest = tail;
            Some(head)
        }
        let mut rest = bytes;
        let count = u32::from_le_bytes(take(&mut rest, 4)?.try_into().ok()?) as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = take(&mut rest, 1)?[0];
            let signing_pub = SigningPublicKey(take(&mut rest, 32)?.try_into().ok()?);
            let intent = match kind {
                0 => {
                    let noise_pub = NoisePublicKey(take(&mut rest, 32)?.try_into().ok()?);
                    let name_len =
                        u16::from_le_bytes(take(&mut rest, 2)?.try_into().ok()?) as usize;
                    let name = String::from_utf8(take(&mut rest, name_len)?.to_vec()).ok()?;
                    PendingIntent::Admit(ManifestMember {
                        noise_pub,
                        signing_pub,
                        name,
                    })
                }
                1 => PendingIntent::Remove(signing_pub),
                2 => PendingIntent::Leave,
                _ => return None,
            };
            let carrier: [u8; 32] = take(&mut rest, 32)?.try_into().ok()?;
            out.push(PendingChange { intent, carrier });
        }
        if !rest.is_empty() {
            return None;
        }
        Some(out)
    }
}

/// The persisted Leaving record (ADR-0027): the outbox refs the Leave waits
/// on. The Leave completes when every referenced entry has been accepted by
/// the Relay (delivered rows are deleted, ADR-0026) — then the device wipes
/// and rotates. Encoding: count(u16 LE) || refs of (object_id(32) ||
/// sequence(u64 LE)).
#[derive(Debug, Clone, PartialEq)]
pub(super) struct LeavingRecord {
    pub refs: Vec<([u8; 32], u64)>,
}

impl LeavingRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.refs.len() as u16).to_le_bytes());
        for (oid, seq) in &self.refs {
            out.extend_from_slice(oid);
            out.extend_from_slice(&seq.to_le_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let count = u16::from_le_bytes(bytes[0..2].try_into().ok()?) as usize;
        let mut rest = &bytes[2..];
        let mut refs = Vec::with_capacity(count);
        for _ in 0..count {
            if rest.len() < 40 {
                return None;
            }
            let oid: [u8; 32] = rest[0..32].try_into().ok()?;
            let seq = u64::from_le_bytes(rest[32..40].try_into().ok()?);
            refs.push((oid, seq));
            rest = &rest[40..];
        }
        if !rest.is_empty() {
            return None;
        }
        Some(Self { refs })
    }
}

/// The persisted Destroying record (ADR-0029): the outbox refs the Destroy
/// waits on — one queued Revoke per recipient in the destroying device's
/// own member view. The Destroy completes when every referenced entry has
/// been accepted by the Relay (delivered rows are deleted, ADR-0026) —
/// then the device wipes, rotates its identity and reports
/// `notJoined(destroyed)`. Same encoding as the Leaving record.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct DestroyingRecord {
    pub refs: Vec<([u8; 32], u64)>,
}

impl DestroyingRecord {
    fn encode(&self) -> Vec<u8> {
        LeavingRecord {
            refs: self.refs.clone(),
        }
        .encode()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        LeavingRecord::decode(bytes).map(|r| Self { refs: r.refs })
    }
}

/// Load and decode the persisted Pending Membership Changes (ADR-0027).
/// A corrupt record fails closed — treated as empty (no re-applications).
fn load_pending_changes(op_log: &Arc<Mutex<Box<dyn OperationLog>>>) -> Vec<PendingChange> {
    let log = op_log.lock().unwrap_or_else(|e| e.into_inner());
    match log.pending_membership_changes() {
        None => Vec::new(),
        Some(bytes) => PendingChange::decode_set(&bytes).unwrap_or_else(|| {
            warn!("[trueseal-sync] undecodable Pending Membership Change record — starting empty");
            Vec::new()
        }),
    }
}

/// Load and decode the persisted Leaving record (ADR-0027).
fn load_leaving(op_log: &Arc<Mutex<Box<dyn OperationLog>>>) -> Option<LeavingRecord> {
    let log = op_log.lock().unwrap_or_else(|e| e.into_inner());
    log.leaving()
        .and_then(|bytes| LeavingRecord::decode(&bytes))
}

/// Load and decode the persisted Destroying record (ADR-0029).
/// A corrupt record fails closed — absent — and the wipe completion check
/// simply never fires; the queued Revokes still replay from the outbox.
fn load_destroying(op_log: &Arc<Mutex<Box<dyn OperationLog>>>) -> Option<DestroyingRecord> {
    let log = op_log.lock().unwrap_or_else(|e| e.into_inner());
    log.destroying()
        .and_then(|bytes| DestroyingRecord::decode(&bytes))
}

/// All mutable key material — replaced atomically on key rotation.
///
/// TODO(P4): `noise_priv` and `signing_priv` are plain byte arrays and are NOT
/// zeroized on drop. An attacker with process-memory read access could extract
/// the private keys from heap. Fix: derive `zeroize::ZeroizeOnDrop` on this
/// struct (add `zeroize` crate feature `zeroize_derive`, wrap fields in
/// `Zeroizing<[u8;32]>`). Low urgency on current platforms (iOS/macOS sandbox
/// provides OS-level memory protection), but expected by any security audit.
pub(super) struct KeyState {
    pub noise_priv: [u8; 32],
    pub noise_pub_key: [u8; 32],
    pub signing_priv: [u8; 32],
    pub noise_pub: NoisePublicKey,
    pub signing_pub: SigningPublicKey,
}

impl KeyState {
    pub fn from_keypair(kp: &DeviceKeypair) -> Self {
        Self {
            noise_priv: kp.noise.private(),
            noise_pub_key: kp.noise.public_key,
            signing_priv: kp.signing.to_bytes(),
            noise_pub: kp.public_key(),
            signing_pub: kp.signing_public_key(),
        }
    }
}

/// A pending member request — stored while waiting for `accept_member(token)`.
pub(super) struct PendingMember {
    pub noise_pub: NoisePublicKey,
    pub signing_pub: SigningPublicKey,
}

/// A relay-link transition (ADR-0028's `connection`, event form). The
/// steady "never connected yet" state (`connecting`) is the FFI getter's
/// initial value, not an event: the library connects in the background
/// from construction, and the first observable transition is `Connected`
/// or `RelayVersionUnsupported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionChange {
    /// The Receive Session is up.
    Connected,
    /// The Receive Session dropped; the library reconnects automatically.
    Disconnected,
    /// The Relay refused our Transport Version and reported the range it
    /// supports (ADR-0022). Every outbox entry stays queued and the
    /// library keeps retrying in case the Relay is upgraded. Surfaced as
    /// the `relayVersionUnsupported{min,max}` connection state, not an
    /// error (ADR-0028).
    RelayVersionUnsupported { min: u32, max: u32 },
}

/// Session-side Delivery Issue channel (ADR-0034 §3).
///
/// The load-time reports of ADR-0025 fire during construction, before any
/// subscriber can exist, so issues fired with no subscribers are buffered
/// and flushed to the first subscriber; issues fired after subscription go
/// to every subscriber. The buffer is one-shot — it drains on the first
/// subscribe, and the dropped entries are gone from the log — so a report
/// still reaches the app exactly once across reloads.
pub(super) struct IssueSink {
    pending: Vec<DeliveryIssue>,
    callbacks: Vec<Box<dyn Fn(DeliveryIssue) + Send + 'static>>,
}

impl IssueSink {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            callbacks: Vec::new(),
        }
    }

    /// Fire an issue: to every subscriber, or into the buffer when there are
    /// none yet. As elsewhere in this module, callbacks fire under the lock
    /// and must not re-enter session methods.
    fn fire(&mut self, issue: DeliveryIssue) {
        if self.callbacks.is_empty() {
            self.pending.push(issue);
            return;
        }
        for cb in &self.callbacks {
            cb(issue.clone());
        }
    }

    /// Register a subscriber. The first subscriber immediately receives
    /// everything buffered since construction; later subscribers see only
    /// issues fired after they register.
    fn subscribe(&mut self, callback: Box<dyn Fn(DeliveryIssue) + Send + 'static>) {
        if self.callbacks.is_empty() {
            for issue in self.pending.drain(..) {
                callback(issue);
            }
        }
        self.callbacks.push(callback);
    }
}

/// A buffered member-event sink (ADR-0026 recipient step 1: "Member events
/// are buffered until their handlers exist").
///
/// The member-event callbacks register AFTER construction (`set_on_member_*`),
/// so a Pair or manifest that arrives in the construction window would
/// previously queue state but never fire the event (the old TODO(P6)). Now
/// events fired before registration are buffered and flushed to the first
/// registered handler — receiving starts on handler registration without
/// losing anything.
pub(super) struct EventSink {
    pending: Vec<(String, String)>,
    callback: Option<Box<dyn Fn(String, String) + Send + Sync>>,
}

impl EventSink {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            callback: None,
        }
    }

    /// Fire an event: to the registered handler, or into the buffer when
    /// none is registered yet. As elsewhere in this module, the callback
    /// fires under the lock and must not re-enter session methods.
    fn fire(&mut self, id: String, name: String) {
        match &self.callback {
            Some(cb) => cb(id, name),
            None => self.pending.push((id, name)),
        }
    }

    /// Register the handler; buffered events flush to it immediately.
    fn set_callback(&mut self, cb: Box<dyn Fn(String, String) + Send + Sync>) {
        for (id, name) in self.pending.drain(..) {
            cb(id, name);
        }
        self.callback = Some(cb);
    }
}

/// Handler attempts before the library gives up on a Blob (ADR-0026
/// recipient step 4): 5 attempts in total with in-memory backoff between
/// them, then ack + drop + `handlerGaveUp`. The dispatch loop is serial,
/// so the backoff stalls this session's delivery — by design.
const MAX_HANDLER_ATTEMPTS: u32 = 5;
const HANDLER_BACKOFF: [Duration; 4] = [
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
];

/// Map a failed manifest verification to its Delivery Issue (ADR-0034
/// §2/§3, SYNC-5):
///
/// - Regression (an older or identical version) is BENIGN STALE: a relay
///   re-delivery, a hostile-relay replay, or the loser of concurrent
///   issuance (ADR-0027 orders by (version, hash)). Replays of control
///   messages must be harmless AND unreported — every resend would
///   otherwise spam the issue stream. → no issue.
/// - Unauthenticated bytes (bad signature, undecodable) are
///   `unreadable(malformed)`.
/// - Everything else is authenticated-but-unacceptable — an over-bound
///   jump, u64::MAX (SYNC-10), an unknown issuer, a foreign group id —
///   and raises `unauthorized`, the case ADR-0034 keeps separate for
///   exactly this.
fn manifest_rejection_issue(err: crate::manifest::ManifestError) -> Option<DeliveryIssue> {
    use crate::manifest::ManifestError as ME;
    match err {
        ME::VersionRegression { .. } => None,
        ME::DecodeFailed(_) | ME::InvalidLength { .. } | ME::InvalidSignature => {
            Some(DeliveryIssue::Unreadable(UnreadableReason::Malformed))
        }
        ME::VersionJumpTooLarge { .. }
        | ME::VersionExhausted
        | ME::UnknownIssuer
        | ME::GroupIdMismatch => Some(DeliveryIssue::Unauthorized),
    }
}

/// Extract a human-readable message from a caught panic payload.
fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "handler panicked".to_string()
    }
}

/// Drop outbox entries over the Protocol Size Limit and report each one as
/// `sendFailed(tooLarge)` (ADR-0025: "Outbox entries already over the limit
/// (only in development stores) are dropped on load and raise the same
/// permanent-failure event"; ADR-0034 §3).
///
/// `send()` refuses oversize bodies before they are queued, so only entries
/// written by a pre-fix build can trigger this. Each entry is removed
/// permanently on the first load that sees it, so the report fires exactly
/// once per entry. The drop is measured against the protocol ceiling, not
/// the session's (possibly lowered) payload limit: an entry queued while a
/// higher limit was in effect is still deliverable.
fn drop_oversize_outbox_entries(
    op_log: &Arc<Mutex<Box<dyn OperationLog>>>,
    signing_pub: &[u8; 32],
    issue_sink: &Arc<Mutex<IssueSink>>,
) {
    let oversized: Vec<(u64, [u8; 32])> = {
        let mut log = op_log.lock().unwrap_or_else(|e| e.into_inner());
        let oversized: Vec<(u64, [u8; 32])> = log
            .undelivered_entries()
            .into_iter()
            .filter(|entry| entry.blob.len() > PROTOCOL_SIZE_LIMIT)
            .map(|entry| (entry.sequence, entry.object_id))
            .collect();
        for (sequence, object_id) in &oversized {
            log.remove(object_id, *sequence);
        }
        oversized
    };
    if oversized.is_empty() {
        return;
    }
    warn!(
        "[trueseal-sync] dropped {} oversize outbox {} on load (Protocol Size Limit is {} bytes)",
        oversized.len(),
        if oversized.len() == 1 {
            "entry"
        } else {
            "entries"
        },
        PROTOCOL_SIZE_LIMIT
    );
    let mut sink = issue_sink.lock().unwrap_or_else(|e| e.into_inner());
    for (sequence, _) in &oversized {
        sink.fire(DeliveryIssue::SendFailed {
            message_id: message_id(signing_pub, *sequence),
            reason: SendFailedReason::TooLarge,
        });
    }
}

// ── TruesealSession ───────────────────────────────────────────────────────────────

/// The opinionated session facade (ADR-0010 / ADR-0014).
///
/// Owns the relay connection, sequence counter, signing keypair, pairing state,
/// and current GroupManifest.
/// Transport-generic so tests can inject in-memory pipes.
pub struct TruesealSession<T: crate::relay::Severable> {
    client: Arc<Mutex<RelayClient<T>>>,
    keys: Arc<Mutex<KeyState>>,
    sequence: Arc<Mutex<u64>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    pub(crate) op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    /// Current group membership record. `None` means not yet in any group.
    /// Updated atomically when a valid higher-version GroupManifest is received.
    pub(crate) manifest: Arc<Mutex<Option<GroupManifest>>>,
    /// Fired when an inbound GroupManifest excludes the local device.
    on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static>,
    /// Fired whenever the local manifest changes (inbound update or accept_pair).
    /// Callers use this to persist the manifest to SQLite.
    on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static>,
    /// The Destroying record (ADR-0029): present while a Destroy waits for
    /// the Relay to accept every queued Revoke. Seeded from the op log at
    /// construction so a crash in Destroying resumes Destroying.
    destroying: Arc<Mutex<Option<DestroyingRecord>>>,
    /// Pending member requests keyed by opaque token, set via set_on_member_request.
    pending_members: Arc<Mutex<HashMap<String, PendingMember>>>,
    /// Fired when a Pair message arrives inside an open pairing window.
    /// `(token, name)` — caller shows UI then calls `accept_member(token)`.
    /// Buffered until the handler registers (ADR-0026 step 1).
    on_member_request: Arc<Mutex<EventSink>>,
    /// Fired when a new member appears in an incoming manifest update.
    /// Buffered until the handler registers.
    on_member_joined: Arc<Mutex<EventSink>>,
    /// Fired when a member disappears from an incoming manifest update (not for local device).
    /// Buffered until the handler registers.
    on_member_left: Arc<Mutex<EventSink>>,
    /// The largest `Sync` body `send()` accepts. Defaults to the Protocol
    /// Size Limit; a caller may lower it (e.g. to match a stricter relay),
    /// never raise it above the protocol ceiling (ADR-0025).
    max_payload_bytes: AtomicUsize,
    /// Delivery Issues raised by the session AND forwarded from the
    /// receive path (SYNC-5: one stream, ADR-0026). Buffered until the
    /// first subscriber registers, so construction-time reports are never
    /// lost. SYNC-15 owns the public FFI surface for it.
    issue_sink: Arc<Mutex<IssueSink>>,
    /// Wakes the sender pump when a new entry is queued (ADR-0026).
    kick: Arc<sender::Kick>,
    /// The Pending Join (ADR-0023): set by `join_group`, cleared by
    /// `cancel_join` and by acceptance of the first manifest. Seeded from
    /// the op log at construction so it survives restarts.
    pending_join: Arc<Mutex<Option<PendingJoin>>>,
    /// This device's Pending Membership Changes (ADR-0027): admissions,
    /// removals and Leaves it issued that a concurrent manifest could still
    /// overwrite. Re-checked on every accepted manifest; persisted with
    /// each membership commit.
    pending_changes: Arc<Mutex<Vec<PendingChange>>>,
    /// The Leaving record (ADR-0027): present while a Leave waits for the
    /// Relay to accept its manifest pushes. Seeded from the op log at
    /// construction so a crash in Leaving resumes Leaving.
    leaving: Arc<Mutex<Option<LeavingRecord>>>,
    /// Fired after the identity is rotated (deliberate removal, completed
    /// Leave): the caller persists the fresh keypair. The FFI wipes the
    /// namespace store here.
    on_identity_rotated: Arc<dyn Fn(DeviceKeypair) + Send + Sync + 'static>,
    /// Set when the identity rotated: the sender pump swaps the receive
    /// client for the disconnected stub so the reconnect loop rebinds the
    /// Receive Session to the fresh keys (an old-key session could never
    /// receive the manifests a re-pair brings).
    rotation_pending: Arc<AtomicBool>,
    /// Set by `close()` (ADR-0028): the reconnect loop and the sender pump
    /// exit, the receive client is severed, and every state-changing call
    /// fails with `Closed`. Session State is untouched.
    shutdown: Arc<AtomicBool>,
}

/// Wipe the group state and rotate the identity (ADR-0027: deliberate
/// removal and completed Leave — "the library wipes the namespace's group
/// state, outbox and dedup table, generates a fresh identity, returns to
/// notJoined").
///
/// Crash-safe ordering: the durable Leaving record disappears only inside
/// the caller's `Store::wipe` transaction (via `on_identity_rotated`), so a
/// crash anywhere before it commits restarts the wipe (the Leaving record
/// is still there and its refs are drained — completion re-runs
/// idempotently); a crash after it finds a wiped store, and a missing
/// identity is regenerated on open.
#[allow(clippy::too_many_arguments)]
pub(super) fn wipe_and_rotate(
    op_log: &Arc<Mutex<Box<dyn OperationLog>>>,
    manifest: &Arc<Mutex<Option<GroupManifest>>>,
    keys: &Arc<Mutex<KeyState>>,
    sequence: &Arc<Mutex<u64>>,
    pending_changes: &Arc<Mutex<Vec<PendingChange>>>,
    leaving: &Arc<Mutex<Option<LeavingRecord>>>,
    destroying: &Arc<Mutex<Option<DestroyingRecord>>>,
    pending_join: &Arc<Mutex<Option<PendingJoin>>>,
    on_identity_rotated: &Arc<dyn Fn(DeviceKeypair) + Send + Sync + 'static>,
    rotation_pending: &Arc<AtomicBool>,
) {
    let fresh = DeviceKeypair::generate();
    {
        let mut ks = keys.lock().unwrap_or_else(|e| e.into_inner());
        *ks = KeyState::from_keypair(&fresh);
    }
    // The FFI wipes the namespace store and persists the rotated identity
    // inside this callback. Fresh identity first, so the callback can save
    // it after the wipe.
    (on_identity_rotated)(fresh);
    {
        let mut log = op_log.lock().unwrap_or_else(|e| e.into_inner());
        log.wipe_group_state();
    }
    *manifest.lock().unwrap_or_else(|e| e.into_inner()) = None;
    pending_changes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    *leaving.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *destroying.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *pending_join.lock().unwrap_or_else(|e| e.into_inner()) = None;
    // A fresh identity starts a fresh sequence space (the high-water mark
    // was wiped with the group state).
    *sequence.lock().unwrap_or_else(|e| e.into_inner()) = 0;
    // The Receive Session is still bound to the OLD keys — it could never
    // receive the manifests a re-pair brings. The sender pump swaps in the
    // disconnected stub; the reconnect loop rebinds with the fresh keys.
    rotation_pending.store(true, Ordering::Release);
}

/// Have all the given outbox refs been accepted by the Relay?
/// (Delivered rows are deleted, ADR-0026.)
pub(super) fn refs_drained(
    op_log: &Arc<Mutex<Box<dyn OperationLog>>>,
    refs: &[([u8; 32], u64)],
) -> bool {
    let log = op_log.lock().unwrap_or_else(|e| e.into_inner());
    let undelivered: std::collections::HashSet<([u8; 32], u64)> = log
        .undelivered_entries()
        .into_iter()
        .map(|e| (e.object_id, e.sequence))
        .collect();
    refs.iter().all(|r| !undelivered.contains(r))
}

/// Have all the Leaving record's outbox refs been accepted by the Relay?
pub(super) fn leaving_refs_drained(
    op_log: &Arc<Mutex<Box<dyn OperationLog>>>,
    record: &LeavingRecord,
) -> bool {
    refs_drained(op_log, &record.refs)
}

/// Builds the full manifest-aware subscribe handler.
///
/// Extracted so both `connect_full` (initial connection) and `reconnect_loop`
/// (every reconnect) share identical dispatch logic — any change to message
/// handling semantics needs to be made exactly once here.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_subscribe_handler(
    keys: Arc<Mutex<KeyState>>,
    manifest: Arc<Mutex<Option<GroupManifest>>>,
    pending_join: Arc<Mutex<Option<PendingJoin>>>,
    on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static>,
    on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static>,
    destroying: Arc<Mutex<Option<DestroyingRecord>>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    pending_members: Arc<Mutex<HashMap<String, PendingMember>>>,
    on_member_request: Arc<Mutex<EventSink>>,
    on_member_joined: Arc<Mutex<EventSink>>,
    on_member_left: Arc<Mutex<EventSink>>,
    issue_sink: Arc<Mutex<IssueSink>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    outbox_sequence: Arc<Mutex<u64>>,
    pending_changes: Arc<Mutex<Vec<PendingChange>>>,
    leaving: Arc<Mutex<Option<LeavingRecord>>>,
    on_identity_rotated: Arc<dyn Fn(DeviceKeypair) + Send + Sync + 'static>,
    rotation_pending: Arc<AtomicBool>,
    on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
) -> impl Fn(Message, [u8; 32], u64, u64) + Send + 'static {
    move |msg, author_signing_pub, sequence, sender_timestamp_ms| {
        // The dedup record outlives the message (ADR-0034 §2): it is kept
        // until 60 days after the LATER of the handling time and the Sender
        // Timestamp. The store prunes on the recorded time, so record the
        // later of the two — a future-dated message can never be replayed
        // after its record expired.
        let dedup_recorded_at = now_secs().max(sender_timestamp_ms / 1000);
        // ── Pair (handled before manifest filter — joiner is not yet a member) ──
        if let Message::Pair {
            noise_pub,
            signing_pub,
            secret,
        } = &msg
        {
            // ADR-0029: a Destroying device is ending the group — inbound
            // Pairs are dropped like manifests. No window can be OPEN while
            // Destroying (pairing_token refuses and destroy_group() closes
            // any open window); this guards the residual race where a Pair
            // passed the secret check just as destroy_group() committed.
            if destroying
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
            {
                return;
            }
            // SYNC-4 (#96): the Pair body's signing_pub must equal the key
            // that actually signed this Envelope. Without the binding, a
            // requester can get a signing key it does not control admitted,
            // or pair a victim's signing key with its own routing address
            // (manifest-trust hijack, repro variant 5). Drop silently before
            // any Join Request is raised; the blob is still acked as handled.
            if *signing_pub != author_signing_pub {
                return;
            }
            // ADR-0023: the Pair must prove knowledge of the open window's
            // Pairing Secret — only a party that saw the Pairing Token
            // out-of-band can know it, and the token is the one channel the
            // Relay never sees. A relay-injected Pair, a wrong secret and a
            // replayed spent secret are all dropped SILENTLY: the Relay can
            // mint arbitrary well-formed Pairs, so reporting each one would
            // let it flood the Delivery Issue stream.
            let secret_ok = pairing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|w| w.is_open() && secret_matches(secret, &w.secret))
                .unwrap_or(false);
            if !secret_ok {
                return;
            }
            // Repeat Pairs from the same joiner keys deduplicate into one
            // request (ADR-0023) — a relay re-delivery must not raise a
            // second Join Request.
            {
                let mut pending = pending_members.lock().unwrap_or_else(|e| e.into_inner());
                if pending
                    .values()
                    .any(|p| p.noise_pub.0 == *noise_pub && p.signing_pub.0 == *signing_pub)
                {
                    return;
                }
                use base64::Engine as _;
                let token_bytes: [u8; 16] = rand::random();
                let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
                let name = member_name(&SigningPublicKey(*signing_pub));
                pending.insert(
                    token.clone(),
                    PendingMember {
                        noise_pub: NoisePublicKey(*noise_pub),
                        signing_pub: SigningPublicKey(*signing_pub),
                    },
                );
                on_member_request
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .fire(token, name);
            }
            return;
        }

        // ── GroupManifest (before the member filter: the FIRST manifest is
        // gated by the Pending Join, not by membership — ADR-0023) ────────
        if let Message::GroupManifest { manifest: incoming } = &msg {
            // ADR-0029: a Destroying device is ending the group — it does
            // not accept manifests (accepting one could trigger a removal
            // wipe before the Relay has accepted its Revokes).
            if destroying
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
            {
                return;
            }
            let (local_signing_pub, local_noise_pub) = {
                let ks = keys.lock().unwrap_or_else(|e| e.into_inner());
                (ks.signing_pub.0, ks.noise_pub.0)
            };
            let mut guard = manifest.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                // ADR-0023: a device with neither a Group Manifest nor a
                // Pending Join accepts no manifest. A Pending Join accepts
                // a first manifest only if it is signed by the token's
                // signing key, the Envelope signer is that same key, and
                // the joiner's own keys are among the members. A failure
                // keeps the Pending Join and is reported — a first manifest
                // is never routine traffic, so a rejection is worth telling
                // the app about (G3 observes the typed issue).
                let mut pending_guard = pending_join.lock().unwrap_or_else(|e| e.into_inner());
                let rejection: Option<DeliveryIssue> = match pending_guard.as_ref() {
                    None => Some(DeliveryIssue::Unauthorized),
                    Some(p) => {
                        if author_signing_pub != p.initiator_signing_pub.0
                            || incoming.issued_by != p.initiator_signing_pub.0
                        {
                            Some(DeliveryIssue::Unauthorized)
                        } else {
                            match incoming.verify(None) {
                                Err(err) => manifest_rejection_issue(err),
                                Ok(()) => match incoming
                                    .members
                                    .iter()
                                    .find(|m| m.signing_pub.0 == local_signing_pub)
                                {
                                    // The joiner's OWN keys must be listed —
                                    // both of them, or routing would point at
                                    // someone else's noise key.
                                    Some(m) if m.noise_pub.0 == local_noise_pub => None,
                                    _ => Some(DeliveryIssue::Unauthorized),
                                },
                            }
                        }
                    }
                };
                if let Some(issue) = rejection {
                    drop(pending_guard);
                    drop(guard);
                    warn!(
                        "[trueseal-sync] rejected first GroupManifest v{}: trust-anchor check failed",
                        incoming.version
                    );
                    issue_sink
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .fire(issue);
                    return;
                }

                // Accepted. Persist-first ordering (ADR-0023 Crash
                // points): the membership commit lands the manifest and
                // the held record (ADR-0027 deliberate-removal history)
                // before the Pending Join record is cleared, so a crash in
                // between is self-healed at construction (a manifest
                // implies the join completed). The Blob is acked after
                // this handler returns, so a crash before the ack
                // re-delivers the manifest.
                let commit = crate::operation_log::MembershipCommit {
                    manifest: incoming.encode(),
                    held: vec![(incoming.hash(), true)],
                    pending_changes: Vec::new(),
                    leaving: None,
                    destroying: None,
                    drop_sync_outbox: false,
                    outbox: Vec::new(),
                };
                if op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .commit_membership(commit)
                    .is_err()
                {
                    // Durable write failed: nothing installed. The Blob is
                    // not acked (the handler returned without recording),
                    // so the manifest is re-delivered.
                    return;
                }
                *guard = Some(incoming.clone());
                let joined: Vec<(String, String)> = incoming
                    .members
                    .iter()
                    .filter(|m| m.signing_pub.0 != local_signing_pub)
                    .map(|m| (member_id(&m.signing_pub), member_name(&m.signing_pub)))
                    .collect();
                *pending_guard = None;
                drop(pending_guard);
                drop(guard);

                (on_manifest_changed)(incoming);
                op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear_pending_join();
                {
                    let mut sink = on_member_joined.lock().unwrap_or_else(|e| e.into_inner());
                    for (id, name) in joined {
                        sink.fire(id, name);
                    }
                }
                return;
            }

            // An update to an existing manifest: the Envelope signer must
            // be a current member (the member filter's job for the update
            // path, now that the manifest branch runs before the filter).
            if !guard
                .as_ref()
                .expect("invariant: checked is_some above")
                .contains_signing_pub(&author_signing_pub)
            {
                return;
            }

            // A manifest that fails verification is acked and dropped. The
            // report depends on WHY it failed (ADR-0034 §2/§3, SYNC-5) —
            // see manifest_rejection_issue. The lock is released before the
            // sink fires, as with every callback in this handler.
            if let Err(err) = incoming.verify(guard.as_ref()) {
                let rejected_version = incoming.version;
                let issue = manifest_rejection_issue(err);
                drop(guard);
                match issue {
                    None => {
                        // Benign stale manifests are routine (concurrent
                        // issuance), so this logs at debug, not warn.
                        log::debug!(
                            "[trueseal-sync] ignoring stale GroupManifest v{rejected_version}"
                        );
                    }
                    Some(issue) => {
                        warn!("[trueseal-sync] rejected GroupManifest v{rejected_version}");
                        issue_sink
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .fire(issue);
                    }
                }
                return;
            }
            let excluded = !incoming.contains_signing_pub(&local_signing_pub);
            let was_leaving = leaving.lock().unwrap_or_else(|e| e.into_inner()).is_some();

            // ── Removal (ADR-0027): deliberate vs false ──────────────────
            if excluded {
                // A device counts itself removed only when the excluding
                // manifest's `parent` is a manifest it holds or has held
                // that includes it — a DELIBERATE removal. The library
                // wipes the namespace's group state, generates a fresh
                // identity, returns to notJoined and fires the removed
                // event. Pending sends are dropped (the wipe drops the
                // whole outbox).
                let deliberate = incoming
                    .parent
                    .map(|p| {
                        op_log
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .is_held_including_self(&p)
                    })
                    .unwrap_or(false);
                if deliberate {
                    drop(guard);
                    wipe_and_rotate(
                        &op_log,
                        &manifest,
                        &keys,
                        &outbox_sequence,
                        &pending_changes,
                        &leaving,
                        &destroying,
                        &pending_join,
                        &on_identity_rotated,
                        &rotation_pending,
                    );
                    if !was_leaving {
                        // A Leaving device that is removed has nothing more
                        // to do — its Leave completes as the wipe — and it
                        // is not "removed": no removed event.
                        (on_removed_from_group)();
                    }
                    return;
                }

                // FALSE REMOVAL (ADR-0027): a manifest that excludes the
                // device but was built concurrently, not on a manifest that
                // included it. Stored as the current view; the device stays
                // alive, does not wipe and waits for its admitter to
                // re-apply the admission. Its own pending changes are
                // dropped (W excludes the issuer — a non-member's changes
                // carry no authority); a Leaving record, if any, stays so
                // the Leave still completes.
                let commit = crate::operation_log::MembershipCommit {
                    manifest: incoming.encode(),
                    held: vec![(incoming.hash(), false)],
                    pending_changes: Vec::new(),
                    leaving: None,
                    destroying: None,
                    drop_sync_outbox: false,
                    outbox: Vec::new(),
                };
                if op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .commit_membership(commit)
                    .is_err()
                {
                    return; // durable write failed; the Blob is re-delivered
                }
                let prev_pubs: std::collections::HashSet<[u8; 32]> = guard
                    .as_ref()
                    .map(|m| m.members.iter().map(|mm| mm.signing_pub.0).collect())
                    .unwrap_or_default();
                let next_pubs: std::collections::HashSet<[u8; 32]> =
                    incoming.members.iter().map(|mm| mm.signing_pub.0).collect();
                let joined: Vec<(String, String)> = incoming
                    .members
                    .iter()
                    .filter(|mm| !prev_pubs.contains(&mm.signing_pub.0))
                    .map(|mm| (member_id(&mm.signing_pub), member_name(&mm.signing_pub)))
                    .collect();
                let left: Vec<(String, String)> = prev_pubs
                    .iter()
                    .filter(|sp| !next_pubs.contains(*sp) && **sp != local_signing_pub)
                    .map(|sp| {
                        let k = SigningPublicKey(*sp);
                        (member_id(&k), member_name(&k))
                    })
                    .collect();
                *guard = Some(incoming.clone());
                pending_changes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear();
                drop(guard);
                (on_manifest_changed)(incoming);
                let mut sj = on_member_joined.lock().unwrap_or_else(|e| e.into_inner());
                for (id, name) in joined {
                    sj.fire(id, name);
                }
                drop(sj);
                let mut sl = on_member_left.lock().unwrap_or_else(|e| e.into_inner());
                for (id, name) in left {
                    sl.fire(id, name);
                }
                return;
            }

            // ── Pending Membership Change re-check (ADR-0027) ─────────────
            // Each pending change is, against W: satisfied (cleared),
            // deliberately superseded (W was built directly on the change's
            // carrier and undid it — cleared), or concurrently overwritten
            // (re-applied on top of W as W.version+1, which becomes the
            // change's new carrier). All overwritten changes re-apply in
            // ONE manifest — an honest issuer always steps by one.
            let self_sp = SigningPublicKey(local_signing_pub);
            // The Leave intent's carrier BEFORE the re-check: a Leaving
            // cancel is only legitimate as deliberate supersession (W was
            // built directly on this carrier). The change set can also lose
            // the Leave intent through a false removal (its changes are
            // cleared — a non-member's changes carry no authority), and
            // cancelling on mere absence would silently drop the Leave on
            // the NEXT accepted manifest (B9 review). Captured here because
            // the false-removal path and the commit below both replace the
            // set.
            let leave_carrier: Option<[u8; 32]> = {
                let changes = pending_changes.lock().unwrap_or_else(|e| e.into_inner());
                changes
                    .iter()
                    .find(|c| c.intent == PendingIntent::Leave)
                    .map(|c| c.carrier)
            };
            let overwritten: Vec<PendingChange> = {
                let changes = pending_changes.lock().unwrap_or_else(|e| e.into_inner());
                changes
                    .iter()
                    .filter(|c| !c.satisfied_by(incoming, &self_sp))
                    .filter(|c| Some(c.carrier) != incoming.parent)
                    .cloned()
                    .collect()
            };

            // The manifest this device ends on, the change set that
            // survives, the outbox entries for any re-application, the
            // Leaving-record update, and any admissions dropped at the
            // Maximum Group Size.
            let mut final_manifest = incoming.clone();
            let mut new_changes: Vec<PendingChange> = Vec::new();
            let mut reapplied_outbox: Vec<([u8; 32], u64, Vec<u8>)> = Vec::new();
            // Some(bytes) sets/clears the Leaving record (empty = cleared);
            // None leaves it untouched.
            let mut leaving_update: Option<Vec<u8>> = None;
            let mut dropped_admissions: Vec<(String, String)> = Vec::new();

            if !overwritten.is_empty() {
                let mut members = incoming.members.clone();
                let mut applied: Vec<PendingIntent> = Vec::new();
                for c in &overwritten {
                    match &c.intent {
                        PendingIntent::Admit(m) => {
                            if members.iter().any(|mm| mm.signing_pub == m.signing_pub) {
                                applied.push(c.intent.clone());
                            } else if members.len() >= MAX_GROUP_SIZE {
                                // ADR-0027: a re-applied admission that
                                // would exceed 32 is dropped with a typed
                                // event; the joiner stays in Pending Join.
                                dropped_admissions
                                    .push((member_id(&m.signing_pub), member_name(&m.signing_pub)));
                            } else {
                                members.push(m.clone());
                                applied.push(c.intent.clone());
                            }
                        }
                        PendingIntent::Remove(sp) => {
                            members.retain(|mm| mm.signing_pub != *sp);
                            applied.push(c.intent.clone());
                        }
                        PendingIntent::Leave => {
                            members.retain(|mm| mm.signing_pub.0 != local_signing_pub);
                            applied.push(c.intent.clone());
                        }
                    }
                }

                if !applied.is_empty() {
                    let signing_key = {
                        let ks = keys.lock().unwrap_or_else(|e| e.into_inner());
                        SigningKey::from_bytes(&ks.signing_priv)
                    };
                    match GroupManifest::update(incoming, members, &signing_key) {
                        Ok(reapplied) => {
                            let carrier = reapplied.hash();
                            new_changes = overwritten
                                .iter()
                                .filter(|c| applied.contains(&c.intent))
                                .map(|c| PendingChange {
                                    intent: c.intent.clone(),
                                    carrier,
                                })
                                .collect();
                            // Push the re-applied manifest to everyone in
                            // either view except self (covers re-removed
                            // targets and the re-admitted joiner).
                            let self_noise =
                                keys.lock().unwrap_or_else(|e| e.into_inner()).noise_pub;
                            let mut recipients: Vec<NoisePublicKey> = Vec::new();
                            for m in incoming.members.iter().chain(reapplied.members.iter()) {
                                if m.noise_pub != self_noise && !recipients.contains(&m.noise_pub) {
                                    recipients.push(m.noise_pub);
                                }
                            }
                            let encoded = Message::GroupManifest {
                                manifest: reapplied.clone(),
                            }
                            .encode();
                            let mut refs: Vec<([u8; 32], u64)> = Vec::new();
                            for peer in &recipients {
                                let seq = {
                                    let mut s =
                                        outbox_sequence.lock().unwrap_or_else(|e| e.into_inner());
                                    let v = *s;
                                    *s += 1;
                                    v
                                };
                                op_log
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .record_sequence(seq);
                                reapplied_outbox.push((peer.0, seq, encoded.clone()));
                                refs.push((peer.0, seq));
                            }
                            if was_leaving {
                                // The Leave was re-applied: the Leaving
                                // record now waits on the NEW pushes.
                                leaving_update = Some(LeavingRecord { refs }.encode());
                            }
                            final_manifest = reapplied;
                        }
                        Err(_) => {
                            // W.version+1 cannot be issued (SYNC-10). The
                            // changes are dropped; the device keeps W.
                            warn!(
                                "[trueseal-sync] cannot re-apply {} pending membership change(s): manifest version exhausted",
                                overwritten.len()
                            );
                        }
                    }
                }
            }

            // A Leave that was deliberately superseded by W (W was built
            // DIRECTLY on the Leave's carrier and includes this device
            // again) cancels Leaving: the record clears and the device is a
            // member. Gating on the carrier — not on the intent's mere
            // absence — closes the silent cancel through the false-removal
            // path (B9 review): after a false removal clears the change
            // set, a later re-including manifest must NOT cancel the Leave;
            // the Leaving record survives and the Leave still completes
            // (ADR-0027: "a Leaving record, if any, stays so the Leave
            // still completes").
            if was_leaving
                && leaving_update.is_none()
                && leave_carrier.is_some()
                && leave_carrier == incoming.parent
                && !new_changes.iter().any(|c| c.intent == PendingIntent::Leave)
            {
                leaving_update = Some(Vec::new());
            }

            let commit = crate::operation_log::MembershipCommit {
                manifest: final_manifest.encode(),
                // Both the accepted `incoming` AND the re-applied final
                // manifest enter the held history (review P2): the device
                // held the intermediate too, so a removal built on it is a
                // deliberate removal, not a false one. (Equal hashes when
                // there was no re-application — recorded once.)
                held: {
                    let mut held = vec![(incoming.hash(), true)];
                    let final_entry = (
                        final_manifest.hash(),
                        final_manifest.contains_signing_pub(&local_signing_pub),
                    );
                    if final_entry.0 != incoming.hash() {
                        held.push(final_entry);
                    }
                    held
                },
                pending_changes: PendingChange::encode_set(&new_changes),
                leaving: leaving_update.clone(),
                destroying: None,
                drop_sync_outbox: false,
                outbox: reapplied_outbox,
            };
            if op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .commit_membership(commit)
                .is_err()
            {
                return; // durable write failed; the Blob is re-delivered
            }

            let (joined, left): (Vec<_>, Vec<_>) = {
                let prev_pubs: std::collections::HashSet<[u8; 32]> = guard
                    .as_ref()
                    .map(|m| m.members.iter().map(|mm| mm.signing_pub.0).collect())
                    .unwrap_or_default();
                let next_pubs: std::collections::HashSet<[u8; 32]> = final_manifest
                    .members
                    .iter()
                    .map(|mm| mm.signing_pub.0)
                    .collect();
                let joined = final_manifest
                    .members
                    .iter()
                    .filter(|mm| !prev_pubs.contains(&mm.signing_pub.0))
                    .map(|mm| (member_id(&mm.signing_pub), member_name(&mm.signing_pub)))
                    .collect();
                let left = prev_pubs
                    .iter()
                    .filter(|sp| !next_pubs.contains(*sp) && **sp != local_signing_pub)
                    .map(|sp| {
                        let k = SigningPublicKey(*sp);
                        (member_id(&k), member_name(&k))
                    })
                    .collect();
                (joined, left)
            };

            *guard = Some(final_manifest.clone());
            *pending_changes.lock().unwrap_or_else(|e| e.into_inner()) = new_changes;
            if let Some(update) = &leaving_update {
                *leaving.lock().unwrap_or_else(|e| e.into_inner()) = if update.is_empty() {
                    None
                } else {
                    LeavingRecord::decode(update)
                };
            }
            drop(guard); // release lock BEFORE firing any callback

            (on_manifest_changed)(&final_manifest);

            if !dropped_admissions.is_empty() {
                let mut sink = issue_sink.lock().unwrap_or_else(|e| e.into_inner());
                for (member_id, name) in dropped_admissions {
                    sink.fire(DeliveryIssue::AdmissionDropped { member_id, name });
                }
            }
            {
                let mut sink = on_member_joined.lock().unwrap_or_else(|e| e.into_inner());
                for (id, name) in joined {
                    sink.fire(id, name);
                }
            }
            {
                let mut sink = on_member_left.lock().unwrap_or_else(|e| e.into_inner());
                for (id, name) in left {
                    sink.fire(id, name);
                }
            }
            return;
        }

        // ── Revoke (BEFORE the member filter: Destroy authority is any
        // PAST or present member, not the current view — ADR-0029) ────────
        if let Message::Revoke = &msg {
            // A device that is already Destroying (or done) ignores further
            // Revokes — each device forwards at most once, and replaying a
            // Revoke changes no state (ADR-0034).
            if destroying
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
            {
                return;
            }
            // `pendingJoin` / `notJoined`: ignored — there is no manifest
            // to check the author against (ADR-0029 state table).
            let view = {
                let guard = manifest.lock().unwrap_or_else(|e| e.into_inner());
                match *guard {
                    Some(ref m) => m.clone(),
                    None => return,
                }
            };
            // Authority: the author appears in ANY Group Manifest this
            // device has held for the group, current or past. A thief who
            // removed the owner first cannot block Destroy. A Revoke from
            // a device that never appeared in a held manifest is ignored.
            let authorised = op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_held_signer(&author_signing_pub);
            if !authorised {
                return;
            }

            // Forward, then wipe (ADR-0029): queue a Revoke to every
            // member of the device's OWN view except the author — this
            // reaches members admitted concurrently, who are missing from
            // the initiator's view. The same rules as the initiator:
            // pending Sync sends and Pending Membership Changes drop
            // without reporting, an in-flight Leave is abandoned, and the
            // whole transition is one durable commit. The ack follows the
            // commit (ADR-0026) — a crash before it re-delivers the Revoke
            // and the transition runs again idempotently.
            let self_noise = keys.lock().unwrap_or_else(|e| e.into_inner()).noise_pub;
            let encoded = Message::Revoke.encode();
            let mut refs: Vec<([u8; 32], u64)> = Vec::new();
            let mut outbox: Vec<([u8; 32], u64, Vec<u8>)> = Vec::new();
            for member in &view.members {
                if member.signing_pub.0 == author_signing_pub || member.noise_pub == self_noise {
                    continue;
                }
                let seq = {
                    let mut s = outbox_sequence.lock().unwrap_or_else(|e| e.into_inner());
                    let v = *s;
                    *s += 1;
                    v
                };
                op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .record_sequence(seq);
                refs.push((member.noise_pub.0, seq));
                outbox.push((member.noise_pub.0, seq, encoded.clone()));
            }
            let record = DestroyingRecord { refs };
            let commit = crate::operation_log::MembershipCommit {
                manifest: view.encode(),
                held: Vec::new(),
                pending_changes: Vec::new(),
                leaving: Some(Vec::new()),
                destroying: Some(record.encode()),
                drop_sync_outbox: true,
                outbox,
            };
            if op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .commit_membership(commit)
                .is_err()
            {
                return; // durable write failed; the Blob is re-delivered
            }
            *destroying.lock().unwrap_or_else(|e| e.into_inner()) = Some(record);
            *leaving.lock().unwrap_or_else(|e| e.into_inner()) = None;
            pending_changes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            // A Destroying device admits no one: close any open Pairing
            // Window (its pending requests die with it).
            *pairing.lock().unwrap_or_else(|e| e.into_inner()) = None;
            pending_members
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            return;
        }

        // ── Manifest-based inbound filtering (Sync only — Revoke returned
        // above with its own authority rule) ─────────────────────────────
        {
            let guard = manifest.lock().unwrap_or_else(|e| e.into_inner());
            match *guard {
                Some(ref m) => {
                    if !m.contains_signing_pub(&author_signing_pub) {
                        return; // not a member — discard
                    }
                }
                // ADR-0023: a device with no manifest drops every Sync.
                // This closes the pre-SYNC-3 fail-open gap (the filter
                // used to be skipped entirely without a manifest).
                // Routine internet garbage — no report.
                None => return,
            }
        }

        // ── Application message: library-owned dedup + handler attempts ─────
        // ADR-0026 recipient steps 3-5. Only `Sync` reaches here today —
        // every control variant returned above. The Message ID derives from
        // the author's signing key and the Envelope sequence, so a relay
        // re-delivery (new blob id, same Envelope) is recognised.
        let mid = message_id(&author_signing_pub, sequence);
        {
            let log = op_log.lock().unwrap_or_else(|e| e.into_inner());
            if log.is_handled(&mid) {
                // Duplicate: the handler already ran for this Message ID.
                // Return without a word — the relay acks silently. This is
                // also the crash-recovery path: a crash between the dedup
                // write and the DeliverAck re-delivers, lands here, and the
                // handler does NOT run twice.
                return;
            }
        }

        // ADR-0027 / ADR-0029: a Leaving or Destroying device runs no
        // handlers. The message is still dedup-recorded and acked — both
        // states are terminal (the wipe drops everything anyway), so
        // holding the Blob unacked would only stall the sender's inbox.
        let terminal_state = {
            let leaving = leaving.lock().unwrap_or_else(|e| e.into_inner()).is_some();
            let destroying = destroying
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some();
            leaving || destroying
        };
        if terminal_state {
            op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_handled(&mid, dedup_recorded_at);
            return;
        }

        // Run the handler: 5 attempts with in-memory backoff (ADR-0026 step
        // 4). A panicking handler is a failed attempt — caught so the
        // receive loop survives. A handler that never finishes stalls this
        // session's delivery (accepted, documented); a handler that fails
        // all attempts is acked, dropped and reported.
        let mut last_error = String::new();
        for attempt in 0..MAX_HANDLER_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(HANDLER_BACKOFF[(attempt - 1) as usize]);
            }
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                on_message(msg.clone(), author_signing_pub, sequence)
            }));
            match result {
                Ok(()) => {
                    // Step 5: record the Message ID, THEN return so the
                    // DeliverAck follows. A crash before the record commits
                    // re-delivers and the handler runs again — the only way
                    // an app sees a duplicate.
                    op_log
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_handled(&mid, dedup_recorded_at);
                    return;
                }
                Err(payload) => {
                    last_error = panic_message(payload);
                    warn!(
                        "[trueseal-sync] message handler failed (attempt {attempt}/{MAX_HANDLER_ATTEMPTS}, {mid}): {last_error}"
                    );
                }
            }
        }
        issue_sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fire(DeliveryIssue::HandlerGaveUp {
                message_id: mid,
                error: last_error,
            });
    }
}

/// Load and decode the persisted Pending Join (ADR-0023). A corrupt record
/// fails closed — cleared and treated as absent, so no manifest is accepted
/// on the strength of unreadable bytes.
fn load_pending_join(op_log: &Arc<Mutex<Box<dyn OperationLog>>>) -> Option<PendingJoin> {
    let mut log = op_log.lock().unwrap_or_else(|e| e.into_inner());
    match log.pending_join() {
        None => None,
        Some(bytes) => match PendingJoin::decode(&bytes) {
            Some(p) => Some(p),
            None => {
                warn!("[trueseal-sync] undecodable Pending Join record — clearing (fail closed)");
                log.clear_pending_join();
                None
            }
        },
    }
}

impl<T: crate::relay::Severable> TruesealSession<T> {
    /// Close the session (ADR-0028): stop the connection and the handlers
    /// but keep Session State. The reconnect loop and the sender pump exit
    /// (woken immediately, not on the next poll), the receive client is
    /// severed — its Noise session's closed flag interrupts a receive
    /// blocked in WouldBlock retry — and every state-changing call fails
    /// with [`SessionError::Closed`] from here on. In-flight handlers run
    /// to completion; their Blobs are then handled by the usual dispatch
    /// (the receive loop exits on the next frame at the latest). A Blob
    /// whose ack could not be sent is re-delivered on the next `open()` —
    /// the at-least-once contract is unaffected.
    ///
    /// Idempotent. The object is not reusable after `close()`; starting
    /// again means constructing a new session on the same namespace.
    pub fn close(&self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return; // already closed
        }
        // Wake the pump so it notices the flag now rather than on its next
        // poll, and sever the receive client. Replacing it with the stub
        // drops the old client, whose Drop closes the Noise session — the
        // receive thread unblocks and the run loop exits (DisconnectGuard
        // marks the link down).
        self.kick.kick();
        let old = {
            let mut guard = self.client.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *guard, RelayClient::disconnected())
        };
        old.close();
    }

    /// True after [`Self::close()`].
    pub fn is_closed(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// The shared `Closed` guard for state-changing methods.
    fn check_open(&self) -> Result<(), SessionError> {
        if self.is_closed() {
            return Err(SessionError::Closed);
        }
        Ok(())
    }

    /// Current noise public key for this session.
    pub fn noise_pub(&self) -> NoisePublicKey {
        self.keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .noise_pub
    }

    /// Current signing public key for this session.
    pub fn signing_pub(&self) -> SigningPublicKey {
        self.keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .signing_pub
    }

    /// List of remote group members (excludes the local device).
    ///
    /// Returns an empty `Vec` when no manifest is set.
    /// Each entry has a stable `id` and an auto-generated `name` derived from
    /// the member's signing public key — see [`crate::member`].
    pub fn members(&self) -> Vec<Member> {
        let local_signing = self
            .keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .signing_pub;
        let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
        match &*guard {
            None => vec![],
            Some(m) => m
                .members
                .iter()
                .filter(|mm| mm.signing_pub.0 != local_signing.0)
                .map(|mm| Member {
                    id: member_id(&mm.signing_pub),
                    name: member_name(&mm.signing_pub),
                })
                .collect(),
        }
    }

    /// Ask to join the Sync Group of the initiator identified by `token`
    /// (ADR-0023, joiner state machine: `NotJoined → PendingJoin`).
    ///
    /// The token is the trust anchor: this device will accept a first
    /// manifest only if it is signed by the token's signing key, the
    /// Envelope signer is that same key, and this device's keys are members.
    ///
    /// The Pending Join and its `Pair` (carrying the token's Pairing
    /// Secret) are persisted and queued in ONE durable transaction, so the
    /// request survives restarts and retries follow the outbox (ADR-0026).
    /// `Ok(())` means durably queued — the caller must not retry.
    ///
    /// Returns `SessionError::AlreadyInGroup` if a manifest exists (one
    /// Sync Group per namespace). A second call while pending REPLACES the
    /// Pending Join. Returns `SessionError::InvalidToken` if the token
    /// cannot be decoded or predates the Pairing Secret (ADR-0022 clean
    /// break). `cancel_join` abandons the wait.
    pub fn join_group(&self, token: &str) -> Result<(), SessionError> {
        self.check_open()?;
        if self
            .destroying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(SessionError::GroupDestroyed);
        }
        if self
            .manifest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(SessionError::AlreadyInGroup);
        }
        let (initiator_noise, initiator_signing, secret, _initiator_name) =
            crate::message::decode_pairing_token(token).map_err(|_| SessionError::InvalidToken)?;
        let pending = PendingJoin {
            initiator_noise_pub: NoisePublicKey(initiator_noise),
            initiator_signing_pub: SigningPublicKey(initiator_signing),
            secret,
        };
        let msg = {
            let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            Message::Pair {
                noise_pub: ks.noise_pub.0,
                signing_pub: ks.signing_pub.0,
                secret,
            }
        };
        let seq = self.next_seq();
        // B8 review F3: propagate a store failure — the in-memory Pending
        // Join is set ONLY after the durable record + queued Pair commit,
        // so a failed join leaves the device honestly NotJoined.
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .begin_pending_join(&pending.encode(), &initiator_noise, seq, msg.encode())
            .map_err(SessionError::Store)?;
        *self.pending_join.lock().unwrap_or_else(|e| e.into_inner()) = Some(pending);
        self.kick.kick();
        Ok(())
    }

    /// Abandon a Pending Join (ADR-0023: `cancelJoin()` moves the device
    /// back to `notJoined`). The manifest gate closes immediately. The
    /// already-queued `Pair` stays in the outbox — if it is delivered, the
    /// initiator may admit this device, but the resulting manifest fails
    /// the (now absent) anchor's checks and is dropped.
    ///
    /// Crash window: clearing the durable record before the in-memory slot
    /// means a crash in between restarts as still-pending — visible,
    /// cancellable, and safe (the anchor only narrows what is accepted).
    pub fn cancel_join(&self) {
        if self.is_closed() {
            return;
        }
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear_pending_join();
        *self.pending_join.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Where this device stands in its namespace's Sync Group (ADR-0023,
    /// ADR-0027, ADR-0028).
    pub fn group_status(&self) -> GroupStatus {
        if self
            .destroying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            GroupStatus::Destroying
        } else if self
            .leaving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            GroupStatus::Leaving
        } else if self
            .manifest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            GroupStatus::Member
        } else if self
            .pending_join
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            GroupStatus::PendingJoin
        } else {
            GroupStatus::NotJoined
        }
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn connect(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
    ) -> Result<Self, SessionError> {
        Self::connect_with_log(
            transport,
            relay_pub,
            keypair,
            on_message,
            Box::new(MemLog::new()),
            push_factory,
        )
    }

    pub fn connect_with_log(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
        op_log: Box<dyn OperationLog>,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
    ) -> Result<Self, SessionError> {
        Self::connect_full(
            transport,
            relay_pub,
            keypair,
            on_message,
            op_log,
            || {},
            |_| {},
            || {},
            push_factory,
        )
    }

    /// `connect_full` without identity-rotation persistence (ADR-0027): the
    /// rotation still happens in memory on a deliberate removal or completed
    /// Leave; the callback is only for persisting the fresh keypair, which
    /// MemLog-backed and test sessions don't need.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_full(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
        op_log: Box<dyn OperationLog>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
    ) -> Result<Self, SessionError> {
        Self::connect_full_rotating(
            transport,
            relay_pub,
            keypair,
            on_message,
            op_log,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            |_| {},
            push_factory,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_full_rotating(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
        op_log: Box<dyn OperationLog>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        on_identity_rotated: impl Fn(DeviceKeypair) + Send + Sync + 'static,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
    ) -> Result<Self, SessionError> {
        let keys = Arc::new(Mutex::new(KeyState::from_keypair(&keypair)));
        let noise_kp = {
            let ks = keys.lock().unwrap_or_else(|e| e.into_inner());
            NoiseKeypair::new(ks.noise_priv, ks.noise_pub_key)
        };

        let manifest: Arc<Mutex<Option<GroupManifest>>> = Arc::new(Mutex::new(None));
        let pairing: Arc<Mutex<Option<PairingWindow>>> = Arc::new(Mutex::new(None));
        let on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_removed_from_group);
        let on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static> =
            Arc::new(on_manifest_changed);
        let on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_group_destroyed);
        // ADR-0029: the Destroying record — seeded from the op log below,
        // once the log exists (a crash in Destroying resumes Destroying).
        let destroying: Arc<Mutex<Option<DestroyingRecord>>> = Arc::new(Mutex::new(None));

        let keys_cb = keys.clone();
        let manifest_cb = manifest.clone();
        let on_rfg_cb = on_removed_from_group.clone();
        let on_mc_cb = on_manifest_changed.clone();
        let destroying_cb = destroying.clone();
        let pending_cb: Arc<Mutex<HashMap<String, PendingMember>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let on_mr_cb: Arc<Mutex<EventSink>> = Arc::new(Mutex::new(EventSink::new()));
        let pending_cb_ret = pending_cb.clone();
        let on_mr_cb_ret = on_mr_cb.clone();
        let pairing_cb = pairing.clone();
        let on_mj_cb: Arc<Mutex<EventSink>> = Arc::new(Mutex::new(EventSink::new()));
        let on_ml_cb: Arc<Mutex<EventSink>> = Arc::new(Mutex::new(EventSink::new()));
        let on_mj_cb_ret = on_mj_cb.clone();
        let on_ml_cb_ret = on_ml_cb.clone();

        let op_log: Arc<Mutex<Box<dyn OperationLog>>> = Arc::new(Mutex::new(op_log));
        let issue_sink = Arc::new(Mutex::new(IssueSink::new()));

        // ADR-0023: restore the Pending Join — it survives restarts.
        // connect_full always starts without a manifest (tests and the
        // CLI's fresh sessions), so no self-heal is needed here.
        let pending_join: Arc<Mutex<Option<PendingJoin>>> =
            Arc::new(Mutex::new(load_pending_join(&op_log)));

        // Restore sequence counter from the op log so it never re-uses a
        // sequence number after a process restart (ADR-0011).
        let initial_seq = op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .max_sequence()
            .map(|s| s + 1)
            .unwrap_or(0);
        let sequence = Arc::new(Mutex::new(initial_seq));

        // ADR-0027: restore the Pending Membership Changes and the Leaving
        // record — both survive restarts (an offline issuer re-applies
        // after reconnecting; a crash in Leaving resumes Leaving).
        let pending_changes: Arc<Mutex<Vec<PendingChange>>> =
            Arc::new(Mutex::new(load_pending_changes(&op_log)));
        let leaving: Arc<Mutex<Option<LeavingRecord>>> =
            Arc::new(Mutex::new(load_leaving(&op_log)));
        *destroying.lock().unwrap_or_else(|e| e.into_inner()) = load_destroying(&op_log);
        let on_identity_rotated: Arc<dyn Fn(DeviceKeypair) + Send + Sync + 'static> =
            Arc::new(on_identity_rotated);
        let rotation_pending = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));

        // SYNC-6 (#98): the handler is built first and registered inside
        // connect, before the receive loop starts reading. A Blob queued in
        // the inbox while this device was offline arrives the moment the
        // session comes up — subscribing afterwards would lose it.
        let handler = build_subscribe_handler(
            keys_cb,
            manifest_cb,
            pending_join.clone(),
            on_rfg_cb,
            on_mc_cb,
            destroying_cb,
            pairing_cb,
            pending_cb,
            on_mr_cb,
            on_mj_cb,
            on_ml_cb,
            issue_sink.clone(),
            op_log.clone(),
            sequence.clone(),
            pending_changes.clone(),
            leaving.clone(),
            on_identity_rotated.clone(),
            rotation_pending.clone(),
            on_message,
        );
        // SYNC-5: the Delivery Issue stream is one channel from the very
        // first frame — receive-path issues (`unreadable`, `heldForUpgrade`)
        // forward into the session sink, alongside session-raised issues.
        let issue_forwarder = {
            let sink = issue_sink.clone();
            move |issue: DeliveryIssue| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).fire(issue);
            }
        };
        let client = RelayClient::connect_subscribed(
            transport,
            relay_pub,
            noise_kp,
            handler,
            Some(Box::new(issue_forwarder)),
        )?;
        let client = Arc::new(Mutex::new(client));
        let push_factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync + 'static> =
            Arc::new(push_factory);

        // ADR-0029: a crash after the Destroying commit or mid-wipe
        // resumes here — a Destroying record whose Revoke refs are already
        // drained completes now (the wipe is idempotent; the destroying row
        // only disappears inside the wipe transaction).
        {
            let rec = destroying.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(rec) = rec {
                if refs_drained(&op_log, &rec.refs) {
                    wipe_and_rotate(
                        &op_log,
                        &manifest,
                        &keys,
                        &sequence,
                        &pending_changes,
                        &leaving,
                        &destroying,
                        &pending_join,
                        &on_identity_rotated,
                        &rotation_pending,
                    );
                    // Fired after the wipe: a crash mid-wipe leaves a wiped
                    // store and the app observes `notJoined` on next open.
                    (on_group_destroyed)();
                }
            }
        }
        // ADR-0027: a crash during the wipe restarts the wipe — a Leaving
        // record whose outbox refs are already drained completes now.
        {
            let rec = leaving.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(rec) = rec {
                if leaving_refs_drained(&op_log, &rec) {
                    wipe_and_rotate(
                        &op_log,
                        &manifest,
                        &keys,
                        &sequence,
                        &pending_changes,
                        &leaving,
                        &destroying,
                        &pending_join,
                        &on_identity_rotated,
                        &rotation_pending,
                    );
                }
            }
        }

        // SYNC-5 (ADR-0026): the sender pump owns the outbox state machine —
        // retries while connected, head-of-line per recipient, typed
        // permanent/temporary classes, expiry, delivered-row deletion. It
        // also completes a Leaving once the Relay has accepted every Leave
        // push, and rebinds the Receive Session after an identity rotation
        // (ADR-0027).
        let kick = Arc::new(sender::Kick::new());
        let on_leave_complete = {
            let op_log = op_log.clone();
            let manifest = manifest.clone();
            let keys = keys.clone();
            let sequence = sequence.clone();
            let pending_changes = pending_changes.clone();
            let leaving = leaving.clone();
            let destroying = destroying.clone();
            let pending_join = pending_join.clone();
            let on_identity_rotated = on_identity_rotated.clone();
            let rotation_pending = rotation_pending.clone();
            move || {
                wipe_and_rotate(
                    &op_log,
                    &manifest,
                    &keys,
                    &sequence,
                    &pending_changes,
                    &leaving,
                    &destroying,
                    &pending_join,
                    &on_identity_rotated,
                    &rotation_pending,
                );
            }
        };
        // ADR-0029: the Destroy completes when the Relay has accepted every
        // queued Revoke — then wipe + rotate (same machinery as a completed
        // Leave) and report the destroy.
        let on_destroy_complete = {
            let op_log = op_log.clone();
            let manifest = manifest.clone();
            let keys = keys.clone();
            let sequence = sequence.clone();
            let pending_changes = pending_changes.clone();
            let leaving = leaving.clone();
            let destroying = destroying.clone();
            let pending_join = pending_join.clone();
            let on_identity_rotated = on_identity_rotated.clone();
            let rotation_pending = rotation_pending.clone();
            let on_group_destroyed = on_group_destroyed.clone();
            move || {
                wipe_and_rotate(
                    &op_log,
                    &manifest,
                    &keys,
                    &sequence,
                    &pending_changes,
                    &leaving,
                    &destroying,
                    &pending_join,
                    &on_identity_rotated,
                    &rotation_pending,
                );
                (on_group_destroyed)();
            }
        };
        sender::spawn_sender(
            client.clone(),
            op_log.clone(),
            keys.clone(),
            relay_pub.0,
            push_factory.clone(),
            issue_sink.clone(),
            destroying.clone(),
            kick.clone(),
            sender::SenderConfig::default(),
            leaving.clone(),
            rotation_pending.clone(),
            Box::new(on_leave_complete),
            Box::new(on_destroy_complete),
            shutdown.clone(),
        );

        // SYNC-8 (#100): drop oversize entries persisted by pre-fix builds —
        // they can never be delivered and would replay forever (ADR-0025).
        // The reports buffer in the sink until the first subscriber registers.
        {
            let signing_pub = keys.lock().unwrap_or_else(|e| e.into_inner()).signing_pub.0;
            drop_oversize_outbox_entries(&op_log, &signing_pub, &issue_sink);
        }

        Ok(Self {
            client,
            keys,
            sequence,
            pairing,
            op_log,
            manifest,
            on_removed_from_group,
            on_manifest_changed,
            destroying,
            pending_members: pending_cb_ret,
            on_member_request: on_mr_cb_ret,
            on_member_joined: on_mj_cb_ret,
            on_member_left: on_ml_cb_ret,
            max_payload_bytes: AtomicUsize::new(PROTOCOL_SIZE_LIMIT),
            issue_sink,
            kick,
            pending_join,
            pending_changes,
            leaving,
            on_identity_rotated,
            rotation_pending,
            shutdown,
        })
    }

    /// `connect_with_reconnect` without identity-rotation persistence (see
    /// [`Self::connect_full`]).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_with_reconnect(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        transport_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        reconnect_cap: Option<Duration>,
        on_connection_changed: Option<Box<dyn Fn(ConnectionChange) + Send + Sync + 'static>>,
    ) -> Result<Self, SessionError> {
        Self::connect_with_reconnect_rotating(
            transport,
            relay_pub,
            keypair,
            on_message,
            op_log,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            |_| {},
            transport_factory,
            push_factory,
            reconnect_cap,
            on_connection_changed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_with_reconnect_rotating(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        on_identity_rotated: impl Fn(DeviceKeypair) + Send + Sync + 'static,
        transport_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        reconnect_cap: Option<Duration>,
        on_connection_changed: Option<Box<dyn Fn(ConnectionChange) + Send + Sync + 'static>>,
    ) -> Result<Self, SessionError> {
        let transport_factory = Arc::new(transport_factory);
        let session = Self::connect_full_rotating(
            transport,
            relay_pub,
            keypair,
            on_message.clone(),
            op_log,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            on_identity_rotated,
            push_factory,
        )?;
        let client_arc = session.client.clone();
        let op_log_arc = session.op_log.clone();
        let keys_arc = session.keys.clone();
        let manifest_arc = session.manifest.clone();
        let on_rfg_arc = session.on_removed_from_group.clone();
        let on_mc_arc = session.on_manifest_changed.clone();
        let destroying_arc = session.destroying.clone();
        let pairing_arc = session.pairing.clone();
        let pending_arc = session.pending_members.clone();
        let on_mr_arc = session.on_member_request.clone();
        let on_mj_arc = session.on_member_joined.clone();
        let on_ml_arc = session.on_member_left.clone();
        let issue_sink_arc = session.issue_sink.clone();
        let pending_join_arc = session.pending_join.clone();
        let sequence_arc = session.sequence.clone();
        let pending_changes_arc = session.pending_changes.clone();
        let leaving_arc = session.leaving.clone();
        let on_ir_arc = session.on_identity_rotated.clone();
        let rotation_pending_arc = session.rotation_pending.clone();
        let shutdown_arc = session.shutdown.clone();
        let cap = reconnect_cap.unwrap_or(DEFAULT_RECONNECT_CAP);
        let on_cc: Arc<dyn Fn(ConnectionChange) + Send + Sync + 'static> = on_connection_changed
            .map(|f| -> Arc<dyn Fn(ConnectionChange) + Send + Sync + 'static> { Arc::new(f) })
            .unwrap_or_else(|| Arc::new(|_| {}));
        std::thread::spawn(move || {
            reconnect::reconnect_loop(
                client_arc,
                op_log_arc,
                relay_pub,
                keys_arc,
                manifest_arc,
                on_message,
                on_rfg_arc,
                on_mc_arc,
                destroying_arc,
                pairing_arc,
                pending_arc,
                on_mr_arc,
                on_mj_arc,
                on_ml_arc,
                issue_sink_arc,
                pending_join_arc,
                sequence_arc,
                pending_changes_arc,
                leaving_arc,
                on_ir_arc,
                rotation_pending_arc,
                shutdown_arc,
                transport_factory,
                cap,
                on_cc,
            );
        });
        Ok(session)
    }

    /// Create a session that starts offline — no relay connection required.
    ///
    /// The session is immediately usable: `members()`, `pairing_token()`, etc.
    /// `push_sync` queues to the outbox.
    /// A background reconnect loop connects to the relay when available using `transport_factory`.
    ///
    /// `manifest` is the session's manifest slot, owned and seeded by the CALLER
    /// before this constructor runs (SYNC-7, #99): a restarted device loads its
    /// persisted Group Manifest into it up front, so the receive path never
    /// observes a transient `None` and early Deliver frames are judged against
    /// the persisted membership. Restoring afterwards instead would reopen the
    /// manifest hijack and could overwrite a newer manifest that arrived first.
    /// Callers that keep a clone (e.g. the FFI's sender-attribution closure)
    /// observe every later manifest update through the same slot.
    ///
    /// Per ADR-0017 / PHILOSOPHY: `create()` is infallible. Use this constructor at the
    /// FFI boundary so `create()` always succeeds regardless of relay reachability.
    ///
    /// This variant has no identity-rotation persistence (see
    /// [`Self::connect_full`]); production callers that persist state (the
    /// FFI) use [`Self::connect_background_rotating`].
    #[allow(clippy::too_many_arguments)]
    pub fn connect_background(
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        manifest: Arc<Mutex<Option<GroupManifest>>>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        transport_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        reconnect_cap: Option<Duration>,
        on_connection_changed: Option<Box<dyn Fn(ConnectionChange) + Send + Sync + 'static>>,
    ) -> Result<Self, SessionError> {
        Self::connect_background_rotating(
            relay_pub,
            keypair,
            on_message,
            op_log,
            manifest,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            |_| {},
            transport_factory,
            push_factory,
            reconnect_cap,
            on_connection_changed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_background_rotating(
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        manifest: Arc<Mutex<Option<GroupManifest>>>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        on_identity_rotated: impl Fn(DeviceKeypair) + Send + Sync + 'static,
        transport_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        push_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        reconnect_cap: Option<Duration>,
        on_connection_changed: Option<Box<dyn Fn(ConnectionChange) + Send + Sync + 'static>>,
    ) -> Result<Self, SessionError> {
        // Build all arcs directly — mirrors connect_full but without an initial transport.
        let keys = Arc::new(Mutex::new(KeyState::from_keypair(&keypair)));
        let pairing: Arc<Mutex<Option<PairingWindow>>> = Arc::new(Mutex::new(None));
        let on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_removed_from_group);
        let on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static> =
            Arc::new(on_manifest_changed);
        let on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_group_destroyed);
        // ADR-0029: the Destroying record — seeded from the op log below,
        // once the log exists (a crash in Destroying resumes Destroying).
        let destroying: Arc<Mutex<Option<DestroyingRecord>>> = Arc::new(Mutex::new(None));
        let pending_members: Arc<Mutex<HashMap<String, PendingMember>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let on_member_request: Arc<Mutex<EventSink>> = Arc::new(Mutex::new(EventSink::new()));
        let on_member_joined: Arc<Mutex<EventSink>> = Arc::new(Mutex::new(EventSink::new()));
        let on_member_left: Arc<Mutex<EventSink>> = Arc::new(Mutex::new(EventSink::new()));

        let transport_factory = Arc::new(transport_factory);
        let push_factory_arc: Arc<dyn Fn() -> Result<T, String> + Send + Sync + 'static> =
            Arc::new(push_factory);

        // Stub client: permanently disconnected — the reconnect loop will replace it.
        let client: Arc<Mutex<RelayClient<T>>> = Arc::new(Mutex::new(RelayClient::disconnected()));
        let op_log_arc: Arc<Mutex<Box<dyn OperationLog>>> = Arc::new(Mutex::new(op_log));
        let issue_sink = Arc::new(Mutex::new(IssueSink::new()));

        // ADR-0023: restore the Pending Join — it survives restarts. A
        // caller-seeded manifest (SYNC-7) means the join completed; a
        // leftover record is the crash window between "manifest persisted"
        // and "pending cleared" (ADR-0023 Crash points) — self-heal it.
        let pending_join: Arc<Mutex<Option<PendingJoin>>> = {
            let loaded = load_pending_join(&op_log_arc);
            let healed = if loaded.is_some()
                && manifest.lock().unwrap_or_else(|e| e.into_inner()).is_some()
            {
                op_log_arc
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear_pending_join();
                None
            } else {
                loaded
            };
            Arc::new(Mutex::new(healed))
        };

        // SYNC-8 (#100): drop oversize entries persisted by pre-fix builds —
        // they can never be delivered and would replay forever (ADR-0025).
        // The reports buffer in the sink until the first subscriber registers.
        {
            let signing_pub = keys.lock().unwrap_or_else(|e| e.into_inner()).signing_pub.0;
            drop_oversize_outbox_entries(&op_log_arc, &signing_pub, &issue_sink);
        }

        // Restore sequence counter from the op log so it never re-uses a
        // sequence number after a process restart (ADR-0011).
        let initial_seq = op_log_arc
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .max_sequence()
            .map(|s| s + 1)
            .unwrap_or(0);
        let sequence = Arc::new(Mutex::new(initial_seq));

        // ADR-0027: restore the Pending Membership Changes and the Leaving
        // record — both survive restarts.
        let pending_changes: Arc<Mutex<Vec<PendingChange>>> =
            Arc::new(Mutex::new(load_pending_changes(&op_log_arc)));
        let leaving: Arc<Mutex<Option<LeavingRecord>>> =
            Arc::new(Mutex::new(load_leaving(&op_log_arc)));
        *destroying.lock().unwrap_or_else(|e| e.into_inner()) = load_destroying(&op_log_arc);
        let on_identity_rotated: Arc<dyn Fn(DeviceKeypair) + Send + Sync + 'static> =
            Arc::new(on_identity_rotated);
        let rotation_pending = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));

        // ADR-0029: a crash after the Destroying commit or mid-wipe
        // resumes here — a Destroying record whose Revoke refs are already
        // drained completes now (the wipe is idempotent; the destroying row
        // only disappears inside the wipe transaction).
        {
            let rec = destroying.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(rec) = rec {
                if refs_drained(&op_log_arc, &rec.refs) {
                    wipe_and_rotate(
                        &op_log_arc,
                        &manifest,
                        &keys,
                        &sequence,
                        &pending_changes,
                        &leaving,
                        &destroying,
                        &pending_join,
                        &on_identity_rotated,
                        &rotation_pending,
                    );
                    // Fired after the wipe: a crash mid-wipe leaves a wiped
                    // store and the app observes `notJoined` on next open.
                    (on_group_destroyed)();
                }
            }
        }
        // ADR-0027: a crash during the wipe restarts the wipe — a Leaving
        // record whose outbox refs are already drained completes now.
        {
            let rec = leaving.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(rec) = rec {
                if leaving_refs_drained(&op_log_arc, &rec) {
                    wipe_and_rotate(
                        &op_log_arc,
                        &manifest,
                        &keys,
                        &sequence,
                        &pending_changes,
                        &leaving,
                        &destroying,
                        &pending_join,
                        &on_identity_rotated,
                        &rotation_pending,
                    );
                }
            }
        }

        // SYNC-5 (ADR-0026): the sender pump owns the outbox state machine.
        // It starts against the disconnected stub client and delivers as
        // soon as the reconnect loop brings the session up. It also
        // completes a Leaving and rebinds the Receive Session after an
        // identity rotation (ADR-0027).
        let kick = Arc::new(sender::Kick::new());
        let on_leave_complete = {
            let op_log = op_log_arc.clone();
            let manifest = manifest.clone();
            let keys = keys.clone();
            let sequence = sequence.clone();
            let pending_changes = pending_changes.clone();
            let leaving = leaving.clone();
            let destroying = destroying.clone();
            let pending_join = pending_join.clone();
            let on_identity_rotated = on_identity_rotated.clone();
            let rotation_pending = rotation_pending.clone();
            move || {
                wipe_and_rotate(
                    &op_log,
                    &manifest,
                    &keys,
                    &sequence,
                    &pending_changes,
                    &leaving,
                    &destroying,
                    &pending_join,
                    &on_identity_rotated,
                    &rotation_pending,
                );
            }
        };
        // ADR-0029: the Destroy completes when the Relay has accepted every
        // queued Revoke — then wipe + rotate (same machinery as a completed
        // Leave) and report the destroy.
        let on_destroy_complete = {
            let op_log = op_log_arc.clone();
            let manifest = manifest.clone();
            let keys = keys.clone();
            let sequence = sequence.clone();
            let pending_changes = pending_changes.clone();
            let leaving = leaving.clone();
            let destroying = destroying.clone();
            let pending_join = pending_join.clone();
            let on_identity_rotated = on_identity_rotated.clone();
            let rotation_pending = rotation_pending.clone();
            let on_group_destroyed = on_group_destroyed.clone();
            move || {
                wipe_and_rotate(
                    &op_log,
                    &manifest,
                    &keys,
                    &sequence,
                    &pending_changes,
                    &leaving,
                    &destroying,
                    &pending_join,
                    &on_identity_rotated,
                    &rotation_pending,
                );
                (on_group_destroyed)();
            }
        };
        sender::spawn_sender(
            client.clone(),
            op_log_arc.clone(),
            keys.clone(),
            relay_pub.0,
            push_factory_arc.clone(),
            issue_sink.clone(),
            destroying.clone(),
            kick.clone(),
            sender::SenderConfig::default(),
            leaving.clone(),
            rotation_pending.clone(),
            Box::new(on_leave_complete),
            Box::new(on_destroy_complete),
            shutdown.clone(),
        );

        let session = Self {
            client: client.clone(),
            keys: keys.clone(),
            sequence: sequence.clone(),
            pairing: pairing.clone(),
            op_log: op_log_arc.clone(),
            manifest: manifest.clone(),
            on_removed_from_group: on_removed_from_group.clone(),
            on_manifest_changed: on_manifest_changed.clone(),
            destroying: destroying.clone(),
            pending_members: pending_members.clone(),
            on_member_request: on_member_request.clone(),
            on_member_joined: on_member_joined.clone(),
            on_member_left: on_member_left.clone(),
            max_payload_bytes: AtomicUsize::new(PROTOCOL_SIZE_LIMIT),
            issue_sink: issue_sink.clone(),
            kick,
            pending_join: pending_join.clone(),
            pending_changes: pending_changes.clone(),
            leaving: leaving.clone(),
            on_identity_rotated: on_identity_rotated.clone(),
            rotation_pending: rotation_pending.clone(),
            shutdown: shutdown.clone(),
        };

        let cap = reconnect_cap.unwrap_or(DEFAULT_RECONNECT_CAP);
        let on_cc: Arc<dyn Fn(ConnectionChange) + Send + Sync + 'static> = on_connection_changed
            .map(|f| -> Arc<dyn Fn(ConnectionChange) + Send + Sync + 'static> { Arc::new(f) })
            .unwrap_or_else(|| Arc::new(|_| {}));
        std::thread::spawn(move || {
            reconnect::reconnect_loop(
                client,
                op_log_arc,
                relay_pub,
                keys,
                manifest,
                on_message,
                on_removed_from_group,
                on_manifest_changed,
                destroying,
                pairing,
                pending_members,
                on_member_request,
                on_member_joined,
                on_member_left,
                issue_sink,
                pending_join,
                sequence,
                pending_changes,
                leaving,
                on_identity_rotated,
                rotation_pending,
                shutdown,
                transport_factory,
                cap,
                on_cc,
            );
        });

        Ok(session)
    }

    /// Encrypt `blob` as a Sync message and fan out to every manifest member except self.
    /// One sequence number is consumed per call regardless of member count.
    /// Returns `SessionError::NotInGroup` if no manifest is set.
    /// Returns `SessionError::GroupDestroyed` if the group has been destroyed.
    ///
    /// ADR-0026: `send()` writes the entry to the outbox before returning.
    /// Delivery is the sender pump's job from here: it retries while
    /// connected (backoff 1 s to 5 min, immediately on reconnect), holds
    /// head-of-line order per recipient, fails permanently-refused and
    /// expired entries with `sendFailed` on the delivery-issue stream, and
    /// deletes delivered rows. `Ok(())` means "durably queued" — the caller
    /// must not retry (ADR-0017); observing failures is optional.
    pub fn push_sync(&self, blob: Vec<u8>) -> Result<(), SessionError> {
        self.check_open()?;
        if self
            .destroying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(SessionError::GroupDestroyed);
        }
        // ADR-0027: a Leaving device does not send Sync.
        if self
            .leaving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(SessionError::NotInGroup);
        }
        // ADR-0025: the Protocol Size Limit is checked synchronously, before
        // anything is written to the Operation Log. An oversize body never
        // enters the Outbox (where it would replay forever — the relay's
        // refusal is permanent) and never consumes a Sequence.
        let max = self.max_payload_bytes.load(Ordering::Acquire);
        if blob.len() > max {
            return Err(SessionError::PayloadTooLarge { max: max as u32 });
        }
        let recipients: Vec<NoisePublicKey> = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            match *guard {
                None => return Err(SessionError::NotInGroup),
                Some(ref m) => {
                    let self_noise = self
                        .keys
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .noise_pub;
                    m.members
                        .iter()
                        .filter(|member| member.noise_pub != self_noise)
                        .map(|member| member.noise_pub)
                        .collect()
                }
            }
        };

        let seq = self.next_seq();
        {
            let mut log = self.op_log.lock().unwrap_or_else(|e| e.into_inner());
            for r in &recipients {
                log.append(&r.0, seq, blob.clone());
            }
        }
        self.kick.kick();
        Ok(())
    }

    /// The largest `Sync` body `send()` currently accepts, in bytes
    /// (ADR-0025). Defaults to the Protocol Size Limit (`PROTOCOL_SIZE_LIMIT`).
    pub fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes.load(Ordering::Acquire)
    }

    /// Lower the payload limit for this session — e.g. to match a stricter
    /// relay's Relay Size Limit. Values above the Protocol Size Limit are
    /// clamped to it: the protocol ceiling can never be raised (ADR-0025).
    /// Returns the effective limit.
    ///
    /// Applies to subsequent `send()` calls only; entries already in the
    /// Outbox are governed by the protocol ceiling (see
    /// `drop_oversize_outbox_entries`).
    pub fn set_max_payload_bytes(&self, requested: usize) -> usize {
        let effective = requested.min(PROTOCOL_SIZE_LIMIT);
        self.max_payload_bytes.store(effective, Ordering::Release);
        effective
    }

    /// Subscribe to Delivery Issues raised by this session (ADR-0034 §3) —
    /// currently `sendFailed(tooLarge)` for outbox entries dropped on load
    /// (ADR-0025). Those load-time reports fire during construction, so they
    /// are buffered and flushed to the first subscriber; issues raised after
    /// subscription go to every subscriber.
    ///
    /// Receive-path issues (`unreadable`, `heldForUpgrade`) are raised on the
    /// RelayClient's own channel (SYNC-1); SYNC-15 unifies the surface on
    /// the FFI. Callbacks fire under the sink lock and must not re-enter
    /// session methods.
    pub fn subscribe_delivery_issues(&self, callback: impl Fn(DeliveryIssue) + Send + 'static) {
        self.issue_sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .subscribe(Box::new(callback));
    }

    /// Queue a control-plane message (Pair, Group Manifest, Revoke) for
    /// `recipient_pub`. Test-only: production control-plane sends commit
    /// atomically through `MembershipCommit` (ADR-0027/0029). ADR-0026:
    /// the control plane goes through the outbox under the same contract
    /// as `Sync` — durable before the caller
    /// proceeds, retried while connected, never expired — and the sender
    /// pump delivers it. An unsupported Transport Version leaves the entry
    /// queued until the library or relay is upgraded (ADR-0022).
    #[cfg(test)]
    pub(crate) fn push_message(
        &self,
        msg: &Message,
        recipient_pub: NoisePublicKey,
    ) -> Result<(), SessionError> {
        let seq = self.next_seq();
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .append_control(&recipient_pub.0, seq, msg.encode());
        self.kick.kick();
        Ok(())
    }

    // ── Destroy Group (ADR-0015) ──────────────────────────────────────────────

    /// Destroy the Sync Group (ADR-0029): persist the **Destroying** state
    /// and queue one Revoke per member of the current view through the
    /// outbox — in ONE transaction. The device then stays Destroying (no
    /// `Sync` sends, no handlers, still connected) until the Relay has
    /// accepted every Revoke; only then does it wipe its group state,
    /// rotate its identity, fire `on_group_destroyed` and return to
    /// `notJoined`. There is no timeout: a crash or going offline resumes
    /// Destroying on the next start.
    ///
    /// Per the ADR state table: a no-op while already Destroying; a typed
    /// `NotInGroup` error in `pendingJoin` / `notJoined`; an in-flight
    /// Leave is abandoned. Pending `Sync` sends and Pending Membership
    /// Changes drop without reporting, as removal does.
    pub fn destroy_group(&self) -> Result<(), SessionError> {
        self.check_open()?;
        if self
            .destroying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(()); // already Destroying — a second call is a no-op
        }

        // Lock discipline: keys copied out and released before the manifest
        // lock (the handler locks manifest → keys).
        let self_noise = self
            .keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .noise_pub;
        let (current, refs, outbox) = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let current = guard.clone().ok_or(SessionError::NotInGroup)?;
            let encoded = Message::Revoke.encode();
            let mut refs = Vec::new();
            let mut outbox = Vec::new();
            for member in current.members.iter() {
                if member.noise_pub == self_noise {
                    continue;
                }
                let seq = self.next_seq();
                refs.push((member.noise_pub.0, seq));
                outbox.push((member.noise_pub.0, seq, encoded.clone()));
            }
            (current, refs, outbox)
        };

        let record = DestroyingRecord { refs };
        // The Destroying record, the queued Revokes, the dropped Sync
        // sends, the abandoned Leave and the cleared Pending Membership
        // Changes commit in ONE transaction (ADR-0029 crash points: before
        // the commit nothing changed; after it, Destroying resumes).
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .commit_membership(crate::operation_log::MembershipCommit {
                manifest: current.encode(),
                held: Vec::new(),
                pending_changes: Vec::new(),
                leaving: Some(Vec::new()),
                destroying: Some(record.encode()),
                drop_sync_outbox: true,
                outbox,
            })
            .map_err(SessionError::Store)?;

        *self.destroying.lock().unwrap_or_else(|e| e.into_inner()) = Some(record);
        *self.leaving.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.pending_changes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        // A Destroying device admits no one: close any open Pairing Window
        // (its pending requests die with it).
        self.cancel_pairing();
        self.kick.kick();
        Ok(())
    }

    // ── Pairing ───────────────────────────────────────────────────────────────

    /// Opens a pairing window and returns a base64url token encoding
    /// a version byte, `noise_pub || signing_pub || secret || device_name`
    /// (ADR-0023). A fresh single-use Pairing Secret is generated per
    /// window; the window and its pending requests live in memory only, so
    /// a restart or `cancel_pairing()` spends the secret. The token dies
    /// when the window closes.
    ///
    /// Documented limitation (ADR-0023): anyone who sees the token while
    /// the window is open can request to join — the admitting user must
    /// confirm the device in front of them. Member names are labels, not
    /// authentication.
    ///
    /// Fails typed with `GroupDestroyed` while Destroying (ADR-0029): a
    /// window opened mid-Destroy could only admit a joiner into a group
    /// every other device has already dropped.
    pub fn pairing_token(&self) -> Result<String, SessionError> {
        self.check_open()?;
        if self
            .destroying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(SessionError::GroupDestroyed);
        }
        let secret: [u8; 32] = rand::random();
        {
            // Hold the window lock across the clear AND the replace (B8
            // review F2), in the handler's lock order (pairing →
            // pending_members). A new window must not inherit requests
            // raised under a spent secret — its pending requests live and
            // die with the window — and clearing BEFORE the replace means
            // a Join Request raised under the NEW window can never be
            // wiped by this clear. Residual, bounded race: a Pair that
            // passed the OLD window's secret check just before the replace
            // can still insert after the clear; the single-use window
            // bounds this — accepting any request spends the window and
            // drops every other pending request.
            let mut window = self.pairing.lock().unwrap_or_else(|e| e.into_inner());
            self.pending_members
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            *window = Some(PairingWindow { secret });
        }
        let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        Ok(crate::message::pairing_token(
            &ks.noise_pub.0,
            &ks.signing_pub.0,
            &secret,
        ))
    }

    pub fn cancel_pairing(&self) {
        if self.is_closed() {
            return;
        }
        // Same lock order as `pairing_token` and the inbound handler
        // (pairing → pending_members): the window close and the clear of
        // its pending requests are one observation.
        let mut window = self.pairing.lock().unwrap_or_else(|e| e.into_inner());
        self.pending_members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *window = None;
    }

    /// Admit a device; requires both noise and signing pub keys.
    /// Returns `Ok(true)` if the device was admitted (window open),
    /// `Ok(false)` if the window was closed or had already expired.
    ///
    /// On success: issues a new `GroupManifest` (genesis or a parent-linked
    /// `version+1` update, ADR-0027), records the admission as a Pending
    /// Membership Change, and pushes the manifest to all existing members
    /// plus the new member — manifest, change and outbox entries committed
    /// in one transaction.
    ///
    /// Errors: `GroupFull` if the admission would exceed the Maximum Group
    /// Size (32, ADR-0027 — the window stays open), `ManifestVersionExhausted`
    /// if no next version can be issued (SYNC-10), `Store` if the durable
    /// commit failed (nothing changed in memory; the caller may retry).
    pub fn accept_pair(
        &self,
        noise_pub: NoisePublicKey,
        signing_pub: SigningPublicKey,
    ) -> Result<bool, SessionError> {
        self.check_open()?;
        // A Destroying device admits no one (ADR-0029): the group is
        // ending and no other device would honour the admission.
        if self
            .destroying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(SessionError::GroupDestroyed);
        }
        // A Leaving device admits no one (ADR-0027).
        if self
            .leaving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(false);
        }
        // The Maximum Group Size and self-membership checks run BEFORE the
        // window is consumed (ADR-0027: "refused locally with a typed
        // error") — the caller may remove a member and retry the admission.
        // A device whose current VIEW excludes it (a false removal) admits
        // no one: a non-member's changes carry no authority (ADR-0027).
        {
            let self_sp = self
                .keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .signing_pub;
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(m) = guard.as_ref() {
                if !m.contains_signing_pub(&self_sp.0) {
                    return Ok(false);
                }
                if m.members.len() >= MAX_GROUP_SIZE {
                    return Err(SessionError::GroupFull {
                        max: MAX_GROUP_SIZE as u32,
                    });
                }
            }
        }
        // Take the window under ONE lock (B8 review F1): the check and the
        // consume are atomic, so two concurrent accepts cannot both observe
        // an open window and issue divergent genesis manifests. The window
        // is spent whether or not it was open — a closed window is not
        // revived.
        let window_open = self
            .pairing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .map(|w| w.is_open())
            .unwrap_or(false);

        if !window_open {
            return Ok(false);
        }

        // Build the new manifest. Lock discipline (B8 review F4): keys are
        // COPIED OUT and released before the manifest lock is taken — the
        // receive handler locks manifest → keys (re-application signing),
        // so no path may hold keys while acquiring manifest.
        let (self_noise, self_signing, signing_key) = {
            let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            (
                ks.noise_pub,
                ks.signing_pub,
                SigningKey::from_bytes(&ks.signing_priv),
            )
        };
        let new_member = ManifestMember {
            noise_pub,
            signing_pub,
            name: device_name(&signing_pub.0),
        };

        let (new_manifest, notify) = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            match &*guard {
                None => {
                    // Genesis: version 1, self + new member.
                    (
                        GroupManifest::new(
                            new_group_id(),
                            1,
                            vec![
                                ManifestMember {
                                    noise_pub: self_noise,
                                    signing_pub: self_signing,
                                    name: device_name(&self_signing.0),
                                },
                                new_member.clone(),
                            ],
                            &signing_key,
                        ),
                        Vec::new(),
                    )
                }
                Some(current) => {
                    let mut members = current.members.clone();
                    members.push(new_member.clone());
                    let manifest = GroupManifest::update(current, members, &signing_key)
                        .map_err(|_| SessionError::ManifestVersionExhausted)?;
                    let notify: Vec<NoisePublicKey> = current
                        .members
                        .iter()
                        .filter(|mb| mb.noise_pub != self_noise)
                        .map(|mb| mb.noise_pub)
                        .collect();
                    (manifest, notify)
                }
            }
        };

        // ADR-0027: manifest + Pending Membership Change + outbox entries
        // commit in ONE transaction.
        let carrier = new_manifest.hash();
        let change_set: Vec<PendingChange> = {
            let mut set = self
                .pending_changes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            set.push(PendingChange {
                intent: PendingIntent::Admit(new_member.clone()),
                carrier,
            });
            set
        };
        let encoded = Message::GroupManifest {
            manifest: new_manifest.clone(),
        }
        .encode();
        let mut outbox = Vec::new();
        for peer in notify.iter().chain(std::iter::once(&noise_pub)) {
            let seq = self.next_seq();
            outbox.push((peer.0, seq, encoded.clone()));
        }
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .commit_membership(crate::operation_log::MembershipCommit {
                manifest: new_manifest.encode(),
                held: vec![(carrier, true)],
                pending_changes: PendingChange::encode_set(&change_set),
                leaving: None,
                destroying: None,
                drop_sync_outbox: false,
                outbox,
            })
            .map_err(SessionError::Store)?;

        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(new_manifest.clone());
        *self
            .pending_changes
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = change_set;
        (self.on_manifest_changed)(&new_manifest);

        // The window is single-use (ADR-0023): every other pending request
        // belonged to the spent secret — drop them so a later window cannot
        // admit a stale request.
        self.pending_members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        // Fire onMemberJoined for the newly admitted device.
        self.on_member_joined
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fire(
                crate::member::member_id(&signing_pub),
                crate::member::member_name(&signing_pub),
            );

        self.kick.kick();
        Ok(true)
    }

    /// Register the callback fired when a `Pair` message arrives within an open pairing window.
    ///
    /// The callback receives `(token, name)`. The caller passes `token` back to
    /// [`Self::accept_member`] to admit the device.
    ///
    /// Registered post-construction, so requests that arrive in the
    /// construction window are buffered (ADR-0026 step 1: member events are
    /// buffered until their handlers exist) and flush to this callback the
    /// moment it registers. The callback fires under the sink lock and must
    /// not re-enter session methods.
    pub fn set_on_member_request(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        self.on_member_request
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_callback(Box::new(cb));
    }

    /// Register the callback fired when a new member appears in an incoming manifest update.
    /// `(id, name)` — same format as [`Self::members`]. Events that arrived
    /// before registration flush on registration (ADR-0026 step 1).
    pub fn set_on_member_joined(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        self.on_member_joined
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_callback(Box::new(cb));
    }

    /// Register the callback fired when a member disappears from an incoming manifest update.
    /// Does NOT fire when the local device is the removed one (that's `on_removed_from_group`).
    /// `(id, name)` — same format as [`Self::members`]. Events that arrived
    /// before registration flush on registration (ADR-0026 step 1).
    pub fn set_on_member_left(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        self.on_member_left
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_callback(Box::new(cb));
    }

    /// Admit a pending member identified by their opaque `token` from `on_member_request`.
    ///
    /// Returns `Ok(true)` if the token was valid and the member was admitted.
    /// Returns `Ok(false)` if the token is unknown or the pairing window has closed.
    /// Clears the pairing window on success (single-use window).
    /// Errors: see [`Self::accept_pair`] (`GroupFull`, `Store`, ...).
    pub fn accept_member(&self, token: &str) -> Result<bool, SessionError> {
        self.check_open()?;
        let pending = self
            .pending_members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
        match pending {
            None => Ok(false),
            Some(pm) => self.accept_pair(pm.noise_pub, pm.signing_pub),
        }
    }

    // ── Soft Removal ──────────────────────────────────────────────────────────

    /// Remove a device from the group by issuing a new manifest that excludes it.
    ///
    /// This is Soft Removal (ADR-0015): cooperative, not cryptographically enforced.
    /// Remaining members filter the removed device's messages once they receive
    /// the new manifest. The removed device also receives the new manifest so its
    /// `on_removed_from_group` can fire.
    ///
    /// Returns `SessionError::NotInGroup` if no manifest is set.
    /// Returns `SessionError::MemberNotFound` if `target` is not in the current manifest.
    pub fn remove_member(&self, target: SigningPublicKey) -> Result<(), SessionError> {
        self.check_open()?;
        // Lock discipline: keys copied out and released before the manifest
        // lock (the handler locks manifest → keys).
        let (self_noise, self_signing, signing_key) = {
            let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            (
                ks.noise_pub,
                ks.signing_pub,
                SigningKey::from_bytes(&ks.signing_priv),
            )
        };
        // Find the target member (need their noise_pub to push the manifest to them).
        let (new_manifest, notify, target_noise) = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let current = guard.as_ref().ok_or(SessionError::NotInGroup)?;
            // A device whose current view excludes it (false removal) has
            // no membership authority (ADR-0027).
            if !current.contains_signing_pub(&self_signing.0) {
                return Err(SessionError::NotInGroup);
            }

            let target_member = current
                .members
                .iter()
                .find(|m| m.signing_pub == target)
                .ok_or(SessionError::MemberNotFound)?;
            let target_noise = target_member.noise_pub;

            let remaining: Vec<ManifestMember> = current
                .members
                .iter()
                .filter(|m| m.signing_pub != target)
                .cloned()
                .collect();

            // ADR-0027: the update is parent-linked with checked arithmetic
            // (SYNC-10) — never panics, wraps, or issues u64::MAX.
            let new_manifest = GroupManifest::update(current, remaining, &signing_key)
                .map_err(|_| SessionError::ManifestVersionExhausted)?;

            // Notify: all remaining members excluding self.
            let notify: Vec<NoisePublicKey> = new_manifest
                .members
                .iter()
                .filter(|m| m.noise_pub != self_noise)
                .map(|m| m.noise_pub)
                .collect();

            (new_manifest, notify, target_noise)
        };

        // ADR-0027: manifest + Pending Membership Change + outbox entries
        // commit in ONE transaction. The removal is pushed to the removed
        // member too, so its deliberate-removal wipe fires.
        let carrier = new_manifest.hash();
        let change_set: Vec<PendingChange> = {
            let mut set = self
                .pending_changes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            set.push(PendingChange {
                intent: PendingIntent::Remove(target),
                carrier,
            });
            set
        };
        let encoded = Message::GroupManifest {
            manifest: new_manifest.clone(),
        }
        .encode();
        let mut outbox = Vec::new();
        for peer in notify.iter().chain(std::iter::once(&target_noise)) {
            let seq = self.next_seq();
            outbox.push((peer.0, seq, encoded.clone()));
        }
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .commit_membership(crate::operation_log::MembershipCommit {
                manifest: new_manifest.encode(),
                held: vec![(carrier, true)],
                pending_changes: PendingChange::encode_set(&change_set),
                leaving: None,
                destroying: None,
                drop_sync_outbox: false,
                outbox,
            })
            .map_err(SessionError::Store)?;

        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(new_manifest.clone());
        *self
            .pending_changes
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = change_set;
        (self.on_manifest_changed)(&new_manifest);
        self.kick.kick();

        Ok(())
    }

    /// Leave the Sync Group (ADR-0027): issue a manifest that excludes the
    /// local Device and enter the persisted **Leaving** state. The device
    /// does not send `Sync` and does not run handlers while Leaving; it
    /// stays connected until the Relay has accepted every push of the Leave
    /// manifest, then wipes its group state, rotates its identity and
    /// returns to `notJoined`. A crash or going offline in Leaving resumes
    /// on the next start. Idempotent while a Leave is already in flight.
    ///
    /// Errors: `NotInGroup` when not a member, `GroupDestroyed`,
    /// `ManifestVersionExhausted`, `Store` (nothing changed in memory).
    pub fn leave_group(&self) -> Result<(), SessionError> {
        self.check_open()?;
        if self
            .destroying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(SessionError::GroupDestroyed);
        }
        if self
            .leaving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(()); // a Leave is already in flight
        }

        // Lock discipline: keys copied out and released before the manifest
        // lock (the handler locks manifest → keys).
        let (self_signing, signing_key) = {
            let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            (ks.signing_pub, SigningKey::from_bytes(&ks.signing_priv))
        };
        let (leave_manifest, refs) = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let current = guard.as_ref().ok_or(SessionError::NotInGroup)?;
            // A device whose current view excludes it (false removal) is
            // already out of the group it sees — nothing to leave.
            if !current.contains_signing_pub(&self_signing.0) {
                return Err(SessionError::NotInGroup);
            }

            let remaining: Vec<ManifestMember> = current
                .members
                .iter()
                .filter(|m| m.signing_pub != self_signing)
                .cloned()
                .collect();
            let leave_manifest = GroupManifest::update(current, remaining, &signing_key)
                .map_err(|_| SessionError::ManifestVersionExhausted)?;

            // Push the Leave manifest to every remaining member; the
            // Leaving record waits on exactly these outbox refs.
            let encoded = Message::GroupManifest {
                manifest: leave_manifest.clone(),
            }
            .encode();
            let mut refs = Vec::with_capacity(leave_manifest.members.len());
            for peer in leave_manifest.members.iter() {
                let seq = self.next_seq();
                // (object_id, sequence, blob) outbox entries are rebuilt
                // from the refs below.
                refs.push((peer.noise_pub.0, seq, encoded.clone()));
            }
            (leave_manifest, refs)
        };

        let carrier = leave_manifest.hash();
        let change_set: Vec<PendingChange> = {
            let mut set = self
                .pending_changes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            set.push(PendingChange {
                intent: PendingIntent::Leave,
                carrier,
            });
            set
        };
        let record = LeavingRecord {
            refs: refs.iter().map(|(oid, seq, _)| (*oid, *seq)).collect(),
        };
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .commit_membership(crate::operation_log::MembershipCommit {
                manifest: leave_manifest.encode(),
                held: vec![(carrier, false)],
                pending_changes: PendingChange::encode_set(&change_set),
                leaving: Some(record.encode()),
                destroying: None,
                drop_sync_outbox: false,
                outbox: refs,
            })
            .map_err(SessionError::Store)?;

        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(leave_manifest.clone());
        *self
            .pending_changes
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = change_set;
        *self.leaving.lock().unwrap_or_else(|e| e.into_inner()) = Some(record);
        // A leaving device admits no one: close any open Pairing Window
        // (its pending requests die with it).
        self.cancel_pairing();
        (self.on_manifest_changed)(&leave_manifest);
        self.kick.kick();
        Ok(())
    }

    /// Remove a member identified by their opaque `member_id` string.
    ///
    /// Resolves the id back to `signing_pub` by scanning the current manifest,
    /// then delegates to [`Self::remove_member`].
    ///
    /// Returns `SessionError::NotInGroup` if no manifest is set.
    /// Returns `SessionError::MemberNotFound` if no member with that id exists.
    pub fn remove_member_by_id(&self, id: &str) -> Result<(), SessionError> {
        self.check_open()?;
        let target = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let m = guard.as_ref().ok_or(SessionError::NotInGroup)?;
            m.members
                .iter()
                .find(|mm| crate::member::member_id(&mm.signing_pub) == id)
                .map(|mm| mm.signing_pub)
                .ok_or(SessionError::MemberNotFound)?
        };
        self.remove_member(target)
    }

    // ── Manifest helpers ──────────────────────────────────────────────────────

    /// Replace the current manifest. Used by tests to seed membership
    /// directly. Also records the held history (ADR-0027): a seeded
    /// manifest is "held" exactly as an accepted one is — deliberate-removal
    /// detection depends on it. Pending changes and the Leaving record are
    /// left untouched.
    pub fn set_manifest(&self, m: GroupManifest) {
        let includes_self = m.contains_signing_pub(
            &self
                .keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .signing_pub
                .0,
        );
        {
            let mut log = self.op_log.lock().unwrap_or_else(|e| e.into_inner());
            let pending = log.pending_membership_changes().unwrap_or_default();
            let _ = log.commit_membership(crate::operation_log::MembershipCommit {
                manifest: m.encode(),
                held: vec![(m.hash(), includes_self)],
                pending_changes: pending,
                leaving: None,
                destroying: None,
                drop_sync_outbox: false,
                outbox: Vec::new(),
            });
        }
        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn next_seq(&self) -> u64 {
        let mut s = self.sequence.lock().unwrap_or_else(|e| e.into_inner());
        let v = *s;
        *s += 1;
        // ADR-0026: delivered outbox rows are deleted, so the consumed
        // sequence must be recorded durably — a restart must never re-use a
        // sequence number, or the recipient's dedup table would drop the new
        // message as a duplicate of the old one.
        self.op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_sequence(v);
        v
    }
}

// ── TCP convenience constructor ───────────────────────────────────────────────

impl TruesealSession<TcpStream> {
    pub fn connect_tcp(
        addr: &str,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
    ) -> Result<Self, SessionError> {
        // Non-blocking on both the receive stream and every push stream, so
        // the Transport Version exchange's deadline is effective (a silent
        // pre-version relay surfaces as a typed timeout, not a hang) and a
        // blocking receive can't starve concurrent sends. This matches the
        // FFI and CLI factories.
        let stream =
            TcpStream::connect(addr).map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;
        stream
            .set_nonblocking(true)
            .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;
        let addr = addr.to_string();
        let push_factory = move || {
            let s = TcpStream::connect(&addr).map_err(|e| e.to_string())?;
            s.set_nonblocking(true).map_err(|e| e.to_string())?;
            Ok(s)
        };
        Self::connect(stream, relay_pub, keypair, on_message, push_factory)
    }
}
