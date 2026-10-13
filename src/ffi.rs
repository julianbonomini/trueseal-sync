// FFI surface for Swift and Kotlin via UniFFI (proc-macro mode).
//
// Exposes a single `TruesealFfiSession` object over TCP transport.
// All key material crosses the boundary as `Vec<u8>`; wrong-length inputs
// return `SessionError` — no silent failures.

use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::device::DeviceKeypair;
use crate::keys::NoisePublicKey;
use crate::member::{member_id, member_name};
use crate::message::Message;
use crate::session::{SessionError as CoreSessionError, TruesealSession};
use crate::store::{PersistentLog, Store};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SessionError {
    #[error("invalid key length: expected {expected} bytes, got {got}")]
    InvalidKeyLength { expected: u32, got: u32 },
    #[error("invalid relay public key")]
    InvalidRelayPublicKey,
    #[error("invalid namespace: {msg}")]
    InvalidNamespace { msg: String },
    #[error("push failed: {msg}")]
    PushFailed { msg: String },
    #[error("invalid pairing token")]
    InvalidToken,
    #[error("not in any group")]
    NotInGroup,
    #[error("member not found")]
    MemberNotFound,
    #[error("group has been destroyed")]
    GroupDestroyed,
    /// The relay refused our Transport Version and reported the range it
    /// supports (ADR-0022). Outbox entries stay queued.
    #[error("relay supports Transport Version {min}..={max}")]
    RelayVersionUnsupported { min: u32, max: u32 },
    /// The `Sync` body exceeds the payload limit — at most the Protocol
    /// Size Limit of 61,440 bytes (ADR-0025; `payloadTooLarge{max}` in
    /// ADR-0028's error list). The body was never queued. Permanent — a
    /// retry with the same body fails the same way.
    #[error("payload too large: maximum {max} bytes")]
    PayloadTooLarge { max: u32 },
    /// The current manifest's version cannot be incremented — issuing would
    /// produce `u64::MAX`, which receivers reject (SYNC-10, ADR-0027).
    /// Membership is exhausted; the group's Devices must pair again.
    #[error("manifest version exhausted: cannot issue a new version")]
    ManifestVersionExhausted,
    /// `joinGroup` while already holding a Group Manifest — one Sync Group
    /// per namespace (ADR-0023; `alreadyInGroup` in ADR-0028's error list).
    #[error("already in a group")]
    AlreadyInGroup,
    /// A durable write failed — the operation did not commit and no
    /// in-memory state changed. The caller may retry.
    #[error("store write failed: {msg}")]
    StoreFailed { msg: String },
    /// The admission would exceed the Maximum Group Size (32, ADR-0027;
    /// `groupFull{max}` in ADR-0028's error list). The Pairing Window
    /// stays open.
    #[error("group is full: maximum {max} members")]
    GroupFull { max: u32 },
    /// The store was written by a newer release (a rollback) and is
    /// refused, unmodified — upgrade the SDK (ADR-0032; the 13th error
    /// case `storeTooNew` in ADR-0028's list).
    #[error("store was written by a newer release (store version {found}; this build supports up to {supported})")]
    StoreTooNew { found: u32, supported: u32 },
}

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
    /// Issued a Leave and waiting for the Relay to accept every push of
    /// it; then the device wipes, rotates its identity and returns to
    /// `NotJoined` (ADR-0027).
    Leaving,
    /// Started or received Destroy Group and waiting for the Relay to
    /// accept every queued Revoke; then the device wipes, rotates its
    /// identity and returns to `NotJoined` (ADR-0029).
    Destroying,
}

impl From<crate::session::GroupStatus> for GroupStatus {
    fn from(s: crate::session::GroupStatus) -> Self {
        match s {
            crate::session::GroupStatus::NotJoined => GroupStatus::NotJoined,
            crate::session::GroupStatus::PendingJoin => GroupStatus::PendingJoin,
            crate::session::GroupStatus::Member => GroupStatus::Member,
            crate::session::GroupStatus::Leaving => GroupStatus::Leaving,
            crate::session::GroupStatus::Destroying => GroupStatus::Destroying,
        }
    }
}

impl From<CoreSessionError> for SessionError {
    fn from(e: CoreSessionError) -> Self {
        match e {
            CoreSessionError::ConnectionFailed(msg) => SessionError::PushFailed { msg },
            CoreSessionError::PushFailed(msg) => SessionError::PushFailed { msg },
            CoreSessionError::NotInGroup => SessionError::NotInGroup,
            CoreSessionError::InvalidKeypairBytes => SessionError::InvalidKeyLength {
                expected: 64,
                got: 0,
            },
            CoreSessionError::InvalidToken => SessionError::InvalidToken,
            CoreSessionError::MemberNotFound => SessionError::MemberNotFound,
            CoreSessionError::GroupDestroyed => SessionError::GroupDestroyed,
            CoreSessionError::RelayVersionUnsupported { min, max } => {
                SessionError::RelayVersionUnsupported { min, max }
            }
            CoreSessionError::PayloadTooLarge { max } => SessionError::PayloadTooLarge { max },
            CoreSessionError::ManifestVersionExhausted => SessionError::ManifestVersionExhausted,
            CoreSessionError::AlreadyInGroup => SessionError::AlreadyInGroup,
            CoreSessionError::Store(msg) => SessionError::StoreFailed { msg },
            CoreSessionError::GroupFull { max } => SessionError::GroupFull { max },
            // The canonical reshape (SYNC-15) makes `closed` a first-class
            // typed case; until the new surface lands, map it honestly
            // rather than into the PushFailed catch-all.
            CoreSessionError::Closed => SessionError::PushFailed {
                msg: "session is closed".into(),
            },
        }
    }
}

// ── Version info ──────────────────────────────────────────────────────────────

/// Version triple reported by every TrueSeal SDK (ADR-0022, ADR-0030 §Reporting).
/// `transport_version` and `end_to_end_version` come from the core constants —
/// the single source of truth. `sdk_version` is this crate's package version.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TruesealInfo {
    pub sdk_version: String,
    pub transport_version: u32,
    pub end_to_end_version: u32,
}

/// The version triple for this build. Package versions imply nothing about
/// wire compatibility — the two protocol versions are the authority.
#[uniffi::export]
pub fn trueseal_info() -> TruesealInfo {
    TruesealInfo {
        sdk_version: env!("CARGO_PKG_VERSION").to_string(),
        transport_version: crate::version::TRANSPORT_VERSION,
        end_to_end_version: crate::version::END_TO_END_VERSION,
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// A remote group member as seen through the FFI surface.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Member {
    /// Stable opaque identifier, e.g. `"YWJjZGVmZ2"`.
    pub id: String,
    /// Auto-generated human-readable name, e.g. `"AmberFalcon"`.
    pub name: String,
}

// ── Callback interfaces ───────────────────────────────────────────────────────

/// Fired when a `Sync` message is delivered to this device.
/// `blob` is the raw application payload; `sender_noise_pub` is the sender's 32-byte X25519 key.
/// `message_id` is stable across re-delivery and opaque to callers.
#[uniffi::export(callback_interface)]
pub trait MessageCallback: Send + Sync {
    fn on_message(&self, blob: Vec<u8>, sender_noise_pub: Vec<u8>, message_id: String);
}

/// Fired when this device is excluded from an incoming `GroupManifest` update.
/// Another group member has issued a Soft Removal of this device (ADR-0015).
/// The session remains connected; the caller decides whether to wipe and re-pair.
#[uniffi::export(callback_interface)]
pub trait RemovedFromGroupCallback: Send + Sync {
    fn on_removed_from_group(&self);
}

/// Fired when a `Pair` message arrives within an open pairing window.
/// The caller shows UI ("Name wants to join — Accept?"), then calls
/// `accept_member(token)` or ignores the request.
#[uniffi::export(callback_interface)]
pub trait MemberRequestCallback: Send + Sync {
    fn on_member_request(&self, token: String, name: String);
}
/// After this fires the session is terminal; call `create()` on the same namespace
/// to start fresh with a new identity.
#[uniffi::export(callback_interface)]
pub trait GroupDestroyedCallback: Send + Sync {
    fn on_group_destroyed(&self);
}

/// Fired when a new member appears in an incoming manifest update or after `acceptMember` succeeds.
#[uniffi::export(callback_interface)]
pub trait MemberJoinedCallback: Send + Sync {
    fn on_member_joined(&self, member_id: String, member_name: String);
}

/// Fired when a member disappears from an incoming manifest update (Soft Removal).
/// Does NOT fire when the local device is the removed one — that fires `onRemovedFromGroup`.
#[uniffi::export(callback_interface)]
pub trait MemberLeftCallback: Send + Sync {
    fn on_member_left(&self, member_id: String, member_name: String);
}

/// Fired when the relay connection state changes.
/// `connected = true` when the relay connects; `false` when it disconnects.
/// Informational only — the library queues outbox messages and reconnects automatically.
/// Does NOT fire at session construction time.
#[uniffi::export(callback_interface)]
pub trait ConnectionChangedCallback: Send + Sync {
    fn on_connection_changed(&self, connected: bool);
}

/// Fired once from `create` when the store was unmigratable — unversioned
/// (a development-build store) or from before a Store Reset release — and
/// was automatically reset: group state wiped, fresh identity generated,
/// status `notJoined` with reason `storeReset` (ADR-0032, ADR-0028). The
/// object stays usable and can pair again. SYNC-15 folds this into the
/// canonical `statusChanged(status, reason)` event stream.
#[uniffi::export(callback_interface)]
pub trait StoreResetCallback: Send + Sync {
    fn on_store_reset(&self);
}

// ── TruesealFfiSession ────────────────────────────────────────────────────────────

/// A connected trueseal-sync session over TCP.
///
/// Create via `TruesealFfiSession.create(...)`.  All key arguments are raw bytes.
#[derive(uniffi::Object)]
pub struct TruesealFfiSession {
    inner: TruesealSession<TcpStream>,
}

#[uniffi::export]
impl TruesealFfiSession {
    /// Create a session. Always succeeds — the relay connects in the background.
    ///
    /// - `base_dir`: directory where the SQLite database is stored
    /// - `namespace`: scopes the database file; one session per namespace
    /// - `relay_host`: relay hostname or IP, e.g. `"relay.example.com"` (no port — ports are managed internally)
    /// - `relay_pub`: 32-byte X25519 relay public key (wrong length → `InvalidRelayPublicKey`)
    /// - `on_message`: called for every inbound `Sync` message
    ///
    /// The identity keypair is loaded from SQLite or auto-generated on first launch.
    /// Automatically reconnects on relay disconnects using an exponential backoff
    /// capped at 30 seconds.
    #[uniffi::constructor]
    pub fn create(
        base_dir: String,
        namespace: String,
        relay_host: String,
        relay_pub: Vec<u8>,
        on_message: Box<dyn MessageCallback>,
        on_removed_from_group: Box<dyn RemovedFromGroupCallback>,
        on_group_destroyed: Box<dyn GroupDestroyedCallback>,
        on_connection_changed: Option<Box<dyn ConnectionChangedCallback>>,
        on_store_reset: Option<Box<dyn StoreResetCallback>>,
    ) -> Result<Arc<Self>, SessionError> {
        // Validate namespace: must be non-empty and match [a-zA-Z0-9_-]+
        if namespace.is_empty()
            || !namespace
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(SessionError::InvalidNamespace {
                msg: format!("namespace must match [a-zA-Z0-9_-]+ (got {:?})", namespace),
            });
        }
        // Validate every fallible argument BEFORE the store open: if
        // create() fails after an automatic Store Reset ran, the reset's
        // callback below would never fire and the wipe would be invisible
        // to the app (B11 review). Cheap pure validation first keeps
        // `storeReset` observable on every path.
        let relay_pub_key =
            noise_pub_from_bytes(&relay_pub).map_err(|_| SessionError::InvalidRelayPublicKey)?;
        // SYNC-13 (ADR-0032): the first open runs the Store Version state
        // machine — chained migrations, an automatic Store Reset for an
        // unmigratable store, a typed refusal for a newer one. Later opens
        // see a current store and are no-ops.
        let (store, open_outcome) =
            Store::open_with_outcome(Path::new(&base_dir), &namespace).map_err(map_store_error)?;
        // After a Store Reset the identity row is empty: the library
        // generates a fresh identity here, and the session below starts
        // NotJoined — `storeReset` is reported once construction succeeds.
        let keypair = load_or_generate_keypair(&store)?;

        // SYNC-7 (#99): the manifest slot is created and seeded from the store
        // BEFORE the session (and its reconnect loop) starts, so the receive
        // path never observes a transient `None`. The on_message closure shares
        // the same slot for sender attribution, so it resolves the sender's
        // noise key from the very first Deliver — no late-bind window.
        // A store read error leaves the slot empty, matching the previous
        // restore-failure tolerance: `create()` stays infallible (ADR-0017).
        let manifest: Arc<Mutex<Option<crate::manifest::GroupManifest>>> =
            Arc::new(Mutex::new(store.load_group_manifest().ok().flatten()));
        // Wrap callbacks in Arc so the on_message closure can be Clone
        // (required by connect_background for the reconnect loop).
        let on_message = Arc::new(on_message);
        let manifest_cb = manifest.clone();

        // Open a second store handle for PersistentLog (same DB file, separate connection).
        let log_store = Store::open(Path::new(&base_dir), &namespace).map_err(map_store_error)?;

        let manifest_store_save = Arc::new(Mutex::new(
            Store::open(Path::new(&base_dir), &namespace).map_err(map_store_error)?,
        ));

        // Open a fourth store handle for the wipe + rotate on deliberate
        // removal, a completed Leave and a completed Destroy Group
        // (ADR-0027, ADR-0029).
        let rotate_store = Arc::new(Mutex::new(
            Store::open(Path::new(&base_dir), &namespace).map_err(map_store_error)?,
        ));

        let receive_addr = format!("{}:7700", relay_host);
        let push_addr = format!("{}:7701", relay_host);
        let relay_addr_factory = receive_addr.clone();
        let inner = TruesealSession::connect_background_rotating(
            relay_pub_key,
            keypair,
            move |msg, author_signing_pub, sequence| {
                if let Message::Sync { body } = msg {
                    let sender_noise_pub = manifest_cb
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                        .and_then(|manifest| manifest.noise_pub_for_signing(&author_signing_pub))
                        .map(|k| k.0.to_vec())
                        .unwrap_or_default();
                    let message_id = crate::message::message_id(&author_signing_pub, sequence);
                    on_message.on_message(body, sender_noise_pub, message_id);
                }
            },
            Box::new(PersistentLog::new(log_store)),
            manifest,
            move || {
                on_removed_from_group.on_removed_from_group();
            },
            move |m: &crate::manifest::GroupManifest| {
                let _ = manifest_store_save
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .save_group_manifest(m);
            },
            // ADR-0029: this fires at Destroy COMPLETION — the Relay has
            // accepted every queued Revoke and the wipe + identity rotation
            // already ran through `on_identity_rotated` (below). Pure
            // notification: wiping here would delete the fresh keypair the
            // rotation just persisted.
            move || {
                on_group_destroyed.on_group_destroyed();
            },
            // ADR-0027: on deliberate removal or a completed Leave the core
            // has already rotated the in-memory identity; here the
            // namespace's store is wiped (manifest, identity, outbox, dedup,
            // pending records — one transaction) and the fresh keypair is
            // persisted, so a restart opens as the rotated device.
            move |fresh: DeviceKeypair| {
                let store = rotate_store.lock().unwrap_or_else(|e| e.into_inner());
                let _ = store.wipe();
                let _ = store.save_keypair(&fresh);
            },
            move || {
                let s = TcpStream::connect(&relay_addr_factory).map_err(|e| e.to_string())?;
                s.set_nonblocking(true).map_err(|e| e.to_string())?;
                Ok(s)
            }, // transport_factory (XX, :7700)
            move || {
                let s = TcpStream::connect(&push_addr).map_err(|e| e.to_string())?;
                s.set_nonblocking(true).map_err(|e| e.to_string())?;
                Ok(s)
            }, // push_factory (NK, :7701)
            None, // use default 30-second cap
            on_connection_changed.map(
                |cb| -> Box<dyn Fn(crate::session::ConnectionChange) + Send + Sync + 'static> {
                    Box::new(move |change| {
                        cb.on_connection_changed(matches!(
                            change,
                            crate::session::ConnectionChange::Connected
                        ))
                    })
                },
            ),
        )
        .map_err(SessionError::from)?;

        let session = Arc::new(Self { inner });
        // ADR-0032: report the automatic Store Reset —
        // `statusChanged(notJoined, storeReset)` in ADR-0028's terms — once
        // the object exists and is usable (it can pair again immediately).
        if open_outcome.reset {
            if let Some(cb) = &on_store_reset {
                cb.on_store_reset();
            }
        }
        Ok(session)
    }

    /// Opens a pairing window and returns an opaque base64url token carrying a
    /// fresh single-use Pairing Secret (ADR-0023): only a party that saw this
    /// token out-of-band can raise a Join Request.
    /// The window stays open until either `acceptMember()` is called (single-use:
    /// the window closes after the first accept) or the caller explicitly calls
    /// `cancelPairing()`. There is no auto-expiry — the caller controls lifetime
    /// by closing the pairing UI and calling `cancelPairing()` on dismiss (ADR-0021).
    /// The token encodes a version byte, `noise_pub || signing_pub || secret ||
    /// device_name` — pass it to the peer's `joinGroup(token)` call.
    ///
    /// Documented limitation (ADR-0023): anyone who sees the token while the
    /// window is open can request to join — confirm the device in front of you.
    /// Fails typed `groupDestroyed` while Destroying (ADR-0029): a Destroying
    /// device admits no one.
    pub fn pairing_token(&self) -> Result<String, SessionError> {
        self.inner.pairing_token().map_err(SessionError::from)
    }

    /// Join a group as the responding device by decoding the initiator's `token`
    /// and durably queueing a `Pair` message with this device's public keys and
    /// the token's Pairing Secret (ADR-0023). The device moves to
    /// `GroupStatus::PendingJoin` and accepts only a first manifest anchored to
    /// the token's signing key. `Ok` means durably queued — do not retry.
    ///
    /// Returns `SessionError::AlreadyInGroup` if a manifest exists; a second
    /// call while pending replaces the Pending Join. Returns
    /// `SessionError::InvalidToken` if the token is malformed or predates the
    /// Pairing Secret.
    pub fn join_group(&self, token: String) -> Result<(), SessionError> {
        self.inner.join_group(&token).map_err(SessionError::from)
    }

    /// Abandon a Pending Join (ADR-0023): the device moves back to
    /// `GroupStatus::NotJoined` and no manifest will be accepted.
    pub fn cancel_join(&self) {
        self.inner.cancel_join();
    }

    /// Where this device stands in its namespace's Sync Group (ADR-0028).
    pub fn group_status(&self) -> GroupStatus {
        self.inner.group_status().into()
    }

    /// Register the callback fired when a `Pair` message arrives within an open pairing window.
    ///
    /// `callback.on_member_request(token, name)` fires with the opaque request token
    /// and the auto-generated member name. Pass `token` to `accept_member(token)` to admit.
    pub fn set_on_member_request(&self, callback: Box<dyn MemberRequestCallback>) {
        self.inner.set_on_member_request(move |token, name| {
            callback.on_member_request(token, name);
        });
    }

    /// Admit a pending member identified by their opaque `token` from `onMemberRequest`.
    ///
    /// Returns `Ok(true)` if admitted, `Ok(false)` if the token is unknown or the
    /// pairing window closed. Errors: `GroupFull` when the admission would exceed
    /// the Maximum Group Size of 32 (ADR-0027), `StoreFailed` if the durable
    /// commit failed (nothing changed — retry is safe).
    pub fn accept_member(&self, token: String) -> Result<bool, SessionError> {
        self.inner.accept_member(&token).map_err(SessionError::from)
    }

    /// Register the callback fired when a new member joins the group.
    ///
    /// Fires both on the admitting device (after `acceptMember`) and on all other
    /// current members when they receive the updated manifest.
    pub fn set_on_member_joined(&self, callback: Box<dyn MemberJoinedCallback>) {
        self.inner.set_on_member_joined(move |id, name| {
            callback.on_member_joined(id, name);
        });
    }

    /// Register the callback fired when a member is removed from the group (Soft Removal).
    ///
    /// Does NOT fire when the local device is removed — that fires `onRemovedFromGroup`.
    pub fn set_on_member_left(&self, callback: Box<dyn MemberLeftCallback>) {
        self.inner.set_on_member_left(move |id, name| {
            callback.on_member_left(id, name);
        });
    }

    /// Close the pairing window without admitting any device.
    pub fn cancel_pairing(&self) {
        self.inner.cancel_pairing();
    }

    /// Stable opaque identifier for the local device.
    /// Derived from the local signing public key — identical to the `id`
    /// field this device would have in a remote device's `members()` list.
    pub fn local_node_id(&self) -> String {
        member_id(&self.inner.signing_pub())
    }

    /// Auto-generated display name for the local device.
    /// Derived from the local signing public key — identical to the `name`
    /// field this device would have in a remote device's `members()` list.
    pub fn local_device_name(&self) -> String {
        member_name(&self.inner.signing_pub())
    }

    /// List remote group members (excludes the local device).
    ///
    /// Returns an empty `Vec` when no manifest is set.
    /// Each `Member` has a stable `id` and an auto-generated `name`.
    pub fn members(&self) -> Vec<Member> {
        self.inner
            .members()
            .into_iter()
            .map(|m| Member {
                id: m.id,
                name: m.name,
            })
            .collect()
    }

    /// Remove a group member by their opaque `member_id` from `members()`.
    ///
    /// Issues a new manifest excluding the target and propagates it to all
    /// remaining members (including the removed device so it can fire
    /// `onRemovedFromGroup`).
    ///
    /// Returns `SessionError::NotInGroup` if no manifest is set.
    /// Returns `SessionError::MemberNotFound` if no member with that id exists.
    pub fn remove_member(&self, member_id: String) -> Result<(), SessionError> {
        self.inner
            .remove_member_by_id(&member_id)
            .map_err(SessionError::from)
    }

    /// Encrypt `blob` and fan out to all current group members.
    /// Returns `SessionError::NotInGroup` if the session has no manifest yet.
    pub fn send(&self, blob: Vec<u8>) -> Result<(), SessionError> {
        self.inner.push_sync(blob).map_err(SessionError::from)
    }

    /// Leave the Sync Group (ADR-0027): issue a manifest excluding this
    /// device and enter `GroupStatus::Leaving`. The device stops sending and
    /// handling `Sync`, stays connected until the Relay has accepted every
    /// Leave push, then wipes its group state, rotates its identity and
    /// returns to `NotJoined`. Survives restarts; idempotent while a Leave
    /// is in flight.
    pub fn leave_group(&self) -> Result<(), SessionError> {
        self.inner.leave_group().map_err(SessionError::from)
    }

    /// Destroy the group (ADR-0029): persist the Destroying state and queue one
    /// Revoke per member through the outbox, in one transaction. The device stays
    /// `GroupStatus::Destroying` — no `send()`, no handlers, still connected —
    /// until the relay has accepted every Revoke; then it wipes, rotates its
    /// identity and `on_group_destroyed` fires as the device returns to
    /// `NotJoined`. No-op while already Destroying; `NotInGroup` in
    /// `pendingJoin` / `notJoined`.
    pub fn destroy_group(&self) -> Result<(), SessionError> {
        self.inner.destroy_group().map_err(SessionError::from)
    }
}

// ── Storage helpers ───────────────────────────────────────────────────────────

/// Load the identity keypair from `store`, or generate and persist a fresh one.
/// Map a store failure to the typed taxonomy (ADR-0028): a newer store is
/// `storeTooNew`; anything else is the `storage` case.
fn map_store_error(e: crate::store::StoreError) -> SessionError {
    match e {
        crate::store::StoreError::StoreTooNew { found, supported } => {
            SessionError::StoreTooNew { found, supported }
        }
        other => SessionError::StoreFailed {
            msg: format!("store: {other}"),
        },
    }
}

fn load_or_generate_keypair(store: &Store) -> Result<DeviceKeypair, SessionError> {
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

// ── Key parsing helpers ───────────────────────────────────────────────────────

fn noise_pub_from_bytes(bytes: &[u8]) -> Result<NoisePublicKey, SessionError> {
    bytes
        .try_into()
        .map(NoisePublicKey)
        .map_err(|_| SessionError::InvalidKeyLength {
            expected: 32,
            got: bytes.len() as u32,
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrong-length relay_pub returns SessionError::InvalidKeyLength.
    #[test]
    fn short_relay_pub_returns_error() {
        let result = noise_pub_from_bytes(&[0u8; 10]);
        assert!(matches!(
            result,
            Err(SessionError::InvalidKeyLength {
                expected: 32,
                got: 10
            })
        ));
    }

    /// SessionError::NotInGroup variant exists and is distinct.
    #[test]
    fn not_in_group_error_variant_exists() {
        let e = SessionError::NotInGroup;
        assert!(matches!(e, SessionError::NotInGroup));
    }

    /// Store::load_or_generate round-trips the same keypair on second call.
    #[test]
    fn store_load_or_generate_is_stable() {
        let dir = tempfile::TempDir::new().unwrap();
        let s1 = crate::store::Store::open(dir.path(), "test").expect("open");
        let kp1 = load_or_generate_keypair(&s1).expect("first");
        let s2 = crate::store::Store::open(dir.path(), "test").expect("reopen");
        let kp2 = load_or_generate_keypair(&s2).expect("second");
        assert_eq!(
            kp1.public_key(),
            kp2.public_key(),
            "same keypair after reopen"
        );
    }

    /// Invalid namespace (empty or bad chars) returns InvalidNamespace.
    #[test]
    fn invalid_namespace_returns_error() {
        struct NoopMsg;
        impl MessageCallback for NoopMsg {
            fn on_message(&self, _blob: Vec<u8>, _snp: Vec<u8>, _message_id: String) {}
        }
        struct NoopRfg;
        impl RemovedFromGroupCallback for NoopRfg {
            fn on_removed_from_group(&self) {}
        }
        struct NoopGd;
        impl GroupDestroyedCallback for NoopGd {
            fn on_group_destroyed(&self) {}
        }
        let dir = tempfile::TempDir::new().unwrap();
        let relay_pub = vec![0u8; 32];

        for bad in &["", "bad namespace", "no/slash", "dot.bad", "sp ace"] {
            let result = TruesealFfiSession::create(
                dir.path().to_string_lossy().into_owned(),
                bad.to_string(),
                "relay.example.com".into(),
                relay_pub.clone(),
                Box::new(NoopMsg),
                Box::new(NoopRfg),
                Box::new(NoopGd),
                None,
                None,
            );
            assert!(
                matches!(result, Err(SessionError::InvalidNamespace { .. })),
                "namespace {bad:?} should return InvalidNamespace"
            );
        }
    }

    /// Two sessions with different namespaces have independent identities.
    #[test]
    fn different_namespaces_have_independent_identities() {
        let dir = tempfile::TempDir::new().unwrap();
        let s1 = crate::store::Store::open(dir.path(), "alpha").expect("open alpha");
        let s2 = crate::store::Store::open(dir.path(), "beta").expect("open beta");
        let kp1 = load_or_generate_keypair(&s1).expect("kp1");
        let kp2 = load_or_generate_keypair(&s2).expect("kp2");
        assert_ne!(
            kp1.public_key(),
            kp2.public_key(),
            "different namespaces must generate independent identities"
        );
    }

    /// trueseal_info() reports the core version constants — the single source
    /// of truth — plus the crate version (ADR-0022 Reporting).
    #[test]
    fn trueseal_info_reports_the_protocol_versions() {
        let info = trueseal_info();
        assert_eq!(info.transport_version, crate::TRANSPORT_VERSION);
        assert_eq!(info.end_to_end_version, crate::END_TO_END_VERSION);
        assert_eq!(info.transport_version, 1);
        assert_eq!(info.end_to_end_version, 1);
        assert!(!info.sdk_version.is_empty());
    }

    /// Same namespace returns the same identity on second open.
    #[test]
    fn same_namespace_is_stable_across_opens() {
        let dir = tempfile::TempDir::new().unwrap();
        let s1 = crate::store::Store::open(dir.path(), "myapp").expect("first open");
        let kp1 = load_or_generate_keypair(&s1).expect("kp1");
        drop(s1);
        let s2 = crate::store::Store::open(dir.path(), "myapp").expect("second open");
        let kp2 = load_or_generate_keypair(&s2).expect("kp2");
        assert_eq!(
            kp1.public_key(),
            kp2.public_key(),
            "same namespace must return same identity after re-open"
        );
    }
}

#[cfg(test)]
mod store_versioning_ffi_tests {
    //! SYNC-13 (#105, ADR-0032): the FFI surface of the Store Version state
    //! machine — the automatic Store Reset reports `storeReset` and the
    //! object can pair again; a newer store is refused with `storeTooNew`.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NoopMsg;
    impl MessageCallback for NoopMsg {
        fn on_message(&self, _blob: Vec<u8>, _snp: Vec<u8>, _message_id: String) {}
    }
    struct NoopRfg;
    impl RemovedFromGroupCallback for NoopRfg {
        fn on_removed_from_group(&self) {}
    }
    struct NoopGd;
    impl GroupDestroyedCallback for NoopGd {
        fn on_group_destroyed(&self) {}
    }

    struct CountingReset(Arc<AtomicUsize>);
    impl StoreResetCallback for CountingReset {
        fn on_store_reset(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A store whose version keys are gone (a development-build artifact) is
    /// unmigratable: create() resets it, fires on_store_reset once, and the
    /// session is NotJoined with a fresh identity, ready to pair again.
    #[test]
    fn unversioned_store_is_reset_reported_and_pairable() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().to_string_lossy().into_owned();
        // A populated store that then loses its version keys.
        {
            let s = crate::store::Store::open(dir.path(), "app").expect("open");
            let kp = DeviceKeypair::generate();
            s.save_keypair(&kp).expect("save");
            let conn = rusqlite::Connection::open(dir.path().join("trueseal_app.db")).unwrap();
            conn.execute(
                "DELETE FROM meta WHERE key IN ('store_version', 'e2e_version')",
                [],
            )
            .unwrap();
        }
        let resets = Arc::new(AtomicUsize::new(0));
        let session = TruesealFfiSession::create(
            base.clone(),
            "app".into(),
            "127.0.0.1:9".into(), // unreachable — connectivity is background
            vec![0u8; 32],
            Box::new(NoopMsg),
            Box::new(NoopRfg),
            Box::new(NoopGd),
            None,
            Some(Box::new(CountingReset(resets.clone()))),
        )
        .expect("create succeeds — the reset is automatic");
        assert_eq!(resets.load(Ordering::SeqCst), 1, "storeReset reported once");
        assert_eq!(session.group_status(), GroupStatus::NotJoined);
        // The object can pair again.
        assert!(!session.pairing_token().expect("window opens").is_empty());
        // Destroying outside a group is a typed error, not a panic
        // (ADR-0029 state table).
        assert!(matches!(
            session.destroy_group(),
            Err(SessionError::NotInGroup)
        ));
    }

    /// A store written by a newer release: create() fails with the typed
    /// StoreTooNew and the store's bytes are unchanged.
    #[test]
    fn newer_store_fails_create_with_store_too_new() {
        let dir = tempfile::TempDir::new().unwrap();
        {
            let _s = crate::store::Store::open(dir.path(), "app").expect("open");
            let conn = rusqlite::Connection::open(dir.path().join("trueseal_app.db")).unwrap();
            conn.execute("UPDATE meta SET value = 99 WHERE key = 'store_version'", [])
                .unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        let before = std::fs::read(dir.path().join("trueseal_app.db")).unwrap();
        let result = TruesealFfiSession::create(
            dir.path().to_string_lossy().into_owned(),
            "app".into(),
            "127.0.0.1:9".into(),
            vec![0u8; 32],
            Box::new(NoopMsg),
            Box::new(NoopRfg),
            Box::new(NoopGd),
            None,
            None,
        );
        match result {
            Err(SessionError::StoreTooNew { found, supported }) => {
                assert_eq!(found, 99);
                assert_eq!(supported, crate::version::STORE_VERSION);
            }
            other => panic!("expected StoreTooNew, got {:?}", other.map(|_| "session")),
        }
        let after = std::fs::read(dir.path().join("trueseal_app.db")).unwrap();
        assert_eq!(before, after, "refused store: bytes unchanged");
    }
}
