// FFI surface for Swift and Kotlin via UniFFI (proc-macro mode).
//
// Exposes a single `HushFfiSession` object over TCP transport.
// All key material crosses the boundary as `Vec<u8>`; wrong-length inputs
// return `SessionError` — no silent failures.

use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::device::DeviceKeypair;
use crate::keys::NoisePublicKey;
use crate::message::Message;
use crate::session::{HushSession, SessionError as CoreSessionError};
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
        }
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
#[uniffi::export(callback_interface)]
pub trait MessageCallback: Send + Sync {
    fn on_message(&self, blob: Vec<u8>, sender_noise_pub: Vec<u8>);
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

// ── HushFfiSession ────────────────────────────────────────────────────────────

/// A connected hush-sync session over TCP.
///
/// Create via `HushFfiSession.create(...)`.  All key arguments are raw bytes.
#[derive(uniffi::Object)]
pub struct HushFfiSession {
    inner: HushSession<TcpStream>,
}

#[uniffi::export]
impl HushFfiSession {
    /// Create a session. Always succeeds — the relay connects in the background.
    ///
    /// - `base_dir`: directory where the SQLite database is stored
    /// - `namespace`: scopes the database file; one session per namespace
    /// - `relay_addr`: TCP address, e.g. `"relay.example.com:4433"`
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
        relay_addr: String,
        relay_pub: Vec<u8>,
        on_message: Box<dyn MessageCallback>,
        on_removed_from_group: Box<dyn RemovedFromGroupCallback>,
        on_group_destroyed: Box<dyn GroupDestroyedCallback>,
        on_connection_changed: Option<Box<dyn ConnectionChangedCallback>>,
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
        let store = Store::open(Path::new(&base_dir), &namespace).map_err(|e| {
            SessionError::InvalidNamespace {
                msg: format!("store: {e}"),
            }
        })?;
        let keypair = load_or_generate_keypair(&store)?;
        let relay_pub_key =
            noise_pub_from_bytes(&relay_pub).map_err(|_| SessionError::InvalidRelayPublicKey)?;

        // Late-bind slot: filled after the session is built so the on_message
        // closure can look up sender noise pub from the session's manifest.
        let manifest_slot: Arc<Mutex<Option<Arc<Mutex<Option<crate::manifest::GroupManifest>>>>>> =
            Arc::new(Mutex::new(None));
        // Wrap callbacks in Arc so the on_message closure can be Clone
        // (required by connect_background for the reconnect loop).
        let on_message = Arc::new(on_message);
        let manifest_slot_cb = manifest_slot.clone();

        // Open a second store handle for PersistentLog (same DB file, separate connection).
        let log_store = Store::open(Path::new(&base_dir), &namespace).map_err(|e| {
            SessionError::InvalidNamespace {
                msg: format!("store: {e}"),
            }
        })?;

        // Open a third store handle for manifest persistence.
        let manifest_store = Store::open(Path::new(&base_dir), &namespace).map_err(|e| {
            SessionError::InvalidNamespace {
                msg: format!("store: {e}"),
            }
        })?;
        let manifest_store_save = Arc::new(Mutex::new(
            Store::open(Path::new(&base_dir), &namespace).map_err(|e| {
                SessionError::InvalidNamespace {
                    msg: format!("store: {e}"),
                }
            })?,
        ));

        // Open a fourth store handle for wiping on group destroy.
        let wipe_store = Arc::new(Mutex::new(
            Store::open(Path::new(&base_dir), &namespace).map_err(|e| {
                SessionError::InvalidNamespace {
                    msg: format!("store: {e}"),
                }
            })?,
        ));

        let relay_addr_factory = relay_addr.clone();
        let inner = HushSession::connect_background(
            relay_pub_key,
            keypair,
            move |msg, author_signing_pub| {
                if let Message::Sync { body } = msg {
                    let sender_noise_pub = manifest_slot_cb
                        .lock()
                        .unwrap()
                        .as_ref()
                        .and_then(|m| {
                            m.lock()
                                .unwrap()
                                .as_ref()
                                .and_then(|manifest| {
                                    manifest.noise_pub_for_signing(&author_signing_pub)
                                })
                                .map(|k| k.0.to_vec())
                        })
                        .unwrap_or_default();
                    on_message.on_message(body, sender_noise_pub);
                }
            },
            Box::new(PersistentLog::new(log_store)),
            move || {
                on_removed_from_group.on_removed_from_group();
            },
            move |m: &crate::manifest::GroupManifest| {
                let _ = manifest_store_save.lock().unwrap().save_group_manifest(m);
            },
            move || {
                let _ = wipe_store.lock().unwrap().wipe();
                on_group_destroyed.on_group_destroyed();
            },
            move || TcpStream::connect(&relay_addr_factory).map_err(|e| e.to_string()),
            None, // use default 30-second cap
            on_connection_changed.map(|cb| -> Box<dyn Fn(bool) + Send + Sync + 'static> {
                Box::new(move |connected| cb.on_connection_changed(connected))
            }),
        )
        .map_err(SessionError::from)?;

        // Restore manifest from store if one was persisted in a previous session.
        if let Ok(Some(manifest)) = manifest_store.load_group_manifest() {
            inner.set_manifest(manifest);
        }

        // Wire the manifest arc into the closure's slot now that the session exists.
        *manifest_slot.lock().unwrap() = Some(inner.manifest.clone());

        Ok(Arc::new(Self { inner }))
    }

    /// Opens a 60-second pairing window and returns an opaque base64url token.
    /// The token encodes `noise_pub || signing_pub || device_name` — pass it to
    /// the peer's `join_group(token)` call.  Single-use; expires with the window.
    pub fn pairing_token(&self) -> String {
        self.inner.pairing_token()
    }

    /// Join a group as the responding device by decoding the initiator's `token`
    /// and sending a `Pair` message with this device's public keys.
    /// Returns `SessionError::InvalidToken` if the token is malformed.
    pub fn join_group(&self, token: String) -> Result<(), SessionError> {
        self.inner.join_group(&token).map_err(SessionError::from)
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
    /// Returns `true` if admitted, `false` if the token is unknown or the pairing window closed.
    pub fn accept_member(&self, token: String) -> bool {
        self.inner.accept_member(&token)
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

    /// Destroy the group: push Revoke to all members, wipe local state, fire on_group_destroyed.
    /// Session becomes terminal — all subsequent `send()` calls return `GroupDestroyed`.
    pub fn destroy_group(&self) {
        self.inner.destroy_group();
    }
}

// ── Storage helpers ───────────────────────────────────────────────────────────

/// Load the identity keypair from `store`, or generate and persist a fresh one.
fn load_or_generate_keypair(store: &Store) -> Result<DeviceKeypair, SessionError> {
    match store.load_keypair() {
        Ok(Some(kp)) => Ok(kp),
        Ok(None) => {
            let kp = DeviceKeypair::generate();
            store
                .save_keypair(&kp)
                .map_err(|e| SessionError::InvalidNamespace {
                    msg: format!("store: {e}"),
                })?;
            Ok(kp)
        }
        Err(e) => Err(SessionError::InvalidNamespace {
            msg: format!("store: {e}"),
        }),
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
            fn on_message(&self, _blob: Vec<u8>, _snp: Vec<u8>) {}
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
            let result = HushFfiSession::create(
                dir.path().to_string_lossy().into_owned(),
                bad.to_string(),
                "relay.example.com:4433".into(),
                relay_pub.clone(),
                Box::new(NoopMsg),
                Box::new(NoopRfg),
                Box::new(NoopGd),
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
