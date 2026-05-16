mod reconnect;
#[cfg(test)]
mod test_helpers;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use trueseal_noise::keypair::Keypair as NoiseKeypair;

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::{member_id, member_name};
use crate::message::{device_name, Message};
use crate::operation_log::{MemLog, OperationLog};
use crate::relay::{build_push_blob, push_send, RelayClient};

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
}

// ── Internal types ────────────────────────────────────────────────────────────

/// An open pairing window — present means open, absent means closed.
/// Lifetime is caller-controlled: open on `pairing_token()`, closed on
/// `accept_pair()` (single-use) or explicit `cancel_pairing()` (ADR-0021).
pub(super) struct PairingWindow;

impl PairingWindow {
    fn is_open(&self) -> bool {
        true
    }
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

// ── TruesealSession ───────────────────────────────────────────────────────────────

/// The opinionated session facade (ADR-0010 / ADR-0014).
///
/// Owns the relay connection, sequence counter, signing keypair, pairing state,
/// and current GroupManifest.
/// Transport-generic so tests can inject in-memory pipes.
pub struct TruesealSession<T: Read + Write + Send + 'static> {
    client: Arc<Mutex<RelayClient<T>>>,
    /// Raw relay public key used as the NK push target (ADR-0018).
    relay_pub_bytes: [u8; 32],
    /// Factory that opens a fresh transport to the relay for each NK push.
    push_factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync + 'static>,
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
    /// Fired when the group is destroyed (destroyGroup or receiving Revoke).
    on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static>,
    /// Set to true after destroy_group() or receiving Revoke. All subsequent
    /// operations that mutate state return SessionError::GroupDestroyed.
    destroyed: Arc<AtomicBool>,
    /// Pending member requests keyed by opaque token, set via set_on_member_request.
    pending_members: Arc<Mutex<HashMap<String, PendingMember>>>,
    /// Fired when a Pair message arrives inside an open pairing window.
    /// `(token, name)` — caller shows UI then calls `accept_member(token)`.
    on_member_request: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
    /// Fired when a new member appears in an incoming manifest update.
    on_member_joined: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
    /// Fired when a member disappears from an incoming manifest update (not for local device).
    on_member_left: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
}

/// Builds the full manifest-aware subscribe handler.
///
/// Extracted so both `connect_full` (initial connection) and `reconnect_loop`
/// (every reconnect) share identical dispatch logic — any change to message
/// handling semantics needs to be made exactly once here.
pub(super) fn build_subscribe_handler(
    keys: Arc<Mutex<KeyState>>,
    manifest: Arc<Mutex<Option<GroupManifest>>>,
    on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static>,
    on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static>,
    on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static>,
    destroyed: Arc<AtomicBool>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    pending_members: Arc<Mutex<HashMap<String, PendingMember>>>,
    on_member_request: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
    on_member_joined: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
    on_member_left: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
    on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static,
) -> impl Fn(Message, [u8; 32], u64) + Send + 'static {
    move |msg, author_signing_pub, sequence| {
        // ── Pair (handled before manifest filter — joiner is not yet a member) ──
        if let Message::Pair {
            noise_pub,
            signing_pub,
        } = &msg
        {
            let window_open = pairing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|w| w.is_open())
                .unwrap_or(false);
            if window_open {
                use base64::Engine as _;
                let token_bytes: [u8; 16] = rand::random();
                let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
                let name = member_name(&SigningPublicKey(*signing_pub));
                pending_members
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        token.clone(),
                        PendingMember {
                            noise_pub: NoisePublicKey(*noise_pub),
                            signing_pub: SigningPublicKey(*signing_pub),
                        },
                    );
                if let Some(cb) = on_member_request
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                {
                    cb(token, name);
                }
            }
            return;
        }

        // ── Manifest-based inbound filtering ──────────────────────────────────
        {
            let guard = manifest.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref m) = *guard {
                if !m.contains_signing_pub(&author_signing_pub) {
                    return; // not a member — discard
                }
            }
        }

        // ── Revoke ────────────────────────────────────────────────────────────
        if let Message::Revoke = &msg {
            let in_group = {
                let guard = manifest.lock().unwrap_or_else(|e| e.into_inner());
                guard
                    .as_ref()
                    .map(|m| m.contains_signing_pub(&author_signing_pub))
                    .unwrap_or(false)
            };
            if in_group {
                *manifest.lock().unwrap_or_else(|e| e.into_inner()) = None;
                destroyed.store(true, Ordering::Release);
                (on_group_destroyed)();
            }
            return;
        }

        // ── GroupManifest update ───────────────────────────────────────────────
        if let Message::GroupManifest { manifest: incoming } = &msg {
            let local_signing_pub = keys.lock().unwrap_or_else(|e| e.into_inner()).signing_pub.0;
            let mut guard = manifest.lock().unwrap_or_else(|e| e.into_inner());
            let accept = match *guard {
                None => incoming.verify(None).is_ok(),
                Some(ref current) => incoming.verify(Some(current)).is_ok(),
            };
            if accept {
                let excluded = !incoming.contains_signing_pub(&local_signing_pub);

                let (joined, left): (Vec<_>, Vec<_>) = {
                    let prev_pubs: std::collections::HashSet<[u8; 32]> = guard
                        .as_ref()
                        .map(|m| m.members.iter().map(|mm| mm.signing_pub.0).collect())
                        .unwrap_or_default();
                    let next_pubs: std::collections::HashSet<[u8; 32]> =
                        incoming.members.iter().map(|mm| mm.signing_pub.0).collect();
                    let joined = incoming
                        .members
                        .iter()
                        .filter(|mm| !prev_pubs.contains(&mm.signing_pub.0))
                        .map(|mm| (member_id(&mm.signing_pub), member_name(&mm.signing_pub)))
                        .collect();
                    let left = guard
                        .as_ref()
                        .map(|m| {
                            m.members
                                .iter()
                                .filter(|mm| {
                                    !next_pubs.contains(&mm.signing_pub.0)
                                        // Don't fire onMemberLeft for local device.
                                        && mm.signing_pub.0 != local_signing_pub
                                })
                                .map(|mm| {
                                    (member_id(&mm.signing_pub), member_name(&mm.signing_pub))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    (joined, left)
                };

                *guard = Some(incoming.clone());
                drop(guard); // release lock BEFORE firing any callback

                (on_manifest_changed)(incoming);

                if let Some(cb) = on_member_joined
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                {
                    for (id, name) in joined {
                        cb(id, name);
                    }
                }
                if let Some(cb) = on_member_left
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                {
                    for (id, name) in left {
                        cb(id, name);
                    }
                }

                if excluded {
                    (on_removed_from_group)();
                }
            }
            return;
        }

        on_message(msg, author_signing_pub, sequence);
    }
}

impl<T: Read + Write + Send + 'static> TruesealSession<T> {
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

    /// Send a `Pair` message to the initiator identified by `token`.
    /// Called by the joining device after scanning a QR code or receiving the token.
    /// Returns `SessionError::InvalidToken` if the token cannot be decoded.
    pub fn join_group(&self, token: &str) -> Result<(), SessionError> {
        let (initiator_noise, _initiator_signing, _initiator_name) =
            crate::message::decode_pairing_token(token).map_err(|_| SessionError::InvalidToken)?;
        let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let msg = Message::Pair {
            noise_pub: ks.noise_pub.0,
            signing_pub: ks.signing_pub.0,
        };
        drop(ks);
        self.push_message(&msg, NoisePublicKey(initiator_noise))
            .map_err(|e| SessionError::PushFailed(e.to_string()))
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
        let destroyed: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

        let keys_cb = keys.clone();
        let manifest_cb = manifest.clone();
        let on_rfg_cb = on_removed_from_group.clone();
        let on_mc_cb = on_manifest_changed.clone();
        let on_gd_cb = on_group_destroyed.clone();
        let destroyed_cb = destroyed.clone();
        let pending_cb: Arc<Mutex<HashMap<String, PendingMember>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let on_mr_cb: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>> =
            Arc::new(Mutex::new(None));
        let pending_cb_ret = pending_cb.clone();
        let on_mr_cb_ret = on_mr_cb.clone();
        let pairing_cb = pairing.clone();
        let on_mj_cb: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>> =
            Arc::new(Mutex::new(None));
        let on_ml_cb: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>> =
            Arc::new(Mutex::new(None));
        let on_mj_cb_ret = on_mj_cb.clone();
        let on_ml_cb_ret = on_ml_cb.clone();

        let client = RelayClient::connect(transport, relay_pub, noise_kp)
            .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;

        client.subscribe(build_subscribe_handler(
            keys_cb,
            manifest_cb,
            on_rfg_cb,
            on_mc_cb,
            on_gd_cb,
            destroyed_cb,
            pairing_cb,
            pending_cb,
            on_mr_cb,
            on_mj_cb,
            on_ml_cb,
            on_message,
        ));

        // Restore sequence counter from the op log so it never re-uses a
        // sequence number after a process restart (ADR-0011).
        let initial_seq = op_log.max_sequence().map(|s| s + 1).unwrap_or(0);

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            relay_pub_bytes: relay_pub.0,
            push_factory: Arc::new(push_factory),
            keys,
            sequence: Arc::new(Mutex::new(initial_seq)),
            pairing,
            op_log: Arc::new(Mutex::new(op_log)),
            manifest,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            destroyed,
            pending_members: pending_cb_ret,
            on_member_request: on_mr_cb_ret,
            on_member_joined: on_mj_cb_ret,
            on_member_left: on_ml_cb_ret,
        })
    }

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
        on_connection_changed: Option<Box<dyn Fn(bool) + Send + Sync + 'static>>,
    ) -> Result<Self, SessionError> {
        let transport_factory = Arc::new(transport_factory);
        let session = Self::connect_full(
            transport,
            relay_pub,
            keypair,
            on_message.clone(),
            op_log,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            push_factory,
        )?;
        let client_arc = session.client.clone();
        let op_log_arc = session.op_log.clone();
        let keys_arc = session.keys.clone();
        let manifest_arc = session.manifest.clone();
        let on_rfg_arc = session.on_removed_from_group.clone();
        let on_mc_arc = session.on_manifest_changed.clone();
        let on_gd_arc = session.on_group_destroyed.clone();
        let destroyed_arc = session.destroyed.clone();
        let pairing_arc = session.pairing.clone();
        let pending_arc = session.pending_members.clone();
        let on_mr_arc = session.on_member_request.clone();
        let on_mj_arc = session.on_member_joined.clone();
        let on_ml_arc = session.on_member_left.clone();
        let push_factory_arc = session.push_factory.clone();
        let cap = reconnect_cap.unwrap_or(DEFAULT_RECONNECT_CAP);
        let on_cc: Arc<dyn Fn(bool) + Send + Sync + 'static> = on_connection_changed
            .map(|f| -> Arc<dyn Fn(bool) + Send + Sync + 'static> { Arc::new(f) })
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
                on_gd_arc,
                destroyed_arc,
                pairing_arc,
                pending_arc,
                on_mr_arc,
                on_mj_arc,
                on_ml_arc,
                transport_factory,
                push_factory_arc,
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
    /// Per ADR-0017 / PHILOSOPHY: `create()` is infallible. Use this constructor at the
    /// FFI boundary so `create()` always succeeds regardless of relay reachability.
    pub fn connect_background(
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
        on_connection_changed: Option<Box<dyn Fn(bool) + Send + Sync + 'static>>,
    ) -> Result<Self, SessionError> {
        // Build all arcs directly — mirrors connect_full but without an initial transport.
        let keys = Arc::new(Mutex::new(KeyState::from_keypair(&keypair)));
        let manifest: Arc<Mutex<Option<GroupManifest>>> = Arc::new(Mutex::new(None));
        let pairing: Arc<Mutex<Option<PairingWindow>>> = Arc::new(Mutex::new(None));
        let on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_removed_from_group);
        let on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static> =
            Arc::new(on_manifest_changed);
        let on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_group_destroyed);
        let destroyed: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let pending_members: Arc<Mutex<HashMap<String, PendingMember>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let on_member_request: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>> =
            Arc::new(Mutex::new(None));
        let on_member_joined: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>> =
            Arc::new(Mutex::new(None));
        let on_member_left: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>> =
            Arc::new(Mutex::new(None));

        let transport_factory = Arc::new(transport_factory);
        let push_factory_arc: Arc<dyn Fn() -> Result<T, String> + Send + Sync + 'static> =
            Arc::new(push_factory);
        let push_factory_for_reconnect = push_factory_arc.clone();

        // Stub client: permanently disconnected — the reconnect loop will replace it.
        let client: Arc<Mutex<RelayClient<T>>> = Arc::new(Mutex::new(RelayClient::disconnected()));
        let op_log_arc: Arc<Mutex<Box<dyn OperationLog>>> = Arc::new(Mutex::new(op_log));

        // Restore sequence counter from the op log so it never re-uses a
        // sequence number after a process restart (ADR-0011).
        let initial_seq = op_log_arc
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .max_sequence()
            .map(|s| s + 1)
            .unwrap_or(0);

        let session = Self {
            client: client.clone(),
            relay_pub_bytes: relay_pub.0,
            push_factory: push_factory_arc,
            keys: keys.clone(),
            sequence: Arc::new(Mutex::new(initial_seq)),
            pairing: pairing.clone(),
            op_log: op_log_arc.clone(),
            manifest: manifest.clone(),
            on_removed_from_group: on_removed_from_group.clone(),
            on_manifest_changed: on_manifest_changed.clone(),
            on_group_destroyed: on_group_destroyed.clone(),
            destroyed: destroyed.clone(),
            pending_members: pending_members.clone(),
            on_member_request: on_member_request.clone(),
            on_member_joined: on_member_joined.clone(),
            on_member_left: on_member_left.clone(),
        };

        let cap = reconnect_cap.unwrap_or(DEFAULT_RECONNECT_CAP);
        let on_cc: Arc<dyn Fn(bool) + Send + Sync + 'static> = on_connection_changed
            .map(|f| -> Arc<dyn Fn(bool) + Send + Sync + 'static> { Arc::new(f) })
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
                on_group_destroyed,
                destroyed,
                pairing,
                pending_members,
                on_member_request,
                on_member_joined,
                on_member_left,
                transport_factory,
                push_factory_for_reconnect,
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
    pub fn push_sync(&self, blob: Vec<u8>) -> Result<(), SessionError> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(SessionError::GroupDestroyed);
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

        if !self
            .client
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_connected()
        {
            // Blob is durably queued in the outbox; delivery is guaranteed on
            // reconnect. Return Ok(()) — the caller should not retry (ADR-0017).
            let seq = self.next_seq();
            for r in &recipients {
                self.op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .append(&r.0, seq, blob.clone());
            }
            return Ok(());
        }

        let msg = Message::Sync { body: blob.clone() };
        let seq = self.next_seq();
        let signing = self.signing();

        let mut last_err: Option<String> = None;
        for recipient_pub in recipients {
            let oid = recipient_pub.0;
            self.op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .append(&oid, seq, blob.clone());
            let result =
                build_push_blob(&msg, recipient_pub, seq, vec![], &signing).and_then(|framed| {
                    (self.push_factory)()
                        .map_err(crate::relay::RelayError::PushFailed)
                        .and_then(|transport| push_send(transport, self.relay_pub_bytes, framed))
                });
            match result {
                Ok(_) => {
                    self.op_log
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .mark_delivered(&oid, seq);
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                }
            }
        }
        match last_err {
            None => Ok(()),
            Some(e) => Err(SessionError::PushFailed(e)),
        }
    }

    pub(crate) fn push_message(
        &self,
        msg: &Message,
        recipient_pub: NoisePublicKey,
    ) -> Result<(), SessionError> {
        let seq = self.next_seq();
        let signing = self.signing();
        build_push_blob(msg, recipient_pub, seq, vec![], &signing)
            .map_err(|e| SessionError::PushFailed(e.to_string()))
            .and_then(|framed| {
                (self.push_factory)()
                    .map_err(SessionError::PushFailed)
                    .and_then(|transport| {
                        push_send(transport, self.relay_pub_bytes, framed)
                            .map(|_| ())
                            .map_err(|e| SessionError::PushFailed(e.to_string()))
                    })
            })
    }

    // ── Destroy Group (ADR-0015) ──────────────────────────────────────────────

    /// Push `Message::Revoke` to all manifest members, wipe local manifest,
    /// set session terminal, and fire `on_group_destroyed`.
    ///
    /// After this call, all subsequent `push_sync` / `send` calls return
    /// `SessionError::GroupDestroyed`. The next `create()` on the same namespace
    /// generates a fresh identity automatically.
    pub fn destroy_group(&self) {
        let self_noise = self
            .keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .noise_pub;
        let peers: Vec<NoisePublicKey> = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            match *guard {
                None => vec![],
                Some(ref m) => m
                    .members
                    .iter()
                    .filter(|mb| mb.noise_pub != self_noise)
                    .map(|mb| mb.noise_pub)
                    .collect(),
            }
        };
        for peer in peers {
            // TODO(P1): Revoke is not queued to the outbox. If the relay is unreachable
            // at this moment, peers will never know the group was destroyed. Fix: add
            // control-plane messages (Revoke, GroupManifest) to the outbox with a
            // non-Sync message type tag, and replay them on reconnect.
            let _ = self.push_message(&Message::Revoke, peer);
        }
        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.destroyed.store(true, Ordering::Release);
        (self.on_group_destroyed)();
    }

    // ── Pairing ───────────────────────────────────────────────────────────────

    /// Opens a pairing window and returns a base64url token encoding
    /// `noise_pub || signing_pub || device_name`.
    /// The token is single-use and expires when the window closes.
    pub fn pairing_token(&self) -> String {
        *self.pairing.lock().unwrap_or_else(|e| e.into_inner()) = Some(PairingWindow);
        let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        crate::message::pairing_token(&ks.noise_pub.0, &ks.signing_pub.0)
    }

    pub fn cancel_pairing(&self) {
        *self.pairing.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.pending_members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Admit a device; requires both noise and signing pub keys.
    /// Returns `true` if the device was admitted (window open), `false` if the window was
    /// closed or had already expired.
    ///
    /// On success: issues a new `GroupManifest` (genesis or version+1), stores it locally,
    /// and pushes it to all existing members plus the new member.
    pub fn accept_pair(&self, noise_pub: NoisePublicKey, signing_pub: SigningPublicKey) -> bool {
        let window_open = {
            let guard = self.pairing.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|w| w.is_open()).unwrap_or(false)
        };
        // Always clear the window.
        *self.pairing.lock().unwrap_or_else(|e| e.into_inner()) = None;

        if !window_open {
            return false;
        }

        // Build new manifest.
        let new_member = ManifestMember {
            noise_pub,
            signing_pub,
            name: device_name(&signing_pub.0),
        };

        let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let self_noise = ks.noise_pub;
        let self_signing = ks.signing_pub;
        let signing_key = SigningKey::from_bytes(&ks.signing_priv);
        drop(ks);

        let new_manifest = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            match &*guard {
                None => {
                    // Genesis: version 1, self + new member.
                    GroupManifest::new(
                        new_group_id(),
                        1,
                        vec![
                            ManifestMember {
                                noise_pub: self_noise,
                                signing_pub: self_signing,
                                name: device_name(&self_signing.0),
                            },
                            new_member,
                        ],
                        &signing_key,
                    )
                }
                Some(current) => {
                    // Extend existing manifest.
                    let mut members = current.members.clone();
                    members.push(new_member);
                    GroupManifest::new(current.group_id, current.version + 1, members, &signing_key)
                }
            }
        };

        // Determine who to notify: all existing members except self + the new member.
        let notify: Vec<NoisePublicKey> = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let existing = guard
                .as_ref()
                .map(|m| {
                    m.members
                        .iter()
                        .filter(|mb| mb.noise_pub != self_noise)
                        .map(|mb| mb.noise_pub)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            existing
        };

        // Store the new manifest.
        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(new_manifest.clone());
        (self.on_manifest_changed)(&new_manifest);

        // Fire onMemberJoined for the newly admitted device.
        if let Some(cb) = self
            .on_member_joined
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            cb(
                crate::member::member_id(&signing_pub),
                crate::member::member_name(&signing_pub),
            );
        }

        // Push GroupManifest to all existing members (excluding self).
        // TODO(P1): GroupManifest pushes are not queued to the outbox. If the relay is
        // unreachable here, the new member never receives the manifest and cannot sync.
        // Fix: queue control-plane messages to the outbox alongside Sync messages.
        let msg = Message::GroupManifest {
            manifest: new_manifest,
        };
        for peer in &notify {
            let _ = self.push_message(&msg, *peer);
        }
        // Push to the new member.
        let _ = self.push_message(&msg, noise_pub);

        true
    }

    /// Register the callback fired when a `Pair` message arrives within an open pairing window.
    ///
    /// The callback receives `(token, name)`. The caller passes `token` back to
    /// [`Self::accept_member`] to admit the device.
    ///
    /// TODO(P6): This callback is registered post-construction whereas `on_message`,
    /// `on_removed_from_group`, and `on_group_destroyed` are constructor params. There
    /// is a window between construction and this call where an inbound Pair message
    /// would be queued to `pending_members` but `on_member_request` would not fire.
    /// In practice this window is closed before the relay delivers any message, but
    /// the asymmetry is surprising. Fix: move all callbacks to the constructor or
    /// make all of them post-construction setters.
    pub fn set_on_member_request(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        *self
            .on_member_request
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(cb));
    }

    /// Register the callback fired when a new member appears in an incoming manifest update.
    /// `(id, name)` — same format as [`Self::members`].
    pub fn set_on_member_joined(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        *self
            .on_member_joined
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(cb));
    }

    /// Register the callback fired when a member disappears from an incoming manifest update.
    /// Does NOT fire when the local device is the removed one (that's `on_removed_from_group`).
    /// `(id, name)` — same format as [`Self::members`].
    pub fn set_on_member_left(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        *self
            .on_member_left
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(cb));
    }

    /// Admit a pending member identified by their opaque `token` from `on_member_request`.
    ///
    /// Returns `true` if the token was valid and the member was admitted.
    /// Returns `false` if the token is unknown or the pairing window has closed.
    /// Clears the pairing window on success (single-use window).
    pub fn accept_member(&self, token: &str) -> bool {
        let pending = self
            .pending_members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
        match pending {
            None => false,
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
        let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let signing_key = SigningKey::from_bytes(&ks.signing_priv);
        drop(ks);

        let (new_manifest, notify, target_noise) = {
            let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let current = guard.as_ref().ok_or(SessionError::NotInGroup)?;

            // Find the target member (need their noise_pub to push the manifest to them).
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

            let new_manifest = GroupManifest::new(
                current.group_id,
                current.version + 1,
                remaining,
                &signing_key,
            );

            // Notify: all remaining members excluding self.
            let self_noise = self
                .keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .noise_pub;
            let notify: Vec<NoisePublicKey> = new_manifest
                .members
                .iter()
                .filter(|m| m.noise_pub != self_noise)
                .map(|m| m.noise_pub)
                .collect();

            (new_manifest, notify, target_noise)
        };

        // Update local manifest and fire persistence callback.
        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(new_manifest.clone());
        (self.on_manifest_changed)(&new_manifest);

        let msg = Message::GroupManifest {
            manifest: new_manifest,
        };
        // TODO(P1): GroupManifest pushes from remove_member are not queued to the
        // outbox. If delivery fails, the removed member is never notified and
        // remaining members don't converge. Fix: outbox support for control-plane messages.
        // Push to remaining members (excluding self).
        for peer in &notify {
            let _ = self.push_message(&msg, *peer);
        }
        // Push to the removed member so their on_removed_from_group fires.
        let _ = self.push_message(&msg, target_noise);

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

    /// Replace the current manifest. Used by acceptMember (#26/#27) and tests.
    pub fn set_manifest(&self, m: GroupManifest) {
        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn next_seq(&self) -> u64 {
        let mut s = self.sequence.lock().unwrap_or_else(|e| e.into_inner());
        let v = *s;
        *s += 1;
        v
    }

    fn signing(&self) -> SigningKeypair {
        let ks = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        SigningKeypair::from_signing_key(SigningKey::from_bytes(&ks.signing_priv))
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
        let stream =
            TcpStream::connect(addr).map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;
        let addr = addr.to_string();
        let push_factory = move || TcpStream::connect(&addr).map_err(|e| e.to_string());
        Self::connect(stream, relay_pub, keypair, on_message, push_factory)
    }
}
