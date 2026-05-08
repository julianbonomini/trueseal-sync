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
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use hush_noise::keypair::Keypair as NoiseKeypair;
use thiserror::Error;

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::{member_id, member_name};
use crate::message::{device_name, Message};
use crate::operation_log::{MemLog, OperationLog};
use crate::relay::RelayClient;

const DEFAULT_PAIRING_WINDOW: Duration = Duration::from_secs(60);
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

pub(super) struct PairingWindow {
    deadline: Instant,
}

impl PairingWindow {
    fn is_open(&self) -> bool {
        Instant::now() < self.deadline
    }
}

/// All mutable key material — replaced atomically on key rotation.
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

// ── HushSession ───────────────────────────────────────────────────────────────

/// The opinionated session facade (ADR-0010 / ADR-0014).
///
/// Owns the relay connection, sequence counter, signing keypair, pairing state,
/// and current GroupManifest.
/// Transport-generic so tests can inject in-memory pipes.
pub struct HushSession<T: Read + Write + Send + 'static> {
    client: Arc<Mutex<RelayClient<T>>>,
    keys: Arc<Mutex<KeyState>>,
    sequence: Arc<Mutex<u64>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    pub op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    /// Current group membership record. `None` means not yet in any group.
    /// Updated atomically when a valid higher-version GroupManifest is received.
    pub manifest: Arc<Mutex<Option<GroupManifest>>>,
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

impl<T: Read + Write + Send + 'static> HushSession<T> {
    /// Current noise public key for this session.
    pub fn noise_pub(&self) -> NoisePublicKey {
        self.keys.lock().unwrap().noise_pub
    }

    /// Current signing public key for this session.
    pub fn signing_pub(&self) -> SigningPublicKey {
        self.keys.lock().unwrap().signing_pub
    }

    /// List of remote group members (excludes the local device).
    ///
    /// Returns an empty `Vec` when no manifest is set.
    /// Each entry has a stable `id` and an auto-generated `name` derived from
    /// the member's signing public key — see [`crate::member`].
    pub fn members(&self) -> Vec<Member> {
        let local_signing = self.keys.lock().unwrap().signing_pub;
        let guard = self.manifest.lock().unwrap();
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
        let ks = self.keys.lock().unwrap();
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
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static,
    ) -> Result<Self, SessionError> {
        Self::connect_with_log(
            transport,
            relay_pub,
            keypair,
            on_message,
            Box::new(MemLog::new()),
        )
    }

    pub fn connect_with_log(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static,
        op_log: Box<dyn OperationLog>,
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
        )
    }

    pub fn connect_full(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static,
        op_log: Box<dyn OperationLog>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, SessionError> {
        let keys = Arc::new(Mutex::new(KeyState::from_keypair(&keypair)));
        let noise_kp = {
            let ks = keys.lock().unwrap();
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

        client.subscribe(move |msg, author_signing_pub| {
            // ── Pair (handled before manifest filter — joiner is not yet a member) ──
            if let Message::Pair {
                noise_pub,
                signing_pub,
            } = &msg
            {
                let window_open = pairing_cb
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|w| w.is_open())
                    .unwrap_or(false);
                if window_open {
                    use base64::Engine as _;
                    let token_bytes: [u8; 16] = rand::random();
                    let token =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
                    let name = crate::member::member_name(&SigningPublicKey(*signing_pub));
                    pending_cb.lock().unwrap().insert(
                        token.clone(),
                        PendingMember {
                            noise_pub: NoisePublicKey(*noise_pub),
                            signing_pub: SigningPublicKey(*signing_pub),
                        },
                    );
                    if let Some(cb) = on_mr_cb.lock().unwrap().as_ref() {
                        cb(token, name);
                    }
                }
                return;
            }

            // ── Manifest-based inbound filtering ──────────────────────────
            {
                let guard = manifest_cb.lock().unwrap();
                if let Some(ref m) = *guard {
                    if !m.contains_signing_pub(&author_signing_pub) {
                        return; // not a member — discard
                    }
                }
            }

            // ── Revoke ────────────────────────────────────────────────────
            if let Message::Revoke = &msg {
                let in_group = {
                    let guard = manifest_cb.lock().unwrap();
                    guard
                        .as_ref()
                        .map(|m| m.contains_signing_pub(&author_signing_pub))
                        .unwrap_or(false)
                };
                if in_group {
                    // Wipe local manifest (keypair rotation is now internal on next create()).
                    *manifest_cb.lock().unwrap() = None;
                    destroyed_cb.store(true, Ordering::Release);
                    (on_gd_cb)();
                }
                return;
            }

            // ── GroupManifest update ───────────────────────────────────────
            if let Message::GroupManifest { manifest: incoming } = &msg {
                let local_signing_pub = keys_cb.lock().unwrap().signing_pub.0;
                let mut guard = manifest_cb.lock().unwrap();
                let accept = match *guard {
                    None => incoming.verify(None).is_ok(),
                    Some(ref current) => incoming.verify(Some(current)).is_ok(),
                };
                if accept {
                    let excluded = !incoming.contains_signing_pub(&local_signing_pub);

                    // Diff previous vs incoming to compute joined/left sets.
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
                            .map(|mm| {
                                (
                                    crate::member::member_id(&mm.signing_pub),
                                    crate::member::member_name(&mm.signing_pub),
                                )
                            })
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
                                        (
                                            crate::member::member_id(&mm.signing_pub),
                                            crate::member::member_name(&mm.signing_pub),
                                        )
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        (joined, left)
                    };

                    *guard = Some(incoming.clone());
                    (on_mc_cb)(incoming);
                    drop(guard);

                    // Fire joined/left callbacks.
                    if let Some(cb) = on_mj_cb.lock().unwrap().as_ref() {
                        for (id, name) in joined {
                            cb(id, name);
                        }
                    }
                    if let Some(cb) = on_ml_cb.lock().unwrap().as_ref() {
                        for (id, name) in left {
                            cb(id, name);
                        }
                    }

                    if excluded {
                        (on_rfg_cb)();
                    }
                }
                return;
            }

            on_message(msg, author_signing_pub);
        });

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            keys,
            sequence: Arc::new(Mutex::new(0)),
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
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        transport_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        reconnect_cap: Option<Duration>,
    ) -> Result<Self, SessionError> {
        let session = Self::connect_full(
            transport,
            relay_pub,
            keypair,
            on_message.clone(),
            op_log,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
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
        let cap = reconnect_cap.unwrap_or(DEFAULT_RECONNECT_CAP);
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
                Arc::new(transport_factory),
                cap,
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
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        on_removed_from_group: impl Fn() + Send + Sync + 'static,
        on_manifest_changed: impl Fn(&GroupManifest) + Send + Sync + 'static,
        on_group_destroyed: impl Fn() + Send + Sync + 'static,
        transport_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        reconnect_cap: Option<Duration>,
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

        // Stub client: permanently disconnected — the reconnect loop will replace it.
        let client: Arc<Mutex<RelayClient<T>>> = Arc::new(Mutex::new(RelayClient::disconnected()));
        let op_log_arc: Arc<Mutex<Box<dyn OperationLog>>> = Arc::new(Mutex::new(op_log));

        let session = Self {
            client: client.clone(),
            keys: keys.clone(),
            sequence: Arc::new(Mutex::new(0)),
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
                Arc::new(transport_factory),
                cap,
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
            let guard = self.manifest.lock().unwrap();
            match *guard {
                None => return Err(SessionError::NotInGroup),
                Some(ref m) => {
                    let self_noise = self.keys.lock().unwrap().noise_pub;
                    m.members
                        .iter()
                        .filter(|member| member.noise_pub != self_noise)
                        .map(|member| member.noise_pub)
                        .collect()
                }
            }
        };

        if !self.client.lock().unwrap().is_connected() {
            // Still append to outbox for each recipient so reconnect can replay.
            let seq = self.next_seq();
            for r in &recipients {
                self.op_log.lock().unwrap().append(&r.0, seq, blob.clone());
            }
            return Err(SessionError::PushFailed("relay disconnected".into()));
        }

        let msg = Message::Sync { body: blob.clone() };
        let seq = self.next_seq();
        let signing = self.signing();

        let mut last_err: Option<String> = None;
        for recipient_pub in recipients {
            let oid = recipient_pub.0;
            self.op_log.lock().unwrap().append(&oid, seq, blob.clone());
            let result =
                self.client
                    .lock()
                    .unwrap()
                    .push(&msg, recipient_pub, seq, vec![], &signing);
            match result {
                Ok(()) => {
                    self.op_log.lock().unwrap().mark_delivered(&oid, seq);
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
        self.client
            .lock()
            .unwrap()
            .push(msg, recipient_pub, seq, vec![], &signing)
            .map_err(|e| SessionError::PushFailed(e.to_string()))
    }

    // ── Destroy Group (ADR-0015) ──────────────────────────────────────────────

    /// Push `Message::Revoke` to all manifest members, wipe local manifest,
    /// set session terminal, and fire `on_group_destroyed`.
    ///
    /// After this call, all subsequent `push_sync` / `send` calls return
    /// `SessionError::GroupDestroyed`. The next `create()` on the same namespace
    /// generates a fresh identity automatically.
    pub fn destroy_group(&self) {
        let peers: Vec<NoisePublicKey> = {
            let guard = self.manifest.lock().unwrap();
            match *guard {
                None => vec![],
                Some(ref m) => m.members.iter().map(|mb| mb.noise_pub).collect(),
            }
        };
        for peer in peers {
            let _ = self.push_message(&Message::Revoke, peer);
        }
        *self.manifest.lock().unwrap() = None;
        self.destroyed.store(true, Ordering::Release);
        (self.on_group_destroyed)();
    }

    // ── Pairing ───────────────────────────────────────────────────────────────

    /// Opens a pairing window and returns a base64url token encoding
    /// `noise_pub || signing_pub || device_name`.
    /// The token is single-use and expires when the window closes.
    pub fn pairing_token(&self) -> String {
        self.pairing_token_with_duration(DEFAULT_PAIRING_WINDOW)
    }

    pub fn pairing_token_with_duration(&self, duration: Duration) -> String {
        *self.pairing.lock().unwrap() = Some(PairingWindow {
            deadline: Instant::now() + duration,
        });
        let ks = self.keys.lock().unwrap();
        crate::message::pairing_token(&ks.noise_pub.0, &ks.signing_pub.0)
    }

    pub fn cancel_pairing(&self) {
        *self.pairing.lock().unwrap() = None;
    }

    /// Admit a device; requires both noise and signing pub keys.
    /// Returns `true` if the device was admitted (window open), `false` if the window was
    /// closed or had already expired.
    ///
    /// On success: issues a new `GroupManifest` (genesis or version+1), stores it locally,
    /// and pushes it to all existing members plus the new member.
    pub fn accept_pair(&self, noise_pub: NoisePublicKey, signing_pub: SigningPublicKey) -> bool {
        let window_open = {
            let guard = self.pairing.lock().unwrap();
            guard.as_ref().map(|w| w.is_open()).unwrap_or(false)
        };
        // Always clear the window.
        *self.pairing.lock().unwrap() = None;

        if !window_open {
            return false;
        }

        // Build new manifest.
        let new_member = ManifestMember {
            noise_pub,
            signing_pub,
            name: device_name(&signing_pub.0),
        };

        let ks = self.keys.lock().unwrap();
        let self_noise = ks.noise_pub;
        let self_signing = ks.signing_pub;
        let signing_key = SigningKey::from_bytes(&ks.signing_priv);
        drop(ks);

        let new_manifest = {
            let guard = self.manifest.lock().unwrap();
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
            let guard = self.manifest.lock().unwrap();
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
        *self.manifest.lock().unwrap() = Some(new_manifest.clone());
        (self.on_manifest_changed)(&new_manifest);

        // Fire onMemberJoined for the newly admitted device.
        if let Some(cb) = self.on_member_joined.lock().unwrap().as_ref() {
            cb(
                crate::member::member_id(&signing_pub),
                crate::member::member_name(&signing_pub),
            );
        }

        // Push GroupManifest to all existing members (excluding self).
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
    pub fn set_on_member_request(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        *self.on_member_request.lock().unwrap() = Some(Box::new(cb));
    }

    /// Register the callback fired when a new member appears in an incoming manifest update.
    /// `(id, name)` — same format as [`Self::members`].
    pub fn set_on_member_joined(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        *self.on_member_joined.lock().unwrap() = Some(Box::new(cb));
    }

    /// Register the callback fired when a member disappears from an incoming manifest update.
    /// Does NOT fire when the local device is the removed one (that's `on_removed_from_group`).
    /// `(id, name)` — same format as [`Self::members`].
    pub fn set_on_member_left(&self, cb: impl Fn(String, String) + Send + Sync + 'static) {
        *self.on_member_left.lock().unwrap() = Some(Box::new(cb));
    }

    /// Admit a pending member identified by their opaque `token` from `on_member_request`.
    ///
    /// Returns `true` if the token was valid and the member was admitted.
    /// Returns `false` if the token is unknown or the pairing window has closed.
    /// Clears the pairing window on success (single-use window).
    pub fn accept_member(&self, token: &str) -> bool {
        let pending = self.pending_members.lock().unwrap().remove(token);
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
        let ks = self.keys.lock().unwrap();
        let signing_key = SigningKey::from_bytes(&ks.signing_priv);
        drop(ks);

        let (new_manifest, notify, target_noise) = {
            let guard = self.manifest.lock().unwrap();
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
            let self_noise = self.keys.lock().unwrap().noise_pub;
            let notify: Vec<NoisePublicKey> = new_manifest
                .members
                .iter()
                .filter(|m| m.noise_pub != self_noise)
                .map(|m| m.noise_pub)
                .collect();

            (new_manifest, notify, target_noise)
        };

        // Update local manifest and fire persistence callback.
        *self.manifest.lock().unwrap() = Some(new_manifest.clone());
        (self.on_manifest_changed)(&new_manifest);

        let msg = Message::GroupManifest {
            manifest: new_manifest,
        };
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
            let guard = self.manifest.lock().unwrap();
            let m = guard.as_ref().ok_or(SessionError::NotInGroup)?;
            m.members
                .iter()
                .find(|mm| crate::member::member_id(&mm.signing_pub) == id)
                .map(|mm| mm.signing_pub)
                .ok_or(SessionError::MemberNotFound)?
        };
        self.remove_member(target)
    }

    pub fn cancel_pairing_window(&self) {
        self.cancel_pairing();
    }

    // ── Manifest helpers ──────────────────────────────────────────────────────

    /// Replace the current manifest. Used by acceptMember (#26/#27) and tests.
    pub fn set_manifest(&self, m: GroupManifest) {
        *self.manifest.lock().unwrap() = Some(m);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn next_seq(&self) -> u64 {
        let mut s = self.sequence.lock().unwrap();
        let v = *s;
        *s += 1;
        v
    }

    fn signing(&self) -> SigningKeypair {
        let ks = self.keys.lock().unwrap();
        SigningKeypair::from_signing_key(SigningKey::from_bytes(&ks.signing_priv))
    }
}

// ── TCP convenience constructor ───────────────────────────────────────────────

impl HushSession<TcpStream> {
    pub fn connect_tcp(
        addr: &str,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static,
    ) -> Result<Self, SessionError> {
        let stream =
            TcpStream::connect(addr).map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;
        Self::connect(stream, relay_pub, keypair, on_message)
    }
}
