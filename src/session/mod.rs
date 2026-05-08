mod reconnect;
#[cfg(test)]
mod test_helpers;
#[cfg(test)]
mod tests;

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
use crate::message::{device_name, pairing_payload, Message};
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

struct PairingWindow {
    deadline: Instant,
    on_paired: Box<dyn Fn(NoisePublicKey) + Send + 'static>,
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

// ── HushSession ───────────────────────────────────────────────────────────────

/// The opinionated session facade (ADR-0010 / ADR-0014).
///
/// Owns the relay connection, sequence counter, signing keypair, pairing state,
/// current GroupManifest, and key-rotation callback.
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
    /// Fired after key rotation with `noise_priv || signing_priv` (64 bytes).
    on_keypair_rotated: Arc<dyn Fn([u8; 64]) + Send + Sync + 'static>,
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
            |_| {},
        )
    }

    pub fn connect_with_log(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static,
        op_log: Box<dyn OperationLog>,
        on_keypair_rotated: impl Fn([u8; 64]) + Send + Sync + 'static,
    ) -> Result<Self, SessionError> {
        Self::connect_full(
            transport,
            relay_pub,
            keypair,
            on_message,
            op_log,
            on_keypair_rotated,
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
        on_keypair_rotated: impl Fn([u8; 64]) + Send + Sync + 'static,
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
        let on_keypair_rotated: Arc<dyn Fn([u8; 64]) + Send + Sync + 'static> =
            Arc::new(on_keypair_rotated);
        let on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_removed_from_group);
        let on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static> =
            Arc::new(on_manifest_changed);
        let on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static> =
            Arc::new(on_group_destroyed);
        let destroyed: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

        let keys_cb = keys.clone();
        let manifest_cb = manifest.clone();
        let on_kpr_cb = on_keypair_rotated.clone();
        let on_rfg_cb = on_removed_from_group.clone();
        let on_mc_cb = on_manifest_changed.clone();
        let on_gd_cb = on_group_destroyed.clone();
        let destroyed_cb = destroyed.clone();

        let client = RelayClient::connect(transport, relay_pub, noise_kp)
            .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;

        client.subscribe(move |msg, author_signing_pub| {
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
                    *guard = Some(incoming.clone());
                    (on_mc_cb)(incoming);
                    drop(guard);
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
            pairing: Arc::new(Mutex::new(None)),
            op_log: Arc::new(Mutex::new(op_log)),
            manifest,
            on_keypair_rotated,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
            destroyed,
        })
    }

    pub fn connect_with_reconnect(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message, [u8; 32]) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        on_keypair_rotated: impl Fn([u8; 64]) + Send + Sync + 'static,
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
            on_keypair_rotated,
            on_removed_from_group,
            on_manifest_changed,
            on_group_destroyed,
        )?;
        let client_arc = session.client.clone();
        let op_log_arc = session.op_log.clone();
        let keys_arc = session.keys.clone();
        let manifest_arc = session.manifest.clone();
        let on_kpr_arc = session.on_keypair_rotated.clone();
        let on_rfg_arc = session.on_removed_from_group.clone();
        let on_mc_arc = session.on_manifest_changed.clone();
        let on_gd_arc = session.on_group_destroyed.clone();
        let destroyed_arc = session.destroyed.clone();
        let cap = reconnect_cap.unwrap_or(DEFAULT_RECONNECT_CAP);
        std::thread::spawn(move || {
            reconnect::reconnect_loop(
                client_arc,
                op_log_arc,
                relay_pub,
                keys_arc,
                manifest_arc,
                on_message,
                on_kpr_arc,
                on_rfg_arc,
                on_mc_arc,
                on_gd_arc,
                destroyed_arc,
                Arc::new(transport_factory),
                cap,
            );
        });
        Ok(session)
    }

    // ── Push ──────────────────────────────────────────────────────────────────

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

    // ── Revocation ────────────────────────────────────────────────────────────

    /// Push `Message::Revoke` to all members in the current manifest, wipe manifest,
    /// and rotate keys.
    pub fn revoke(&self) {
        let peers: Vec<NoisePublicKey> = {
            let guard = self.manifest.lock().unwrap();
            match *guard {
                None => vec![],
                Some(ref m) => m.members.iter().map(|member| member.noise_pub).collect(),
            }
        };
        for peer in peers {
            let _ = self.push_message(&Message::Revoke, peer);
        }
        self.execute_rotation();
    }

    fn execute_rotation(&self) {
        let new_kp = DeviceKeypair::generate();
        let mut rotated = [0u8; 64];
        rotated[..32].copy_from_slice(&new_kp.noise.private());
        rotated[32..].copy_from_slice(&new_kp.signing.to_bytes());
        *self.keys.lock().unwrap() = KeyState::from_keypair(&new_kp);
        *self.manifest.lock().unwrap() = None;
        (self.on_keypair_rotated)(rotated);
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
            on_paired: Box::new(|_| {}),
        });
        let ks = self.keys.lock().unwrap();
        crate::message::pairing_token(&ks.noise_pub.0, &ks.signing_pub.0)
    }

    /// Opens a pairing window and returns the raw 64-byte payload (noise_pub || signing_pub).
    /// Kept for internal use by session tests.
    pub(crate) fn start_pairing(
        &self,
        on_paired: impl Fn(NoisePublicKey) + Send + 'static,
    ) -> Vec<u8> {
        self.start_pairing_with_duration(DEFAULT_PAIRING_WINDOW, on_paired)
    }

    pub(crate) fn start_pairing_with_duration(
        &self,
        duration: Duration,
        on_paired: impl Fn(NoisePublicKey) + Send + 'static,
    ) -> Vec<u8> {
        *self.pairing.lock().unwrap() = Some(PairingWindow {
            deadline: Instant::now() + duration,
            on_paired: Box::new(on_paired),
        });
        let ks = self.keys.lock().unwrap();
        pairing_payload(&ks.noise_pub.0, &ks.signing_pub.0)
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

    pub fn cancel_pairing(&self) {
        *self.pairing.lock().unwrap() = None;
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
