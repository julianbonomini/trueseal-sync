mod reconnect;
#[cfg(test)]
mod test_helpers;
#[cfg(test)]
mod tests;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use hush_noise::keypair::Keypair as NoiseKeypair;
use thiserror::Error;

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::message::{pairing_payload, Message};
use crate::operation_log::{MemLog, OperationLog};
use crate::relay::RelayClient;
use crate::revocation::{handle_revoke_by_signing_pub, PairedList};

const DEFAULT_PAIRING_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_RECONNECT_CAP: Duration = Duration::from_secs(30);

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid keypair bytes")]
    InvalidKeypairBytes,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("push failed: {0}")]
    PushFailed(String),
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

/// The opinionated session facade (ADR-0010).
///
/// Owns the relay connection, sequence counter, signing keypair, pairing state,
/// paired-device list, and key-rotation callback.
/// Transport-generic so tests can inject in-memory pipes.
pub struct HushSession<T: Read + Write + Send + 'static> {
    client: Arc<Mutex<RelayClient<T>>>,
    keys: Arc<Mutex<KeyState>>,
    sequence: Arc<Mutex<u64>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    pub op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    /// Devices paired with this session — populated by `accept_pair`, cleared on revoke.
    pub paired: Arc<Mutex<PairedList>>,
    /// Fired after key rotation with `noise_priv || signing_priv` (64 bytes).
    on_keypair_rotated: Arc<dyn Fn([u8; 64]) + Send + Sync + 'static>,
}

impl<T: Read + Write + Send + 'static> HushSession<T> {
    /// Current noise public key for this session.
    pub fn noise_pub(&self) -> NoisePublicKey {
        self.keys.lock().unwrap().noise_pub
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn connect(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message) + Send + 'static,
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
        on_message: impl Fn(Message) + Send + 'static,
        op_log: Box<dyn OperationLog>,
        on_keypair_rotated: impl Fn([u8; 64]) + Send + Sync + 'static,
    ) -> Result<Self, SessionError> {
        let keys = Arc::new(Mutex::new(KeyState::from_keypair(&keypair)));
        let noise_kp = {
            let ks = keys.lock().unwrap();
            NoiseKeypair::new(ks.noise_priv, ks.noise_pub_key)
        };

        let paired: Arc<Mutex<PairedList>> = Arc::new(Mutex::new(PairedList::new()));
        let on_keypair_rotated: Arc<dyn Fn([u8; 64]) + Send + Sync + 'static> =
            Arc::new(on_keypair_rotated);

        let keys_cb = keys.clone();
        let paired_cb = paired.clone();
        let on_kpr_cb = on_keypair_rotated.clone();

        let client = RelayClient::connect(transport, relay_pub, noise_kp)
            .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;

        client.subscribe(move |msg, author_signing_pub| {
            if let Message::Revoke = &msg {
                if let Some(new_kp) = handle_revoke_by_signing_pub(
                    &mut paired_cb.lock().unwrap(),
                    &author_signing_pub,
                ) {
                    let mut rotated = [0u8; 64];
                    rotated[..32].copy_from_slice(&new_kp.noise.private());
                    rotated[32..].copy_from_slice(&new_kp.signing.to_bytes());
                    *keys_cb.lock().unwrap() = KeyState::from_keypair(&new_kp);
                    (on_kpr_cb)(rotated);
                }
                return; // never forward Revoke to caller
            }
            on_message(msg);
        });

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            keys,
            sequence: Arc::new(Mutex::new(0)),
            pairing: Arc::new(Mutex::new(None)),
            op_log: Arc::new(Mutex::new(op_log)),
            paired,
            on_keypair_rotated,
        })
    }

    pub fn connect_with_reconnect(
        transport: T,
        relay_pub: NoisePublicKey,
        keypair: DeviceKeypair,
        on_message: impl Fn(Message) + Send + 'static + Clone,
        op_log: Box<dyn OperationLog>,
        transport_factory: impl Fn() -> Result<T, String> + Send + Sync + 'static,
        reconnect_cap: Option<Duration>,
    ) -> Result<Self, SessionError> {
        let session = Self::connect_with_log(
            transport,
            relay_pub,
            keypair,
            on_message.clone(),
            op_log,
            |_| {},
        )?;
        let client_arc = session.client.clone();
        let op_log_arc = session.op_log.clone();
        let keys_arc = session.keys.clone();
        let cap = reconnect_cap.unwrap_or(DEFAULT_RECONNECT_CAP);
        std::thread::spawn(move || {
            reconnect::reconnect_loop(
                client_arc,
                op_log_arc,
                relay_pub,
                keys_arc,
                on_message,
                Arc::new(transport_factory),
                cap,
            );
        });
        Ok(session)
    }

    // ── Push ──────────────────────────────────────────────────────────────────

    /// Encrypt `blob` as a Sync message and push to `recipient_pub`.
    /// Appended to the outbox first; marked delivered on success.
    pub fn push_sync(
        &self,
        recipient_pub: NoisePublicKey,
        blob: Vec<u8>,
    ) -> Result<(), SessionError> {
        let msg = Message::Sync { body: blob.clone() };
        let seq = self.next_seq();
        let oid = recipient_pub.0;
        self.op_log.lock().unwrap().append(&oid, seq, blob);

        if !self.client.lock().unwrap().is_connected() {
            return Err(SessionError::PushFailed("relay disconnected".into()));
        }

        let signing = self.signing();
        let result = self
            .client
            .lock()
            .unwrap()
            .push(&msg, recipient_pub, seq, vec![], &signing);
        if result.is_ok() {
            self.op_log.lock().unwrap().mark_delivered(&oid, seq);
        }
        result.map_err(|e| SessionError::PushFailed(e.to_string()))
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

    /// Push `Message::Revoke` to all paired peers, wipe the paired list, and rotate keys.
    pub fn revoke(&self) {
        let peers: Vec<NoisePublicKey> = self.paired.lock().unwrap().iter().cloned().collect();
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
        self.paired.lock().unwrap().clear();
        (self.on_keypair_rotated)(rotated);
    }

    // ── Pairing ───────────────────────────────────────────────────────────────

    pub fn start_pairing(&self, on_paired: impl Fn(NoisePublicKey) + Send + 'static) -> Vec<u8> {
        self.start_pairing_with_duration(DEFAULT_PAIRING_WINDOW, on_paired)
    }

    pub fn start_pairing_with_duration(
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

    /// Admit a device; requires both noise and signing pub keys for revoke-by-signing-key lookup.
    pub fn accept_pair(&self, noise_pub: NoisePublicKey, signing_pub: SigningPublicKey) {
        let mut guard = self.pairing.lock().unwrap();
        if let Some(ref window) = *guard {
            if window.is_open() {
                self.paired.lock().unwrap().add(noise_pub, signing_pub);
                (window.on_paired)(noise_pub);
                *guard = None;
                return;
            }
        }
        *guard = None;
    }

    pub fn cancel_pairing(&self) {
        *self.pairing.lock().unwrap() = None;
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
        on_message: impl Fn(Message) + Send + 'static,
    ) -> Result<Self, SessionError> {
        let stream =
            TcpStream::connect(addr).map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;
        Self::connect(stream, relay_pub, keypair, on_message)
    }
}
