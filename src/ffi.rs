// FFI surface for Swift and Kotlin via UniFFI (proc-macro mode).
//
// Exposes a single `HushFfiSession` object over TCP transport.
// All key material crosses the boundary as `Vec<u8>`; wrong-length inputs
// return `SessionError` — no silent failures.

use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::device::DeviceKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::message::Message;
use crate::session::{HushSession, SessionError as CoreSessionError};
use crate::store::{PersistentLog, Store};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SessionError {
    #[error("invalid key length: expected {expected} bytes, got {got}")]
    InvalidKeyLength { expected: u32, got: u32 },
    #[error("connection failed: {msg}")]
    ConnectionFailed { msg: String },
    #[error("push failed: {msg}")]
    PushFailed { msg: String },
    #[error("invalid pairing token")]
    InvalidToken,
    #[error("not in any group")]
    NotInGroup,
    #[error("group has been destroyed")]
    GroupDestroyed,
}

impl From<CoreSessionError> for SessionError {
    fn from(e: CoreSessionError) -> Self {
        match e {
            CoreSessionError::ConnectionFailed(msg) => SessionError::ConnectionFailed { msg },
            CoreSessionError::PushFailed(msg) => SessionError::PushFailed { msg },
            CoreSessionError::NotInGroup => SessionError::NotInGroup,
            CoreSessionError::InvalidKeypairBytes => SessionError::InvalidKeyLength {
                expected: 64,
                got: 0,
            },
            CoreSessionError::InvalidToken => SessionError::InvalidToken,
        }
    }
}

// ── Callback interfaces ───────────────────────────────────────────────────────

/// Fired when a `Sync` message is delivered to this device.
/// `blob` is the raw application payload; `sender_noise_pub` is the sender's 32-byte X25519 key.
#[uniffi::export(callback_interface)]
pub trait MessageCallback: Send + Sync {
    fn on_message(&self, blob: Vec<u8>, sender_noise_pub: Vec<u8>);
}

/// Fired after this device's keypair is rotated (revocation).
/// `keypair_bytes` is `noise_priv (32) || signing_priv (32)` — 64 bytes total.
/// The caller must persist this to replace the stored keypair.
#[uniffi::export(callback_interface)]
pub trait KeypairRotatedCallback: Send + Sync {
    fn on_keypair_rotated(&self, keypair_bytes: Vec<u8>);
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
    /// Connect to a relay and start the session.
    ///
    /// - `base_dir`: directory where the SQLite database is stored
    /// - `namespace`: scopes the database file; one session per namespace
    /// - `relay_addr`: TCP address, e.g. `"relay.example.com:4433"`
    /// - `relay_pub`: 32-byte X25519 relay public key
    /// - `on_message`: called for every inbound `Sync` message
    /// - `on_keypair_rotated`: called after key rotation (Destroy Group)
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
        on_keypair_rotated: Box<dyn KeypairRotatedCallback>,
    ) -> Result<Arc<Self>, SessionError> {
        let store = Store::open(Path::new(&base_dir), &namespace).map_err(|e| {
            SessionError::ConnectionFailed {
                msg: format!("store: {e}"),
            }
        })?;
        let keypair = load_or_generate_keypair(&store)?;
        let relay_pub_key = noise_pub_from_bytes(&relay_pub)?;

        let stream = TcpStream::connect(&relay_addr)
            .map_err(|e| SessionError::ConnectionFailed { msg: e.to_string() })?;

        // Late-bind slot: filled after the session is built so the on_message
        // closure can look up sender noise pub from the session's manifest.
        let manifest_slot: Arc<Mutex<Option<Arc<Mutex<Option<crate::manifest::GroupManifest>>>>>> =
            Arc::new(Mutex::new(None));
        // Wrap callbacks in Arc so the on_message closure can be Clone
        // (required by connect_with_reconnect for the reconnect loop).
        let on_message = Arc::new(on_message);
        let manifest_slot_cb = manifest_slot.clone();

        // Open a second store handle for PersistentLog (same DB file, separate connection).
        let log_store = Store::open(Path::new(&base_dir), &namespace).map_err(|e| {
            SessionError::ConnectionFailed {
                msg: format!("store: {e}"),
            }
        })?;

        let relay_addr_factory = relay_addr.clone();
        let inner = HushSession::connect_with_reconnect(
            stream,
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
            move |bytes| {
                on_keypair_rotated.on_keypair_rotated(bytes.to_vec());
            },
            move || TcpStream::connect(&relay_addr_factory).map_err(|e| e.to_string()),
            None, // use default 30-second cap
        )
        .map_err(SessionError::from)?;

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

    /// Admit a device identified by its noise (32 B) and signing (32 B) public keys.
    /// Returns `true` if admitted (window was open), `false` if the window was closed
    /// or had already expired.  Returns an error only if the key bytes are invalid length.
    pub fn accept_pair(
        &self,
        noise_pub: Vec<u8>,
        signing_pub: Vec<u8>,
    ) -> Result<bool, SessionError> {
        let noise = noise_pub_from_bytes(&noise_pub)?;
        let signing = signing_pub_from_bytes(&signing_pub)?;
        Ok(self.inner.accept_pair(noise, signing))
    }

    /// Close the pairing window without admitting any device.
    pub fn cancel_pairing(&self) {
        self.inner.cancel_pairing();
    }

    /// Encrypt `blob` and fan out to all current group members.
    /// Returns `SessionError::NotInGroup` if the session has no manifest yet.
    pub fn send(&self, blob: Vec<u8>) -> Result<(), SessionError> {
        self.inner.push_sync(blob).map_err(SessionError::from)
    }

    /// Send `Message::Revoke` to all paired peers and rotate this device's keypair.
    /// `on_keypair_rotated` fires with the new 64-byte keypair bytes.
    pub fn revoke(&self) {
        self.inner.revoke();
    }

    /// This session's current noise public key (32 bytes).
    pub fn noise_pub(&self) -> Vec<u8> {
        self.inner.noise_pub().0.to_vec()
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
                .map_err(|e| SessionError::ConnectionFailed {
                    msg: format!("store: {e}"),
                })?;
            Ok(kp)
        }
        Err(e) => Err(SessionError::ConnectionFailed {
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

fn signing_pub_from_bytes(bytes: &[u8]) -> Result<SigningPublicKey, SessionError> {
    bytes
        .try_into()
        .map(SigningPublicKey)
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

    /// Wrong-length signing pub returns SessionError::InvalidKeyLength.
    #[test]
    fn short_signing_pub_returns_error() {
        let result = signing_pub_from_bytes(&[0u8; 5]);
        assert!(matches!(
            result,
            Err(SessionError::InvalidKeyLength {
                expected: 32,
                got: 5
            })
        ));
    }
}
