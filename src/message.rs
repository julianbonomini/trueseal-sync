use thiserror::Error;

use crate::manifest::{GroupManifest, ManifestError};

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("unknown message type: {0}")]
    UnknownType(u8),
    #[error("message too short")]
    TooShort,
    #[error("invalid pairing payload")]
    InvalidPairingPayload,
    #[error("invalid group manifest: {0}")]
    InvalidManifest(#[from] ManifestError),
}

// 1-byte type tags — private to hush-sync, invisible to the Relay
const TAG_PAIR: u8 = 0x01;
const TAG_SYNC: u8 = 0x02;
const TAG_REVOKE: u8 = 0x03;
const TAG_GROUP_MANIFEST: u8 = 0x04;

/// The message types hush-sync defines.
/// Callers receive this from subscribe callbacks after decryption and parsing.
/// The Relay never sees the type tag — it lives inside the encrypted payload.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A Device requesting to join a Sync Group.
    /// Body: the sender's noise public key + signing public key.
    Pair {
        noise_pub: [u8; 32],
        signing_pub: [u8; 32],
    },
    /// An opaque application blob — clipboard entry, secret, or any caller data.
    /// hush-sync delivers the body verbatim; the caller interprets it.
    Sync { body: Vec<u8> },
    /// Full Sync Group reset. Recipients wipe their group state and rotate keypairs.
    Revoke,
    /// A signed, versioned Group Manifest update.
    GroupManifest { manifest: GroupManifest },
}

impl Message {
    /// Encode this Message into plaintext bytes suitable for addressed encryption.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Pair {
                noise_pub,
                signing_pub,
            } => {
                let mut out = vec![TAG_PAIR];
                out.extend_from_slice(noise_pub);
                out.extend_from_slice(signing_pub);
                out
            }
            Message::Sync { body } => {
                let mut out = vec![TAG_SYNC];
                out.extend_from_slice(body);
                out
            }
            Message::Revoke => vec![TAG_REVOKE],
            Message::GroupManifest { manifest } => {
                let mut out = vec![TAG_GROUP_MANIFEST];
                out.extend_from_slice(&manifest.encode());
                out
            }
        }
    }

    /// Decode plaintext bytes (after decryption) into a Message.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.is_empty() {
            return Err(MessageError::TooShort);
        }
        match bytes[0] {
            TAG_PAIR => {
                if bytes.len() < 1 + 32 + 32 {
                    return Err(MessageError::InvalidPairingPayload);
                }
                let noise_pub = bytes[1..33].try_into().unwrap();
                let signing_pub = bytes[33..65].try_into().unwrap();
                Ok(Message::Pair {
                    noise_pub,
                    signing_pub,
                })
            }
            TAG_SYNC => Ok(Message::Sync {
                body: bytes[1..].to_vec(),
            }),
            TAG_REVOKE => Ok(Message::Revoke),
            TAG_GROUP_MANIFEST => {
                let manifest = GroupManifest::decode(&bytes[1..])?;
                Ok(Message::GroupManifest { manifest })
            }
            other => Err(MessageError::UnknownType(other)),
        }
    }
}

/// Produce pairing payload bytes for a QR code.
/// Contains this device's noise public key and signing public key.
/// The caller encodes these bytes as a QR image — hush-sync never does that.
pub fn pairing_payload(noise_pub: &[u8; 32], signing_pub: &[u8; 32]) -> Vec<u8> {
    // Same encoding as a Pair message body — the receiver decodes it as such
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(noise_pub);
    out.extend_from_slice(signing_pub);
    out
}

/// Decode a pairing payload (from a scanned QR code).
/// Returns (noise_pub, signing_pub) of the initiating device.
pub fn decode_pairing_payload(bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), MessageError> {
    if bytes.len() < 64 {
        return Err(MessageError::InvalidPairingPayload);
    }
    let noise_pub = bytes[0..32].try_into().unwrap();
    let signing_pub = bytes[32..64].try_into().unwrap();
    Ok((noise_pub, signing_pub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{NoisePublicKey, SigningPublicKey};
    use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Tracer bullet: a Sync message encodes and decodes to the same body.
    #[test]
    fn sync_message_round_trips() {
        let body = b"clipboard content".to_vec();
        let msg = Message::Sync { body: body.clone() };
        let decoded = Message::decode(&msg.encode()).expect("should decode");
        assert_eq!(decoded, msg);
    }

    /// A Pair message round-trips with both public keys intact.
    #[test]
    fn pair_message_round_trips() {
        let msg = Message::Pair {
            noise_pub: [1u8; 32],
            signing_pub: [2u8; 32],
        };
        let decoded = Message::decode(&msg.encode()).expect("should decode");
        assert_eq!(decoded, msg);
    }

    /// A Revoke message round-trips.
    #[test]
    fn revoke_message_round_trips() {
        let msg = Message::Revoke;
        let decoded = Message::decode(&msg.encode()).expect("should decode");
        assert_eq!(decoded, msg);
    }

    /// A GroupManifest message round-trips with all manifest data intact.
    #[test]
    fn group_manifest_message_round_trips() {
        let key = SigningKey::generate(&mut OsRng);
        let member = ManifestMember {
            noise_pub: NoisePublicKey([7u8; 32]),
            signing_pub: SigningPublicKey(key.verifying_key().to_bytes()),
            name: "CobaltEagle".into(),
        };
        let manifest = GroupManifest::new(new_group_id(), 1, vec![member], &key);
        let msg = Message::GroupManifest {
            manifest: manifest.clone(),
        };
        let decoded = Message::decode(&msg.encode()).expect("should decode");
        assert_eq!(decoded, msg);
    }

    /// GroupManifest message preserves signature and verifies correctly after decode.
    #[test]
    fn group_manifest_message_verifies_after_decode() {
        let key = SigningKey::generate(&mut OsRng);
        let member = ManifestMember {
            noise_pub: NoisePublicKey([9u8; 32]),
            signing_pub: SigningPublicKey(key.verifying_key().to_bytes()),
            name: "SilverHawk".into(),
        };
        let manifest = GroupManifest::new(new_group_id(), 1, vec![member], &key);
        let msg = Message::GroupManifest { manifest };
        let decoded = Message::decode(&msg.encode()).expect("should decode");
        if let Message::GroupManifest { manifest: m } = decoded {
            assert!(m.verify(None).is_ok());
        } else {
            panic!("expected GroupManifest variant");
        }
    }

    /// An unknown type tag returns an error.
    #[test]
    fn unknown_type_tag_returns_error() {
        let result = Message::decode(&[0xFF, 1, 2, 3]);
        assert!(matches!(result, Err(MessageError::UnknownType(0xFF))));
    }

    /// Empty bytes return an error.
    #[test]
    fn empty_bytes_return_error() {
        assert!(matches!(Message::decode(&[]), Err(MessageError::TooShort)));
    }

    /// A truncated Pair payload returns an error.
    #[test]
    fn truncated_pair_returns_error() {
        // Only 1 + 32 bytes instead of 1 + 32 + 32
        let mut bytes = vec![0x01u8];
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            Message::decode(&bytes),
            Err(MessageError::InvalidPairingPayload)
        ));
    }

    /// Pairing payload encodes and decodes the device's two public keys.
    #[test]
    fn pairing_payload_round_trips() {
        let noise_pub = [3u8; 32];
        let signing_pub = [4u8; 32];
        let payload = pairing_payload(&noise_pub, &signing_pub);
        let (n, s) = decode_pairing_payload(&payload).expect("should decode");
        assert_eq!(n, noise_pub);
        assert_eq!(s, signing_pub);
    }

    /// A truncated pairing payload returns an error.
    #[test]
    fn truncated_pairing_payload_returns_error() {
        let short = vec![0u8; 32]; // only 32 bytes, needs 64
        assert!(decode_pairing_payload(&short).is_err());
    }
}
