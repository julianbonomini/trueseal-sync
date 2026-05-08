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
                let noise_pub = bytes[1..33]
                    .try_into()
                    .expect("invariant: bytes.len() >= 65 checked above");
                let signing_pub = bytes[33..65]
                    .try_into()
                    .expect("invariant: bytes.len() >= 65 checked above");
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
    let noise_pub = bytes[0..32]
        .try_into()
        .expect("invariant: bytes.len() >= 64 checked above");
    let signing_pub = bytes[32..64]
        .try_into()
        .expect("invariant: bytes.len() >= 64 checked above");
    Ok((noise_pub, signing_pub))
}

/// Generate a deterministic, human-readable device name from a signing public key.
/// Format: first 4 bytes of the key hex-encoded (e.g. `"ab12cd34"`).
pub fn device_name(signing_pub: &[u8; 32]) -> String {
    let hex_chars: Vec<char> = "0123456789abcdef".chars().collect();
    let mut name = String::with_capacity(8);
    for b in &signing_pub[..4] {
        name.push(hex_chars[(b >> 4) as usize]);
        name.push(hex_chars[(b & 0xf) as usize]);
    }
    name
}

/// Encode a pairing token as a base64url string.
/// Format: `base64url(noise_pub[32] || signing_pub[32] || name_utf8_bytes)`
pub fn pairing_token(noise_pub: &[u8; 32], signing_pub: &[u8; 32]) -> String {
    let name = device_name(signing_pub);
    let mut raw = Vec::with_capacity(64 + name.len());
    raw.extend_from_slice(noise_pub);
    raw.extend_from_slice(signing_pub);
    raw.extend_from_slice(name.as_bytes());
    base64url_encode(&raw)
}

/// Decode a pairing token produced by `pairing_token`.
/// Returns `(noise_pub, signing_pub, name)`.
pub fn decode_pairing_token(token: &str) -> Result<([u8; 32], [u8; 32], String), MessageError> {
    let raw = base64url_decode(token).ok_or(MessageError::InvalidPairingPayload)?;
    if raw.len() < 64 {
        return Err(MessageError::InvalidPairingPayload);
    }
    let noise_pub: [u8; 32] = raw[0..32]
        .try_into()
        .expect("invariant: raw.len() >= 64 checked above");
    let signing_pub: [u8; 32] = raw[32..64]
        .try_into()
        .expect("invariant: raw.len() >= 64 checked above");
    let name =
        String::from_utf8(raw[64..].to_vec()).map_err(|_| MessageError::InvalidPairingPayload)?;
    Ok((noise_pub, signing_pub, name))
}

// ── base64url helpers (no external crate) ─────────────────────────────────────

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64_CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push(B64_CHARS[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64_CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64_CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut table = [0xffu8; 256];
    for (i, &c) in B64_CHARS.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let bytes: Vec<u8> = input.bytes().collect();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len * 3 / 4);
    let mut i = 0;
    while i + 4 <= len {
        let a = table[bytes[i] as usize];
        let b = table[bytes[i + 1] as usize];
        let c = table[bytes[i + 2] as usize];
        let d = table[bytes[i + 3] as usize];
        if a == 0xff || b == 0xff || c == 0xff || d == 0xff {
            return None;
        }
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    let rem = len - i;
    if rem == 2 {
        let a = table[bytes[i] as usize];
        let b = table[bytes[i + 1] as usize];
        if a == 0xff || b == 0xff {
            return None;
        }
        let n = ((a as u32) << 18) | ((b as u32) << 12);
        out.push((n >> 16) as u8);
    } else if rem == 3 {
        let a = table[bytes[i] as usize];
        let b = table[bytes[i + 1] as usize];
        let c = table[bytes[i + 2] as usize];
        if a == 0xff || b == 0xff || c == 0xff {
            return None;
        }
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    } else if rem != 0 {
        return None;
    }
    Some(out)
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

    /// pairing_token encodes and decodes recovering noise_pub, signing_pub, and name.
    #[test]
    fn pairing_token_encodes_and_decodes() {
        let noise_pub = [5u8; 32];
        let signing_pub = [6u8; 32];
        let token = pairing_token(&noise_pub, &signing_pub);
        // token must be a non-empty string
        assert!(!token.is_empty());
        let (n, s, name) = decode_pairing_token(&token).expect("should decode");
        assert_eq!(n, noise_pub);
        assert_eq!(s, signing_pub);
        // name is deterministic from signing_pub
        assert!(!name.is_empty());
        assert_eq!(name, device_name(&signing_pub));
    }
}
