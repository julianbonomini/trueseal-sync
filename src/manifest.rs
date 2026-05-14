use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::keys::{NoisePublicKey, SigningPublicKey};

// ── Proto generated types ─────────────────────────────────────────────────────

mod proto {
    include!(concat!(env!("OUT_DIR"), "/trueseal.sync.v0.rs"));
}

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct ManifestMember {
    pub noise_pub: NoisePublicKey,
    pub signing_pub: SigningPublicKey,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupManifest {
    pub group_id: [u8; 32],
    pub version: u64,
    pub members: Vec<ManifestMember>,
    pub issued_by: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("decode failed: {0}")]
    DecodeFailed(String),
    #[error("invalid field length: {field} expected {expected} bytes, got {got}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("version regression: incoming {incoming} <= current {current}")]
    VersionRegression { incoming: u64, current: u64 },
    #[error("group id mismatch: incoming manifest belongs to a different group")]
    GroupIdMismatch,
    #[error("unknown issuer: issued_by not in previous manifest members")]
    UnknownIssuer,
}

// ── Signing message ───────────────────────────────────────────────────────────

/// Canonical bytes that are signed/verified for a manifest.
/// group_id(32) || version(8 LE) || members_encoded
fn signing_message(group_id: &[u8; 32], version: u64, members: &[ManifestMember]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(group_id);
    msg.extend_from_slice(&version.to_le_bytes());
    for m in members {
        msg.extend_from_slice(&m.noise_pub.0);
        msg.extend_from_slice(&m.signing_pub.0);
        msg.extend_from_slice(m.name.as_bytes());
        msg.push(0u8); // null separator between members
    }
    msg
}

// ── GroupManifest impl ────────────────────────────────────────────────────────

impl GroupManifest {
    /// Create and sign a new GroupManifest.
    pub fn new(
        group_id: [u8; 32],
        version: u64,
        members: Vec<ManifestMember>,
        signing_key: &SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let issued_by: [u8; 32] = signing_key.verifying_key().to_bytes();
        let msg = signing_message(&group_id, version, &members);
        let sig = signing_key.sign(&msg);
        Self {
            group_id,
            version,
            members,
            issued_by,
            signature: sig.to_bytes(),
        }
    }

    /// Generate a genesis manifest (first manifest for a new group).
    /// `previous` is None for genesis.
    pub fn verify(&self, previous: Option<&GroupManifest>) -> Result<(), ManifestError> {
        use ed25519_dalek::{Signature, VerifyingKey};

        // Check issuer is in previous manifest (skip for genesis)
        if let Some(prev) = previous {
            if self.group_id != prev.group_id {
                return Err(ManifestError::GroupIdMismatch);
            }
            if self.version <= prev.version {
                return Err(ManifestError::VersionRegression {
                    incoming: self.version,
                    current: prev.version,
                });
            }
            let issuer_known = prev
                .members
                .iter()
                .any(|m| m.signing_pub.0 == self.issued_by);
            if !issuer_known {
                return Err(ManifestError::UnknownIssuer);
            }
        }

        // Verify signature
        let vk = VerifyingKey::from_bytes(&self.issued_by)
            .map_err(|_| ManifestError::InvalidSignature)?;
        let sig = Signature::from_bytes(&self.signature);
        let msg = signing_message(&self.group_id, self.version, &self.members);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| ManifestError::InvalidSignature)
    }

    pub fn encode(&self) -> Vec<u8> {
        use prost::Message;
        let proto = proto::GroupManifest {
            group_id: self.group_id.to_vec(),
            version: self.version,
            members: self
                .members
                .iter()
                .map(|m| proto::ManifestMember {
                    noise_pub: m.noise_pub.0.to_vec(),
                    signing_pub: m.signing_pub.0.to_vec(),
                    name: m.name.clone(),
                })
                .collect(),
            issued_by: self.issued_by.to_vec(),
            signature: self.signature.to_vec(),
        };
        proto.encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        use prost::Message;
        let proto = proto::GroupManifest::decode(bytes)
            .map_err(|e| ManifestError::DecodeFailed(e.to_string()))?;

        let group_id: [u8; 32] =
            proto
                .group_id
                .as_slice()
                .try_into()
                .map_err(|_| ManifestError::InvalidLength {
                    field: "group_id",
                    expected: 32,
                    got: proto.group_id.len(),
                })?;

        let issued_by: [u8; 32] =
            proto
                .issued_by
                .as_slice()
                .try_into()
                .map_err(|_| ManifestError::InvalidLength {
                    field: "issued_by",
                    expected: 32,
                    got: proto.issued_by.len(),
                })?;

        let signature: [u8; 64] =
            proto
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| ManifestError::InvalidLength {
                    field: "signature",
                    expected: 64,
                    got: proto.signature.len(),
                })?;

        let members = proto
            .members
            .into_iter()
            .map(|m| {
                let noise_pub: [u8; 32] = m.noise_pub.as_slice().try_into().map_err(|_| {
                    ManifestError::InvalidLength {
                        field: "member.noise_pub",
                        expected: 32,
                        got: m.noise_pub.len(),
                    }
                })?;
                let signing_pub: [u8; 32] = m.signing_pub.as_slice().try_into().map_err(|_| {
                    ManifestError::InvalidLength {
                        field: "member.signing_pub",
                        expected: 32,
                        got: m.signing_pub.len(),
                    }
                })?;
                Ok(ManifestMember {
                    noise_pub: NoisePublicKey(noise_pub),
                    signing_pub: SigningPublicKey(signing_pub),
                    name: m.name,
                })
            })
            .collect::<Result<Vec<_>, ManifestError>>()?;

        Ok(Self {
            group_id,
            version: proto.version,
            members,
            issued_by,
            signature,
        })
    }

    /// Convenience: does this manifest contain a member with the given signing pub?
    pub fn contains_signing_pub(&self, signing_pub: &[u8; 32]) -> bool {
        self.members.iter().any(|m| &m.signing_pub.0 == signing_pub)
    }

    /// Look up a member's noise_pub by their signing_pub.
    pub fn noise_pub_for_signing(&self, signing_pub: &[u8; 32]) -> Option<NoisePublicKey> {
        self.members
            .iter()
            .find(|m| &m.signing_pub.0 == signing_pub)
            .map(|m| m.noise_pub)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a random group_id.
pub fn new_group_id() -> [u8; 32] {
    use rand::RngCore;
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    id
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_member(signing_key: &SigningKey) -> ManifestMember {
        use x25519_dalek::{PublicKey, StaticSecret};
        let noise_priv = StaticSecret::random_from_rng(OsRng);
        let noise_pub = PublicKey::from(&noise_priv);
        ManifestMember {
            noise_pub: NoisePublicKey(*noise_pub.as_bytes()),
            signing_pub: SigningPublicKey(signing_key.verifying_key().to_bytes()),
            name: "TestDevice".into(),
        }
    }

    #[test]
    fn genesis_manifest_encodes_and_decodes() {
        let key = make_signing_key();
        let member = make_member(&key);
        let group_id = new_group_id();

        let manifest = GroupManifest::new(group_id, 1, vec![member.clone()], &key);
        let bytes = manifest.encode();
        let decoded = GroupManifest::decode(&bytes).expect("decode");

        assert_eq!(decoded.group_id, group_id);
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.members.len(), 1);
        assert_eq!(decoded.members[0].noise_pub, member.noise_pub);
        assert_eq!(decoded.members[0].signing_pub, member.signing_pub);
        assert_eq!(decoded.members[0].name, "TestDevice");
        assert_eq!(decoded.issued_by, key.verifying_key().to_bytes());
        assert_eq!(decoded.signature, manifest.signature);
    }

    #[test]
    fn genesis_manifest_verifies_with_no_previous() {
        let key = make_signing_key();
        let member = make_member(&key);
        let manifest = GroupManifest::new(new_group_id(), 1, vec![member], &key);
        assert!(manifest.verify(None).is_ok());
    }

    #[test]
    fn valid_update_verifies_against_previous() {
        let key_a = make_signing_key();
        let key_b = make_signing_key();
        let member_a = make_member(&key_a);
        let member_b = make_member(&key_b);
        let group_id = new_group_id();

        let v1 = GroupManifest::new(group_id, 1, vec![member_a.clone()], &key_a);
        let v2 = GroupManifest::new(
            group_id,
            2,
            vec![member_a.clone(), member_b.clone()],
            &key_a,
        );

        assert!(v1.verify(None).is_ok());
        assert!(v2.verify(Some(&v1)).is_ok());
    }

    #[test]
    fn version_regression_rejected() {
        let key = make_signing_key();
        let member = make_member(&key);
        let group_id = new_group_id();

        let v2 = GroupManifest::new(group_id, 2, vec![member.clone()], &key);
        let v1 = GroupManifest::new(group_id, 1, vec![member.clone()], &key);

        // v1 arriving after v2 should be rejected
        assert!(matches!(
            v1.verify(Some(&v2)),
            Err(ManifestError::VersionRegression { .. })
        ));
    }

    #[test]
    fn same_version_rejected() {
        let key = make_signing_key();
        let member = make_member(&key);
        let group_id = new_group_id();

        let v1a = GroupManifest::new(group_id, 1, vec![member.clone()], &key);
        let v1b = GroupManifest::new(group_id, 1, vec![member.clone()], &key);

        assert!(matches!(
            v1b.verify(Some(&v1a)),
            Err(ManifestError::VersionRegression { .. })
        ));
    }

    #[test]
    fn group_id_mismatch_rejected() {
        let key_a = make_signing_key();
        let member_a = make_member(&key_a);
        let group_id_1 = new_group_id();
        let group_id_2 = new_group_id();

        let v1 = GroupManifest::new(group_id_1, 1, vec![member_a.clone()], &key_a);
        // v2 issued by a valid member but with a different group_id — must be rejected.
        let v2 = GroupManifest::new(group_id_2, 2, vec![member_a.clone()], &key_a);

        assert!(matches!(
            v2.verify(Some(&v1)),
            Err(ManifestError::GroupIdMismatch)
        ));
    }

    #[test]
    fn unknown_issuer_rejected() {
        let key_a = make_signing_key();
        let key_stranger = make_signing_key();
        let member_a = make_member(&key_a);
        let group_id = new_group_id();

        let v1 = GroupManifest::new(group_id, 1, vec![member_a], &key_a);
        // Stranger tries to issue v2 — not in v1's member list
        let stranger_member = make_member(&key_stranger);
        let v2 = GroupManifest::new(group_id, 2, vec![stranger_member], &key_stranger);

        assert!(matches!(
            v2.verify(Some(&v1)),
            Err(ManifestError::UnknownIssuer)
        ));
    }

    #[test]
    fn tampered_member_list_fails_verification() {
        let key = make_signing_key();
        let key_b = make_signing_key();
        let member = make_member(&key);
        let group_id = new_group_id();

        let mut manifest = GroupManifest::new(group_id, 1, vec![member], &key);
        // Inject an extra member after signing
        manifest.members.push(make_member(&key_b));

        assert!(matches!(
            manifest.verify(None),
            Err(ManifestError::InvalidSignature)
        ));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let key = make_signing_key();
        let member = make_member(&key);
        let mut manifest = GroupManifest::new(new_group_id(), 1, vec![member], &key);
        manifest.signature[0] ^= 0xff;

        assert!(matches!(
            manifest.verify(None),
            Err(ManifestError::InvalidSignature)
        ));
    }

    #[test]
    fn contains_signing_pub_works() {
        let key = make_signing_key();
        let member = make_member(&key);
        let manifest = GroupManifest::new(new_group_id(), 1, vec![member], &key);

        assert!(manifest.contains_signing_pub(&key.verifying_key().to_bytes()));
        assert!(!manifest.contains_signing_pub(&[0u8; 32]));
    }

    #[test]
    fn noise_pub_for_signing_resolves_correctly() {
        let key = make_signing_key();
        let member = make_member(&key);
        let expected_noise = member.noise_pub;
        let manifest = GroupManifest::new(new_group_id(), 1, vec![member], &key);

        let resolved = manifest.noise_pub_for_signing(&key.verifying_key().to_bytes());
        assert_eq!(resolved, Some(expected_noise));
        assert_eq!(manifest.noise_pub_for_signing(&[0u8; 32]), None);
    }
}
