use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::keys::{NoisePublicKey, SigningPublicKey};

/// The Maximum Manifest Version Jump: the largest version increase a
/// receiver accepts between its current Group Manifest and an incoming one
/// (ADR-0027 "Manifest format and ordering", bound fixed at 1024 by SYNC-10).
///
/// Honest issuers always step by one — a re-applied Pending Membership
/// Change is `W.version + 1` too — so a larger jump marks a hostile or
/// corrupt manifest. The bound's job is to stop a single manifest from
/// freezing the group (the `u64::MAX` attack), not to bound honest churn,
/// which is human-scale: a Device that somehow misses more than 1024
/// membership changes can no longer accept manifests and must re-pair.
/// Recorded in CONTEXT.md and added to the test vectors by SYNC-2.
pub const MAX_MANIFEST_VERSION_JUMP: u64 = 1024;

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
    /// The hash of the manifest this one was built on (ADR-0027). `None`
    /// for the genesis manifest. Covered by the signature.
    pub parent: Option<[u8; 32]>,
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
    /// The incoming manifest is not strictly greater than the current one
    /// in the (version, hash) total order (ADR-0027): an older version, or
    /// the same version with an equal-or-higher hash (a concurrent-issuer
    /// loser or a relay re-delivery — benign stale).
    #[error("version regression: incoming {incoming} <= current {current}")]
    VersionRegression { incoming: u64, current: u64 },
    #[error(
        "version jump too large: incoming {incoming} is more than {max} above current {current}"
    )]
    VersionJumpTooLarge {
        incoming: u64,
        current: u64,
        max: u64,
    },
    #[error("version exhausted: u64::MAX can never be incremented; accepting it would freeze membership")]
    VersionExhausted,
    #[error("group id mismatch: incoming manifest belongs to a different group")]
    GroupIdMismatch,
    #[error("unknown issuer: issued_by not in previous manifest members")]
    UnknownIssuer,
}

// ── Signing message ───────────────────────────────────────────────────────────

/// Canonical bytes that are signed/verified for a manifest.
/// domain || group_id(32) || version(8 LE) || members_encoded || parent
/// The domain separator carries the End-to-End Version (ADR-0022). The
/// parent is covered by the signature (ADR-0027): a 1-byte flag (0 =
/// genesis, 1 = update) followed by the 32-byte parent hash when present.
fn signing_message(
    group_id: &[u8; 32],
    version: u64,
    members: &[ManifestMember],
    parent: &Option<[u8; 32]>,
) -> Vec<u8> {
    signing_message_for(
        &crate::version::manifest_signing_domain(),
        group_id,
        version,
        members,
        parent,
    )
}

/// [`signing_message`] under an explicit domain. The migration re-seal
/// (ADR-0034 §1, SYNC-13) re-signs queued manifests under the End-to-End
/// Version being migrated to.
///
/// `pub(crate)` so the SYNC-2 test vectors pin the exact bytes the code
/// signs rather than a re-implementation of the layout.
pub(crate) fn signing_message_for(
    domain: &[u8],
    group_id: &[u8; 32],
    version: u64,
    members: &[ManifestMember],
    parent: &Option<[u8; 32]>,
) -> Vec<u8> {
    let mut msg = domain.to_vec();
    msg.extend_from_slice(group_id);
    msg.extend_from_slice(&version.to_le_bytes());
    for m in members {
        msg.extend_from_slice(&m.noise_pub.0);
        msg.extend_from_slice(&m.signing_pub.0);
        msg.extend_from_slice(m.name.as_bytes());
        msg.push(0u8); // null separator between members
    }
    match parent {
        None => msg.push(0u8),
        Some(p) => {
            msg.push(1u8);
            msg.extend_from_slice(p);
        }
    }
    msg
}

// ── GroupManifest impl ────────────────────────────────────────────────────────

impl GroupManifest {
    /// Create and sign a genesis GroupManifest (no parent).
    pub fn new(
        group_id: [u8; 32],
        version: u64,
        members: Vec<ManifestMember>,
        signing_key: &SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let issued_by: [u8; 32] = signing_key.verifying_key().to_bytes();
        let msg = signing_message(&group_id, version, &members, &None);
        let sig = signing_key.sign(&msg);
        Self {
            group_id,
            version,
            members,
            issued_by,
            signature: sig.to_bytes(),
            parent: None,
        }
    }

    /// Create and sign the next GroupManifest built on `base` (ADR-0027):
    /// `version = base.version + 1` with checked arithmetic (SYNC-10 —
    /// never panics, never wraps, never issues `u64::MAX`) and
    /// `parent = base.hash()`.
    pub fn update(
        base: &GroupManifest,
        members: Vec<ManifestMember>,
        signing_key: &SigningKey,
    ) -> Result<Self, ManifestError> {
        use ed25519_dalek::Signer;
        let version = base
            .version
            .checked_add(1)
            .filter(|&v| v < u64::MAX)
            .ok_or(ManifestError::VersionExhausted)?;
        let parent = Some(base.hash());
        let issued_by: [u8; 32] = signing_key.verifying_key().to_bytes();
        let msg = signing_message(&base.group_id, version, &members, &parent);
        let sig = signing_key.sign(&msg);
        Ok(Self {
            group_id: base.group_id,
            version,
            members,
            issued_by,
            signature: sig.to_bytes(),
            parent,
        })
    }

    /// The manifest hash — the tiebreaker of the (version, hash) total
    /// order and the value a child names as its `parent` (ADR-0027).
    /// SHA-256 over the canonical protobuf encoding, the same pattern as
    /// [`crate::envelope::Envelope::hash`]. SYNC-2 pins it in the test
    /// vectors.
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.encode()).into()
    }

    /// Verify a manifest. `previous` is None for genesis.
    ///
    /// An update is accepted only if it is STRICTLY GREATER than
    /// `previous` in the (version, hash) total order (ADR-0027): a higher
    /// version (within the Maximum Manifest Version Jump), or the same
    /// version with a lower hash — the tie rule that makes every device
    /// pick the same winner from the same concurrent pair.
    pub fn verify(&self, previous: Option<&GroupManifest>) -> Result<(), ManifestError> {
        // SYNC-10 (#102): a manifest at u64::MAX can never be incremented,
        // so accepting it would freeze membership for good — reject it on
        // receipt, as genesis or update (ADR-0027).
        if self.version == u64::MAX {
            return Err(ManifestError::VersionExhausted);
        }

        // Check issuer is in previous manifest (skip for genesis)
        if let Some(prev) = previous {
            if self.group_id != prev.group_id {
                return Err(ManifestError::GroupIdMismatch);
            }
            match self.version.cmp(&prev.version) {
                std::cmp::Ordering::Less => {
                    return Err(ManifestError::VersionRegression {
                        incoming: self.version,
                        current: prev.version,
                    });
                }
                std::cmp::Ordering::Equal => {
                    // The tie rule (ADR-0027): the LOWER manifest hash wins.
                    // Accept only if this manifest beats the current one;
                    // an equal-or-higher hash is a benign stale (a relay
                    // re-delivery or the concurrent loser).
                    if self.hash() >= prev.hash() {
                        return Err(ManifestError::VersionRegression {
                            incoming: self.version,
                            current: prev.version,
                        });
                    }
                }
                std::cmp::Ordering::Greater => {
                    // SYNC-10 (#102): bound the version jump.
                    let jump = self.version - prev.version;
                    if jump > MAX_MANIFEST_VERSION_JUMP {
                        return Err(ManifestError::VersionJumpTooLarge {
                            incoming: self.version,
                            current: prev.version,
                            max: MAX_MANIFEST_VERSION_JUMP,
                        });
                    }
                }
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
        self.verify_signature_for_version(crate::version::END_TO_END_VERSION)
    }

    /// Verify only the issuer's signature, under the signing domain of an
    /// explicit End-to-End Version. The migration re-seal checks its own
    /// re-signed manifests against the version being migrated to; normal
    /// acceptance goes through [`GroupManifest::verify`], which uses this
    /// build's version.
    pub(crate) fn verify_signature_for_version(
        &self,
        e2e_version: u32,
    ) -> Result<(), ManifestError> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&self.issued_by)
            .map_err(|_| ManifestError::InvalidSignature)?;
        let sig = Signature::from_bytes(&self.signature);
        let msg = signing_message_for(
            &crate::version::manifest_signing_domain_for(e2e_version),
            &self.group_id,
            self.version,
            &self.members,
            &self.parent,
        );
        vk.verify_strict(&msg, &sig)
            .map_err(|_| ManifestError::InvalidSignature)
    }

    /// Re-sign this manifest under the signing domain of End-to-End Version
    /// `e2e_version`, keeping `group_id`, `version` and `members` and naming
    /// `parent` (already remapped by the caller when an ancestor was itself
    /// re-signed). The migration re-seal (ADR-0034 §1, SYNC-13) uses this on
    /// queued, never-accepted manifests this Device issued. The re-signed
    /// manifest has a different hash than the original — the caller owns
    /// propagating the old→new hash remap.
    ///
    /// Refuses to re-sign another Device's issuance (`issued_by` must be the
    /// key's public half): only the issuer may re-sign.
    pub(crate) fn resign_for_version(
        &self,
        parent: Option<[u8; 32]>,
        e2e_version: u32,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, ManifestError> {
        use ed25519_dalek::Signer;
        let issued_by: [u8; 32] = signing_key.verifying_key().to_bytes();
        if issued_by != self.issued_by {
            return Err(ManifestError::UnknownIssuer);
        }
        let msg = signing_message_for(
            &crate::version::manifest_signing_domain_for(e2e_version),
            &self.group_id,
            self.version,
            &self.members,
            &parent,
        );
        let sig = signing_key.sign(&msg);
        Ok(Self {
            group_id: self.group_id,
            version: self.version,
            members: self.members.clone(),
            issued_by,
            signature: sig.to_bytes(),
            parent,
        })
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
            parent: self.parent.map(|p| p.to_vec()).unwrap_or_default(),
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

        let parent: Option<[u8; 32]> =
            if proto.parent.is_empty() {
                None
            } else {
                Some(proto.parent.as_slice().try_into().map_err(|_| {
                    ManifestError::InvalidLength {
                        field: "parent",
                        expected: 32,
                        got: proto.parent.len(),
                    }
                })?)
            };

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
            parent,
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

    // ── SYNC-10 (#102): checked version arithmetic + bounded jumps ──────────
    // Red before the fix: none of these rejections exist, so a hostile or
    // corrupt manifest at u64::MAX (or any huge jump) is accepted and freezes
    // membership for good. The bound literal here is 1024; the fix commit
    // switches these tests to the MAX_MANIFEST_VERSION_JUMP constant and
    // exact error variants.

    #[test]
    fn u64_max_update_rejected() {
        let key = make_signing_key();
        let member = make_member(&key);
        let group_id = new_group_id();

        let v1 = GroupManifest::new(group_id, 1, vec![member.clone()], &key);
        let hostile = GroupManifest::new(group_id, u64::MAX, vec![member], &key);

        assert!(
            matches!(
                hostile.verify(Some(&v1)),
                Err(ManifestError::VersionExhausted)
            ),
            "a manifest at u64::MAX can never be incremented; accepting it freezes membership"
        );
    }

    #[test]
    fn u64_max_genesis_rejected() {
        let key = make_signing_key();
        let member = make_member(&key);

        let hostile = GroupManifest::new(new_group_id(), u64::MAX, vec![member], &key);

        assert!(
            matches!(hostile.verify(None), Err(ManifestError::VersionExhausted)),
            "a genesis at u64::MAX freezes the group from the start"
        );
    }

    #[test]
    fn version_jump_over_bound_rejected() {
        let key = make_signing_key();
        let member = make_member(&key);
        let group_id = new_group_id();

        let v1 = GroupManifest::new(group_id, 1, vec![member.clone()], &key);
        // One past the Maximum Manifest Version Jump (ADR-0027).
        let far = GroupManifest::new(
            group_id,
            1 + MAX_MANIFEST_VERSION_JUMP + 1,
            vec![member],
            &key,
        );

        assert!(
            matches!(
                far.verify(Some(&v1)),
                Err(ManifestError::VersionJumpTooLarge {
                    max: MAX_MANIFEST_VERSION_JUMP,
                    ..
                })
            ),
            "a version jump beyond the sanity bound must be rejected"
        );
    }

    #[test]
    fn version_jump_at_bound_accepted() {
        let key = make_signing_key();
        let member = make_member(&key);
        let group_id = new_group_id();

        let v1 = GroupManifest::new(group_id, 1, vec![member.clone()], &key);
        // Exactly at the bound — accepted before and after the fix.
        let at_bound =
            GroupManifest::new(group_id, 1 + MAX_MANIFEST_VERSION_JUMP, vec![member], &key);

        assert!(
            at_bound.verify(Some(&v1)).is_ok(),
            "a version jump exactly at the bound is accepted"
        );
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
