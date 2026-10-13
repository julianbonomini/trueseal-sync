//! SYNC-9 (#101): membership convergence — red tests for the (version, hash)
//! total order and `parent` linkage (ADR-0027). These run against
//! `GroupManifest` directly; session-level convergence tests live alongside.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestError, ManifestMember};

fn sk() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn member(key: &SigningKey) -> ManifestMember {
    use x25519_dalek::{PublicKey, StaticSecret};
    let noise_priv = StaticSecret::random_from_rng(OsRng);
    let noise_pub = PublicKey::from(&noise_priv);
    ManifestMember {
        noise_pub: NoisePublicKey(*noise_pub.as_bytes()),
        signing_pub: SigningPublicKey(key.verifying_key().to_bytes()),
        name: "TestDevice".into(),
    }
}

/// An update names the manifest it was built on: `parent` is the base's
/// hash and the version steps by exactly one (ADR-0027).
#[test]
fn update_sets_parent_and_steps_version() {
    let key = sk();
    let m = member(&key);
    let group = new_group_id();
    let base = GroupManifest::new(group, 1, vec![m.clone()], &key);
    let next = GroupManifest::update(&base, vec![m], &key).expect("version steps");

    assert_eq!(next.version, 2);
    assert_eq!(next.parent, Some(base.hash()));
    assert!(next.verify(Some(&base)).is_ok());
}

/// Genesis has no parent; the parent round-trips through encode/decode.
#[test]
fn parent_round_trips_through_encoding() {
    let key = sk();
    let m = member(&key);
    let group = new_group_id();
    let genesis = GroupManifest::new(group, 1, vec![m.clone()], &key);
    assert_eq!(genesis.parent, None);
    let decoded = GroupManifest::decode(&genesis.encode()).expect("decode");
    assert_eq!(decoded.parent, None);

    let next = GroupManifest::update(&genesis, vec![m], &key).expect("update");
    let decoded = GroupManifest::decode(&next.encode()).expect("decode");
    assert_eq!(decoded.parent, Some(genesis.hash()));
}

/// `parent` is covered by the signature: flipping it after issuance fails
/// verification (ADR-0027: "parent is covered by the manifest signature").
#[test]
fn tampered_parent_fails_verification() {
    let key = sk();
    let m = member(&key);
    let group = new_group_id();
    let base = GroupManifest::new(group, 1, vec![m.clone()], &key);
    let mut next = GroupManifest::update(&base, vec![m], &key).expect("update");
    next.parent = Some([0xAB; 32]);

    assert!(matches!(
        next.verify(Some(&base)),
        Err(ManifestError::InvalidSignature)
    ));
}

/// Issuing on an exhausted base fails typed — never panics, never wraps
/// (SYNC-10 rules apply to the update constructor too).
#[test]
fn update_on_exhausted_version_fails_typed() {
    let key = sk();
    let m = member(&key);
    let group = new_group_id();
    // Hand-build a base at u64::MAX - 1... its update would be u64::MAX,
    // which receivers reject, so issuance refuses.
    let base = GroupManifest::new(group, u64::MAX - 1, vec![m.clone()], &key);
    assert!(matches!(
        GroupManifest::update(&base, vec![m], &key),
        Err(ManifestError::VersionExhausted)
    ));
}

/// The (version, hash) total order: on an equal version the LOWER manifest
/// hash wins — every device picks the same winner from the same pair
/// (ADR-0027).
#[test]
fn equal_version_lower_hash_wins() {
    let key_a = sk();
    let key_b = sk();
    let ma = member(&key_a);
    let mb = member(&key_b);
    let group = new_group_id();
    let base = GroupManifest::new(group, 1, vec![ma.clone()], &key_a);

    // Two concurrent v2 manifests from different issuers.
    let mut m2a = GroupManifest::update(&base, vec![ma.clone(), mb.clone()], &key_a).expect("a");
    let mut m2b = GroupManifest::update(&base, vec![ma.clone()], &key_b).expect("b");
    // Order them by hash so m_low is the winner.
    if m2b.hash() < m2a.hash() {
        std::mem::swap(&mut m2a, &mut m2b);
    }
    let (m_low, m_high) = (m2a, m2b);

    // A device holding the higher-hash manifest ACCEPTS the lower-hash one.
    assert!(
        m_low.verify(Some(&m_high)).is_ok(),
        "the lower-hash manifest wins the tie"
    );
    // A device holding the winner rejects the loser as a benign stale.
    assert!(
        matches!(
            m_high.verify(Some(&m_low)),
            Err(ManifestError::VersionRegression { .. })
        ),
        "the higher-hash manifest loses the tie"
    );
}

/// A lower version always loses, whatever the hash.
#[test]
fn lower_version_loses_regardless_of_hash() {
    let key = sk();
    let m = member(&key);
    let group = new_group_id();
    let v1 = GroupManifest::new(group, 1, vec![m.clone()], &key);
    let v2 = GroupManifest::update(&v1, vec![m], &key).expect("update");

    assert!(matches!(
        v1.verify(Some(&v2)),
        Err(ManifestError::VersionRegression { .. })
    ));
}
