//! Upgrade-fixture emission for the G6 release gate (ADR-0032, SYNC-13).
//!
//! The e2e suite opens real stores written by every earlier release since
//! the migration floor. This module emits those stores through the same
//! public code paths the library itself uses — nothing is built by hand.
//!
//! States that are pure storage (an identity, a manifest, queued outbox
//! entries, a dedup table in use) are emitted here. States that are
//! protocol state machines — Pending Join, Leaving, Destroying — are
//! emitted by driving a real session (the e2e scenario drivers), because
//! their persisted records are session-owned encodings that must be valid
//! for the next release to resume them.

use std::path::Path;

use crate::device::DeviceKeypair;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::message::Message;
use crate::operation_log::{now_secs, OperationLog};
use crate::store::{PersistentLog, Store, StoreError};

/// A G6 fixture state. Each value maps to a store in a documented,
/// reproducible state, written at the current Store Version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureState {
    /// A group member with two queued `Sync` entries and one queued
    /// Group Manifest control entry, delivered to nobody yet.
    MemberWithOutbox,
    /// The dedup table in use: one handled Message ID on record.
    DedupInUse,
}

impl FixtureState {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "member-with-outbox" => Some(Self::MemberWithOutbox),
            "dedup-in-use" => Some(Self::DedupInUse),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::MemberWithOutbox => "member-with-outbox",
            Self::DedupInUse => "dedup-in-use",
        }
    }

    pub fn all() -> &'static [FixtureState] {
        &[Self::MemberWithOutbox, Self::DedupInUse]
    }
}

/// Emit a G6 upgrade fixture: a real store at `{base_dir}/trueseal_{namespace}.db`
/// in the requested state, at the current Store Version (ADR-0032).
pub fn emit_upgrade_fixture(
    base_dir: &Path,
    namespace: &str,
    state: FixtureState,
) -> Result<(), StoreError> {
    let store = Store::open(base_dir, namespace)?;
    let kp = DeviceKeypair::generate();
    store.save_keypair(&kp)?;
    let sp = kp.signing_public_key();
    let member = ManifestMember {
        noise_pub: kp.public_key(),
        signing_pub: sp,
        name: member_name(&sp),
    };
    let manifest = GroupManifest::new(new_group_id(), 0, vec![member], &kp.signing);
    store.save_group_manifest(&manifest)?;

    let mut log = PersistentLog::new(store);
    match state {
        FixtureState::MemberWithOutbox => {
            let peer = DeviceKeypair::generate();
            log.append(
                &peer.public_key().0,
                1,
                b"fixture: queued sync one".to_vec(),
            );
            log.append(
                &peer.public_key().0,
                2,
                b"fixture: queued sync two".to_vec(),
            );
            log.append_control(
                &peer.public_key().0,
                3,
                Message::GroupManifest { manifest }.encode(),
            );
        }
        FixtureState::DedupInUse => {
            log.record_handled("tsm_fixture_handled", now_secs());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitted_fixtures_open_clean_at_the_current_version() {
        for state in FixtureState::all() {
            let dir = tempfile::tempdir().unwrap();
            emit_upgrade_fixture(dir.path(), "fixture", *state).expect("emit");
            let (s, outcome) = Store::open_with_outcome(dir.path(), "fixture").expect("open");
            assert_eq!(
                outcome,
                crate::store::OpenOutcome::default(),
                "fixture {} opens with nothing to do",
                state.name()
            );
            assert!(s.load_keypair().expect("kp").is_some());
        }
    }

    #[test]
    fn member_with_outbox_fixture_has_queued_entries() {
        let dir = tempfile::tempdir().unwrap();
        emit_upgrade_fixture(dir.path(), "fixture", FixtureState::MemberWithOutbox).expect("emit");
        let s = Store::open(dir.path(), "fixture").expect("open");
        let entries = PersistentLog::new(s).undelivered_entries();
        assert_eq!(entries.len(), 3, "two Sync + one manifest control entry");
    }
}
