//! SYNC-10 (#102): unchecked manifest version arithmetic let a single hostile
//! or corrupt manifest freeze membership for good — a manifest at `u64::MAX`
//! was accepted, after which every legitimate manifest looked like a
//! regression and the next issuance overflowed (panic in debug, wrap in
//! release). These tests prove the defect and pin the fix (ADR-0027):
//! receivers reject `u64::MAX` and jumps over the sanity bound (1024), and
//! issuance uses checked arithmetic with a typed refusal.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::delivery_issue::{DeliveryIssue, UnreadableReason};
use crate::device::DeviceKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::message::Message;

use super::super::test_helpers::*;
use super::super::{SessionError, TruesealSession};

fn member(noise_pub: NoisePublicKey, signing_pub: SigningPublicKey, name: &str) -> ManifestMember {
    ManifestMember {
        noise_pub,
        signing_pub,
        name: name.into(),
    }
}

/// Seed B with a v1 manifest issued by A, connect both ends of a routing
/// relay, and return the pieces a hostile-manifest test needs.
struct HostileRig {
    session_a: TruesealSession<MemPipe>,
    session_b: TruesealSession<MemPipe>,
    a_noise: NoisePublicKey,
    a_signing: SigningPublicKey,
    b_noise: NoisePublicKey,
    b_signing: SigningPublicKey,
    a_sk: SigningKey,
    group_id: [u8; 32],
    issues: Arc<Mutex<Vec<DeliveryIssue>>>,
}

fn hostile_rig() -> HostileRig {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let group_id = new_group_id();

    // Relay accepts src (a) first, then dst (b) — connect in the same order.
    let session_a = TruesealSession::connect(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("session A");
    let session_b = TruesealSession::connect(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("session B");

    let v1 = GroupManifest::new(
        group_id,
        1,
        vec![
            member(a_noise, a_signing, "DeviceA"),
            member(b_noise, b_signing, "DeviceB"),
        ],
        &a_sk,
    );
    session_b.set_manifest(v1);

    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(Vec::new()));
    let ix = issues.clone();
    session_b.subscribe_delivery_issues(move |issue| {
        ix.lock().unwrap_or_else(|e| e.into_inner()).push(issue);
    });

    HostileRig {
        session_a,
        session_b,
        a_noise,
        a_signing,
        b_noise,
        b_signing,
        a_sk,
        group_id,
        issues,
    }
}

impl HostileRig {
    /// A signs and pushes an arbitrary-version manifest carrying the given
    /// members to B — the channel a hostile (or corrupt) member would use.
    fn push_manifest(&self, version: u64, members: Vec<ManifestMember>) {
        let manifest = GroupManifest::new(self.group_id, version, members, &self.a_sk);
        self.session_a
            .push_message(&Message::GroupManifest { manifest }, self.b_noise)
            .expect("push manifest");
    }

    fn two_members(&self) -> Vec<ManifestMember> {
        vec![
            member(self.a_noise, self.a_signing, "DeviceA"),
            member(self.b_noise, self.b_signing, "DeviceB"),
        ]
    }

    fn three_members(&self) -> Vec<ManifestMember> {
        let device_c = DeviceKeypair::generate();
        let mut members = self.two_members();
        members.push(member(
            device_c.public_key(),
            device_c.signing_public_key(),
            "DeviceC",
        ));
        members
    }

    fn unreadable_malformed_reported(&self) -> bool {
        self.issues
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|i| matches!(i, DeliveryIssue::Unreadable(UnreadableReason::Malformed)))
    }
}

/// The defect itself: a manifest at `u64::MAX` must never become current, and
/// membership must keep moving afterwards — a legitimate v2 issued right after
/// the hostile manifest is accepted. Before the fix, B accepts the `u64::MAX`
/// manifest and rejects v2 as a regression: membership is frozen for good.
#[test]
fn hostile_manifest_at_max_version_never_freezes_membership() {
    let rig = hostile_rig();
    rig.push_manifest(u64::MAX, rig.two_members());
    std::thread::sleep(Duration::from_millis(150));

    rig.push_manifest(2, rig.three_members());
    wait_for(
        || rig.session_b.members().len() == 2,
        Duration::from_secs(2),
    );
    assert_eq!(
        rig.session_b.members().len(),
        2,
        "a legitimate manifest after the hostile u64::MAX one must still be accepted (members() excludes the local device)"
    );
    assert!(
        rig.unreadable_malformed_reported(),
        "the rejected manifest must be reported as a typed Delivery Issue"
    );
}

/// A jump beyond the sanity bound is rejected on receipt; the group still
/// accepts the next legitimate manifest. Before the fix the jump was
/// unbounded, so the hostile manifest became current and v2 was rejected.
#[test]
fn hostile_manifest_with_jump_over_bound_is_rejected() {
    let rig = hostile_rig();
    // One past the sanity bound of 1024 (ADR-0027).
    rig.push_manifest(1 + 1024 + 1, rig.two_members());
    std::thread::sleep(Duration::from_millis(150));

    rig.push_manifest(2, rig.three_members());
    wait_for(
        || rig.session_b.members().len() == 2,
        Duration::from_secs(2),
    );
    assert_eq!(
        rig.session_b.members().len(),
        2,
        "a legitimate manifest after an over-bound jump must still be accepted (members() excludes the local device)"
    );
    assert!(
        rig.unreadable_malformed_reported(),
        "the rejected manifest must be reported as a typed Delivery Issue"
    );
}

/// Guard: a jump exactly at the bound is accepted — before and after the fix.
#[test]
fn manifest_with_jump_at_bound_is_accepted() {
    let rig = hostile_rig();
    rig.push_manifest(1 + 1024, rig.three_members());
    wait_for(
        || rig.session_b.members().len() == 2,
        Duration::from_secs(2),
    );
    assert_eq!(rig.session_b.members().len(), 2);
}

/// Issuing on a manifest at the last issuable version must fail typed, not
/// produce a `u64::MAX` manifest every receiver rejects. Before the fix the
/// unchecked `version + 1` happily issued `u64::MAX`.
#[test]
fn remove_member_at_max_issuable_version_returns_typed_error() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = crate::version::testutil::xx_accept_after_prefix(pipe_relay, kp);
        });
    }
    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let b_signing = device_b.signing_public_key();
    let b_member = member(device_b.public_key(), b_signing, "DeviceB");
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());

    let session = TruesealSession::connect(
        pipe_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        || Err("push factory: errors swallowed".into()),
    )
    .expect("connect");
    let nearly_maxed = GroupManifest::new(
        new_group_id(),
        u64::MAX - 1,
        vec![member(a_noise, a_signing, "DeviceA"), b_member],
        &a_sk,
    );
    session.set_manifest(nearly_maxed);

    let result = session.remove_member(b_signing);
    assert!(
        matches!(result, Err(SessionError::ManifestVersionExhausted)),
        "issuing past the maximum allowed version must fail with a typed error"
    );
    assert_eq!(
        session.members().len(),
        1,
        "a refused issuance must not change the current manifest"
    );
}

/// Issuing on a manifest at `u64::MAX` must fail typed — before the fix the
/// unchecked increment panicked in debug builds and wrapped to 0 in release.
#[test]
fn remove_member_at_u64_max_does_not_panic_or_wrap() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = crate::version::testutil::xx_accept_after_prefix(pipe_relay, kp);
        });
    }
    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let b_signing = device_b.signing_public_key();
    let b_member = member(device_b.public_key(), b_signing, "DeviceB");
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());

    let session = TruesealSession::connect(
        pipe_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        || Err("push factory: errors swallowed".into()),
    )
    .expect("connect");
    let maxed = GroupManifest::new(
        new_group_id(),
        u64::MAX,
        vec![member(a_noise, a_signing, "DeviceA"), b_member],
        &a_sk,
    );
    session.set_manifest(maxed);

    let result = session.remove_member(b_signing);
    assert!(
        matches!(result, Err(SessionError::ManifestVersionExhausted)),
        "issuing from u64::MAX must fail typed, not panic or wrap"
    );
    assert_eq!(session.members().len(), 1);
}
