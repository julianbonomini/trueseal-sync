mod accept_pair;
mod fanout;
mod join_group;
mod manifest_filter;
mod outbox;
mod pairing;
mod push;
mod revocation;

use ed25519_dalek::SigningKey;

use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};

pub(super) fn make_two_member_manifest(
    a_noise: NoisePublicKey,
    a_signing: SigningPublicKey,
    a_signing_key: &SigningKey,
    b_noise: NoisePublicKey,
    b_signing: SigningPublicKey,
) -> GroupManifest {
    GroupManifest::new(
        new_group_id(),
        1,
        vec![
            ManifestMember {
                noise_pub: a_noise,
                signing_pub: a_signing,
                name: "DeviceA".into(),
            },
            ManifestMember {
                noise_pub: b_noise,
                signing_pub: b_signing,
                name: "DeviceB".into(),
            },
        ],
        a_signing_key,
    )
}

pub(super) fn make_one_member_manifest(
    noise: NoisePublicKey,
    signing: SigningPublicKey,
    signing_key: &SigningKey,
) -> GroupManifest {
    GroupManifest::new(
        new_group_id(),
        1,
        vec![ManifestMember {
            noise_pub: noise,
            signing_pub: signing,
            name: "DeviceA".into(),
        }],
        signing_key,
    )
}
