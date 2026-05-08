# Two removal operations: soft removal and destroy group

## Context

ADR-0007 defined a single revocation operation: `REVOKE_ALL` — a full group reset that wipes all paired device lists and rotates every device's keypair. This is correct and sufficient for security incidents (stolen phone, compromised device).

With the introduction of Group Manifests (ADR-0014), a second removal scenario exists that `REVOKE_ALL` handles poorly: reorganising group membership without a security incident. Removing a device because you got a new phone, left a job, or simply want to reorganise your devices should not destroy the entire group and force everyone to re-pair.

These two scenarios have fundamentally different semantics, costs, and threat models. Collapsing them into a single operation forces the caller to use a sledgehammer for a task that needs a scalpel.

## Decision

Two distinct removal operations are supported:

---

### `removeMember(device: noise_pub)` — soft removal

Any current group member may remove any other member by issuing a new Group Manifest version that excludes the target device (ADR-0014). No keypairs are rotated. No reconnection required.

**Effect:**
- A new manifest version is issued and propagated to all current members.
- All remaining members begin filtering the removed device's inbound messages (author not in manifest → discard).
- All remaining members stop sending future blobs to the removed device.
- The removed device, on receiving the new manifest, fires `onRemovedFromGroup()`.
- The removed device's existing keypair remains valid — it can still push blobs to the relay, but no remaining member will accept them.

**Threat model:** Cooperative. The enforcement is social, not cryptographic. A modified or adversarial app on the removed device can bypass filtering. This is acceptable for the trusted-group use cases this primitive targets (personal devices, small teams). It is not acceptable as the sole response to a security incident.

**Use when:** Reorganising devices (new phone, old laptop decommissioned), removing a departing team member cooperatively, routine group maintenance.

---

### `destroyGroup()` — full reset (supersedes `REVOKE_ALL` from ADR-0007)

Any current group member may destroy the group entirely. This pushes a `REVOKE` message to every known member, then every device:

1. Fires `onGroupDestroyed()`.
2. Wipes the local SQLite database for that namespace — identity, manifest, and outbox (ADR-0016).

The next `create()` call on that namespace auto-generates a fresh identity. The caller never handles or persists keypair bytes directly — the library owns the full identity lifecycle.

No device in the former group can receive future blobs addressed to any member's old keypair, because no legitimate device addresses blobs to those keys anymore. The relay remains zero-knowledge and enforces nothing — exclusion works by key rotation, not key blocking.

**Threat model:** Cryptographic. A compromised or adversarial device cannot receive future data after a destroy, regardless of what software it runs, because its old keypair is no longer an active recipient address.

**Use when:** Security incident (stolen or compromised device), complete group teardown, "nuke" scenario.

---

## Why soft removal cannot be upgraded to cryptographic enforcement without key rotation

In a zero-trust, relay-agnostic system with no key revocation server, the only mechanism to cryptographically exclude a device is to stop addressing blobs to its public key. The only way to ensure a removed device cannot decrypt future blobs is to ensure those blobs are not encrypted to its key. This requires either:

(a) All remaining members rotate their keypairs simultaneously, so the removed device has no valid recipient addresses for them — equivalent to a partial destroy, with all the offline coordination complexity that entails; or  
(b) The relay blocks the removed device's key — which breaks zero-trust.

Neither is acceptable at this primitive level. Soft removal is therefore explicitly cooperative, and this is documented rather than hidden.

## The gap: removing one device with cryptographic enforcement

A future v2 could implement targeted key rotation (rotate everyone except the removed device, auto-rekey via encrypted key-agreement messages). Signal's Sender Keys protocol is the reference design. This is explicitly deferred — it requires a distributed key agreement sub-protocol with offline delivery semantics that would significantly increase the complexity of this primitive. The current split (cooperative soft removal + nuclear full reset) covers the vast majority of real use cases and is honest about its limits.

## Consequences

- ADR-0007 is superseded by this decision. `REVOKE` / `REVOKE_ALL` is renamed conceptually to `destroyGroup()`. The wire encoding (`Message::Revoke`, tag `0x03`) is unchanged — the semantics are clarified, not the protocol.
- `removeMember` is implemented as a manifest update (ADR-0014), not a new message type.
- Two new callbacks are added to the session facade: `onRemovedFromGroup()` (fires when the local device is excluded from a manifest update) and `onGroupDestroyed()` (fires when a `REVOKE` is received or sent).
- Any member can remove any other member and can destroy the group. There is no permission hierarchy. This is consistent with the "all nodes are equal" principle and the trusted-group threat model.
- Callers who need a permission hierarchy (only admins can remove members) must implement that policy above this primitive. The primitive enforces nothing about who may issue manifest updates — only that the issuer was a member at the time of issuance.
