# Group Manifest: first-class Sync Group membership

## Context

Prior to this decision, trueseal-sync had no first-class concept of a Sync Group. Each Device maintained a flat `PairedList` populated one device at a time through pairwise pairing ceremonies. Those lists were never synchronised between devices, so membership was inconsistent by construction:

- Device A paired with B and C meant A knew both, but B and C had no knowledge of each other.
- If A went offline, B and C could not reach each other.
- On revocation, each device wiped its own list independently with no guarantee that all members received the revocation.
- A new device joining an existing group received only the view that the admitting device had at the moment of admission — not a canonical group state.

This made the "delivery to the group" guarantee unenforceable: the library did not know who was in the group.

## Decision

A **Group** is now a first-class concept, represented by a **Group Manifest** — a signed, versioned document that is the authoritative membership record for a Sync Group.

### Structure

A Group Manifest contains:

- `version` — monotonically increasing integer, scoped to the group (not per-device)
- `group_id` — a stable random identifier generated at group creation, never changes
- `members` — ordered list of `{ noise_pub: [u8;32], signing_pub: [u8;32] }` for every current member
- `issued_by` — the `signing_pub` of the member who issued this version
- `signature` — Ed25519 signature over `group_id || version || members`, signed by `issued_by`

### Validity rules

A manifest version N+1 is accepted by a recipient if and only if:

1. The signature verifies against `issued_by`.
2. `issued_by` is a member in the recipient's current manifest version N (i.e. the issuer was a legitimate member at the time of issuance).
3. `version` is strictly greater than the recipient's current version.

Last-version-wins. If two members simultaneously issue conflicting manifest versions (e.g. A removes B while C removes D), the higher version number wins when they propagate and converge. This is eventual consistency for membership, identical to the existing per-sender blob ordering model — no consensus protocol is required.

### Delivery

A Group Manifest is delivered as a new `GROUP_MANIFEST` message type (tag `0x04`) inside the existing Envelope infrastructure — encrypted, signed, and relayed identically to `SYNC` messages. It is pushed to every current member on every membership change.

### No group-level signing key

The manifest is signed by the issuing member's existing Ed25519 signing key — the same key that signs Envelopes. No separate group key exists. Authority to modify the manifest derives from current membership, not from possession of a special key. All members are equal.

### Inbound message filtering

Recipients filter all inbound messages (any type) against their current manifest: if `author_signing_pub` is not in `manifest.members`, the message is silently discarded. This extends the existing signature verification step — a message that passes Ed25519 verification but whose author is not in the manifest is treated as if it failed verification.

This makes soft removal effective: a removed device's messages are discarded by all remaining members, even though the relay still accepts and forwards them. The enforcement is cooperative, not cryptographic — which is sufficient for the trusted-group threat model this primitive targets.

### New device bootstrap

When device A admits device D:

1. A sends D the current Group Manifest (so D knows the full member list immediately).
2. A issues a new manifest version N+1 that includes D, signs it, and pushes it to every existing member.
3. Every existing member updates their local manifest and begins sending future blobs to D.

D receives one authoritative document and has a complete, consistent view of the group from the moment of admission. There is no convergence lag.

### Offline devices

Offline devices receive the updated manifest when they reconnect, via the existing outbox replay mechanism. Until they reconnect, they operate with a stale manifest — they will not send to newly added members, and will not filter newly removed members. This is acceptable: the outbox replays the manifest update as soon as connectivity is restored, and the offline device converges immediately on reconnect.

## Consequences

- `PairedList` is superseded by `GroupManifest` as the source of truth for who to send to and whose messages to accept.
- Pairing now has two steps: (1) the existing QR/accept ceremony to exchange keys, and (2) issuing a new manifest version that includes the new member. The session facade handles both.
- The `PAIR` message type retains its existing role (key exchange bootstrap), but the act of "joining the group" is now formalised as a manifest update rather than a `PairedList.add()` call.
- A device that receives a manifest that excludes itself fires `onRemovedFromGroup()` — a new callback. The caller decides what to do (wipe local data, show UI, etc.).
- Manifest version history is not retained — each device stores only the current manifest version. Historical versions are not needed for any operation this primitive supports.

## Considered alternatives

**Gossip (pairwise propagation without a manifest document)**
Rejected. Membership convergence is eventual and has partial states that are difficult to reason about. Revocation is brittle — if peer lists diverge at the moment of revocation, some members may not receive it. Offline device catch-up is ambiguous. Gossip does not give the caller a clear answer to "who is in the group right now."

**Designated coordinator**
Rejected. One device as the source of truth for membership is a single point of failure, violates the "all nodes are equal" principle, and contradicts the fault-tolerance goal.

**Group-level signing key (separate from any device key)**
Rejected. Introduces a key management problem: who holds the group key, what happens when the device holding it is lost, how does the group key rotate. Deriving manifest authority from current membership (any member can issue, verified by chain of custody) achieves the same goal without the extra key.
