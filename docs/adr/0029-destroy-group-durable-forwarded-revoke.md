# Destroy Group: a durable, forwarded Revoke, then wipe and re-pair

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#10](https://github.com/julianbonomini/trueseal-roadmap/issues/10); not yet implemented). This completes the Destroy Group transitions that ADR-0027 left open. It keeps ADR-0028's rule that the same `TrueSeal` object is reused after a wipe, and it adds a `destroying` status.

Destroy Group ends a Sync Group. The initiator stays in a persisted **Destroying** state until the Relay has accepted a Revoke for every member. Every device that receives a valid Revoke passes it on to the members it knows about, and then wipes in the same way. A Revoke is honoured from any device that appears in any Group Manifest the receiver has held for that group. There is no key rotation inside the session. Every surviving device starts over with a fresh identity, and the user pairs again.

## Why

Before this decision (verified from `session/mod.rs`):

- **Revoke was fire-and-forget.** `destroy_group()` pushed one Revoke per peer, ignored any error, and wiped at once. If the Relay was unreachable, peers never learned that the group was gone.
- **A hostile member could block Destroy.** A receiver honoured a Revoke only from a member of its *current* manifest. A thief could remove the owner's device first, and the owner's Revoke would then be dropped by every device that had already seen that removal.
- **Concurrent admissions escaped.** The Revoke went only to members in the initiator's view. A device admitted at the same moment by another member kept a manifest that still contained the stolen device, and it kept sending to it.
- **The docs overclaimed.** They promised "a cryptographic guarantee that nothing future ever lands on it". The code was best effort.

## Decision

### Authority

- Any current member may call `destroyGroup()`, including a stolen device (ADR-0027: every current member is fully trusted).
- A receiver honours a Revoke whose author appears in **any** Group Manifest it has held for this group, current or past. A hostile ex-member can therefore end the group. That affects availability only, and a thief could already do it. Honest removed devices never send a stale Revoke, because removal replaces their identity.
- A Revoke from a device that never appeared in a held manifest is ignored.

### Initiator: the Destroying state

`destroyGroup()` persists **Destroying**, and in the same transaction it queues one Revoke per member of the current view through the outbox. It then drops pending `Sync` sends and Pending Membership Changes without reporting them, as removal does. In Destroying, the device sends no `Sync`, runs no handlers, and stays connected. It stays until the Relay has accepted every Revoke push. Then it wipes the namespace's group state, outbox and dedup table, generates a fresh identity, and reports `statusChanged(notJoined, destroyed)`.

There is no timeout. A timeout would quietly break the promise at exactly the moment the Relay is unreachable. The app shows `destroying` until the wipe happens.

### Receiver: forward, then wipe

A valid Revoke moves a `member` or `leaving` device into Destroying. That device queues a Revoke to every member in its *own* view except the author, following the same rules as the initiator. The ack is sent after Destroying commits (ADR-0026). Forwarding reaches members that were admitted concurrently and are missing from the initiator's view. Each device forwards at most once, because a device that is already in Destroying or `notJoined` ignores further Revokes. The worst case at the Maximum Group Size is about 32 × 31 Revoke blobs.

### State transitions (one Device, one namespace)

| State | Local `destroyGroup()` | Incoming valid Revoke |
|---|---|---|
| `member` | → `destroying` | → `destroying` (forward) |
| `leaving` | → `destroying`. The Leave is abandoned. | → `destroying` (forward) |
| `pendingJoin` | Typed error: not in a group | Ignored. There is no manifest to check the author against. |
| `destroying` | No-op | Ignored |
| `notJoined` | Typed error: not in a group | Ignored |

`destroying → notJoined` happens once the Relay has accepted every queued Revoke.

**Crash points:**
- **Before the Destroying transaction commits:** nothing has changed. For a receiver, the Relay redelivers the Revoke because it wasn't acked.
- **After the commit, and during the pushes:** Destroying resumes on the next start, and the outbox replays the Revokes the Relay hasn't yet accepted.
- **During the wipe:** the wipe restarts. It never runs twice against a fresh identity, because the identity is replaced as the last step.

### Key rotation

There is no rotation inside the session. Bootstrapping a new group that a thief could not join would need a new authenticated protocol. After Destroy Group, surviving devices are `notJoined` with fresh identities, and the user rebuilds the group by pairing again. The stolen device can ask to join like any stranger, and it is admitted only if a member explicitly accepts it.

### Public wording

This replaces the old "cryptographic guarantee" wording in the docs and the threat model:

> **Destroy Group ends the group for every device that receives it.** Each device that receives it passes the Destroy on to the members it knows about, deletes all group state, and starts over with a new identity. After that, no device that received it sends anything to any old device address, the stolen one included. To use TrueSeal together again, pair your devices from scratch.
>
> **What it does not do:**
> - It can't recover or erase anything the stolen device already received or stored.
> - It can't force the stolen device to wipe itself.
> - It doesn't reach a device that stays offline longer than the relay's message lifetime (30 days by default). That device keeps its old group until the user destroys or leaves it there too.
> - It doesn't complete while your device can't reach the relay. Your device shows "destroying" until it can.
> - Any current or former member can trigger it. That includes a stolen device, which can end your group, though that cuts it off from the group as well.

## Considered alternatives

- **Honour Revoke only from current members.** Rejected. A hostile member could block Destroy by removing the initiator first.
- **Quorum or confirmation for Destroy.** Rejected. It adds a lot of complexity and fails when one of only two devices is stolen.
- **Wipe after a timeout even if Revokes are undelivered.** Rejected. It silently breaks the promise.
- **No forwarding.** Rejected. Concurrently admitted devices would keep sending to the stolen device.
- **Rotation inside the session to a new group.** Rejected for the preview. It is a new protocol for bootstrapping trust.

## Consequences

- This adds Session State (Destroying and its queued Revokes) and the `destroying` value of ADR-0028's `status`. Revoke goes through the outbox as ADR-0026 required. The wire format of Revoke is unchanged beyond ADR-0022's clean break.
- Receivers must keep the signing keys of every manifest they have held for the group, until the group is wiped.
- Tests:
  - Relay unreachable at `destroyGroup()`: the device stays Destroying, then delivers and wipes after reconnect.
  - A crash before commit, after commit, mid-push and mid-wipe resumes correctly and never double-wipes.
  - The thief removes the initiator first, and the Revoke is still honoured.
  - A concurrently admitted device receives the forwarded Revoke and wipes.
  - Leave and Destroy, in both orders, end in `notJoined`.
  - A Revoke is ignored in `pendingJoin`, `notJoined` and `destroying`, and from a device that never appeared in a held manifest.
  - A 32-member group sends at most one Revoke round per device.
- **E2E, across SDKs over a real Relay:**
  - Every device reports `notJoined(destroyed)` with a new identity.
  - After the destroy, no Blob is addressed to any old key, and the stolen device's `send()` reaches no one.
  - An offline recipient wipes after it reconnects.
  - Re-pairing works, and the stolen device isn't admitted without explicit acceptance.
  - The TTL case, a device offline for more than 30 days, belongs to the E2E gate's TTL-boundary test.
- Docs: use the public wording above in the revocation concept page and the threat model.
