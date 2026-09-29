# Membership: any-member authority, parent-linked manifests, library-owned convergence

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#9](https://github.com/julianbonomini/trueseal-roadmap/issues/9); not yet implemented). This refines ADR-0014's validity rules and "last-version-wins", and ADR-0015's removed-device behaviour. Destroy Group and Revoke semantics are out of scope here and belong to trueseal-roadmap#10.

Any current member may change membership: admit, remove, or leave. Every current member is fully trusted for membership. Each Group Manifest names the manifest it was built on. Devices order manifests by `(version, manifest hash)`. The issuer of a change keeps it as a Pending Membership Change and re-applies it automatically if a concurrent manifest overwrites it. The app never has to redo a membership change.

The promise, which is tested:

> Once every member has received the same set of Group Manifests, all members hold an identical manifest. A membership change from an honest member is never lost, unless that member was itself removed concurrently.

## Why

Before this decision (verified from `manifest.rs` and `session/mod.rs`):

- **Equal versions forked.** A device kept whichever equal-version manifest it saw first and rejected the other as a regression. A manifest carried no reference to its predecessor, and the next change from anyone replaced the whole list. The losing side's change, including a removal, was silently undone.
- **Version jumps were unbounded.** A manifest at `u64::MAX` froze membership for good, because `version + 1` overflows.
- **Stale devices were exposed.** A removed device could rewrite membership on devices that had not yet seen its removal, because the only check was that the issuer belongs to the receiver's current manifest.
- **There was no leave operation.** `onRemovedFromGroup` left clean-up to the app.

The guiding rule from ADR-0026 applies: nothing the app must get right for correctness.

## Decision

### Authority and trust boundary

- Any current member may issue a manifest (unchanged from ADR-0014). There are no admins and no creator role. Apps that need roles enforce them above the library.
- **Every current member is fully trusted for membership.** A hostile current member can remove everyone else. A removed device that does not cooperate can still rewrite membership on devices that have not yet seen its removal. Neither is defended against. The response to a hostile or compromised device is Destroy Group. This is documented in the threat model and not hidden.

### Manifest format and ordering

- A manifest adds `parent`, the hash of the manifest it was built on. The genesis manifest has no parent. `parent` is covered by the manifest signature, whose signing input is domain-separated (ADR-0022).
- An issuer always sets `version = base.version + 1`, using checked arithmetic.
- A receiver accepts an incoming manifest if all of the following hold:
  - the signature verifies;
  - the group ID matches;
  - the issuer is a member of the receiver's current manifest;
  - `(version, hash)` is strictly greater than the current manifest's;
  - the version jump is within a sanity bound.
  On an equal version, the **lower** manifest hash wins. A manifest that fails is acked and dropped with a typed event (ADR-0026).
- **Maximum Group Size is 32 members.** An admission that would exceed it is refused locally with a typed error. A test proves that a 32-member manifest fits in one frame (ADR-0025).

### Pending Membership Changes (issuer side)

- Admitting, removing or leaving writes three things in one Session State transaction: the new manifest, its outbox entries (ADR-0026: Group Manifest entries never expire), and a **Pending Membership Change**. The change records its intent, such as "D is a member" or "X is not a member", and the hash of the manifest that carried it.
- Each time the issuer accepts a newer manifest `W`, it checks each pending change:
  - **Satisfied**, meaning `W` already reflects the intent: the change is cleared.
  - **Deliberately superseded**, meaning `W` descends from a manifest the issuer knows carried the change: the change is cleared. This is the case where a later, deliberate change undoes an earlier one, for example removing a device that was admitted earlier.
  - **Concurrently overwritten**, meaning `W` does not descend from the change and does not satisfy it: the issuer re-applies the change on top of `W` as a new manifest, `W.version + 1`. That manifest in turn becomes the change's carrier.
  - **Issuer removed**, meaning `W` excludes the issuer: the change is dropped. This is correct, because a non-member's changes carry no authority.
  - **Re-applied admission would exceed 32:** the change is dropped with a typed event, and the joiner stays in Pending Join.
- An issuer that is offline re-applies after it reconnects. Pending changes survive restarts.

### Removed and leaving devices

- **Leave.** `leaveGroup()` issues a manifest that excludes the local device and enters a persisted **Leaving** state. In Leaving, the device does not send `Sync` and does not run handlers. It stays connected until the Relay has accepted every one of its manifest pushes, then wipes and rotates as below. A crash or going offline in Leaving resumes on the next start.
- **Removal.** A device counts itself removed only when the excluding manifest's `parent` is a manifest it holds or has held that includes it. That is a deliberate removal. On a deliberate removal the library wipes the namespace's group state, outbox and dedup table, generates a fresh identity, returns to `notJoined`, and fires the removed event. Pending sends are dropped.
- **False removal is not removal.** A manifest that excludes the device but was built concurrently, not on a manifest that included it, is stored as the current view. The device stays alive and does not wipe, and it waits for its admitter to re-apply the admission. A new joiner whose admission lost a tie is the typical case.

### Events

`memberJoined` and `memberLeft` follow the device's current view. While a concurrent change is being re-applied, a device can briefly see a member leave and rejoin. This is documented. Apps should render the member list, not treat events as permanent facts.

## State machine (one Device, one namespace)

`NotJoined → PendingJoin → Member → Leaving → NotJoined`, and `Member → NotJoined` on a deliberate removal. Destroy Group transitions are defined in ADR-0029. Within `Member`, the current manifest and the set of Pending Membership Changes evolve as above.

**Crash points:**
- **Before the issuing transaction commits:** there's no change, and the app sees the call fail or never return.
- **After the commit:** the manifest is redelivered from the outbox, and the pending change is re-checked on the next accepted manifest.
- **Receiving:** accepting a manifest, updating pending changes, and queuing any re-application commit together. A crash before that commit means the Relay redelivers the manifest (ack after handling, ADR-0026).
- **Leaving:** a crash during Leaving resumes Leaving. The wipe and rotation happen only after the last manifest push is persisted by the Relay. A crash during the wipe restarts the wipe.

## Considered alternatives

- **Creator-only or admin authority.** Rejected. A creator-only group can't change membership once the creator device is lost, except by Destroy Group. Admin sets add handover and last-admin-loss problems. Neither fits personal devices or small teams.
- **Hardening against removed or hostile members** (never accept an issuer seen removed, causal rejection). Rejected for the preview. It closes a narrow window and still leaves a hostile current member all-powerful. Destroy Group is the answer.
- **Convergence only, with the loser told to redo the change.** Rejected: the app would have to get it right.
- **Receiver-side merge (remove-wins add/remove sets).** Rejected for the preview. It survives an issuer that never returns, but it redesigns the manifest and grows the state machine considerably.
- **Holding events until membership looks settled.** Rejected: it needs timers and still can't promise stability without consensus.

## Consequences

- This is a wire change to the Group Manifest (`parent`, new ordering), covered by the clean break in ADR-0022. It adds Session State: Pending Membership Changes and the Leaving state.
- It needs new API: `leaveGroup()`, a typed group-full error, a typed dropped-change event, and the Leaving join state. Exact names belong to the SDK API shape work.
- Tests: concurrent admit and remove converge on every device; an equal-version tie resolves the same way everywhere; a concurrently overwritten change is re-applied after an issuer restart and after an offline period; a deliberate later removal is not undone; a joiner that loses a tie does not wipe itself; Leave resumes after a crash; a 32-member manifest fits in a frame and a 33rd admission is refused; a version jump and `u64::MAX` are rejected.
- Docs: document the trust boundary, the membership promise, the event flicker, the 32-member limit, and the automatic wipe on removal or leave.
