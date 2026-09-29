# Pairing is anchored to the Pairing Token on both sides

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#5](https://github.com/julianbonomini/trueseal-roadmap/issues/5); not yet implemented)

A joining Device trusts exactly one key: the initiator signing key carried in the Pairing Token it received out-of-band. It holds a persisted **Pending Join** and accepts its first Group Manifest only if that manifest is signed by the token's signing key, the Envelope signer is that same key, and the joiner's own keys are among the members. The group ID and version can be anything (joining an existing group lands at N+1). The token also carries a random, single-use **Pairing Secret**. A `Pair` must prove it knows the secret, so only someone who saw the token can raise a member request. A device with no manifest and no Pending Join never accepts a manifest, and a device with no manifest drops every `Sync` and `Revoke`.

We need this because of [trueseal-roadmap#4](https://github.com/julianbonomini/trueseal-roadmap/issues/4). Envelope author keys are self-asserted, and a device without a manifest accepted any self-signed manifest. So the Relay alone could put a device into a group of its choosing. Separately, a token held no secret, and the initiator's `noise_pub` is its routing address, so the Relay could inject join requests. Member names (about 14 bits) can be ground to match a real joiner, so a human accept based on the name was not authentication. The token is the one channel the Relay never sees, so both directions of trust are anchored there.

## State machine

**Admitter (initiator).** `Idle → WindowOpen(secret) → Idle`.
- `pairingToken()` generates a fresh secret and opens the window. The window and its pending requests live in memory only. A restart or `cancelPairing()` closes the window and spends the secret, and a new window always gets a new secret.
- A `Pair` with a valid secret proof becomes a pending request. Repeat `Pair`s from the same joiner keys deduplicate into one request. Several distinct requests may coexist, and the user picks one.
- `acceptMember()` is single-use. It persists the new manifest and queues it for delivery before returning true, and then the window closes. Later `Pair`s under the spent secret are dropped.
- There is no decline message. A request that is not accepted gets no reply.

**Joiner.** `NotJoined → PendingJoin(initiator keys, secret) → Member`.
- `joinGroup(token)` fails with `AlreadyInGroup` if a manifest exists (one Sync Group per namespace). Otherwise it persists the Pending Join in Session State and queues `Pair` in the durable outbox, in one transaction. A second `joinGroup` replaces the Pending Join, and `cancelJoin()` clears it.
- A Pending Join has no timer (consistent with ADR-0021) and survives restarts. `Pair` is not re-sent on restart. Retries follow the outbox.
- A manifest that fails the checks is dropped, and the Pending Join is kept. A valid one is stored and the Pending Join cleared, in one transaction. Then a single "joined" event fires. The caller can always query `notJoined | pendingJoin | member`.

**Crash points.** A crash before a transaction commits leaves the prior state. On the joiner that means `NotJoined` (retry `joinGroup`) or `PendingJoin`, where a manifest that was received but not committed is redelivered by the Relay. On the admitter, a crash before accept commits loses the window, and the joiner stays pending until its caller cancels or re-scans. A crash after commit re-sends the queued manifest from the outbox.

## Considered alternatives

- **Rely on the explicit human accept, with no secret.** Rejected: the Relay can raise requests, and the displayed names can be forged.
- **Require a fresh group ID on the joiner.** Rejected: a device joining an existing group receives that group's ID at version N+1.
- **Persist the admitter's window.** Rejected: ADR-0021 ties the window to the pairing UI, and closing it on restart keeps secrets short-lived.
- **Add a SAS now.** Deferred, as in ADR-0002. A sound SAS needs a commitment scheme, and after the secret is added the remaining threat is an out-of-band leak of the token.

## Consequences

- This is a wire change to the Pairing Token and the `Pair` message, covered by the clean break in ADR-0022. It also adds new Session State (the Pending Join) and a new caller-visible join state and event. Exact API names belong to the SDK API shape work.
- Binding the `Pair` `signing_pub` to the Envelope signer is a separate defect fix, and it is required alongside this.
- Durable delivery of the admission manifest depends on the delivery contract ([trueseal-roadmap#7](https://github.com/julianbonomini/trueseal-roadmap/issues/7)). Until then, a lost manifest leaves the joiner pending.
- Documented limitation: anyone who sees the Pairing Token while the window is open can request to join. The admitting user must confirm the device in front of them. Member names are labels, not authentication.
