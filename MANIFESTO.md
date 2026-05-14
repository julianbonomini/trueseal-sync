# trueseal-sync Manifesto

## Purpose

There is no free, easy primitive for private and secure sync. Developers who care about user privacy have no default building block — so they either build it themselves at great cost, or default to infrastructure that can spy on users. trueseal-sync exists to remove that excuse.

## Principles

**Zero trust**
The relay cannot be trusted — not because it is malicious, but because trust should never be required. Data is encrypted before it leaves the device. The relay is structurally incapable of reading it. This is not a promise. It is a constraint.

**Anonymity**
The system has no concept of human identity. No accounts. No registration. No email, no phone number, no username. A device is identified only by its keypair. Who owns that device is never part of the protocol. trueseal-sync will never know who you are — and is designed so that it cannot.

**Fault tolerant**
The primitive must survive the environment it runs in: devices go offline, networks drop, processes crash. No human intervention required. Any device can be offline indefinitely and return current. No single device is load-bearing.

**Guaranteed delivery**
A blob sent will reach every group member. Eventually, unconditionally. This is not best-effort — it is the contract. Without it, sync is not sync.

## Boundary

- **Not a messaging primitive** — there is no point-to-point send. Sync fans out to the whole group. No read receipts, no message history API. Build those on top.
- **Not a conflict resolution engine** — delivery and ordering are guaranteed. What you do when two devices send conflicting data is your responsibility.
- **Not an identity system** — no accounts, no display names beyond keypair-derived identifiers. Associating a human to a device is the caller's problem.
- **Not a platform** — no permission hierarchies, no admin roles. Any member can do anything. Build authority above this primitive.

## Consequences

- **Dumb relay** — the relay stores and forwards encrypted blobs. It knows no group membership, no identity, no content. It can be self-hosted, replaced, or run by an adversary. The security model does not change.
- **E2EE on device** — encryption happens before data leaves. Not configurable, not optional. Follows from zero trust.
- **Identity = keypair** — generated on device at first launch, never registered anywhere. Follows from anonymity.
- **Embedded local storage** — session state, identity, and outbox are fully managed by the library. The caller implements zero storage code. Follows from fault tolerance.
- **Outbox replay** — undelivered blobs survive crashes and reconnect automatically. Follows from guaranteed delivery.
