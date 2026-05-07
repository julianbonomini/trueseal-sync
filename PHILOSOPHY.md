# hush-sync: Design Philosophy

## What this is

hush-sync is a sync primitive. Not a messaging app, not a database, not a platform. A primitive — the smallest useful building block for encrypted, local-first data sync between trusted devices.

The measure of a good primitive is not how many features it has. It's how cleanly it disappears. When you build on hush-sync, you should be thinking about your app, not about encryption, not about key management, not about network reliability. hush-sync handles all of that. You handle what your app means.

---

## First principles

Everything in this library traces back to four principles. They were chosen before any code was written, and every design decision since has been evaluated against them.

**1. Fully secure, without identity management.**

E2EE is non-negotiable. Every blob is encrypted before it leaves the device. The relay never sees plaintext. Revocation is real — a destroyed group cryptographically terminates future data access for all former members. But security should not require the caller to understand cryptography. Keys are the identity, but the caller never touches a key. The library generates, stores, rotates, and retires keys entirely on its own.

**2. Zero trust.**

The relay is infrastructure, not a gatekeeper. It stores and forwards encrypted blobs. It knows nothing about who is in a group, what a blob contains, or whether a sender is authorised. It cannot be compelled to reveal group membership because it does not know it. Authorisation is enforced at the receiving device by verifying signatures and checking against the Group Manifest — not by asking a server. The relay can be self-hosted, replaced, or run by an adversary. The security model does not change.

**3. Guaranteed delivery and ordering within the group.**

A blob you send will eventually be received by every group member. If they are offline, it waits. If the app crashes, it survives. If the network drops mid-send, it retries. Per-sender ordering is guaranteed — you will never receive blob 7 from a device before blob 6. Causal ordering across devices (the full DAG model) is the v1 goal — the wire format supports it today, the library behaviour will follow.

**4. Fault tolerant and self-healing.**

No single device is load-bearing. Any device can be offline. The library detects disconnection, backs off, and reconnects silently. Membership is defined by a Group Manifest that every device holds locally — not by a server that can go down. A device that was offline for a week comes back, receives all the manifest updates and blobs it missed, and is current. No human intervention required.

---

## How we got here: the journey

### We started with a working implementation

hush-sync already had E2EE, Noise XX sessions, pairing, revocation, and an outbox. The crypto was correct. The relay was zero-knowledge. The reconnect logic was solid.

But the caller API was leaking internals. To use the library, you needed to understand the difference between a noise_pub and a signing_pub. You needed to manage 64-byte keypairs yourself. You needed to know what an operation log was and persist it. The first principles were in the implementation, but not in the interface.

### We identified the missing first principle

The most important gap was not a missing feature. It was a missing concept: there was no Group. Each device maintained its own flat list of trusted peers, and those lists could diverge. A "group" of three devices might actually be three disconnected pairwise relationships. Delivery to "the group" was unenforceable because the library had no authoritative definition of what the group was.

This led to the Group Manifest — a signed, versioned, authoritative document that every device in the group holds. It is the single source of truth for membership. Any current member can update it. The highest version wins. No coordinator, no consensus, no server.

### We resolved the revocation model

With a Group Manifest, revocation splits cleanly into two distinct operations with different semantics:

**Soft Removal** removes a device from the manifest. All remaining members filter that device's messages. It is cooperative — not cryptographically enforced — but sufficient for the trusted-group threat model: reorganising personal devices, removing a departing team member, routine maintenance. No key rotation, no disruption.

**Destroy Group** is the nuclear option. It pushes a revoke message to all members, every device rotates its keypair, and the group ceases to exist. The old keypairs become dead addresses. Used for security incidents — stolen phones, compromised devices. Cryptographic, unconditional, irreversible.

We explicitly rejected a middle option — "remove one device with cryptographic enforcement without disrupting others" — because it requires distributed key agreement and is not achievable in a zero-trust relay-agnostic system without significant added complexity. That is a v2 problem, and it has a name: Signal's Sender Keys protocol.

### We simplified the caller interface from first principles

Starting from "a friend who is a developer should be able to implement this in an afternoon," we worked backwards from the desired experience to the API.

Every decision was made by asking: does the caller need to know this? Usually the answer was no.

- **Keypair management**: no. The library generates, persists, and retires keys. The caller never sees bytes.
- **Sender identity in callbacks**: no. By the time `onReceived` fires, the library has already verified the sender is a current group member. That fact is the guarantee. The caller does not need to cross-reference a public key.
- **Storage**: no. SQLite is embedded. Identity, manifest, and outbox are fully managed. The caller implements zero storage code.
- **Point-to-point targeting**: no. This is sync, not messaging. `send()` fans out to the entire group. There is no "send to device B only."
- **Display names**: no. Auto-generated from the public key. Deterministic, unique within realistic group sizes, zero configuration.
- **Relay connectivity at startup**: no. `create()` always succeeds. The relay connects in the background. The library is local-first — fully functional offline.

What remained after removing everything the caller does not need to know:

```swift
HushFfiSession.create(relayUrl, relayPublicKey, namespace, ...callbacks)
session.pairingToken() -> String
session.joinGroup(token: String)
session.acceptMember(token: String)
session.send(blob: Data)
session.members() -> [(id, name)]
session.removeMember(memberId: String)
session.destroyGroup()
```

That is the entire surface area. A developer who has never heard of Noise XX, Ed25519, or Group Manifests can read that and know exactly what the library does.

### We added namespace for spaces without building spaces

One device, one keypair, one group, one session — that is the v0 model. Spaces (one device in multiple independent groups) are not implemented. But they are not foreclosed. The `namespace` parameter scopes the SQLite database to a string. A caller who wants spaces creates one `HushFfiSession` per namespace. The library does not need to know about spaces. The caller composes multiple sessions. This cost nothing to add and keeps a real use case permanently open.

---

## What hush-sync is not

**Not a messaging primitive.** There is no point-to-point send, no read receipts, no message history API. If you need those things, build them on top using `send()` and your own data model.

**Not a conflict resolution engine.** The library guarantees delivery and per-sender ordering. What you do when two devices send conflicting data is your problem. For clipboard (last-write-wins), you need nothing. For collaborative documents, you layer a CRDT. The library does not take a position.

**Not an identity system.** There are no accounts, no usernames, no passwords, no registration. A device's identity is its keypair. The library generates and manages it. If you need to associate a human identity with a device, do that in your app.

**Not a relay.** The relay is a separate service (hush-relay, in Go). It is stateless with respect to group membership. It is replaceable. You can self-host it. You can run it behind a CDN. hush-sync does not care which relay you use as long as the public key matches.

---

## The boundary

hush-sync is a **transport primitive with E2EE, group membership, delivery, and ordering guarantees**.

The caller is responsible for: what the bytes mean, conflict resolution, historical state bootstrapping for new members, permission hierarchies above "any member can do anything," and UI.

Everything else is hush-sync's problem.

---

## Known limitations and the v1 roadmap

**Soft Removal is cooperative, not cryptographic.** A modified app on a removed device can bypass manifest filtering. The only cryptographic removal is Destroy Group. This is an honest limitation of zero-trust relay-agnostic systems without a key revocation server. Documented in ADR-0015.

**Per-sender ordering only.** The current implementation guarantees you receive all of device A's blobs in order, and all of device B's blobs in order, but cannot establish the interleaving order between A and B. The Envelope wire format already carries parent hashes for a full DAG model (ADR-0004). Activating causal ordering via CRDTs on the DAG is the v1 priority for ordering guarantees.

**30-day relay TTL.** The relay holds blobs for offline recipients for 30 days and deletes on delivery. A device offline for longer than 30 days may miss blobs. The sender's outbox marks blobs delivered once the relay confirms receipt — not when the recipient confirms. For ephemeral sync use cases this is acceptable. Long-lived persistent sync may require a different relay contract.

**Single-member removal without Destroy Group is a v2 problem.** Targeted key rotation (rotate everyone except the removed device, auto-rekey remaining members) requires a distributed key agreement sub-protocol. The reference design is Signal's Sender Keys. Explicitly deferred.
