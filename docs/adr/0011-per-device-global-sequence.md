# Per-device global sequence counter, not per-object

## Decision

The `sequence` field in an Envelope is a **per-device global counter** — it increments monotonically for every Envelope a Device ever sends, regardless of which Object the payload belongs to. It is not scoped per object.

## Rationale

### Gap detection is more useful at the device level

If sequence is per-object, a recipient can detect missed Envelopes only within a single Object's history. With a global counter, the recipient can detect any gap from any Device in a single comparison — "I last saw sequence 41 from Device A, and this new Envelope is sequence 43, so I missed one" — without knowing which Object the missing Envelope belongs to.

### Object identity belongs inside the encrypted payload

The Object ID is caller-defined data. The Relay is zero-knowledge — it must not see Object IDs. Keeping sequence global means the Envelope header (visible to the Relay) carries no Object-level information. Object ID lives inside the encrypted payload, decoded only by the recipient.

### Simpler coordination

A per-object sequence requires the sender to maintain N counters (one per Object) and coordinate them to avoid collisions in the parent-hash DAG. A single global counter per Device requires no coordination — increment once per send.

## Consequences

- The `OperationLog` stores entries as `(object_id, sequence, blob)` where `sequence` is the **global device sequence**, not an object-scoped counter. Two entries for different Objects on the same Device will have different sequences.
- The `OperationLog` must be queryable by both `object_id` (to reconstruct an Object's history) and by `sequence` (to replay the outbox in send order on reconnect).
- Callers must not assume sequences are contiguous within a single Object — gaps are normal when a Device sends Envelopes for multiple Objects interleaved.
- The parent hash DAG (ADR-0004) references prior Envelopes by hash, not by sequence — so per-object ordering is preserved through parent hashes, not through sequence numbers.
