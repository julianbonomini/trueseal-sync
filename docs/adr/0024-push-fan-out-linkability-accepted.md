# Push fan-out linkability is accepted as a documented limitation

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#6](https://github.com/julianbonomini/trueseal-roadmap/issues/6)). This narrows the anonymity framing of ADR-0018.

A single send fans out to every group member inside one anonymous Push Session, as several Push frames. The Relay therefore sees which recipient keys receive Blobs together. They arrive in the same connection, from the same network address, within milliseconds, with matching sizes. From this a Relay operator can infer which Devices likely share a Sync Group. We keep this behaviour and document it. We don't claim that group structure is hidden from the Relay.

ADR-0018 still holds for what it removed: the Relay cannot learn the sender's identity. It does not hide which recipients share a group, and no document may say it does. The phrases "no communication graph" and "structurally unknowable membership" are retired.

## Considered alternatives

- **One Push Session per recipient.** Rejected. The pushes still share the sender's address and timing and have equal sizes, so they stay linkable. It adds a handshake per recipient for no real gain.
- **Per-recipient jitter.** Rejected. Hiding the correlation needs delays of seconds or more, which costs latency and battery, and the address and size signals remain.
- **Batching across unrelated groups.** Rejected. It amounts to cover traffic, which is out of scope for the preview, alongside padding.

A real fix needs cover traffic, padding, or a mixnet-style transport. None of these is planned for the preview.

## Consequences

- The threat model states the limitation plainly. Proposed wording: "The relay cannot read content or learn who sent a message. It can, however, observe which devices receive messages together: a single send fans out to every group member in one connection, with matching sizes and timing, from the sender's network address. A relay operator can therefore infer which devices likely share a group. TrueSeal does not hide group structure from the relay." The final wording is set in the preview threat-model decision.
- Docs and READMEs that claim no communication graph, or that membership is unknowable, must be corrected.
