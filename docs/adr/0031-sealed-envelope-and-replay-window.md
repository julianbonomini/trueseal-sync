# Sealed Envelope: sender metadata and a Replay Window inside the ciphertext

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#16](https://github.com/julianbonomini/trueseal-roadmap/issues/16); not yet implemented). It uses the clean wire break from ADR-0022 and tightens the dedup rule from ADR-0026. Amended by ADR-0034.

The Relay-readable part of an Envelope shrinks to what routing and version rejection need: the End-to-End Version, the recipient public key, and the sealed payload. The sequence, parent hashes, sender timestamp and signature all move inside the Addressed Encryption. A receiver rejects any message whose signed sender timestamp is older than the **Replay Window** (60 days). It also keeps each handled Message ID until that message's own window has ended. Together these make the claim "a message is never delivered to your handler twice, even from a malicious Relay" true and testable.

## Why

Before this decision (verified from `envelope.rs`, `proto/envelope.proto`, `crypto.rs` and `session/mod.rs`):

- **The sequence was a sender pseudonym.**
  - The per-device global Sequence was a cleartext Envelope field.
  - One `send()` fans out with the same sequence to every recipient, and the value grows by one per send.
  - A Relay could therefore link all of a sender's Envelopes, across recipients and over time, even though Push Sessions are anonymous.
- **The signature was testable against visible bytes.**
  - The Ed25519 signature covered `seq || parents || recipient_pub || ciphertext`, which the Relay can read in full.
  - Anyone who holds a candidate signing key can test which device signed a stored blob: any group member, or a Relay colluding with one.
- **Replay was only suppressed for a while.**
  - ADR-0026 keeps Message IDs for 60 days.
  - A malicious Relay ignores the TTL, so it could re-deliver a stored blob on day 61, and the handler would run again.
- **The ciphertext was not bound to its context.** The ephemeral key and recipient key were not in the KDF or the AEAD associated data.

## Decision

### What the Relay reads

The outer Envelope carries only:
- the End-to-End Version, a plaintext field, so a device can reject a version before it decrypts (ADR-0022);
- the recipient public key, for routing;
- the Addressed Encryption output: the ephemeral public key and the AEAD ciphertext.

Nothing else is added in plaintext. Unknown fields still carry no meaning (ADR-0022).

### What moves inside

The sealed plaintext is `author_pub`, sequence, parent hashes, sender timestamp (Unix milliseconds), message tag and body, and the signature. Exact byte layouts are fixed by the Sync-level test vectors, not by this ADR.

- **Signature.** It covers a domain-separated input that includes the End-to-End Version, the recipient public key, the ephemeral public key, and every sealed field except the signature itself. A blob can't be re-addressed or have its body swapped without the signature failing.
- **Encryption.** HKDF info and AEAD associated data bind the End-to-End Version, the ephemeral public key and the recipient public key (ADR-0022).
- **Message ID.** It stays derived from `author_pub` and sequence, now both read from inside the ciphertext.

### Replay Window

- **Rejecting old messages.** A receiver drops a message whose sender timestamp is more than 60 days before its own clock. It acks the blob so the Relay deletes it, and reports a Delivery Issue (permanent, never sent off the device).
- **Future timestamps are accepted.** They are not rejected, so a sender whose clock runs fast still gets through.
- **How long a Message ID is kept.** It is kept until 60 days after the *later* of the handling time and the sender timestamp. A future-dated message can therefore never outlive its dedup record and be replayed.
- **Why 60 days is enough.** The window is twice the 30-day Relay TTL and the 30-day Outbox expiry. Clock skew would have to reach weeks before an honest message is lost.
- **When the timestamp is taken (ADR-0034).** A `Sync` message is stamped once at `send()`, and every re-seal keeps that timestamp. Control messages are stamped at each seal, and replaying them must be harmless. The Relay TTL is capped at 30 days.

State: this adds no new Device state beyond the per-Message-ID expiry above. Crash behaviour is ADR-0026's:
- The Message ID is recorded and the ack sent only after the handler finishes, or after the rejection is recorded.
- A crash before that point means the Relay re-delivers, and the message is judged again from scratch.

## Consequences

- The Relay can still link blobs by timing, size and fan-out (ADR-0024). It also knows each device's key and when it is online (Receive Session), and can often link pushes to devices by IP or timing. These stay documented limitations. This ADR removes the *persistent, stored* sender pseudonym, not network-level linkability.
- A group member who obtains a blob addressed to someone else still can't identify its sender, because the signature is sealed to the recipient.
- Tests required:
  - replaying a byte-identical blob delivers once;
  - a blob timestamped at 59 days old is accepted, and one at 61 days is rejected;
  - a future-dated message whose Message ID would otherwise expire is still deduplicated;
  - a re-addressed or ephemeral-swapped blob fails;
  - two sends from the same device share no Relay-readable value except the End-to-End Version, plus the recipient key when both go to the same device.
- The trueseal-e2e case "duplicate envelope keeps one stable application message ID" changes from expecting two deliveries to expecting one.
- The Envelope, Sequence and Addressed Encryption entries in `CONTEXT.md` are updated to match.
