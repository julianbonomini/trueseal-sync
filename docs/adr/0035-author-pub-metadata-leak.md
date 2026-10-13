# ADR-0035: author_pub is unencrypted in the Envelope — relay observes the sender↔recipient graph

(Renumbered from the duplicate ADR-0018 in SYNC-19; the anonymous-push-sessions ADR keeps 0018.)

## Status

Accepted — gap documented; resolved by ADR-0031 (the Sealed Envelope moved the sender's signing key, sequence and timestamp inside the ciphertext; the relay now reads only the End-to-End Version, the recipient key and the sealed payload).

## Context

_Historical — describes the pre-ADR-0031 wire format._ `Envelope` (defined in `src/envelope.rs`) contained the following unencrypted fields:

```
sequence       u64        — per-device monotonic counter
parents        [[u8;32]]  — parent hashes (DAG causality)
recipient_pub  [u8;32]    — X25519 noise key (relay routes by this)
author_pub     [u8;32]    — Ed25519 signing key ← unencrypted, relay reads this
signature      [u8;64]    — over all fields including payload
payload        Vec<u8>    — encrypted (ChaCha20-Poly1305)
```

ADR-0001 claims: "the relay learns only recipient public keys." That claim is **false**. Every envelope the relay forwards carries `author_pub` — the sender's Ed25519 signing key, which is the device's long-term identity. The relay observes every (sender_signing_key → recipient_noise_key) pair across time. For a group of N devices exchanging blobs, the relay can reconstruct the full communication graph with precise timestamps.

`author_pub` was unencrypted because signature verification requires the verifying key: it sat in the envelope header so the recipient could verify the signature without first decrypting the payload.

## Decision

> **RESOLVED — read the rest as history.** The Developer Preview's clean wire break (ADR-0022) made bundling the fix free, and ADR-0031 implemented it: `author_pub`, the sequence and the Sender Timestamp moved inside the addressed encryption, and the relay reads only the End-to-End Version, the recipient key and the sealed payload (tested, including a raw-wire assertion of exactly which fields are relay-visible). The "deferred to v1" reasoning below is why it was *originally* deferred, not the current state. ADR-0001 was updated in place as the Consequences below require.

**The gap was accepted and documented at the time.** The fix (moving `author_pub` inside the encrypted payload) was deferred for the following reasons:

1. **Breaking wire format change.** Moving `author_pub` into the ciphertext changes the Envelope structure. Any relay or client built against the current format is incompatible. Since the project is pre-launch, there is no migration cost yet — but the fix should be bundled with other v1 breaking changes rather than done in isolation.

2. **The fix is straightforward.** The recipient decrypts first, extracts `author_pub` from the plaintext, then calls `verify()`. The 32-byte `author_pub` is prepended inside the plaintext before addressed encryption. Recipients always decrypt before verifying in this model. ADR-0005's guidance to "verify before consuming" still holds — the recipient verifies before dispatching to the application callback, just after rather than before decryption.

3. **No confidentiality or integrity break.** The current gap is a metadata privacy concern, not a correctness or security vulnerability. The encrypted payload remains confidential. Envelope integrity is guaranteed by the Ed25519 signature. The relay cannot substitute, modify, or replay blobs without detection. The gap is limited to communication graph metadata.

## Corrected claim for ADR-0001

ADR-0001 should read: "the relay learns recipient public keys and sender signing public keys." The zero-knowledge claim in CONTEXT.md ("The relay is structurally incapable of reading it") applies only to payload content, not to envelope metadata. The relay is zero-knowledge with respect to *content*; it is not zero-knowledge with respect to *communication graph metadata* in v0.

## Consequences

- CONTEXT.md's description of the relay as "zero-knowledge" is narrowed: it applies to blob content only, not to the sender↔recipient graph.
- The fix for v1 is: move `author_pub` into the plaintext before addressed encryption; remove it from the `Envelope` proto fields or keep it as a reserved/empty field for wire compatibility.
- v1 recipients: decrypt → extract `author_pub` from plaintext → verify signature using the extracted key.
- ADR-0001 is updated in place to reflect the accurate claim.
