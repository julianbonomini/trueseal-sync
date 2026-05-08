# author_pub is unencrypted in the Envelope — relay observes the sender↔recipient graph

## Status

Accepted — gap documented, fix deferred to v1.

## Context

`Envelope` (defined in `src/envelope.rs`) contains the following unencrypted fields:

```
sequence       u64        — per-device monotonic counter
parents        [[u8;32]]  — parent hashes (DAG causality)
recipient_pub  [u8;32]    — X25519 noise key (relay routes by this)
author_pub     [u8;32]    — Ed25519 signing key ← unencrypted, relay reads this
signature      [u8;64]    — over all fields including payload
payload        Vec<u8>    — encrypted (ChaCha20-Poly1305)
```

ADR-0001 claims: "the relay learns only recipient public keys." That claim is **false**. Every envelope the relay forwards carries `author_pub` — the sender's Ed25519 signing key, which is the device's long-term identity. The relay observes every (sender_signing_key → recipient_noise_key) pair across time. For a group of N devices exchanging blobs, the relay can reconstruct the full communication graph with precise timestamps.

`author_pub` is unencrypted because signature verification requires the verifying key. In the current design, `author_pub` is in the envelope header so the recipient can verify the signature without first decrypting the payload.

## Decision

**The gap is accepted and documented.** The fix (moving `author_pub` inside the encrypted payload) is deferred to v1 for the following reasons:

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
