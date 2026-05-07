# ADR-0013: Payload included in Envelope signature — zero-trust relay

## Status

Accepted

## Context

The Envelope's `signing_message` originally covered only metadata fields:
`sequence || parents || recipient_pub || author_pub`. The encrypted `payload`
was excluded from the signed material.

This meant a relay (or any party in transit) could substitute any `payload`
bytes without breaking `Envelope::verify()`. Two attack classes followed:

1. **Denial of service** — a compromised relay swaps the payload with garbage.
   The recipient's `decrypt` call fails with `CryptoError` and the message is
   silently dropped.

2. **Content substitution** — if an adversary intercepts two envelopes from
   device A to device B addressed to the same recipient key, they can swap the
   payloads. Both envelopes still pass signature verification. The recipient
   decrypts and processes incorrect content without knowing.

The CONTEXT.md describes the relay as "zero-knowledge" — it never decrypts
content. The original design did not make the stronger "zero-trust" claim, but
the intended security model (E2EE, relay has no privileged position) implies
it. A relay that can silently swap ciphertext is not compatible with E2EE
guarantees.

## Decision

Include the `payload` bytes at the end of `signing_message`:

```
sequence (8 LE) || each parent (32) || recipient_pub (32) || author_pub (32) || payload (N)
```

The relay is **zero-trust**: any mutation of any Envelope field — including the
encrypted payload — is detectable by the recipient. `Envelope::verify()`
returns `Err(InvalidSignature)` if the payload has been tampered with.

This is a breaking wire format change. All Envelopes signed under the old
scheme will fail verification. No migration is needed because the project has
not launched.

## Consequences

- **Recipients** can now detect payload substitution during `verify()`.
- **No behavior change for honest relays** — the relay does not inspect or
  modify payloads; correctly forwarded Envelopes continue to verify.
- **Wire format is now final for v0** — the signing scheme must not change
  again without a version field in the Envelope proto.
- **Performance** — signing and verification now process the full payload.
  For v0 blob sizes (≤ 64 KB per ADR-0006) this is negligible.
