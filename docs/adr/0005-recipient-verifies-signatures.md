# Relay does not verify envelope signatures; recipients verify

The relay stores and forwards envelopes without verifying the author signature. Signature verification is the recipient's responsibility — performed after decryption, before the payload is consumed.

Relay-side signature verification would require the relay to maintain a registry of known sender public keys, or at minimum to learn the association between a sender and a recipient. Either approach gives the relay knowledge of trust relationships between devices — violating the zero-knowledge property. Privacy is the top priority; the relay enforces nothing about sender identity.

Rate limiting at the relay mitigates abuse (blob flooding). Cryptographic integrity is enforced end-to-end by the recipient. A blob with an invalid signature is silently discarded by the recipient — the relay never needs to know.
