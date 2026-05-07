# Unauthenticated push; relay enforces nothing about sender identity

Any device that knows a recipient's public key can push a blob addressed to it. The relay does not verify that the sender is a member of any group or has a prior relationship with the recipient. Garbage blobs from unknown senders are harmless — they cannot decrypt without the recipient's private key and are silently discarded at the application layer.

This keeps the relay fully privacy-preserving: it learns only recipient public keys, never group membership or sender-recipient relationships. Rate limiting at the relay level is the mitigation for denial-of-service, not trust logic. The tradeoff (any sender can push to any recipient) was accepted because the cryptographic guarantee is end-to-end and the relay enforcing sender identity would require it to know trust relationships — violating the zero-knowledge property.

As a consequence, the same mechanism naturally supports sharing across users: if two parties perform a pairing ceremony (or exchange public keys out-of-band), they can sync with each other using the same protocol, with no special server-side concept of "group" or "user".
