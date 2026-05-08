# Unauthenticated push; relay enforces nothing about sender identity

Any device that knows a recipient's public key can push a blob addressed to it. The relay does not verify that the sender is a member of any group or has a prior relationship with the recipient. Garbage blobs from unknown senders are harmless — they cannot decrypt without the recipient's private key and are silently discarded at the application layer.

This keeps the relay's knowledge of content minimal: it never decrypts payload content and never learns group membership. However, the relay **does** observe sender identity: every `Envelope` carries an unencrypted `author_pub` field (the sender's Ed25519 signing key) alongside the encrypted payload. The relay therefore observes (sender_signing_key → recipient_noise_key) pairs for every forwarded envelope. See ADR-0018 for the full analysis and the v1 fix plan.

Rate limiting at the relay level is the mitigation for denial-of-service, not trust logic. The tradeoff (any sender can push to any recipient) was accepted because the cryptographic guarantee is end-to-end and the relay enforcing sender identity would require it to know trust relationships — violating the zero-knowledge content property.

As a consequence, the same mechanism naturally supports sharing across users: if two parties perform a pairing ceremony (or exchange public keys out-of-band), they can sync with each other using the same protocol, with no special server-side concept of "group" or "user".
