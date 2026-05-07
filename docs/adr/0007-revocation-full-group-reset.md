# Revocation is full group reset triggered by any paired device

When a device is lost or compromised, the operator triggers a "destroy sync" from any remaining trusted device. This pushes a `REVOKE_ALL` envelope — signed by the triggering device's keypair — to every known paired device's public key.

Every device that receives `REVOKE_ALL`:
1. Wipes its paired device list entirely
2. Generates a fresh keypair
3. Disconnects from the relay

All subsequent blobs are addressed to the new keypairs. The compromised device's old keypair receives zero future blobs — not because the relay blocks it, but because no legitimate device addresses blobs to it anymore. The relay remains zero-knowledge and enforces nothing.

`REVOKE_ALL` is accepted from any paired device. A stolen device triggering `REVOKE_ALL` is not an attack — it is the correct outcome. The group is isolated, the compromised key is rendered useless, and the operator re-pairs legitimate devices. The cost is re-pairing; the benefit is immediate termination of future data leakage.

Past blobs already delivered to the compromised device cannot be recovered — this is a fundamental constraint of any zero-knowledge delivery system. `REVOKE_ALL` stops future leakage only.
