# trueseal-sync is a delivery primitive; no conflict resolution, no schema awareness

trueseal-sync guarantees delivery of encrypted blobs in causal order. It has no knowledge of blob content, no conflict resolution logic, and no schema versioning. These are entirely the caller's responsibility.

The alternative — building LWW conflict resolution into trueseal-sync — would require either decrypting blob content to compare timestamps (breaking zero-knowledge) or moving timestamps into unencrypted envelope metadata (leaking recency information to the relay). Both violate the zero-trust property. There is no conflict resolution strategy compatible with a zero-knowledge relay that does not push the logic to the client.

Consequence: schema evolution, backward compatibility, and conflict resolution are the caller's problem. trueseal-clip implements LWW. A future document editor implements CRDT merging. trueseal-sync knows nothing about either. This is the same contract TCP has with its callers.
