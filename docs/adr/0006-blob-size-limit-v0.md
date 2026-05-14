# Hard blob size limit for v0; content-addressed file store deferred

Individual blobs are subject to a hard size limit enforced by the relay (exact value TBD at implementation time, likely 64KB–1MB). The relay rejects envelopes exceeding the limit before storing. Callers are responsible for staying within the limit.

Large file support (images, documents, arbitrary binary) is explicitly deferred to a future `trueseal-sync/filestore` package. That layer will use content-addressed chunk storage — the operation log carries a pointer (hash + decryption key), not the file itself. This is a distinct infrastructure problem from log transport and must not be mixed into the core relay.

Keeping the relay as a log transport with a size limit preserves the simplicity of the primitive and avoids the relay becoming a general-purpose file store.
