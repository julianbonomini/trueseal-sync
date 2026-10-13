# Changelog

One changelog for the lockstep **TrueSeal Release**: trueseal-sync (core) and
the Swift, Kotlin and TS SDKs always release together under one version number
(ADR-0030). Each GitHub Release in the lockstep group links here.

Breaking releases carry a **Breaking** section with upgrade steps, per the
preview lifecycle (ADR-0033). Fixed labels:

- a protocol-version bump: "every device and the relay must upgrade together";
- a Store Reset: "local data is wiped and every group must pair again".

## [0.6.0] — Unreleased

First gated Developer Preview release. Everything is `0.x`: any release may
break the API, the wire format or stored data without notice, but every
breaking release carries upgrade steps (ADR-0033).

### Breaking

- every device and the relay must upgrade together: the wire is versioned for
  the first time (Transport Version 1, End-to-End Version 1) and the
  pre-version format is refused (ADR-0022).

### trueseal-sync (core)

- Fixed Transport and End-to-End Versions, bound into the cryptography, with
  typed rejection (ADR-0022).
- Delivery contract: ack after the handler, library dedup with a 60-day
  Replay Window, typed retry classes, control plane through the outbox
  (ADR-0026, ADR-0031, ADR-0034).
- Pairing trust anchor: Pairing Secret, Pending Join, unsolicited manifests
  never accepted (ADR-0023).
- Membership convergence: parent-linked manifests, `leave()`, wipe and rotate
  on removal, groups capped at 32 (ADR-0027).
- Destroy Group as a durable, forwarded Revoke (ADR-0029).
- Sealed Envelope: the relay reads only the End-to-End Version, the recipient
  key and the sealed payload (ADR-0031).
- Versioned Session State with chained migrations, Store Reset and
  `storeTooNew` (ADR-0032).
- The canonical `TrueSeal` FFI API: awaited handler, event and issue streams,
  14 typed errors, `close()`, Relay Address parsing (ADR-0028).
- Sync JSON test vectors and generated Shared Facts ship with every release
  (gates G5, G11, G12).
- Licence metadata corrected to Apache-2.0 everywhere (the code has always
  been Apache-2.0; stale MIT metadata claimed otherwise) (SYNC-19).
- Behaviour change: local store failures are typed `storage` errors instead
  of panics — the `PersistentLog` is panic-free, and the outbox pump backs
  off and retries on a store error instead of crashing (SYNC-19). Apps that
  relied on the process dying on a corrupt store now get errors they must
  surface.
- Private key material in long-lived session state zeroizes on drop
  (rotation, removal wipe, Destroy Group); transient copies remain and are
  documented honestly (SYNC-19).

### Swift SDK (trueseal-sync-swift)

- First release on the canonical API. Details land with the SDK-1 work.

### Kotlin SDK (dev.trueseal:trueseal-sync)

- First release on the canonical API, published to Maven Central. Details
  land with the SDK-1 work.

### TS SDK (@trueseal/sync)

- First release on the canonical API, published to npm. Details land with the
  SDK-1 work.

## How releases work here

This repo does not release from tag pushes. The Release Conductor (e2e
ADR-0002) drives two workflows:

1. **Candidate** (`.github/workflows/candidate.yml`) builds every artifact
   from a given commit and stages it in a draft GitHub Release — no tag.
2. **Promote** (`.github/workflows/promote.yml`) verifies the staged bytes
   (Cargo version matches, changelog entry exists, checksums verify) and
   publishes the draft, which pushes the tag. Idempotent.
