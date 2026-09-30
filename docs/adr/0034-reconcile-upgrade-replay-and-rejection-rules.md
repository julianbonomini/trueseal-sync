# Re-seal every outbox entry, a Sender Timestamp fixed at send(), a 30-day relay TTL cap, and reasons on `unreadable`

Status: accepted (decided 2026-09-30 in [trueseal-roadmap#30](https://github.com/julianbonomini/trueseal-roadmap/issues/30); not yet implemented). This amends ADR-0022, ADR-0026, ADR-0028, ADR-0031 and ADR-0032, and trueseal-relay ADR-0012. Where they disagree with this ADR, this ADR wins.

Compiling the Developer Preview Release Spec turned up three places where accepted ADRs contradicted each other or the code. This ADR settles all three.

## 1. An End-to-End Version bump re-seals app `Sync` entries too

ADR-0022 and ADR-0032 removed queued `Sync` entries on an End-to-End Version bump, saying the outbox keeps no plaintext for app bodies. The code does keep it: the outbox stores the `Sync` body and re-seals it on every replay (`src/session/reconnect.rs`).

- In the migration transaction, the library rebuilds and re-seals **every** outbox entry under the new End-to-End Version: `Sync`, Pair, Group Manifest and Revoke. Sequence ordering stays unchanged, as in ADR-0032.
- Nothing is lost on an upgrade. `undeliverableAfterUpgrade` is removed from the Delivery Issue cases, and nothing replaces it.
- A re-sealed `Sync` entry keeps its original Sender Timestamp and its 30-day expiry, both counted from `send()` (see 2).
- The at-rest exposure is unchanged: ADR-0031 already deletes an outbox body once the Relay has accepted it.

## 2. Sender Timestamp and the relay TTL

**Sender Timestamp.** A message's timestamp belongs to the message, not to each seal of it.
- A `Sync` message is stamped once, at `send()`. Every re-seal (reconnect replay, retry, or an upgrade re-seal) carries the same timestamp.
- A control message (Pair, Group Manifest, Leave, Revoke) is stamped at each seal. Control entries never expire. A timestamp from `send()` would push a long-offline Leave or Destroy Group outside the Replay Window, and peers would reject it.

**Why "never handled twice" now holds against any Relay.** Take a `Sync` message stamped at T:
- every copy of it carries T, so the Replay Window rejects every copy after T + 60 days;
- a handled copy's Message ID is kept until 60 days after the later of the handling time and T, so it's never forgotten before T + 60 days;
- so no copy can reach the handler after its dedup record has gone. This doesn't depend on the Relay honouring its TTL.

A timestamp taken at each seal would break this. Suppose a message is handled on day 0, the sender never sees the Relay accept it, and it re-seals on day 30. A hostile Relay can then deliver that copy on day 75: it passes the window at 45 days old, and its dedup record expired on day 60.

**Control messages are not guarded by the dedup table.** Replaying them must be harmless, and each state machine must prove it with a test:
- an old Group Manifest loses on (version, hash) and its parent link (ADR-0027);
- a Pair for a closed Pairing Window is dropped (ADR-0023);
- a Revoke for a group that is already destroyed does nothing, because every device has a fresh identity (ADR-0029);
- a Leave from a device that is no longer a member does nothing.

**Relay TTL cap: 30 days.** That's the Replay Window minus the 30-day Outbox expiry. The Relay refuses to start with a TTL longer than 30 days (previously 60, in relay ADR-0012). The default stays 30 days, and Operators can only lower it.
- Why: a `Sync` message pushed on its last outbox day (T + 30) is then delivered by T + 60 at the latest, still inside the window.
- A longer TTL would let an honest message arrive after T + 60 and be rejected, while the sender believes it was delivered. That's a lost message, not a double handle, but it breaks the ADR-0026 promise of delivery "within the TTL".
- Accepted edge: a message pushed on its last outbox day that then waits the full 30 days on the Relay arrives exactly at the 60-day line. A receiver clock running fast drops it, and the drop is reported as `unreadable(expired)`. No extra margin is added.

## 3. Rejected incoming messages report `unreadable` with a reason

ADR-0028's `unreadable` case gains a reason. The number of Delivery Issue cases stays the same.

| Reason | Covers |
|---|---|
| `malformed` | undecodable or unauthenticated bytes, an unknown frame type, an unknown message tag |
| `senderOutdated` | a Blob in an older End-to-End Version than this device supports (ADR-0022) |
| `expired` | a message older than the Replay Window (ADR-0031) |
| `droppedWhileHeld` | the oldest held newer-version Blob, acked and dropped when the hold cap (about 100 per Device) overflows (ADR-0022) |

- `senderOutdated` is the one an app can act on ("one of your devices needs an update"). It mirrors `heldForUpgrade`, since there's no mixed-version operation.
- `unauthorized` stays a separate case.
- The Delivery Issue cases become: `unreadable(reason)`, `unauthorized`, `heldForUpgrade(version)`, `handlerGaveUp(messageId, error)` and `sendFailed(messageId, tooLarge | malformed | expired)`.

## Crash behaviour

This adds no new states:
- The upgrade re-seal runs inside ADR-0032's single migration transaction, so a crash leaves either every entry at the old version or every entry at the new one.
- Rejecting a message with a reason follows ADR-0031: the rejection is recorded before the ack, and a crash before the ack means the message is judged again from scratch.

## Considered alternatives

- **Keep purging `Sync` on upgrade, so the outbox could later hold only sealed bytes.** Rejected. It loses app messages on every protocol bump, for a storage change nobody has planned. That change would need its own store migration anyway.
- **Stamp every message at each seal.** Rejected. A hostile Relay could replay a re-sealed `Sync` copy after its dedup record expired (see 2).
- **Stamp control messages at `send()` and exempt them from the Replay Window.** Rejected. It relies on the same idempotency argument, but adds an exception to the window rule.
- **Keep relay TTLs up to 60 days.** Rejected. Honest messages could be lost silently at the window edge.
- **Fold every rejection into `unreadable` with no detail.** Rejected. It hides `senderOutdated`, the one rejection an app can act on.
- **A separate Delivery Issue case per rejection.** Rejected. Four new public cases in three SDKs, when only one is actionable.

## Consequences

- ADR-0022's and ADR-0032's purge rule for `Sync` and ADR-0028's `undeliverableAfterUpgrade` case are withdrawn. ADR-0026's delivery-issue list follows ADR-0028 as amended here.
- ADR-0031 gains the stamping rule, and its "twice the 30-day Relay TTL" reasoning now holds, because the TTL is capped.
- trueseal-relay ADR-0012's TTL ceiling drops from 60 to 30 days; the relay change is recorded there.
- Tests required:
  - an End-to-End Version bump re-seals a queued `Sync` entry and it is delivered once, with its original Message ID and Sender Timestamp;
  - a `Sync` entry re-sealed on day 30 and replayed by a Hostile Relay on day 75 is rejected as `unreadable(expired)` and never reaches the handler;
  - a control entry queued for more than 60 days offline is accepted by peers after reconnect;
  - replaying each control message type (Group Manifest, Pair, Leave, Revoke) changes no state;
  - the relay refuses to start with a TTL of 30 days plus one second, and starts at exactly 30 days;
  - each `unreadable` reason is raised by the matching adversarial frame in the E2E suite.
