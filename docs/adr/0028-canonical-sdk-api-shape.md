# One public API shape for the Swift, Kotlin and TS SDKs

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#12](https://github.com/julianbonomini/trueseal-roadmap/issues/12); not yet implemented). The side-by-side sketch is on the throwaway trueseal-roadmap branch [`prototype/sdk-api-shape`](https://github.com/julianbonomini/trueseal-roadmap/tree/prototype/sdk-api-shape/prototypes/sdk-api-shape).

The three SDKs expose the same API: the same operations, the same names, the same event and error cases, and the same behaviour. Only the syntax is platform-idiomatic. The core FFI (`ffi.rs`) is reshaped to this API, so every SDK stays a thin wrapper over it. TS already wraps `TruesealFfiSession` through a NAPI shim; it does not re-implement session wiring.

This applies the ADR-0026 guiding rule: correct defaults, the least possible wiring, and nothing the app must get right for correctness.

## Surface

Written in neutral form below. Swift uses `async throws`, Kotlin `suspend` with exceptions, and TS Promises.

- **Entry.** The type is named `TrueSeal`. `TrueSeal.open(relay, storage, namespace = "default", maxPayloadBytes?)` is async. It returns before the connection is up and connects in the background, and `send()` works immediately. `close()` stops the connection and the handlers but keeps Session State. After `close()`, every call fails with `closed`. Kotlin takes an explicit storage location, and `Storage.android(context)` is a helper for it.
- **Relay Address.** A single string, `trueseal://<relay public key hex>@host[:receivePort][?push=pushPort]`. The ports default to 7700 and 7701. There is also a typed form, `RelayAddress(host, publicKey, receivePort, pushPort)`, and `open()` accepts either. The relay CLI prints the string. The port is never dropped silently.
- **State.** `status` is one of `notJoined | pendingJoin | member | leaving`. `me` is `Member{id, name}`, and `members` lists every other member. `connection` is one of `connecting | connected | disconnected | relayVersionUnsupported{min, max}`. State is observable in each platform's native way: Swift `@Observable`, Kotlin `StateFlow`, and in TS getters plus `statusChanged`, `membersChanged` and `connectionChanged` events.
- **Receiving.** `onMessage(handler)` registers the single message handler, and registering it starts receiving (ADR-0026). A second registration fails with `messageHandlerAlreadySet`. The handler is async and awaited. `Message` is `{id, from: Member, body: bytes}`, and `from.id` is the same identifier as in `members`.
- **Sending.** `send(bytes)` returns the `MessageId` once the message is in the outbox. It fails immediately with `payloadTooLarge{max}` (ADR-0025) or `notMember{status}`. The text-convenience overloads are removed.
- **Pairing, admitting side.** `startPairing()` returns the Pairing Token as a string and opens the window. Requests arrive as `joinRequest(JoinRequest{id, name})` events. `accept(request)` either succeeds or fails with `pairingClosed` or `groupFull{max}`. `cancelPairing()` closes the window. There is no reject, since the protocol sends no decline (ADR-0023); an unaccepted request disappears when the window closes.
- **Pairing, joining side.** `join(token)` moves the device to `pendingJoin`, or fails with `alreadyInGroup` or `invalidPairingToken`. `cancelJoin()` moves it back to `notJoined`.
- **Membership.** `remove(memberId)` takes an id in all three SDKs. `leave()` moves the device to `leaving`, and later to `notJoined` with reason `left` (ADR-0027). `destroyGroup()` keeps its name.
- **Events.** `onEvent(listener)` accepts any number of listeners and delivers one sum type. The cases are `statusChanged(status, reason)`, `membersChanged(members)`, `joinRequest(request)`, `connectionChanged(connection)` and `admissionDropped(name, reason)`. The reasons are `created | joined | left | removed | destroyed | storeReset` (`storeReset` added by ADR-0032). Membership is delivered as the whole current list, not as join and leave deltas (ADR-0027). Events raised before the first listener is registered are buffered.
- **Delivery issues.** `onDeliveryIssue(listener)` is optional. The cases are `unreadable`, `unauthorized`, `heldForUpgrade(version)`, `handlerGaveUp(messageId, error)`, `sendFailed(messageId, tooLarge | malformed | expired)` and `undeliverableAfterUpgrade(messageIds)` (ADR-0022, ADR-0026).
- **Registration.** Every `on…` call returns a cancel handle: `Subscription.cancel()` in Swift and Kotlin, and an unsubscribe function in TS. Events and issues use handlers in every SDK, not platform streams.
- **Errors.** There are the same 12 cases everywhere: `invalidRelayAddress`, `invalidNamespace`, `storage`, `closed`, `notMember{status}`, `alreadyInGroup`, `invalidPairingToken`, `pairingClosed`, `groupFull{max}`, `memberNotFound`, `payloadTooLarge{max}` and `messageHandlerAlreadySet`. ADR-0032 adds a 13th, `storeTooNew`, raised when `open()` finds Session State written by a newer release. Swift uses an enum, Kotlin a sealed exception class, and TS one `TrueSealError` class whose `code` is a string union, with typed extras.
- **Version and limits.** `TrueSeal.info` holds `{sdkVersion, transportVersion, endToEndVersion}`. `maxPayloadBytes` (61,440) and `maxGroupSize` (32) are constants. Nothing is negotiated (ADR-0022).

## Lifecycle rule

The `TrueSeal` object outlives group membership. After removal, leave or Destroy Group, the library wipes the namespace and generates a fresh identity. It then reports `statusChanged(notJoined, reason)`, and the same object can pair again. No app has to write code to rebuild a session. This replaces today's behaviour, where `destroyGroup` leaves the session unusable. What Destroy Group itself does, and how Revoke stays durable, is decided in [trueseal-roadmap#10](https://github.com/julianbonomini/trueseal-roadmap/issues/10). That decision must keep this rule or reopen it.

## Considered alternatives

- **Native streams for events and issues** (AsyncSequence, Flow, async iterators). Rejected. The message path has to be an awaited handler, so the SDKs would mix two styles, and parity would be harder to keep and to test. Stream adapters can be added later without breaking anything.
- **Separate host, port and key fields.** Rejected. Self-hosters would copy three or four values that can drift apart, and this is how Swift came to drop the port.
- **A session that can't be used after removal or destroy.** Rejected. Every app would need to write rebuild code.
- **`TrueSealClient` or `TrueSealSession` as the name.** Rejected. The glossary says to avoid "client" for a Device, and "Session" already names the relay's Receive Session and Push Session.
- **A local-only reject for join requests.** Rejected. It sends nothing, and letting the window close already does the same job.

## Consequences

- This breaks the public API of all three SDKs. It is approved pre-launch, and the preview is 0.x.
- `ffi.rs` changes too: one async handler interface for messages, an event callback, a delivery-issue callback, typed errors (no more `PushFailed{msg}` catch-all, no store errors reported as `InvalidNamespace`), `close()`, Relay Address parsing, and configurable ports.
- The relay gains a CLI command that prints the Relay Address.
- The cross-SDK e2e suite should assert the same behaviour through each SDK's public API, and a parity check should compare the error and event cases.
- The docs and every SDK README move to these names.
