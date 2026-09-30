# Preview lifecycle and the criteria for 1.0

Status: accepted (decided 2026-09-30 in [trueseal-roadmap#28](https://github.com/julianbonomini/trueseal-roadmap/issues/28)). This builds on ADR-0022 (one protocol version, no negotiation), ADR-0030 (lockstep 0.x TrueSeal Release) and ADR-0032 (Store Version and Store Reset).

**While the preview lasts (0.x).**
- **No notice period for breaking releases.** Any 0.x release may break the API, the wire format or stored data, and it may ship without advance warning.
- **Upgrade Notes are required.** Every breaking release carries a "Breaking" section with upgrade steps. It is published in the changelog, on the GitHub Release and on one Upgrade Notes page on the docs site. The pre-promotion metadata check fails a breaking release that has no such section. Two breaks carry fixed labels:
  - a Transport Version or End-to-End Version bump: "every device and the relay must upgrade together";
  - a Store Reset: "local data is wiped and every group must pair again".
- **No end date.** The preview ends only when the 1.0 criteria below are met. No target date is published anywhere.
- **Fixes are best effort, with no promise.** Fixes, security fixes included, land only in the next 0.x release. Nothing is backported to an older 0.x. This matches the `SECURITY.md` wording from the threat model decision.

**What must be true before 1.0.**
1. Identity keys are stored in Keychain (Apple) and Keystore (Android), and the local store is encrypted at rest.
2. The public SDK APIs follow semver: a breaking change needs a new major version. A CI API-diff check enforces this in each SDK.
3. Stored data migrates forward only within a major version, for both Session State and the relay store. There is no Store Reset inside a major version. The upgrade fixtures (G6) enforce this without a Store Reset exemption.
4. Each major version speaks exactly one Transport Version and one End-to-End Version, as in the preview. A protocol bump is a new major version.

**Not required for 1.0.** These stay documented limitations, or they are not criteria at all:
- **An external security audit.** "Not independently audited" is a documented limitation in the preview and at 1.0. Every public claim still names the tests that prove it.
- **End-to-end forward secrecy (a ratchet).** 1.x ships without one. Because criterion 4 makes every protocol bump a major version, a ratchet is a 2.0 candidate and is tracked as one.
- **Network-level IP hiding** (Tor, a proxy option). It can be added later without a protocol break.
- **A hosted relay.** It is a business and cost decision, not a readiness criterion.
- **Rust crates on crates.io.** That depends on a separate decision to promise a stable Rust API.

## Considered alternatives

- **A notice period (N weeks) before breaking releases.** Rejected. There are no production users, and it is a promise a solo maintainer must keep for nobody.
- **Notice only for protocol and store breaks.** Rejected for the same reason. The fixed labels in the Upgrade Notes carry the warning instead.
- **A target date for 1.0.** Rejected. A date is a public commitment, and the criteria are what define readiness.
- **Backporting security fixes to the previous 0.x minor.** Rejected. With one protocol version and lockstep releases, an older 0.x can't talk to a current relay after a wire bump, so a backport line would serve no one.
- **An external audit as a 1.0 criterion.** Rejected by the product owner. No audit is planned, and the tested-claims rule plus an honest "not audited" limitation replace it.
- **A ratchet required for 1.0.** Rejected. It is large state-machine work (out-of-order delivery, multiple devices, crash recovery) that a sync primitive for indie developers does not need to reach 1.0. The no-forward-secrecy limitation stays published.
- **Supporting the current and previous protocol version (N-1) at 1.0, or every version within a major.** Rejected as more than 1.0 needs. Mixed-version operation would need negotiation, a wider test matrix and a retention policy. Keeping one version per major is the simplest policy, and it matches the preview.

## Consequences

- The spec's Preview lifecycle section and the docs' preview lifecycle page state these rules.
- The pre-promotion metadata check (G9) gains a "Breaking" section check.
- trueseal-docs ships an Upgrade Notes page and adds "not independently audited" to the Threat Model limitations.
- Keychain/Keystore storage and encrypting the store at rest become the first 1.0 work, after the preview.
- Each SDK needs an API-diff check in CI before 1.0.
- A ratchet is filed as a 2.0 candidate.
