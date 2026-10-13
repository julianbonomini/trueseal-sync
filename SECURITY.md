# Security Policy

TrueSeal is a **developer preview**. Everything here is `0.x`, published and installable,
and openly allowed to break. This policy is the same across every `trueseal-*` repository.

## Reporting a vulnerability

**Please report security issues privately through
[GitHub Security Advisories](../../security/advisories/new) (private vulnerability
reporting) — never in a public issue, discussion, or pull request.**

Include what you can: the affected component and version or commit, the scenario, a
reproduction or failing test if you have one, and which property you believe is broken
(confidentiality, integrity, authenticity, delivery, availability, or metadata privacy —
they are different claims).

If private vulnerability reporting is unavailable for some reason, open a public issue
describing only that you have something to report privately, and we will arrange a channel.

## What to expect

- **Best effort, no SLA.** We will acknowledge and investigate as time allows. There is no
  response-time commitment.
- **No bounty.** There is no paid program.
- **Fixes land only in the next 0.x release.** Nothing is backported to earlier versions
  (see [ADR-0033: preview lifecycle](docs/adr/0033-preview-lifecycle-and-1.0-criteria.md)).
  There is no notice period: any 0.x release may change the API, the wire format or stored
  data, and every breaking release carries Upgrade Notes.
- **Disclosure.** Confirmed findings are published as GitHub Security Advisories, crediting
  the reporter unless you ask otherwise. We ask that you give us a reasonable window to
  ship a fix before public disclosure.

## Scope: what is a security finding

In scope for a report:

- Anything that breaks a claim the project actually makes — see the **Security at a
  glance** section of the [README](README.md) and the Threat Model page at
  [trueseal.dev](https://trueseal.dev), where every claim names the tests that prove it.
  Examples: the relay reading or forging a message, a device accepting a manifest it
  should reject, a delivered message being handled twice, a removed member still receiving
  fan-out.

The following are **documented limitations, not findings** — they are stated publicly, and
reporting them as vulnerabilities will be closed as known:

- **No end-to-end forward secrecy or post-compromise security** (a 2.0 candidate).
- **Data at rest is protected only by the OS sandbox** — the store is excluded from
  backups, but it is not encrypted (1.0 work).
- **What the relay can see:** device keys, online times, recipient keys, blob sizes,
  timing, fan-out shape (likely co-membership), the End-to-End Version, and often which
  device pushed. The relay never logs, stores or uses IP addresses; the server it runs on
  still sees the connection, as with any internet service.
- **No SAS in pairing:** anyone who sees a Pairing Token while its window is open can
  request to join — member names are labels, not authentication.
- **Availability:** any holder of a public key can consume inbox quota; any current or
  former member can trigger Destroy Group. Every current member is fully trusted for
  membership.
- **No relay key rotation** — changing the relay key breaks every client configuration.
- **Not independently audited.**

If you are unsure whether something is a limitation or a finding, report it privately —
we would rather hear it twice than miss it once.
