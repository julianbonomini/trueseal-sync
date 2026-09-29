# Distribution channels, package names and lockstep versions for the Developer Preview

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#14](https://github.com/julianbonomini/trueseal-roadmap/issues/14), from the findings of [trueseal-roadmap#13](https://github.com/julianbonomini/trueseal-roadmap/issues/13)). This complements ADR-0022, which keeps package versions independent of Protocol Versions.

The preview ships through standard registries, with signed or attested, immutable artifacts:

| Package | Channel | Name |
|---|---|---|
| Swift SDK | SwiftPM `binaryTarget` on GitHub Releases | `trueseal-sync-swift` |
| Kotlin SDK (Android AAR) | Maven Central, GPG-signed | `dev.trueseal:trueseal-sync` (namespace verified by DNS on `trueseal.dev`) |
| TS SDK | npm, napi-rs per-platform packages, provenance | `@trueseal/sync`, `@trueseal/sync-<platform>` |
| Relay | GHCR, multi-arch (amd64, arm64), build attestation | `ghcr.io/julianbonomini/trueseal-relay` |
| `trueseal-noise`, `trueseal-sync` crates | git tags only; **not** published to crates.io | — |

**Versions.**
- **TrueSeal Release (lockstep).** `trueseal-sync` and the three SDKs share one version number and always release together, even when a package has no changes. Swift 0.6.2, Kotlin 0.6.2 and TS 0.6.2 are the same core build with the same API shape (ADR-0028). The lockstep group starts at **0.6.0**, above every existing tag.
- `trueseal-noise` and `trueseal-relay` are versioned independently and restart at **0.2.0**, because both change wire format under ADR-0022.
- The preview marker is **`0.x` alone**, with no `-preview.N` suffix, because SwiftPM `from:` and npm `^` ranges skip pre-releases. "Developer Preview" is stated in READMEs, the docs and registry descriptions.
- Tags are `vX.Y.Z` and **immutable**. A bad release is fixed with a new patch version, never by moving or re-uploading a tag.
- The docs publish a **Compatibility Table** that maps TrueSeal Release, relay and noise versions to Transport and End-to-End Versions. It is generated from release metadata, not written by hand.

**What each component reports about its versions.**
- Each SDK exposes the package version (`TrueSeal.version`) and the `transportVersion` and `endToEndVersion` constants. All three are generated from the core, so they can't drift.
- The relay reports its Transport Version on `/healthz`.

**Pinned inputs are a release gate.** Every cross-repo input to a release must be pinned to an exact version and checksum. That means no `releases/latest`, no sibling `path =` dependencies and no `:latest` images, and CI enforces the rule where it can. Self-hosting docs pin an exact relay image tag.

**License.** Everything is Apache-2.0. The MIT metadata in the `trueseal-noise` and `trueseal-sync` Cargo.toml files and in the Kotlin POM is wrong and must be corrected to match the LICENSE files before the first publish.

**Supported npm targets.** The prebuilt binaries are macOS arm64 and x64, Linux x64 and arm64 (glibc), and Windows x64. The minimum is Node 20. Linux musl and Windows arm64 are documented as unsupported.

**Publishing identities.** The maintainer's personal accounts own the npm org `trueseal`, the Central Portal account, the `dev.trueseal` namespace and the GHCR package, all protected with 2FA. The Maven signing key is a dedicated project GPG key. It is kept offline in the maintainer's password manager and exists in CI only as a secret on `trueseal-sync-kotlin`. npm uses trusted publishing (OIDC) after the first publish, so no long-lived npm token exists.

## Considered alternatives

- **Publish the Rust crates to crates.io.** Rejected for the preview. The names and versions are permanent, and publishing signals a Rust API that people can depend on before the protocol has settled. The TS SDK is built in CI and can pin a git tag. A public Rust SDK is out of scope for the preview.
- **JitPack for Kotlin.** Rejected. It produces unsigned artifacts whose rebuilds aren't reproducible, and it forces native `.so` files into git with force-moved tags. That is a weak trust story for a security SDK.
- **GitHub Packages as the main channel.** Rejected. Every consumer would need a GitHub access token, even for public packages.
- **`io.github.julianbonomini` as the Maven namespace.** Rejected. It would tie the coordinates to a personal handle forever. (`io.github.trueseal` belongs to an unrelated account.)
- **Unscoped npm names.** Rejected. Each platform package name could be squatted separately.
- **Independent versions for every repo.** Rejected. SDK parity would be invisible, and every pairing of versions would need the table.
- **Shared minor version with per-SDK patch versions.** Rejected. It weakens the "same version, same core" promise.
- **Docker Hub alongside GHCR.** Rejected. It adds another account for no preview benefit.

## Consequences

- The Swift release stops force-moving tags. It writes `version`, `url` and `checksum` constants and pins the core artifact.
- The Kotlin release moves from JitPack to Maven Central with the `com.vanniktech.maven.publish` plugin. It stops committing `.so` files, and the POM's `url` owner is corrected.
- The TS package is renamed to `@trueseal/sync`, upgraded to napi v3, and gets a CI matrix. It depends on a pinned `trueseal-sync` git tag instead of a sibling path.
- Core release CI drops `TRUESEAL_READ_TOKEN`, and Cargo versions match tags.
- The maintainer does the approval steps by hand: the npm org, the Central Portal account, the DNS TXT record on `trueseal.dev`, the GPG key, and the first publish of each package.
