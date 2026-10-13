#!/usr/bin/env bash
# check-cargo-version.sh <version-or-tag>
# ─────────────────────────────────────────────────────────────────────────────
# ADR-0030 (G9): Cargo versions match tags. Fails unless Cargo.toml's package
# version equals the given version (with or without the leading "v").
#
# Run by the candidate workflow (fail early) and the promote workflow (hard
# gate). The Release Conductor's pre-promotion check (G9) can call this on the
# candidate commit.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

TAG="${1:?usage: check-cargo-version.sh <version-or-tag>}"
VERSION="${TAG#v}"

CARGO_VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/^version = "//; s/"$//')

echo "Cargo.toml version: $CARGO_VERSION"
echo "expected (from $TAG): $VERSION"

if [ "$CARGO_VERSION" != "$VERSION" ]; then
  echo "FAIL: Cargo.toml version does not match the release version (ADR-0030)" >&2
  exit 1
fi
echo "OK: Cargo version matches"
