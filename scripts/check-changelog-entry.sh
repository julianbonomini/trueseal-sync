#!/usr/bin/env bash
# check-changelog-entry.sh <version-or-tag>
# ─────────────────────────────────────────────────────────────────────────────
# G9: every release has a changelog entry. The lockstep group keeps ONE
# changelog (ADR-0002) with a section per TrueSeal Release and a subsection
# per SDK. Fails unless CHANGELOG.md has, for the given version:
#   - a `## [<version>]` section
#   - the three SDK subsections (core, Swift, Kotlin, TS)
#   - a `### Breaking` subsection (required heading even when empty — the
#     preview lifecycle, ADR-0033, requires an explicit Breaking section on
#     breaking releases, and an absent heading is how breaking notes get lost)
#
# Run by the candidate workflow (fail early) and the promote workflow (hard
# gate). The Release Conductor's pre-promotion check (G9) can call this.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

TAG="${1:?usage: check-changelog-entry.sh <version-or-tag>}"
VERSION="${TAG#v}"

[ -f CHANGELOG.md ] || { echo "FAIL: CHANGELOG.md does not exist" >&2; exit 1; }

grep -q "^## \[$VERSION\]" CHANGELOG.md \
  || { echo "FAIL: no '## [$VERSION]' section in CHANGELOG.md" >&2; exit 1; }

# The section runs from this heading to the next `## ` heading (or EOF).
SECTION=$(awk -v v="$VERSION" '$0 ~ "^## \\[" v "\\]" {found=1; next} /^## / {found=0} found' CHANGELOG.md)

for SUB in "trueseal-sync (core)" "Swift SDK" "Kotlin SDK" "TS SDK"; do
  echo "$SECTION" | grep -q "^### .*$SUB" \
    || { echo "FAIL: '## [$VERSION]' is missing the '$SUB' subsection" >&2; exit 1; }
done

echo "$SECTION" | grep -q "^### Breaking" \
  || { echo "FAIL: '## [$VERSION]' is missing the '### Breaking' subsection (ADR-0033)" >&2; exit 1; }

echo "OK: CHANGELOG.md has a complete entry for $VERSION"
