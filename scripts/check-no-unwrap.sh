#!/usr/bin/env bash
# check-no-unwrap.sh
# ─────────────────────────────────────────────────────────────────────────────
# Fails with exit code 1 if any .unwrap() appears in non-test production code.
# Run as part of CI after `cargo test` passes.
#
# Exclusions:
#   - src/session/tests/       — test modules
#   - src/session/test_helpers.rs
#   - src/bin/prototype_*      — throwaway prototype files
#   - Lines inside #[cfg(test)] blocks are NOT excluded by this grep approach;
#     instead we rely on the fact that all test modules are in the paths above.
#     relay.rs and ffi.rs test code is inside #[cfg(test)] but lives in the same
#     file as production code — we verify those separately via cargo clippy.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

FOUND=$(grep -rn '\.unwrap()' src/ \
  --include='*.rs' \
  --exclude-dir=tests \
  | grep -v 'src/session/test_helpers' \
  | grep -v 'src/bin/prototype_' \
  | grep -v 'src/member\.rs.*#\[test\]' \
  || true)

# Filter out lines that are inside #[cfg(test)] blocks by checking
# if the file has a cfg(test) section above that line.
# Simple heuristic: skip files where the match line number is >= the
# #[cfg(test)] line number in that same file.
PRODUCTION_FOUND=""
while IFS= read -r line; do
  if [[ -z "$line" ]]; then continue; fi
  file=$(echo "$line" | cut -d: -f1)
  lineno=$(echo "$line" | cut -d: -f2)

  # Find the first #[cfg(test)] line in this file (if any)
  test_start=$(grep -n '#\[cfg(test)\]' "$file" 2>/dev/null | head -1 | cut -d: -f1 || echo "999999")

  if [[ "$lineno" -lt "$test_start" ]]; then
    PRODUCTION_FOUND="${PRODUCTION_FOUND}${line}\n"
  fi
done <<< "$FOUND"

if [[ -n "$PRODUCTION_FOUND" ]]; then
  echo "❌ ERROR: .unwrap() found in production code (outside #[cfg(test)]):"
  echo ""
  printf "$PRODUCTION_FOUND"
  echo ""
  echo "Replace with .unwrap_or_else(|e| e.into_inner()) for Mutex locks,"
  echo ".expect(\"invariant: ...\") for provably-unreachable conversions,"
  echo "or proper error propagation."
  exit 1
fi

echo "✅ No .unwrap() found in production code."
