#!/usr/bin/env bash
# check-connection-factory.sh
# ─────────────────────────────────────────────────────────────────────────────
# SYNC-17 (#109): fails with exit code 1 if any TcpStream::connect appears in
# production code outside src/connection.rs. The connection factory is the
# only place sockets are opened, so a future IP-hiding transport
# (trueseal-roadmap#26) is one local change and no code path can quietly
# bypass the seam. Run as part of CI.
#
# Exclusions (test-only code):
#   - src/connection.rs      — the factory module itself
#   - src/session/tests/     — test modules
#   - src/session/test_helpers.rs
#   - src/ffi/tests.rs
#   - src/bin/prototype_*    — throwaway prototype files
# Tests build sessions through injected factories or in-memory pipes; a test
# that ever needs a real socket must go through ConnectionFactory::open like
# production does, so this list stays honest.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

FOUND=$(grep -rn 'TcpStream::connect' src/ \
  --include='*.rs' \
  | grep -v 'src/connection\.rs' \
  | grep -v 'src/session/tests/' \
  | grep -v 'src/session/test_helpers' \
  | grep -v 'src/ffi/tests' \
  | grep -v 'src/bin/prototype_' \
  || true)

if [ -n "$FOUND" ]; then
  echo "❌ ERROR: TcpStream::connect found outside the connection factory:"
  echo ""
  echo "$FOUND"
  echo ""
  echo "Production code opens sockets only in src/connection.rs (SYNC-17)."
  echo "Route the call site through ConnectionFactory::open / into_factories(),"
  echo "or decorate the factory's stream (see SlowStream in trueseal-cli.rs)."
  exit 1
fi

echo "✅ All sockets are opened in the connection factory (src/connection.rs)."
