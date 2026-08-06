#!/usr/bin/env bash
# 1.0 verification on a Linux box. Runs every integration surface once.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILED=0

step() { echo; echo "==> $1"; }

step "build + tests"
(cd "$ROOT" && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo build --release)

step "integration (agent <-> server)"
"$ROOT/scripts/integration-test.sh"

step "discover"
"$ROOT/target/release/watchtower-agent" --config /dev/null discover | tee /tmp/watchtower-discover.txt
grep -q "Docker detected" /tmp/watchtower-discover.txt || { echo "discover output missing rows" >&2; FAILED=1; }

step "demo scenario"
"$ROOT/scripts/demo.sh"

step "install (fresh unit)"
SERVER_URL="http://127.0.0.1:18789" TOKEN="verify-token" \
  WATCHTOWER_BINARY="$ROOT/target/release/watchtower-agent" \
  "$ROOT/scripts/install.sh" 2>&1 | tee /tmp/watchtower-install.txt
grep -q "install complete" /tmp/watchtower-install.txt || { echo "install failed" >&2; FAILED=1; }
systemctl status watchtower-agent --no-pager | grep -q "Active: active" || { echo "unit not active" >&2; FAILED=1; }

if [ "$FAILED" -eq 0 ]; then
  echo
  echo "VERIFY-LINUX PASSED"
else
  echo "VERIFY-LINUX FAILED" >&2
  exit 1
fi
