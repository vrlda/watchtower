#!/usr/bin/env bash
# 1.0 verification on a Linux box. Runs every integration surface once.
#
# Invoke as root with an intact PATH and bash (sudo sh strips PATH → cargo
# not found, and dash has no pipefail):
#   sudo env "PATH=$PATH" bash scripts/verify-linux.sh
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
# a live server so the agent's registration is provable
cat > /tmp/watchtower-verify-server.toml <<EOF
listen = "127.0.0.1:18789"
db_url = "sqlite:///tmp/watchtower-verify.db"
auth_token = "verify-token"
EOF
"$ROOT/target/release/watchtower-server" --config /tmp/watchtower-verify-server.toml &
VERIFY_SERVER_PID=$!
trap 'kill "$VERIFY_SERVER_PID" 2>/dev/null || true; systemctl stop watchtower-agent 2>/dev/null || true; rm -f /tmp/watchtower-verify-server.toml /tmp/watchtower-verify.db /tmp/watchtower-install.txt' EXIT
sleep 1

SERVER_URL="http://127.0.0.1:18789" TOKEN="verify-token" \
  WATCHTOWER_BINARY="$ROOT/target/release/watchtower-agent" \
  "$ROOT/scripts/install.sh" 2>&1 | tee /tmp/watchtower-install.txt
grep -q "install complete" /tmp/watchtower-install.txt || { echo "install failed" >&2; FAILED=1; }
systemctl status watchtower-agent --no-pager | grep -q "Active: active" || { echo "unit not active" >&2; FAILED=1; }
sleep 5
HOSTS=$(curl -fsS -H "Authorization: Bearer verify-token" "http://127.0.0.1:18789/v1/hosts" || true)
echo "$HOSTS" | grep -q '"host_id"' || { echo "agent never registered via heartbeat" >&2; FAILED=1; }
journalctl -u watchtower-agent --no-pager -n 20 2>/dev/null | grep -q "\[audit\]" || echo "note: audit lines not found in journal (check journald access)"

if [ "$FAILED" -eq 0 ]; then
  echo
  echo "VERIFY-LINUX PASSED"
else
  echo "VERIFY-LINUX FAILED" >&2
  exit 1
fi
