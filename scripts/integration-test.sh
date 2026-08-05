#!/usr/bin/env bash
# M2 integration check: build both binaries, run the server locally with a
# temp config, push a sample batch + heartbeat through real HTTP, verify the
# API returns them. macOS-safe (no GNU timeout, no /proc-dependent sensors).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

PORT=18787
TOKEN="integration-test-token"

cat > "$WORK/server.toml" <<EOF
listen = "127.0.0.1:$PORT"
db_url = "sqlite://$WORK/test.db"
auth_token = "$TOKEN"
EOF

cat > "$WORK/agent.toml" <<EOF
host_id = "itest-host"
server_url = "http://127.0.0.1:$PORT"
token = "$TOKEN"
poll_interval_secs = 1
heartbeat_secs = 1
spool_dir = "$WORK/spool"
EOF

echo "==> building"
(cd "$ROOT" && cargo build --release -q)

echo "==> starting server"
"$ROOT/target/release/watchtower-server" --config "$WORK/server.toml" &
SERVER_PID=$!
sleep 1

echo "==> heartbeat round-trip (agent binary, run 3s)"
"$ROOT/target/release/watchtower-agent" --config "$WORK/agent.toml" run &
AGENT_PID=$!
sleep 3
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

echo "==> verifying host registry"
HOSTS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/hosts")
echo "$HOSTS" | grep -q '"host_id":"itest-host"' && echo "OK host registered"

echo "==> verifying events endpoint"
curl -fsS -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch":[{"id":"e-1","ts":1000,"host_id":"itest-host","key":"k","kind":"ServiceFailed","severity":"Critical","summary":"integration event","evidence":[]}]}' \
  "http://127.0.0.1:$PORT/v1/telemetry" >/dev/null
EVENTS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/events?host=itest-host")
echo "$EVENTS" | grep -q '"summary":"integration event"' && echo "OK event stored"

echo "==> verifying auth rejection"
CODE=$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/v1/hosts")
[ "$CODE" = "401" ] && echo "OK unauthorized rejected"

echo "ALL INTEGRATION CHECKS PASSED"
