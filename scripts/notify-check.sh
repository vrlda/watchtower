#!/usr/bin/env bash
# End-to-end notification check against real channels.
# Usage:
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... sh scripts/notify-check.sh
#   SLACK_URL=... sh scripts/notify-check.sh
# Requires a running watchtower-server configured with the same credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${NOTIFY_CHECK_PORT:-18790}"
TOKEN="${NOTIFY_CHECK_TOKEN:-notify-check-token}"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

cat > "$WORK/server.toml" <<EOF
listen = "127.0.0.1:$PORT"
db_url = "sqlite://$WORK/notify.db"
auth_token = "$TOKEN"
EOF

if [ -n "${TELEGRAM_BOT_TOKEN:-}" ]; then
  TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}" \
    "$ROOT/target/release/watchtower-server" --config "$WORK/server.toml" &
else
  "$ROOT/target/release/watchtower-server" --config "$WORK/server.toml" &
fi
SERVER_PID=$!
sleep 1

NOW_MS=$(( $(date +%s) * 1000 ))
curl -fsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"batch\":[{\"id\":\"nc-fail\",\"ts\":$((NOW_MS - 50000)),\"host_id\":\"notify-check\",\"key\":\"svc:check.service\",\"kind\":\"ServiceFailed\",\"severity\":\"Critical\",\"summary\":\"notify check\",\"evidence\":[]}]}" \
  "http://127.0.0.1:$PORT/v1/telemetry" >/dev/null

echo "triggered — check your configured channels for the incident notification"
echo "the incident is: notify check (ServiceFailed, Critical)"
echo "done (a Telegram handshake without TELEGRAM_CHAT_ID requires messaging the bot first)"
