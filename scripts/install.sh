#!/usr/bin/env bash
# Watchtower agent installer.
# Usage:
#   SERVER_URL=https://control.example.com TOKEN=secret sh install.sh
#   WATCHTOWER_BINARY=/path/to/watchtower-agent sh install.sh   # local build
set -euo pipefail

SERVER_URL="${SERVER_URL:-}"
TOKEN="${TOKEN:-}"
BINARY_SRC="${WATCHTOWER_BINARY:-}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/watchtower"
SPOOL_DIR="/var/lib/watchtower/spool"
UNIT_NAME="watchtower-agent.service"

if [ -z "$SERVER_URL" ] || [ -z "$TOKEN" ]; then
  echo "usage: SERVER_URL=<url> TOKEN=<token> sh install.sh" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 1
fi

echo "==> installing binary"
if [ -z "$BINARY_SRC" ]; then
  echo "set WATCHTOWER_BINARY to a local build (release hosting is post-MVP)" >&2
  exit 1
fi
install -m 0755 "$BINARY_SRC" "$INSTALL_DIR/watchtower-agent"

echo "==> creating service user"
if ! getent passwd watchtower >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin watchtower
fi

echo "==> writing config"
mkdir -p "$CONFIG_DIR" "$SPOOL_DIR"
cat > "$CONFIG_DIR/agent.toml" <<EOF
host_id = "auto"
server_url = "$SERVER_URL"
token = "$TOKEN"
poll_interval_secs = 15
heartbeat_secs = 30
spool_dir = "$SPOOL_DIR"
EOF
chown -R watchtower:watchtower "$SPOOL_DIR"
chown watchtower:watchtower "$CONFIG_DIR/agent.toml"
chmod 600 "$CONFIG_DIR/agent.toml"

echo "==> installing systemd unit"
# supplementary groups: journal + adm always exist; docker only where present
SUPP_GROUPS="systemd-journal adm"
if getent group docker >/dev/null 2>&1; then
  SUPP_GROUPS="$SUPP_GROUPS docker"
fi
cat > "/etc/systemd/system/$UNIT_NAME" <<UNIT
[Unit]
Description=Watchtower agent
After=network-online.target
Wants=network-online.target

[Service]
User=watchtower
Group=watchtower
SupplementaryGroups=$SUPP_GROUPS
ExecStart=$INSTALL_DIR/watchtower-agent run
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$SPOOL_DIR
RuntimeDirectory=watchtower
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
systemctl start "$UNIT_NAME"

echo "==> discovery checklist"
"$INSTALL_DIR/watchtower-agent" --config "$CONFIG_DIR/agent.toml" discover || true

echo "install complete: server will register on first heartbeat"
