# Watchtower 1.0 — Release Notes

## What ships

- `watchtower-agent`: health/resource/systemd/ssh-auth/file-integrity/netflow/
  reboot/error-rate/docker/TLS sensors; local detection; telemetry with spool.
- `watchtower-server`: ingest, hosts, events, incidents + correlation,
  webhook/Slack notifications, watchdog, timeline UI.
- `scripts/install.sh`: agent install (user, unit, config, discovery checklist).
- `scripts/release.sh`: release tarballs + SHA256SUMS.

## Install the agent

    INSTALL_URL=<tarball-url> INSTALL_SHA256=<from SHA256SUMS> \
      SERVER_URL=<server-url> TOKEN=<shared-token> \
      sudo sh scripts/install.sh

The agent runs as the dedicated `watchtower` user (journal/docker group access,
no capabilities). Hosts self-register on the first heartbeat.

## Install the server (from the same tarball)

    # prerequisites — the unit does not create these
    mkdir -p /var/lib/watchtower /etc/watchtower
    chown watchtower:watchtower /var/lib/watchtower

    # config (auth_token is REQUIRED — the server refuses to run without it)
    cat > /etc/watchtower/server.toml <<EOF
    listen = "127.0.0.1:8787"
    db_url = "sqlite:///var/lib/watchtower/watchtower.db"
    auth_token = "changeme"
    EOF
    chown watchtower:watchtower /etc/watchtower/server.toml

    install -m 0755 watchtower-server /usr/local/bin/watchtower-server
    cp -R static /usr/local/bin/static
    cp watchtower-server.service /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now watchtower-server

    # optional: Telegram notifications (token from the environment)
    TELEGRAM_BOT_TOKEN=<bot token> watchtower-server --config server.toml
    # multi-server: same token on every server; pin the chat for determinism
    TELEGRAM_BOT_TOKEN=<token> TELEGRAM_CHAT_ID=<chat-id> watchtower-server ...
    # optional: require a password before a chat can register
    TELEGRAM_BOT_PASSWORD=<secret> watchtower-server --config server.toml

The UI serves at http://127.0.0.1:8787/ (token prompt on first load).
Expose the listener only where the UI + agents can reach it (default localhost).

## Verification

    # on a fresh Linux box — the 1.0 gate
    sudo sh scripts/verify-linux.sh

## Known limitations (post-1.0 backlog)

See docs/roadmap.md — docker over the API socket, telemetry bandwidth budget,
signed binaries (checksummed today; signing infra is external), Kubernetes,
Windows. Multi-host correlation shipped but live multi-site testing at scale
is not yet exercised. Access-log parsing, persistent seen-IP/cert state,
multi-host correlation, per-host tokens, and Postgres all shipped in the
2026-08-07 full batch (see docs/specs/audit.md).
