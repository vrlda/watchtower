# Watchtower

Production server autopilot: one agent that watches the health and security of your server.
See `docs/specs/product-spec.md` and `docs/specs/architecture.md`.

## Build

    cargo build --release

## M1 status

- Sensors: resource (mem, swap, load, netdev, cpu spikes), systemd service states + crash loops
- Security sensors (M3): SSH login/auth + brute-force + first-seen IPs (journald),
  root/sudo activity (journald), file-integrity (inotify, Linux), network flow
  (new ports, new outbound destinations, connection-rate spikes)
- M5 sensors: reboot detection, app error-rate spikes (journald patterns),
  docker containers (states + crash loops), TLS certificate expiry
- Local engine: rolling-median spike detection, dedup windows, threshold rules
- Telemetry: batched POST, JSONL disk spool + ack-based drain, heartbeat
- CLI: `check` (one-shot), `run` (continuous), config at `/etc/watchtower/agent.toml`
- Deploy: `deploy/watchtower-agent.service`

## Try it (no control plane required)

    cargo build --release
    ./target/release/watchtower-agent --config /dev/null check

The control plane (`watchtower-server`: incidents, correlation, notifications) is M2+.

## M2 status

Control plane core (`watchtower-server`):

    cargo build --release
    # server.toml: listen, db_url, auth_token, [[probes]] entries
    ./target/release/watchtower-server --config /etc/watchtower/server.toml

- API: `POST /v1/telemetry` (idempotent per event id), `POST /v1/heartbeat`,
  `GET /v1/hosts`, `GET /v1/events?host=&kind=&severity=&since=&limit=`
  (ordered by ts desc, id — never arrival order)
- Uptime probes: `[[probes]] url=... interval_secs=30 fail_threshold=3` →
  Critical `HostUnreachable` events after consecutive failures
- Web UI at `http://127.0.0.1:8787/` (token prompt; evidence expandable).
  Serve from the repo root, or set `WATCHTOWER_UI_DIR` for installed deploys.
- Integration check: `./scripts/integration-test.sh`
- M3 security sensors: see M1 status above. Config keys: `watch_paths`,
  `ssh_brute_threshold`, `ssh_brute_window_secs` in agent.toml.
- M5 config keys: `error_patterns`, `error_window_secs`, `error_threshold`,
  `docker_enabled`, `cert_paths`, `cert_warn_days`, `cert_crit_days`,
  `cert_scan_interval_secs` in agent.toml

Incidents, correlation, notifications: M4.

## Known M1 limitations

- Spool is capped at 10 MB (drops new batches with a loud log beyond that; backoff is a fixed 30 s heartbeat-throttle — exponential backoff is M2)
- No fsync on spool append (process crash is safe; power loss may lose the last batch)
- `check` never drains the spool (one-shot diagnostics by design)
- systemctl timeout path is untested (kill-on-timeout logic is covered only by review)
