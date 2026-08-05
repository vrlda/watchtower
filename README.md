# Watchtower

Production server autopilot: one agent that watches the health and security of your server.
See `docs/specs/product-spec.md` and `docs/specs/architecture.md`.

## Build

    cargo build --release

## M1 status

- Sensors: resource (mem, swap, load, netdev, cpu spikes), systemd service states + crash loops
- Local engine: rolling-median spike detection, dedup windows, threshold rules
- Telemetry: batched POST, JSONL disk spool + ack-based drain, heartbeat
- CLI: `check` (one-shot), `run` (continuous), config at `/etc/watchtower/agent.toml`
- Deploy: `deploy/watchtower-agent.service`

## Try it (no control plane required)

    cargo build --release
    ./target/release/watchtower-agent --config /dev/null check

The control plane (`watchtower-server`: incidents, correlation, notifications) is M2+.
