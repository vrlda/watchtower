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

## Known M1 limitations

- Spool is capped at 10 MB (drops new batches with a loud log beyond that; backoff is a fixed 30 s heartbeat-throttle — exponential backoff is M2)
- No fsync on spool append (process crash is safe; power loss may lose the last batch)
- `check` never drains the spool (one-shot diagnostics by design)
- systemctl timeout path is untested (kill-on-timeout logic is covered only by review)
