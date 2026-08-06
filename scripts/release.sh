#!/usr/bin/env bash
# Build a release tarball + checksums.
# Usage: TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu" sh scripts/release.sh
# Cross targets need a C toolchain (see the zig wrapper used during M3-M5 checks).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(grep -m1 '^version' "$ROOT/crates/wt-common/Cargo.toml" | sed 's/version = "\(.*\)"/\1/' | tr -d ' "')"
TARGETS="${TARGETS:-$(rustc -vV | sed -n 's/^host: //p')}"
DIST="$ROOT/dist"
mkdir -p "$DIST"

for target in $TARGETS; do
  echo "==> building $target"
  (cd "$ROOT" && cargo build --release --target "$target" -p watchtower-agent -p watchtower-server)
  TARBALL="$DIST/watchtower-$VERSION-$target.tar.gz"
  mkdir -p "$ROOT/target/$target/release/static"
  cp -R "$ROOT/crates/server/static/." "$ROOT/target/$target/release/static/"
  cat > "$ROOT/target/$target/release/watchtower-server.service" <<UNIT
[Unit]
Description=Watchtower control plane
After=network-online.target
Wants=network-online.target

[Service]
User=watchtower
Group=watchtower
Environment=WATCHTOWER_UI_DIR=/usr/local/bin/static
ExecStart=/usr/local/bin/watchtower-server
Restart=always
RestartSec=5
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/watchtower
NoNewPrivileges=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
  tar -C "$ROOT/target/$target/release" -czf "$TARBALL" watchtower-agent watchtower-server static watchtower-server.service
  echo "built $TARBALL"
done

echo "==> checksums"
(cd "$DIST" && shasum -a 256 watchtower-*.tar.gz > SHA256SUMS)
cat "$DIST/SHA256SUMS"
