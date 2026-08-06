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
  tar -C "$ROOT/target/$target/release" -czf "$TARBALL" watchtower-agent watchtower-server
  echo "built $TARBALL"
done

echo "==> checksums"
(cd "$DIST" && shasum -a 256 watchtower-*.tar.gz > SHA256SUMS)
cat "$DIST/SHA256SUMS"
