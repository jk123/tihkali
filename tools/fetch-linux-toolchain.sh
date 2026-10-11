#!/usr/bin/env bash
# Fetch the project-local aarch64-linux-musl cross toolchain (musl.cc).
# Idempotent: skips when already present. ~100 MB download.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/.toolchain"
BIN="$DEST/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

if [ -x "$BIN" ]; then
    echo "toolchain present: $BIN"
    "$BIN" --version | head -1
    exit 0
fi

mkdir -p "$DEST"
TARBALL="$DEST/aarch64-linux-musl-cross.tgz"
if [ ! -f "$TARBALL" ]; then
    echo "downloading https://musl.cc/aarch64-linux-musl-cross.tgz ..."
    curl -fL --retry 3 -o "$TARBALL" https://musl.cc/aarch64-linux-musl-cross.tgz
fi
echo "extracting into $DEST ..."
tar -xzf "$TARBALL" -C "$DEST"
rm -f "$TARBALL"
test -x "$BIN" || { echo "error: $BIN missing after extraction" >&2; exit 1; }
echo "toolchain ready:"
"$BIN" --version | head -1
