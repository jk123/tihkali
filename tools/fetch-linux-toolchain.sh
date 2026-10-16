#!/usr/bin/env bash
# Fetch the project-local aarch64-linux-musl cross toolchain (musl.cc).
# Idempotent: skips when already present. ~100 MB download.
#
# NOTE FOR CI: musl.cc is not reachable from GitHub Actions runners --
# the connection to port 443 times out. There is no substitute in
# Ubuntu's archive: musl-tools is published for amd64/i386/arm64 only
# and musl-dev is host-arch, so nothing in noble provides an aarch64
# musl libc for cross compilation. The C probes in kernel/assets/c
# need real musl headers and a static libc.a, so the toolchain cannot
# be substituted. If this fails on a runner, seed the toolchain into
# the Actions cache from a machine that can reach musl.cc.
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

# Probe first with a short timeout. Against an unreachable host the
# --retry loop costs ~9 minutes of 133s timeouts, which burns the CI
# job budget before failing with a confusing tar error.
if ! curl -fsS --connect-timeout 10 --max-time 20 -o /dev/null \
        https://musl.cc/ 2>/dev/null; then
    cat >&2 <<'MSG'
error: musl.cc is unreachable from this host.

  kernel/build.rs compiles kernel/assets/c/*.c with a static aarch64
  musl gcc, and no Ubuntu package provides one (musl-tools is
  amd64/i386/arm64 only, musl-dev is host-arch).

  Local build: this machine can reach musl.cc, so run it directly.
  CI runner:  seed .toolchain/aarch64-linux-musl-cross into the
              Actions cache from a machine that can, or install the
              compiler to the path above by hand.
MSG
    exit 1
fi

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