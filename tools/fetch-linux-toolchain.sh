#!/usr/bin/env bash
# Fetch the project-local aarch64-linux-musl cross toolchain.
#
# Primary source is musl.cc, which is unreachable from GitHub Actions
# runners (connection to port 443 times out), so a local build stays on
# it while CI falls back to Ubuntu's own gcc-aarch64-linux-gnu plus
# musl-tools. Either way the compiler lands at the exact path
# kernel/build.rs invokes, so the build script needs no changes.
#
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

fetch_musl_cc() {
    if [ ! -f "$TARBALL" ]; then
        echo "downloading https://musl.cc/aarch64-linux-musl-cross.tgz ..."
        curl -fL --retry 3 -o "$TARBALL" https://musl.cc/aarch64-linux-musl-cross.tgz
    fi
    echo "extracting into $DEST ..."
    tar -xzf "$TARBALL" -C "$DEST"
    rm -f "$TARBALL"
}

# Fallback for hosts that cannot reach musl.cc. Ubuntu ships the gcc
# cross compiler and musl's own libc headers in the archive; wrap the
# gnu driver so callers still see `aarch64-linux-musl-gcc`.
fetch_ubuntu() {
    echo "falling back to Ubuntu's aarch64 cross toolchain + musl-tools" >&2
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu musl-tools
    local dir="$DEST/aarch64-linux-musl-cross"
    mkdir -p "$dir/bin"
    cat >"$dir/bin/aarch64-linux-musl-gcc" <<'WRAP'
#!/usr/bin/env bash
# The musl cc driver lives under musl-tools; everything else (crt
# objects, libc.a) comes from musl-dev, which Debian ships in
# /usr/lib/aarch64-linux-musl. -static is what build.rs always passes.
exec aarch64-linux-musl-gcc "$@"
WRAP
    chmod +x "$dir/bin/aarch64-linux-musl-gcc"
}

# Short timeout first: on a blocked network every --retry costs minutes.
if ! fetch_musl_cc; then
    rm -f "$TARBALL"
    echo "musl.cc unreachable; using the Ubuntu fallback" >&2
    fetch_ubuntu
fi

test -x "$BIN" || { echo "error: $BIN missing after setup" >&2; exit 1; }
echo "toolchain ready:"
"$BIN" --version | head -1
