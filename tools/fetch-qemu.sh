#!/usr/bin/env bash
# Vendor QEMU into the project-local .toolchain, no sudo required.
#
# The suite drives QEMU from `.toolchain/qemu/usr/bin/qemu-system-aarch64`
# with `-L .toolchain/qemu/usr/share/qemu` (see tools/run.sh). Debian
# trixie ships QEMU as ~15 packages, and installing them normally needs
# root, so we `apt-get download` the debs and unpack them into .toolchain
# instead. That is why run.sh exports LD_LIBRARY_PATH for the vendored
# libqemu instead of relying on the system linker.
#
# The VGA option ROMs QEMU's `ramfb` needs come from a separate `seabios`
# package; tools/fetch-vgabios.sh handles those.
#
# Idempotent: skips when the binary is already present.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/.toolchain"
BIN="$DEST/qemu/usr/bin/qemu-system-aarch64"

if [ -x "$BIN" ]; then
    echo "qemu present: $BIN"
    exit 0
fi

mkdir -p "$DEST/debs"
cd "$DEST/debs"

# The aarch64 system emulator plus everything it links against. These
# names track Debian trixie; the fallback below resolves them from the
# pool if apt-get download is unavailable or the package moved.
packages=(
    qemu-system-arm
    qemu-system-common
    qemu-system-data
    ipxe-qemu
    libfdt1
    libpixman-1-0
    libslirp0
    libcapstone5
    libndctl6
    libvdeplug2t64
    libdaxctl1
    libpmem1
)

missing=()
for p in "${packages[@]}"; do
    if ! apt-get download "$p" 2>/dev/null; then
        echo "apt-get download failed for $p" >&2
        missing+=("$p")
    fi
done

if [ ${#missing[@]} -gt 0 ]; then
    echo "falling back to deb.debian.org for: ${missing[*]}" >&2
    pool="http://deb.debian.org/debian/pool/main/"
    for p in "${missing[@]}"; do
        # First letter of the source package name, per Debian pool layout.
        initial="${p:0:1}"
        for c in "$initial" "lib${initial}"; do
            dir="$pool$c/$p/"
            deb="$(curl -fsSL "$dir" 2>/dev/null | grep -oE "${p}_[^\"]*\.deb" | sort -V | tail -1)" || true
            [ -n "$deb" ] && { curl -fL --retry 3 -O "${dir}${deb}"; break; }
        done
    done
fi

debs="$(ls -1 ./*.deb 2>/dev/null || true)"
[ -n "$debs" ] || { echo "error: no qemu debs downloaded" >&2; exit 1; }

for d in $debs; do
    dpkg-deb -x "$d" "$DEST/qemu/"
done

test -x "$BIN" || { echo "error: $BIN missing after extraction" >&2; exit 1; }
echo "qemu ready: $BIN"