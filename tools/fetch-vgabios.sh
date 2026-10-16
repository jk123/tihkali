#!/usr/bin/env bash
# Install the VGA option ROMs QEMU's `ramfb` device requires.
#
# `ramfb` calls rom_add_vga("vgabios-ramfb.bin") at realize time (QEMU
# hw/display/ramfb.c), so QEMU ABORTS AT STARTUP without it. Debian trixie
# ships these in a separate `seabios` package that the base vendoring did
# not pull in, and they must land in the `-L` datadir (usr/share/qemu),
# not in the deb's own usr/share/seabios.
#
# Idempotent: skips when the ROM is already present. No sudo — extracted
# into the project-local .toolchain like everything else.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/.toolchain"
DATADIR="$DEST/qemu/usr/share/qemu"
ROM="$DATADIR/vgabios-ramfb.bin"

if [ -f "$ROM" ]; then
    echo "vgabios present: $ROM"
    exit 0
fi

mkdir -p "$DEST/debs"
cd "$DEST/debs"

# Prefer the distribution package manager so the version tracks the distro;
# fall back to a direct pool fetch.
if ! apt-get download seabios 2>/dev/null; then
    echo "apt-get download failed; fetching seabios from deb.debian.org" >&2
    url="http://deb.debian.org/debian/pool/main/s/seabios/"
    deb="$(curl -fsSL "$url" | grep -oE 'seabios_[^"]*_all\.deb' | sort -V | tail -1)"
    curl -fL --retry 3 -O "${url}${deb}"
fi

debs="$(ls -1t seabios_*_all.deb 2>/dev/null | head -1)"
[ -n "$debs" ] || { echo "error: no seabios deb found" >&2; exit 1; }

dpkg-deb -x "$debs" "$DEST/qemu/"
# The -L datadir overrides the package's own usr/share/seabios location.
cp "$DEST"/qemu/usr/share/seabios/*.bin "$DATADIR/"

test -f "$ROM" || { echo "error: $ROM missing after extraction" >&2; exit 1; }
echo "vgabios ready: $ROM"