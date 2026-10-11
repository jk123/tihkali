#!/usr/bin/env bash
# Run the tihkali kernel in QEMU (project-local QEMU, no root needed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/aarch64-unknown-none/release/tihkali"

cargo build --release --manifest-path "$ROOT/Cargo.toml"

IMG="$ROOT/target/initramfs.img"
DRIVE_ARGS=()
if [ -f "$IMG" ]; then
    DRIVE_ARGS=(-drive "file=$IMG,if=none,id=hd0,format=raw"
                -device virtio-blk-device,drive=hd0)
else
    echo "run.sh: warning: target/initramfs.img missing (run cargo build); kernel will use embedded fallback" >&2
fi

# `--no-drive` (consumed here) boots without a disk to exercise the
# kernel's embedded-initramfs fallback path.
QEMU_ARGS=()
for a in "$@"; do
    if [ "$a" = "--no-drive" ]; then
        DRIVE_ARGS=()
    else
        QEMU_ARGS+=("$a")
    fi
done

QEMU="$ROOT/.toolchain/qemu/usr/bin/qemu-system-aarch64"
export LD_LIBRARY_PATH="$ROOT/.toolchain/qemu/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

exec "$QEMU" \
    -L "$ROOT/.toolchain/qemu/usr/share/qemu" \
    -machine virt,gic-version=3 \
    -cpu cortex-a57 \
    -m 256M \
    -display none -serial stdio -monitor none \
    -global virtio-mmio.force-legacy=false \
    "${DRIVE_ARGS[@]}" \
    -kernel "$BIN" \
    "${QEMU_ARGS[@]}"
