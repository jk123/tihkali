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
# kernel's embedded-initramfs fallback path. `--rpi` (also consumed)
# rebuilds for the Raspberry Pi 3 and boots via -M raspi3b (no disk:
# raspi3 has no virtio — the embedded initramfs is used).
QEMU_ARGS=()
MODE=virt
HOSTFWD=""
i=1
while [ "$i" -le "$#" ]; do
    a="$1"
    if [ "$a" = "--no-drive" ]; then
        DRIVE_ARGS=()
    elif [ "$a" = "--rpi" ]; then
        MODE=rpi
        DRIVE_ARGS=()
    elif [ "$a" = "--hostfwd" ]; then
        # Consume the next arg: a SLIRP hostfwd rule body, e.g.
        # "tcp:127.0.0.1:18082-10.0.2.15:18082". Attached to the -netdev
        # user line so the host can reach a guest port.
        shift
        HOSTFWD="$1"
        i=$((i+1))
    else
        QEMU_ARGS+=("$a")
    fi
    shift
    i=$((i+1))
done

if [ "$MODE" = "rpi" ]; then
    cargo build --release --manifest-path "$ROOT/Cargo.toml" \
        --no-default-features --features rpi3
    IMG8="$ROOT/target/kernel8.img"
    llvm-objcopy-19 -O binary "$BIN" "$IMG8"
    QEMU="$ROOT/.toolchain/qemu/usr/bin/qemu-system-aarch64"
    export LD_LIBRARY_PATH="$ROOT/.toolchain/qemu/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    exec "$QEMU" \
        -L "$ROOT/.toolchain/qemu/usr/share/qemu" \
        -M raspi3b \
        -display none -serial stdio -monitor none \
        -kernel "$IMG8" \
        "${QEMU_ARGS[@]}"
fi

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
    -device virtio-net-device,netdev=n0 \
    $( [ -n "$HOSTFWD" ] && echo "-netdev user,id=n0,hostfwd=$HOSTFWD" || echo "-netdev user,id=n0" ) \
    -kernel "$BIN" \
    "${QEMU_ARGS[@]}"
