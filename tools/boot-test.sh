#!/usr/bin/env bash
# Boot the kernel headless, run a scripted stdin, and grep the output.
#
# Usage: tools/boot-test.sh [--script '<printf escapes>'] [extra qemu args...]
#
# run.sh leaves QEMU holding target/initramfs.img if it is SIGKILLed rather
# than allowed to exit, and the next run then dies with `Failed to get
# "write" lock`. This helper always reaps by numeric PID.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Reap any QEMU left over from an interrupted run (numeric PID only —
# `pkill -f` self-matches the invoking shell).
for pid in $(ps -C qemu-system-aarch64 -o pid= 2>/dev/null); do
    kill -9 "$pid" 2>/dev/null
done

STDIN_SCRIPT='exit\n'
if [ "${1:-}" = "--script" ]; then
    shift
    STDIN_SCRIPT="$1"
    shift
fi

LOG=/tmp/tihkali-boot.log
( sleep 6; printf '%b' "$STDIN_SCRIPT"; sleep 3 ) \
    | timeout 40 "$ROOT/tools/run.sh" "$@" >"$LOG" 2>&1

# Give QEMU a moment, then make sure nothing survives this run.
sleep 1
for pid in $(ps -C qemu-system-aarch64 -o pid= 2>/dev/null); do
    kill -9 "$pid" 2>/dev/null
done

echo "--- log: $LOG ---"
cat "$LOG"