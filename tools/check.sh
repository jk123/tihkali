#!/usr/bin/env bash
# tihkali acceptance suite — the one gate for "milestone done".
# Exit 0 = green. Each session is a scripted QEMU run; logs land in /tmp.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

FAIL=0
BAD='panic|unhandled|bad syscall|sync exception|unhandled data fault|exec fault'
T=/tmp/tihkali-check
mkdir -p "$T"

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAIL=1; }

gate_bad() { # <name> <log>
    if grep -qE "$BAD" "$2"; then
        fail "$1: bad strings present"
        grep -nE "$BAD" "$2" | head -3 | sed 's/^/          /'
    else
        pass "$1: no bad strings"
    fi
}

gate_has() { # <name> <log> <ERE>
    if grep -qE -- "$3" "$2"; then pass "$1"; else fail "$1 (missing: $3)"; fi
}

gate_count() { # <name> <log> <ERE> <expected>
    local n
    n=$(grep -cE -- "$3" "$2")
    if [ "$n" -eq "$4" ]; then pass "$1 (x$n)"; else fail "$1: got x$n, want x$4"; fi
}

echo "== build"
B=$(cargo build --release 2>&1) || true
if echo "$B" | grep -qE "^(warning|error)(\[|:)"; then
    fail "build is warning/error free"
    echo "$B" | grep -E "^(warning|error)" | head -5 | sed 's/^/          /'
else
    pass "build: 0 warnings, 0 errors"
fi
if [ -f target/initramfs.img ]; then
    pass "initramfs.img present"
else
    fail "initramfs.img missing"
fi
if [ -x .toolchain/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc ]; then
    pass "musl cross toolchain present"
else
    fail "musl toolchain missing (run tools/fetch-linux-toolchain.sh)"
fi
if [ -x .toolchain/alpine/busybox ]; then
    pass "alpine busybox present"
else
    fail "busybox missing (run tools/fetch-alpine-busybox.sh)"
fi

echo "== session 1: fs ops + write-back"
S1="$T/s1.log"
( sleep 3
  printf 'mkdir /w\n';      sleep 0.3
  printf 'save /w/a alpha data\n'; sleep 0.3
  printf 'sync\n';          sleep 2.0
  printf 'exit\n'
) | timeout 15 ./tools/run.sh >"$S1" 2>&1
gate_has "s1: file saved"     "$S1" 'saved /w/a'
gate_has "s1: sync wrote"     "$S1" 'sync: wrote [0-9]+ sectors'
gate_has "s1: clean exit"     "$S1" 'proc: pid 0 exited \(0\)'
gate_bad  "s1" "$S1"

echo "== session 2: persistence across reboot"
S2="$T/s2.log"
( sleep 3
  printf 'ls /w\n';          sleep 0.3
  printf 'cat /w/a\n';       sleep 0.3
  printf 'rm /w/a\n';        sleep 0.3
  printf 'rmdir /w\n';       sleep 0.3
  printf 'sync\n';           sleep 2.0
  printf 'exit\n'
) | timeout 15 ./tools/run.sh >"$S2" 2>&1
gate_has "s2: file survived reboot" "$S2" 'alpha data'
gate_has "s2: removal synced"       "$S2" 'sync: wrote [0-9]+ sectors'
gate_bad  "s2" "$S2"

echo "== session 3: signals + mask + jobs"
S3="$T/s3.log"
( sleep 3
  printf 'trap 15\n';        sleep 0.3
  printf 'kill 15\n';        sleep 0.5
  printf 'sigblock 15\n';    sleep 0.3
  printf 'kill 15\n';        sleep 0.5
  printf 'sigunblock 15\n';  sleep 0.5
  printf 'greet &\n';        sleep 1.0
  printf 'jobs\n';           sleep 1.0
  printf 'killchild 9\n';    sleep 2.0
  printf 'kill 2\n';         sleep 1.5
) | timeout 18 ./tools/run.sh >"$S3" 2>&1
gate_count "s3: caught exactly twice (15 suppressed while blocked)" \
    "$S3" 'caught signal 15' 2
gate_has "s3: unblock delivered"   "$S3" 'sigunblock 15'
gate_has "s3: background spawned"  "$S3" '\[1\] pid [0-9]+'
gate_has "s3: background reaped"   "$S3" '\[1\] pid [0-9]+ exited 5'
gate_has "s3: sleep-kill signaled" "$S3" 'killchild: terminated by signal 9'
gate_has "s3: default terminate"   "$S3" 'proc: pid 0 killed by signal 2'
gate_bad  "s3" "$S3"

echo "== session 4: embedded fallback (--no-drive)"
S4="$T/s4.log"
( sleep 3
  printf 'ls /bin\n';        sleep 0.3
  printf 'cat /etc/motd\n';  sleep 0.3
  printf 'exit\n'
) | timeout 12 ./tools/run.sh --no-drive >"$S4" 2>&1
gate_has "s4: fallback engaged"  "$S4" 'no device in 32 MMIO slots'
gate_has "s4: fs served"         "$S4" 'Welcome to tihkali'
gate_has "s4: sh listed"         "$S4" '^sh'
gate_has "s4: clean exit"        "$S4" 'proc: pid 0 exited \(0\)'
gate_bad  "s4" "$S4"

echo "== session 5: Linux ABI personality"
S5="$T/s5.log"
( sleep 3
  printf 'linux-hello\n'
  sleep 2.0
  printf 'exit\n'
) | timeout 12 ./tools/run.sh >"$S5" 2>&1
gate_has "s5: linux binary ran"  "$S5" 'hello from linux/musl \(EL0 via Linux ABI\)'
gate_has "s5: exit code via wait4" "$S5" 'sh: linux-hello exited 42'
gate_has "s5: clean exit"         "$S5" 'proc: pid 0 exited \(0\)'
gate_bad  "s5" "$S5"

echo "== session 6: Raspberry Pi 3 (raspi3b, embedded initramfs)"
S6="$T/s6.log"
( sleep 3
  printf 'ls /bin\n';    sleep 0.6
  printf 'busybox sleep 0.5\n'; sleep 1.4
  printf 'greet\n';      sleep 1.5
  printf 'exit\n'
) | timeout 15 ./tools/run.sh --rpi >"$S6" 2>&1
gate_has "s6: booted on raspi3b"     "$S6" 'entered at EL'
gate_has "s6: no-GIC dispatcher"     "$S6" 'BCM283x poll dispatcher'
gate_has "s6: fallback initramfs"    "$S6" 'no device in 32 MMIO slots'
gate_has "s6: timer armed"           "$S6" 'timer: 100 Hz'
gate_has "s6: timer IRQ woke sleep"  "$S6" 'sh: busybox exited 0'
gate_has "s6: shell listed ls"       "$S6" 'linux-hello'
gate_has "s6: fork/exec on Pi"       "$S6" 'sh: greet exited 5'
gate_has "s6: clean exit"            "$S6" 'proc: pid 0 exited \(0\)'
gate_bad  "s6" "$S6"

echo "== session 7: Linux ABI depth + Alpine busybox"
S7="$T/s7.log"
( sleep 3
  printf 'linux-probe\n'
  sleep 3
  printf 'busybox echo hello-from-alpine\n'
  sleep 2
  printf 'busybox ls /bin\n'
  sleep 2
  printf 'busybox cat /etc/motd\n'
  sleep 2
  printf 'exit\n'
) | timeout 20 ./tools/run.sh >"$S7" 2>&1
gate_has "s7: probe all ok"          "$S7" 'linux-probe: all ok'
gate_has "s7: probe exited 0"        "$S7" 'sh: linux-probe exited 0'
gate_count "s7: busybox echo ran"    "$S7" 'hello-from-alpine' 2
gate_has "s7: busybox ls via getdents64" "$S7" 'linux-probe'
gate_has "s7: busybox cat read"      "$S7" 'Welcome to tihkali'
gate_has "s7: busybox exited 0"      "$S7" 'sh: busybox exited 0'
gate_bad  "s7" "$S7"

echo "== session 8: busybox ash (POSIX shell: script + pipeline + applets)"
S8="$T/s8.log"
( sleep 3
  printf 'busybox ash /etc/demo.sh\n'
  sleep 3
  printf 'busybox cat /etc/motd\n'
  sleep 2
  printf 'busybox ls /bin\n'
  sleep 2
  printf 'exit\n'
) | timeout 18 ./tools/run.sh >"$S8" 2>&1
gate_has "s8: ash ran demo script"      "$S8" 'hello-from-pipeline'
gate_has "s8: pipeline second line"     "$S8" '^done'
gate_has "s8: ash exited 0"             "$S8" 'sh: busybox exited 0'
gate_has "s8: file cat via sendfile"    "$S8" 'Welcome to tihkali'
gate_has "s8: applet symlink ls"        "$S8" 'linux-hello'
gate_count "s8: no ENOSYS noise"        "$S8" 'ENOSYS' 0
gate_bad  "s8" "$S8"

echo "== session 9: job control — interactive ash, ppoll line editing, Ctrl-C"
S9="$T/s9.log"
( sleep 3
  printf 'busybox ash\n'
  sleep 3
  printf 'echo interactive-ok\n'
  sleep 2
  printf 'sleep 100\n'
  sleep 2
  printf '\003'
  sleep 2
  printf 'echo alive-after-ctrlc\n'
  sleep 2
  printf 'exit\n'
  sleep 1.5
  printf 'exit\n'
) | timeout 20 ./tools/run.sh >"$S9" 2>&1
gate_has "s9: interactive line editing (ppoll)" "$S9" 'interactive-ok'
gate_has "s9: ^C killed fg sleep"               "$S9" 'proc: pid [0-9]+ killed by signal 2'
gate_has "s9: ash survived ^C"                  "$S9" 'alive-after-ctrlc'
gate_count "s9: job control enabled"           "$S9" 'job control turned off' 0
gate_count "s9: no ENOSYS noise"                "$S9" 'ENOSYS' 0
gate_has "s9: ash exited 0"                     "$S9" 'sh: busybox exited 0'
gate_has "s9: clean exit"                       "$S9" 'proc: pid 0 exited \(0\)'
gate_bad  "s9" "$S9"

echo "== session 10: writable FS depth — stage mode/mtime/rename/symlink + sync"
S10="$T/s10.log"
( sleep 3
  printf 'busybox rm -rf /w\n';                 sleep 0.4
  printf 'busybox mkdir -m 700 /w\n';           sleep 0.4
  printf 'save /w/f m19-fs-depth\n';            sleep 0.4
  printf 'busybox chmod 600 /w/f\n';            sleep 0.4
  printf 'busybox touch -t 200001010000 /w/f\n'; sleep 0.5
  printf 'busybox mv /w/f /w/g\n';              sleep 0.4
  printf 'busybox ln -s /etc/motd /w/l\n';      sleep 0.4
  printf 'busybox sync\n';                      sleep 1.5
  printf 'sync\n';                              sleep 2.0
  printf 'exit\n'
) | timeout 18 ./tools/run.sh >"$S10" 2>&1
gate_has "s10: sync wrote"     "$S10" 'sync: wrote [0-9]+ sectors'
gate_count "s10: no ENOSYS"    "$S10" 'ENOSYS' 0
gate_count "s10: no bad syscalls from *at arms" "$S10" 'sh: busybox exited 1' 0
gate_has "s10: clean exit"     "$S10" 'proc: pid 0 exited \(0\)'
gate_bad  "s10" "$S10"

echo "== session 11: FS depth persistence across reboot (modes/mtime/rename/symlink)"
S11="$T/s11.log"
( sleep 3
  printf 'busybox ls -ld /w\n';                 sleep 0.5
  printf 'busybox ls -l /w\n';                  sleep 0.5
  printf 'busybox cat /w/g\n';                  sleep 0.4
  printf 'busybox readlink /w/l\n';             sleep 0.4
  printf 'busybox stat -c %%Y /w/g\n';          sleep 0.5
  printf 'busybox cat /w/f\n';                  sleep 0.5
  printf 'busybox rm /w/g\n';                   sleep 0.4
  printf 'busybox rm /w/l\n';                   sleep 0.4
  printf 'busybox rmdir /w\n';                  sleep 0.4
  printf 'sync\n';                              sleep 2.0
  printf 'exit\n'
) | timeout 18 ./tools/run.sh >"$S11" 2>&1
gate_has "s11: dir mode 700 persisted"   "$S11" 'drwx------'
gate_has "s11: file mode 600 persisted"  "$S11" '-rw-------'
gate_has "s11: symlink lstat persisted"  "$S11" 'lrwxrwxrwx'
gate_has "s11: content after reboot"     "$S11" 'm19-fs-depth'
gate_has "s11: readlink target"          "$S11" '^/etc/motd'
gate_has "s11: mtime year 2000"          "$S11" '946684800'
gate_count "s11: rename: old name gone (only failing cmd)" \
    "$S11" 'sh: busybox exited 1' 1
gate_has "s11: removal synced"           "$S11" 'sync: wrote [0-9]+ sectors'
gate_count "s11: no ENOSYS"              "$S11" 'ENOSYS' 0
gate_has "s11: clean exit"               "$S11" 'proc: pid 0 exited \(0\)'
gate_bad  "s11" "$S11"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: GREEN — all gates passed"
else
    echo "RESULT: RED — see FAIL lines above (logs in $T)"
fi
exit "$FAIL"
