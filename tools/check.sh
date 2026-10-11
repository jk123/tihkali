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
    if grep -qE "$3" "$2"; then pass "$1"; else fail "$1 (missing: $3)"; fi
}

gate_count() { # <name> <log> <ERE> <expected>
    local n
    n=$(grep -cE "$3" "$2")
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

echo "== session 1: fs ops + write-back"
S1="$T/s1.log"
( sleep 1.5
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
( sleep 1.5
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
( sleep 1.5
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
( sleep 1.5
  printf 'ls /bin\n';        sleep 0.3
  printf 'cat /etc/motd\n';  sleep 0.3
  printf 'exit\n'
) | timeout 12 ./tools/run.sh --no-drive >"$S4" 2>&1
gate_has "s4: fallback engaged"  "$S4" 'no device in 32 MMIO slots'
gate_has "s4: fs served"         "$S4" 'Welcome to tihkali'
gate_has "s4: sh listed"         "$S4" '^sh'
gate_has "s4: clean exit"        "$S4" 'proc: pid 0 exited \(0\)'
gate_bad  "s4" "$S4"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: GREEN — all gates passed"
else
    echo "RESULT: RED — see FAIL lines above (logs in $T)"
fi
exit "$FAIL"
