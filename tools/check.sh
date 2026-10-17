#!/usr/bin/env bash
# tihkali acceptance suite — the one gate for "milestone done".
# Exit 0 = green. Each session is a scripted QEMU run; logs land in /tmp.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

FAIL=0
BAD='panic|unhandled|bad syscall|sync exception|unhandled data fault|exec fault'
T=${TIHKALI_CHECK_DIR:-/tmp/tihkali-check}
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
( sleep 8
  printf 'mkdir /w\n';      sleep 0.3
  printf 'save /w/a alpha data\n'; sleep 0.3
  printf 'sync\n';          sleep 2.0
  printf 'exit\n'
) | timeout 21 ./tools/run.sh >"$S1" 2>&1
gate_has "s1: file saved"     "$S1" 'saved /w/a'
gate_has "s1: sync wrote"     "$S1" 'sync: wrote [0-9]+ sectors'
gate_has "s1: clean exit"     "$S1" 'proc: pid 0 exited \(0\)'
gate_bad  "s1" "$S1"

echo "== session 2: persistence across reboot"
S2="$T/s2.log"
( sleep 8
  printf 'ls /w\n';          sleep 0.3
  printf 'cat /w/a\n';       sleep 0.3
  printf 'rm /w/a\n';        sleep 0.3
  printf 'rmdir /w\n';       sleep 0.3
  printf 'sync\n';           sleep 2.0
  printf 'exit\n'
) | timeout 21 ./tools/run.sh >"$S2" 2>&1
gate_has "s2: file survived reboot" "$S2" 'alpha data'
gate_has "s2: removal synced"       "$S2" 'sync: wrote [0-9]+ sectors'
gate_bad  "s2" "$S2"

echo "== session 3: signals + mask + jobs"
S3="$T/s3.log"
( sleep 8
  printf 'trap 15\n';        sleep 0.3
  printf 'kill 15\n';        sleep 0.5
  printf 'sigblock 15\n';    sleep 0.3
  printf 'kill 15\n';        sleep 0.5
  printf 'sigunblock 15\n';  sleep 0.5
  printf 'greet &\n';        sleep 1.0
  printf 'jobs\n';           sleep 1.0
  printf 'killchild 9\n';    sleep 2.0
  printf 'kill 2\n';         sleep 1.5
) | timeout 24 ./tools/run.sh >"$S3" 2>&1
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
( sleep 8
  printf 'ls /bin\n';        sleep 0.3
  printf 'cat /etc/motd\n';  sleep 0.3
  printf 'exit\n'
) | timeout 18 ./tools/run.sh --no-drive >"$S4" 2>&1
gate_has "s4: fallback engaged"  "$S4" 'no device in 32 MMIO slots'
gate_has "s4: fs served"         "$S4" 'Welcome to tihkali'
gate_has "s4: sh listed"         "$S4" '^sh'
gate_has "s4: clean exit"        "$S4" 'proc: pid 0 exited \(0\)'
gate_bad  "s4" "$S4"

echo "== session 5: Linux ABI personality"
S5="$T/s5.log"
( sleep 8
  printf 'linux-hello\n'
  sleep 2.0
  printf 'exit\n'
) | timeout 18 ./tools/run.sh >"$S5" 2>&1
gate_has "s5: linux binary ran"  "$S5" 'hello from linux/musl \(EL0 via Linux ABI\)'
gate_has "s5: exit code via wait4" "$S5" 'sh: linux-hello exited 42'
gate_has "s5: clean exit"         "$S5" 'proc: pid 0 exited \(0\)'
gate_bad  "s5" "$S5"

echo "== session 6: Raspberry Pi 3 (raspi3b, embedded initramfs)"
S6="$T/s6.log"
( sleep 8
  printf 'ls /bin\n';    sleep 0.6
  printf 'busybox sleep 0.5\n'; sleep 1.4
  printf 'greet\n';      sleep 1.5
  printf 'exit\n'
) | timeout 21 ./tools/run.sh --rpi >"$S6" 2>&1
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
( sleep 8
  printf 'linux-probe\n'
  sleep 3
  printf 'busybox echo hello-from-alpine\n'
  sleep 2
  printf 'busybox ls /bin\n'
  sleep 2
  printf 'busybox cat /etc/motd\n'
  sleep 2
  printf 'exit\n'
) | timeout 26 ./tools/run.sh >"$S7" 2>&1
gate_has "s7: probe all ok"          "$S7" 'linux-probe: all ok'
gate_has "s7: probe exited 0"        "$S7" 'sh: linux-probe exited 0'
gate_count "s7: busybox echo ran"    "$S7" 'hello-from-alpine' 2
gate_has "s7: busybox ls via getdents64" "$S7" 'linux-probe'
gate_has "s7: busybox cat read"      "$S7" 'Welcome to tihkali'
gate_has "s7: busybox exited 0"      "$S7" 'sh: busybox exited 0'
gate_bad  "s7" "$S7"

echo "== session 8: busybox ash (POSIX shell: script + pipeline + applets)"
S8="$T/s8.log"
( sleep 8
  printf 'busybox ash /etc/demo.sh\n'
  sleep 3
  printf 'busybox cat /etc/motd\n'
  sleep 2
  printf 'busybox ls /bin\n'
  sleep 2
  printf 'exit\n'
) | timeout 24 ./tools/run.sh >"$S8" 2>&1
gate_has "s8: ash ran demo script"      "$S8" 'hello-from-pipeline'
gate_has "s8: pipeline second line"     "$S8" '^done'
gate_has "s8: ash exited 0"             "$S8" 'sh: busybox exited 0'
gate_has "s8: file cat via sendfile"    "$S8" 'Welcome to tihkali'
gate_has "s8: applet symlink ls"        "$S8" 'linux-hello'
gate_count "s8: no ENOSYS noise"        "$S8" 'ENOSYS' 0
gate_bad  "s8" "$S8"

echo "== session 9: job control — interactive ash, ppoll line editing, Ctrl-C"
S9="$T/s9.log"
( sleep 8
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
) | timeout 26 ./tools/run.sh >"$S9" 2>&1
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
( sleep 8
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
) | timeout 24 ./tools/run.sh >"$S10" 2>&1
gate_has "s10: sync wrote"     "$S10" 'sync: wrote [0-9]+ sectors'
gate_count "s10: no ENOSYS"    "$S10" 'ENOSYS' 0
gate_count "s10: no bad syscalls from *at arms" "$S10" 'sh: busybox exited 1' 0
gate_has "s10: clean exit"     "$S10" 'proc: pid 0 exited \(0\)'
gate_bad  "s10" "$S10"

echo "== session 11: FS depth persistence across reboot (modes/mtime/rename/symlink)"
S11="$T/s11.log"
( sleep 8
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
) | timeout 24 ./tools/run.sh >"$S11" 2>&1
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

echo "== session 12: net smoke (virtio-net + slirp ARP/ICMP)"
S12="$T/s12.log"
( sleep 8; printf 'exit\n' ) | timeout 18 ./tools/run.sh >"$S12" 2>&1
gate_has   "s12: link up"        "$S12" 'net: link up, 10\.0\.2\.15/24 gw 10\.0\.2\.2 \(dhcp\)'
gate_has   "s12: arp resolved"   "$S12" 'net: arp 10\.0\.2\.2 -> ([0-9a-f]{2}:){5}[0-9a-f]{2}'
gate_has   "s12: icmp reply"     "$S12" 'net: icmp reply from 10\.0\.2\.2, .* rtt'
gate_count "s12: no ENOSYS"      "$S12" 'ENOSYS' 0
gate_has   "s12: clean exit"     "$S12" 'proc: pid 0 exited \(0\)'
gate_bad   "s12" "$S12"

echo "== session 13: TCP connect to host listener via SLIRP (N2)"
S13="$T/s13.log"
python3 -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 18080))
s.listen(1)
c, _ = s.accept()
c.recv(64)
c.sendall(b"tihkali-tcp-ok")
c.close()
s.close()
' >/dev/null 2>&1 &
SRV=$!
sleep 1
( sleep 5
  printf 'linux-tcp\n'; sleep 3
  printf 'exit\n'; sleep 1
) | timeout 26 ./tools/run.sh >"$S13" 2>&1
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null
gate_has   "s13: tcp all ok"   "$S13" 'tcp: all ok'
gate_has   "s13: probe exit 0" "$S13" 'sh: linux-tcp exited 0'
gate_count "s13: no ENOSYS"    "$S13" 'ENOSYS' 0
gate_has   "s13: clean exit"   "$S13" 'proc: pid 0 exited \(0\)'
gate_bad   "s13" "$S13"

echo "== session 14: busybox ping/wget + NetBSD-door nettest (N3)"
S14="$T/s14.log"
N3DIR=$(mktemp -d)
echo "tihkali-n3-ok" > "$N3DIR/n3.txt"
python3 -m http.server 18081 --bind 127.0.0.1 --directory "$N3DIR" >/dev/null 2>&1 &
HTTP=$!
sleep 1
( sleep 5
  printf 'busybox ping -c 3 10.0.2.2\n'; sleep 6
  printf 'busybox wget -O - http://10.0.2.2:18081/n3.txt\n'; sleep 4
  printf 'nettest\n'; sleep 4
  printf 'exit\n'; sleep 1
) | timeout 36 ./tools/run.sh >"$S14" 2>&1
kill "$HTTP" 2>/dev/null
wait "$HTTP" 2>/dev/null
rm -rf "$N3DIR"
gate_has   "s14: ping reply"  "$S14" '64 bytes from 10.0.2.2'
# A multi-packet ping only finishes if repeating SIGALRM reaches the
# process; -c 1 passed even when every alarm after the first was lost.
gate_count "s14: ping 3 replies" "$S14" '64 bytes from 10\.0\.2\.2' 3
gate_has   "s14: ping summary" "$S14" '3 packets transmitted, 3 packets received'
gate_has   "s14: wget body"   "$S14" 'tihkali-n3-ok'
gate_has   "s14: nettest ok"  "$S14" 'nettest: ok'
gate_count "s14: no ENOSYS"   "$S14" 'ENOSYS' 0
gate_has   "s14: clean exit"  "$S14" 'proc: pid 0 exited \(0\)'
gate_bad   "s14" "$S14"

echo "== session 15: TCP listen/accept — host connects to guest server (N4)"
S15="$T/s15.log"
S15H="$T/s15host.log"
python3 - "$S15H" <<'PY' &
import socket, time, sys
out = open(sys.argv[1], "w")
time.sleep(6)  # let the guest boot + start listening
try:
    s = socket.create_connection(("127.0.0.1", 18082), timeout=15)
    s.sendall(b"X")
    time.sleep(0.5)  # let the guest echo + FIN settle before the read
    got = s.recv(16)
    out.write(f"s15host: echo={got!r}\n")
    s.close()
except Exception as e:
    out.write(f"s15host: connect failed: {e}\n")
out.close()
PY
HOSTP=$!
( sleep 5
  printf 'netserver\n'; sleep 14
  printf '\n'; sleep 1
  printf 'exit\n'; sleep 4
) | timeout 51 ./tools/run.sh --hostfwd "tcp:127.0.0.1:18082-10.0.2.15:18082" >"$S15" 2>&1
wait "$HOSTP" 2>/dev/null
gate_has   "s15: accepted peer" "$S15" 'netserver: peer port'
gate_has   "s15: host echo"     "$S15H" "s15host: echo=b'X'"
gate_count "s15: no ENOSYS"     "$S15" 'ENOSYS' 0
gate_has   "s15: clean exit"    "$S15" 'proc: pid 0 exited \(0\)'
gate_bad   "s15" "$S15"

echo "== session 16: busybox HTTP client via SLIRP (N5 sendmsg/recvmsg)"
S16="$T/s16.log"
N5DIR=$(mktemp -d)
echo "tihkali-n5-ok" > "$N5DIR/n5.txt"
python3 -m http.server 18083 --bind 127.0.0.1 --directory "$N5DIR" >/dev/null 2>&1 &
HTTP=$!
sleep 1
( sleep 5
  printf 'wget -O - http://10.0.2.2:18083/n5.txt\n'; sleep 4
  printf 'exit\n'; sleep 1
) | timeout 46 ./tools/run.sh >"$S16" 2>&1
kill "$HTTP" 2>/dev/null
wait "$HTTP" 2>/dev/null
rm -rf "$N5DIR"
gate_has   "s16: wget body"   "$S16" 'tihkali-n5-ok'
gate_count "s16: no ENOSYS"   "$S16" 'ENOSYS' 0
gate_has   "s16: clean exit"  "$S16" 'proc: pid 0 exited \(0\)'
gate_bad   "s16" "$S16"

echo "== session 17: guest TCP sendmsg/recvmsg/shutdown probe (N5)"
S17="$T/s17.log"
S17H="$T/s17host.log"
python3 - "$S17H" <<'PY' &
import socket, time, sys
out = open(sys.argv[1], "w")
time.sleep(6)  # let the guest boot + start listening
try:
    s = socket.create_connection(("127.0.0.1", 18086), timeout=15)
    s.sendall(b"n5-msg")
    time.sleep(0.5)
    got = s.recv(16)
    out.write(f"s17host: echo={got!r}\n")
    s.close()
except Exception as e:
    out.write(f"s17host: connect failed: {e}\n")
out.close()
PY
HOSTP=$!
( sleep 5
  printf 'netsend\n'; sleep 10
  printf '\n'; sleep 1
  printf 'exit\n'; sleep 3
) | timeout 51 ./tools/run.sh --hostfwd "tcp:127.0.0.1:18086-10.0.2.15:18086" >"$S17" 2>&1
wait "$HOSTP" 2>/dev/null
gate_has   "s17: recvmsg echo" "$S17" 'netsend: recv=[0-9]+'
gate_has   "s17: probe exit 0" "$S17" 'sh: netsend exited 0'
gate_has   "s17: host echo"    "$S17H" "s17host: echo=b'n5-msg'"
gate_count "s17: no ENOSYS"    "$S17" 'ENOSYS' 0
gate_has   "s17: clean exit"   "$S17" 'proc: pid 0 exited \(0\)'
gate_bad   "s17" "$S17"

echo "== session 18: setsockopt/getsockopt SO_* options probe (N5c)"
S18="$T/s18.log"
( sleep 8
  printf '/bin/sockopt\n'; sleep 6
  printf 'sockopt\n'; sleep 6
  printf '/bin/nosuchfile\n'; sleep 2
  printf 'nosuchcmd\n'; sleep 2
  printf 'exit\n'; sleep 3
) | timeout 66 ./tools/run.sh >"$S18" 2>&1
# An absolute path must exec directly; it must not be re-prefixed to
# /bin//bin/<cmd> (which missed and exited 127). The bare name must
# resolve through $PATH to the same binary: two execs, not one.
gate_count "s18: exec twice"     "$S18" 'exec /bin/sockopt' 2
gate_has   "s18: missing abs 127" "$S18" 'sh: /bin/nosuchfile: not found'
gate_count "s18: missing bare 127" "$S18" 'sh: nosuchcmd: not found' 1
gate_has   "s18: SO_TYPE"        "$S18" 'so_type=1'
gate_has   "s18: SO_REUSEADDR"   "$S18" 'so_reuseaddr=1'
gate_has   "s18: SO_KEEPALIVE"   "$S18" 'so_keepalive=1'
gate_has   "s18: SO_BROADCAST"   "$S18" 'so_broadcast=1'
gate_has   "s18: SO_SNDBUF dflt" "$S18" 'so_sndbuf_def=[1-9][0-9]*'
gate_has   "s18: SO_SNDBUF set"  "$S18" 'so_sndbuf=16384'
gate_has   "s18: SO_RCVBUF dflt" "$S18" 'so_rcvbuf_def=[1-9][0-9]*'
gate_has   "s18: SO_RCVBUF set"  "$S18" 'so_rcvbuf=32768'
gate_has   "s18: SO_ERROR clear" "$S18" 'so_error=0'
gate_has   "s18: SO_ERROR latch" "$S18" 'so_error_after=[1-9][0-9]*'
gate_has   "s18: SO_ERROR cleard" "$S18" 'so_error_cleared=0'
gate_has   "s18: readonly EINVAL" "$S18" 'ro_errno=0'
gate_has   "s18: readonly msg"   "$S18" 'sockopt: readonly rejected'
gate_has   "s18: EBADF"          "$S18" 'sockopt: ebadf ok'
gate_has   "s18: probe ok"       "$S18" 'sockopt: ok'
gate_has   "s18: exit 0"         "$S18" 'sh: /bin/sockopt exited 0'
gate_count "s18: no EINVAL spam" "$S18" '\[linux\] EINVAL' 0
gate_count "s18: no ENOSYS"      "$S18" 'ENOSYS' 0
gate_has   "s18: clean exit"     "$S18" 'proc: pid 0 exited \(0\)'
gate_bad   "s18" "$S18"

echo "== session 19: in-kernel DNS resolver (smoltcp dns::Socket)"
S19="$T/s19.log"
( sleep 5
  printf 'dnsprobe\n'; sleep 8
  # musl's resolver (busybox ping/wget) is a separate path from
  # dnsprobe's in-kernel socket: it binds 0.0.0.0:0, opens the socket
  # SOCK_NONBLOCK, and reads replies with recvmsg. No -4: the kernel
  # strips AAAA records from replies, so busybox sees only the A record.
  printf 'ping -c 1 example.com\n'; sleep 9
  printf 'wget -q -O - http://example.com\n'; sleep 12
  printf 'exit\n'; sleep 6
) | timeout 52 ./tools/run.sh >"$S19" 2>&1
# The A record for example.com is a live CDN address, so gate the shape
# (four dotted octets in 1-255), not the exact value.
gate_has   "s19: A record"      "$S19" 'dns: example\.com = [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
gate_has   "s19: hosts file"    "$S19" 'dns: gateway = 10\.0\.2\.2'
gate_has   "s19: bogus rejected" "$S19" 'dns: bogus name rejected'
gate_has   "s19: probe ok"      "$S19" 'dnsprobe: ok'
gate_has   "s19: exit 0"        "$S19" 'sh: dnsprobe exited 0'
# musl resolved the name itself: ping prints the A record it looked up.
gate_has   "s19: musl resolved" "$S19" 'PING example\.com \([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)'
gate_has   "s19: musl ping ok"  "$S19" '1 packets transmitted, 1 packets received'
# wget over the same musl resolver: name -> A record -> TCP -> body.
gate_has   "s19: wget body"      "$S19" 'Example Domain'
gate_count "s19: no ENOSYS"     "$S19" 'ENOSYS' 0
gate_has   "s19: clean exit"    "$S19" 'proc: pid 0 exited \(0\)'
gate_bad   "s19" "$S19"

echo "== session 20: framebuffer (fw_cfg/ramfb) + user-space display server"
S20="$T/s20.log"
# The guest needs -device ramfb (run.sh adds it by default; NO_GUI=1 omits
# it). /bin/gui paints 120 frames of animation, so give it room beyond the
# 5 s first-input margin plus the animation itself.
( sleep 9
  printf 'gui\n'; sleep 14
  printf 'exit\n'; sleep 3
) | timeout 52 ./tools/run.sh >"$S20" 2>&1
gate_has   "s20: ramfb entry found"  "$S20" 'fb: fw_cfg etc/ramfb at selector 0x[0-9a-f]+'
gate_has   "s20: framebuffer mapped" "$S20" 'fb: framebuffer 640x480 xrgb8888 at 0x[0-9a-f]+'
gate_has   "s20: pixels written"     "$S20" 'fb: paint \+ readback ok'
gate_has   "s20: display ready"      "$S20" 'fb: display ready'
gate_has   "s20: wm geometry"        "$S20" 'gui: wm up fb=640x480'
gate_has   "s20: wm demo ok"         "$S20" 'gui: demo ok frames=120'
gate_has   "s20: wm exit 0"          "$S20" 'sh: gui exited 0'
gate_count "s20: no panic"           "$S20" 'gui: panic' 0
gate_count "s20: no ENOSYS"          "$S20" 'ENOSYS' 0
gate_has   "s20: clean exit"         "$S20" 'proc: pid 0 exited \(0\)'
gate_bad   "s20" "$S20"

echo "== session 21: NetBSD memory syscalls (mmap/mprotect/munmap)"
S21="$T/s21.log"
# NetBSD's mmap takes a PAD word at x5, so a Linux-ABI order would read
# the offset out of the pad -- /bin/memtest calls it the NetBSD way and
# fails if the kernel dispatched the Linux register layout.
( sleep 5
  printf 'memtest\n'; sleep 3
  printf 'exit\n'; sleep 3
) | timeout 24 ./tools/run.sh >"$S21" 2>&1
gate_has   "s21: mmap anon"        "$S21" 'memtest: ok   mmap anon'
gate_has   "s21: mmap aligned"     "$S21" 'memtest: ok   mmap page aligned'
gate_has   "s21: mmap writable"    "$S21" 'memtest: ok   mmap writable'
gate_has   "s21: mprotect none"    "$S21" 'memtest: ok   mprotect none'
gate_has   "s21: mprotect restore" "$S21" 'memtest: ok   mprotect restore'
gate_has   "s21: madvise"          "$S21" 'memtest: ok   madvise'
gate_has   "s21: msync"            "$S21" 'memtest: ok   msync'
gate_has   "s21: still writable"   "$S21" 'memtest: ok   still writable'
gate_has   "s21: second mmap"      "$S21" 'memtest: ok   second mmap'
gate_has   "s21: munmap"           "$S21" 'memtest: ok   munmap'
gate_has   "s21: munmap unaligned" "$S21" 'memtest: ok   munmap rejects unaligned'
gate_has   "s21: all ok"           "$S21" 'memtest: all ok'
gate_has   "s21: exit 0"           "$S21" 'sh: memtest exited 0'
gate_count "s21: no ENOSYS"        "$S21" 'ENOSYS' 0
gate_count "s21: no panic"         "$S21" 'panic' 0
gate_has   "s21: clean exit"       "$S21" 'proc: pid 0 exited \(0\)'
gate_bad   "s21" "$S21"

echo "== session 22: NetBSD metadata + time syscalls (stat/lseek/clock)"
S22="$T/s22.log"
# /bin/statprobe asserts on struct stat *values* (S_IFREG vs S_IFDIR, a
# real st_size, S_IFLNK from lstat), not on the calls returning 0. A
# Linux-shaped stat writer would pass the return-value checks and fail
# every field check.
( sleep 5
  printf 'statprobe\n'; sleep 4
  printf 'exit\n'; sleep 3
) | timeout 25 ./tools/run.sh >"$S22" 2>&1
gate_has   "s22: stat regular file"  "$S22" 'stat: ok   stat regular file'
gate_has   "s22: stat size"          "$S22" 'stat: ok   stat size is 4 octets'
gate_has   "s22: stat dir"           "$S22" 'stat: ok   stat dir is S_IFDIR'
gate_has   "s22: stat follows link"  "$S22" 'stat: ok   stat follows symlink'
gate_has   "s22: lstat S_IFLNK"      "$S22" 'stat: ok   lstat sees S_IFLNK'
gate_has   "s22: readlink target"    "$S22" 'stat: ok   readlink target'
gate_has   "s22: readlink EINVAL"    "$S22" 'stat: ok   readlink EINVAL on file'
gate_has   "s22: lseek end"          "$S22" 'stat: ok   lseek end matches size'
gate_has   "s22: read after seek"    "$S22" 'stat: ok   read after seek'
gate_has   "s22: access ENOENT"      "$S22" 'stat: ok   access missing ENOENT'
gate_has   "s22: getuid"             "$S22" 'stat: ok   getuid 0'
gate_has   "s22: clock realtime"     "$S22" 'stat: ok   realtime after 2023'
gate_has   "s22: gettimeofday"       "$S22" 'stat: ok   gettimeofday'
gate_has   "s22: nanosleep"          "$S22" 'stat: ok   nanosleep 0.05s'
gate_has   "s22: all ok"             "$S22" 'stat: all ok'
gate_has   "s22: exit 0"             "$S22" 'sh: statprobe exited 0'
gate_count "s22: no panic"           "$S22" 'panic' 0
gate_count "s22: no unknown syscall" "$S22" 'unknown syscall' 0
gate_has   "s22: clean exit"         "$S22" 'proc: pid 0 exited \(0\)'
gate_bad   "s22" "$S22"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: GREEN — all gates passed"
else
    echo "RESULT: RED — see FAIL lines above (logs in $T)"
fi
exit "$FAIL"
