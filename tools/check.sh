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
# PROT_* must be REAL, not advisory: the pages are demand-paged, so a
# prot discarded at mmap time yields a writable mapping. The enforcement
# check runs in a forked child because a successful write kills nothing --
# it proves the kernel simply allowed it, so the parent asserts the fault.
gate_has   "s21: prot_read read"   "$S21" 'memtest: ok   prot_read readable'
gate_has   "s21: prot_read enforced" "$S21" 'memtest: ok   prot_read enforced'
gate_has   "s21: prot_read munmap" "$S21" 'memtest: ok   prot_read munmap'
gate_has   "s21: prot_none refused" "$S21" 'memtest: ok   prot_none refused'
gate_has   "s21: bad prot EINVAL"  "$S21" 'memtest: ok   bad prot EINVAL'
# mprotect on a range nobody mapped walks no present PTE and would
# return success -- a change that never happened. ENOMEM is actionable.
gate_has   "s21: mprotect unmapped" "$S21" 'memtest: ok   mprotect unmapped ENOMEM'
# The record is split per mapping; a mapping starting ABOVE addr is the
# case a naive range-overlap test skips, leaving it unprotected.
gate_has   "s21: two maps"         "$S21" 'memtest: ok   two maps'
gate_has   "s21: mprotect across"  "$S21" 'memtest: ok   mprotect across two'
gate_has   "s21: second protected" "$S21" 'memtest: ok   second map protected'
gate_has   "s21: munmap region"    "$S21" 'memtest: ok   munmap region'
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

echo "== session 23: NetBSD vectored I/O (readv/writev)"
S23="$T/s23.log"
# /bin/iovtest writes four vectors (one empty) to stdout and reads a file
# back through four more. NetBSD numbers these 120/121, not Linux's 65/66,
# so a wrong number shows up as ENOSYS rather than as a wrong count.
( sleep 5
  printf 'iovtest\n'; sleep 4
  printf 'exit\n'; sleep 3
) | timeout 25 ./tools/run.sh >"$S23" 2>&1
# The 9 bytes the four writev vectors carry, in order and with no NUL.
gate_has   "s23: writev payload"     "$S23" '^abcdefghiiov: ok'
gate_has   "s23: writev sums"        "$S23" 'iov: ok   writev sums vectors'
gate_has   "s23: readv fills"        "$S23" 'iov: ok   readv fills vectors'
gate_has   "s23: readv vector 0"     "$S23" 'iov: ok   readv vector 0'
gate_has   "s23: readv skips 0-len"  "$S23" 'iov: ok   readv skipped 0-len vector'
gate_has   "s23: iovcnt 0"           "$S23" 'iov: ok   writev zero iovcnt'
gate_has   "s23: iovcnt EINVAL"      "$S23" 'iov: ok   writev EINVAL iovcnt'
gate_has   "s23: iovec EFAULT"       "$S23" 'iov: ok   writev EFAULT iovec'
gate_has   "s23: bad fd EBADF"       "$S23" 'iov: ok   writev EBADF'
gate_has   "s23: all ok"             "$S23" 'iov: all ok'
gate_has   "s23: exit 0"             "$S23" 'sh: iovtest exited 0'
gate_count "s23: no panic"           "$S23" 'panic' 0
gate_count "s23: no unknown syscall" "$S23" 'unknown syscall' 0
gate_has   "s23: clean exit"         "$S23" 'proc: pid 0 exited \(0\)'
gate_bad   "s23" "$S23"

echo "== session 24: NetBSD descriptor calls (dup/dup2/fcntl)"
S24="$T/s24.log"
# /bin/fdtest duplicates a descriptor (the copy must SHARE the file
# position), forces dup2 onto an exact number, and round-trips
# O_NONBLOCK through fcntl. NetBSD's O_NONBLOCK is 0x4, Linux's is 0x800;
# a kernel that stored the Linux bit would answer 0 here.
( sleep 5
  printf 'fdtest\n'; sleep 4
  printf 'exit\n'; sleep 3
) | timeout 25 ./tools/run.sh >"$S24" 2>&1
gate_has   "s24: open"              "$S24" 'fdctl: ok   open'
gate_has   "s24: dup new fd"        "$S24" 'fdctl: ok   dup returns new fd'
gate_has   "s24: dup shares pos"    "$S24" 'fdctl: ok   dup shares position'
gate_has   "s24: dup next bytes"    "$S24" 'fdctl: ok   dup reads next bytes'
gate_has   "s24: dup2 exact"        "$S24" 'fdctl: ok   dup2 exact fd'
gate_has   "s24: dup2 self noop"    "$S24" 'fdctl: ok   dup2 self is no-op'
gate_has   "s24: dup2 replaces"     "$S24" 'fdctl: ok   dup2 replaces target'
gate_has   "s24: F_DUPFD"           "$S24" 'fdctl: ok   F_DUPFD >= min'
gate_has   "s24: F_DUPFD_CLOEXEC"   "$S24" 'fdctl: ok   F_DUPFD_CLOEXEC'
gate_has   "s24: F_SETFL"           "$S24" 'fdctl: ok   F_SETFL accepted'
gate_has   "s24: F_GETFL nonblock"  "$S24" 'fdctl: ok   F_GETFL NetBSD nonblock'
gate_has   "s24: no Linux bit"      "$S24" 'fdctl: ok   F_GETFL no Linux bit'
gate_has   "s24: F_GETFL clears"    "$S24" 'fdctl: ok   F_GETFL clears'
gate_has   "s24: unknown EINVAL"    "$S24" 'fdctl: ok   unknown cmd EINVAL'
gate_has   "s24: fcntl EBADF"       "$S24" 'fdctl: ok   fcntl EBADF'
gate_has   "s24: all ok"            "$S24" 'fdctl: all ok'
gate_has   "s24: exit 0"            "$S24" 'sh: fdtest exited 0'
gate_count "s24: no panic"          "$S24" 'panic' 0
gate_count "s24: no unknown syscall" "$S24" 'unknown syscall' 0
gate_has   "s24: clean exit"        "$S24" 'proc: pid 0 exited \(0\)'
gate_bad   "s24" "$S24"

echo "== session 25: NetBSD path calls (getcwd/chdir/rename/chmod)"
S25="$T/s25.log"
# These four interact: chdir moves the cwd, and getcwd/stat/rename
# either report it or resolve relative names against it. A getcwd that
# ignored chdir, or a rename that resolved against "/", passes in
# isolation and fails here.
( sleep 5
  printf 'pathtest\n'; sleep 5
  printf 'exit\n'; sleep 3
) | timeout 28 ./tools/run.sh >"$S25" 2>&1
gate_has   "s25: getcwd is /"       "$S25" 'pathctl: ok   getcwd is /'
gate_has   "s25: getcwd NUL len"    "$S25" 'pathctl: ok   getcwd len has NUL'
gate_has   "s25: getcwd ERANGE"     "$S25" 'pathctl: ok   getcwd ERANGE'
gate_has   "s25: getcwd follows"    "$S25" 'pathctl: ok   getcwd tracks chdir'
gate_has   "s25: relative stat"     "$S25" 'pathctl: ok   relative stat uses cwd'
gate_has   "s25: relative tracks"   "$S25" 'pathctl: ok   relative stat follows cwd'
gate_has   "s25: .. normalizes"     "$S25" 'pathctl: ok   chdir normalizes ..'
gate_has   "s25: clamps at root"    "$S25" 'pathctl: ok   chdir clamps at root'
gate_has   "s25: chdir ENOTDIR"     "$S25" 'pathctl: ok   chdir ENOTDIR'
gate_has   "s25: chmod in stat"     "$S25" 'pathctl: ok   chmod visible in stat'
gate_has   "s25: chmod restored"    "$S25" 'pathctl: ok   chmod restored'
gate_has   "s25: rename relative"   "$S25" 'pathctl: ok   rename relative'
gate_has   "s25: rename moved it"   "$S25" 'pathctl: ok   old name gone'
gate_has   "s25: rename ENOENT"     "$S25" 'pathctl: ok   rename ENOENT'
gate_has   "s25: all ok"            "$S25" 'pathctl: all ok'
gate_has   "s25: exit 0"            "$S25" 'sh: pathtest exited 0'
gate_count "s25: no panic"          "$S25" 'panic' 0
gate_count "s25: no unknown syscall" "$S25" 'unknown syscall' 0
gate_has   "s25: clean exit"        "$S25" 'proc: pid 0 exited \(0\)'
gate_bad   "s25" "$S25"

echo "== session 26: NetBSD socket identity (getpeername/getsockname)"
S26="$T/s26.log"
# The sockaddr checks read the BYTES back, not the return code: NetBSD
# stores sa_len and sa_family as u8 with the port big-endian after them,
# so a Linux-shaped writer returns 0 here and still fails every field.
( sleep 5
  printf 'sockidtest\n'; sleep 5
  printf 'exit\n'; sleep 3
) | timeout 28 ./tools/run.sh >"$S26" 2>&1
gate_has   "s26: unbound succeeds"   "$S26" 'sockid: ok   getsockname unbound ok'
gate_has   "s26: sa_len is u8"       "$S26" 'sockid: ok   getsockname sa_len'
gate_has   "s26: family is u8"       "$S26" 'sockid: ok   getsockname family u8'
gate_has   "s26: unbound port 0"     "$S26" 'sockid: ok   getsockname port 0'
gate_has   "s26: wildcard"           "$S26" 'sockid: ok   getsockname wildcard'
gate_has   "s26: writes addrlen"     "$S26" 'sockid: ok   getsockname wrote len'
gate_has   "s26: ENOTCONN"           "$S26" 'sockid: ok   getpeername ENOTCONN'
gate_has   "s26: bound port"         "$S26" 'sockid: ok   getsockname bound port'
gate_has   "s26: real iface ip"      "$S26" 'sockid: ok   getsockname real ip'
gate_has   "s26: udp ephemeral"      "$S26" 'sockid: ok   udp ephemeral nonzero'
gate_has   "s26: socketpair refusal" "$S26" 'sockid: ok   socketpair EOPNOTSUPP'
gate_has   "s26: AF_UNIX refusal"    "$S26" 'sockid: ok   socketpair AF_UNIX too'
gate_has   "s26: all ok"             "$S26" 'sockid: all ok'
gate_has   "s26: exit 0"             "$S26" 'sh: sockidtest exited 0'
gate_count "s26: no panic"           "$S26" 'panic' 0
gate_count "s26: no unknown syscall" "$S26" 'unknown syscall' 0
gate_has   "s26: clean exit"         "$S26" 'proc: pid 0 exited \(0\)'
gate_bad   "s26" "$S26"

echo "== session 27: NetBSD kqueue/kevent (event interface)"
S27="$T/s27.log"
# The struct-offset checks matter more than the behavioural ones here: a
# kevent layout that is wrong in any field still returns the right COUNT for
# a readiness query, so a count-only gate would pass a completely broken
# reader. `returned udata` is the one that proves the offsets, because it
# reads a caller-supplied value back out of kernel-written memory.
( sleep 5
  printf 'kqtest\n'; sleep 28
  printf 'exit\n'; sleep 3
) | timeout 55 ./tools/run.sh >"$S27" 2>&1
gate_has   "s27: offset ident"    "$S27" 'kq: ok    offset ident'
gate_has   "s27: offset filter"   "$S27" 'kq: ok    offset filter'
gate_has   "s27: offset flags"    "$S27" 'kq: ok    offset flags'
gate_has   "s27: offset fflags"   "$S27" 'kq: ok    offset fflags'
gate_has   "s27: offset data"     "$S27" 'kq: ok    offset data'
gate_has   "s27: offset udata"    "$S27" 'kq: ok    offset udata'
gate_has   "s27: sizeof kevent"   "$S27" 'kq: ok    sizeof kevent'
gate_has   "s27: kqueue returns"  "$S27" 'kq: ok    kqueue'
gate_has   "s27: second kqueue"   "$S27" 'kq: ok    second kqueue'
gate_has   "s27: distinct fds"    "$S27" 'kq: ok    kqueue fds differ'
gate_has   "s27: add fires"       "$S27" 'kq: ok    add read fires'
gate_has   "s27: ident roundtrip" "$S27" 'kq: ok    returned ident'
gate_has   "s27: filter roundtrip" "$S27" 'kq: ok    returned filter'
gate_has   "s27: udata roundtrip" "$S27" 'kq: ok    returned udata'
gate_has   "s27: data is count"   "$S27" 'kq: ok    returned data is 1'
gate_has   "s27: changelist only" "$S27" 'kq: ok    changelist only returns 0'
gate_has   "s27: state persists"  "$S27" 'kq: ok    two events harvested'
gate_has   "s27: both filters"    "$S27" 'kq: ok    write event present'
gate_has   "s27: delete"          "$S27" 'kq: ok    delete returns 0'
gate_has   "s27: survivor"        "$S27" 'kq: ok    survivor is read'
gate_has   "s27: double del ENOENT" "$S27" 'kq: ok    double delete ENOENT'
gate_has   "s27: disable"         "$S27" 'kq: ok    disabled reports nothing'
gate_has   "s27: enable"          "$S27" 'kq: ok    re-enabled fires'
gate_has   "s27: oneshot once"    "$S27" 'kq: ok    oneshot fires once'
gate_has   "s27: oneshot consumed" "$S27" 'kq: ok    oneshot then silent'
gate_has   "s27: bad fd EBADF"    "$S27" 'kq: ok    bad fd EBADF'
gate_has   "s27: zero timespec"   "$S27" 'kq: ok    zero timeout polls'
gate_has   "s27: vnode ENOENT"    "$S27" 'kq: ok    vnode add on missing ENOENT'
gate_has   "s27: vnode add"       "$S27" 'kq: ok    vnode add succeeds'
gate_has   "s27: silent untouched" "$S27" 'kq: ok    vnode silent when untouched'
gate_has   "s27: fires on write"  "$S27" 'kq: ok    vnode fires on write'
gate_has   "s27: vnode filter"    "$S27" 'kq: ok    vnode filter is VNODE'
gate_has   "s27: vnode udata"     "$S27" 'kq: ok    vnode udata roundtrips'
gate_has   "s27: fflags WRITE"    "$S27" 'kq: ok    vnode fflags has WRITE'
gate_has   "s27: edge preserving" "$S27" 'kq: ok    vnode not level-triggered'
gate_has   "s27: fires on extend" "$S27" 'kq: ok    vnode fires on extend'
gate_has   "s27: NOTE_EXTEND"     "$S27" 'kq: ok    extend sets NOTE_EXTEND'
gate_has   "s27: ffands set"      "$S27" 'kq: ok    vnode fflags set'
gate_has   "s27: narrowed ignores" "$S27" 'kq: ok    narrowed ignores write'
gate_has   "s27: narrowed pending" "$S27" 'kq: ok    narrowed still silent'
gate_has   "s27: pending survives" "$S27" 'kq: ok    pending note survives narrowing'
gate_has   "s27: recovered WRITE" "$S27" 'kq: ok    recovered note is WRITE'
gate_has   "s27: ffor matches"    "$S27" 'kq: ok    ffor matches write'
gate_has   "s27: ffor selective"  "$S27" 'kq: ok    ffor delete ignores write'
gate_has   "s27: fires on delete" "$S27" 'kq: ok    vnode fires on delete'
gate_has   "s27: NOTE_DELETE"     "$S27" 'kq: ok    delete sets NOTE_DELETE'
gate_has   "s27: delete ENOENT"   "$S27" 'kq: ok    vnode delete missing ENOENT'
# EVFILT_PROC gates. The two that matter most are `exec watch child ok`
# and `proc fires on exec` together: a registration list held in a global
# instead of per-process passes every filter-local check and loses the
# parent's watchers the moment ANY child execs. `proc gone is silent` is
# the other: it proves the registration was not silently dropped after its
# first event.
gate_has   "s27: proc pid known"  "$S27" 'kq: ok    proc pid known'
gate_has   "s27: proc ppid known" "$S27" 'kq: ok    proc ppid known'
gate_has   "s27: proc ESRCH"      "$S27" 'kq: ok    proc missing ESRCH'
gate_has   "s27: watch self"      "$S27" 'kq: ok    proc watch self'
gate_has   "s27: watch self fork" "$S27" 'kq: ok    proc watch self fork'
gate_has   "s27: fires on fork"   "$S27" 'kq: ok    proc fires on fork'
gate_has   "s27: fork filter"     "$S27" 'kq: ok    fork filter is PROC'
gate_has   "s27: fork fflags"     "$S27" 'kq: ok    fork fflags'
gate_has   "s27: fork udata"      "$S27" 'kq: ok    fork udata'
gate_has   "s27: fork ident"      "$S27" 'kq: ok    fork ident is me'
gate_has   "s27: fork data child" "$S27" 'kq: ok    fork data is child'
gate_has   "s27: not level-trig"  "$S27" 'kq: ok    proc not level-triggered'
gate_has   "s27: narrow set"      "$S27" 'kq: ok    proc narrow set'
gate_has   "s27: narrowed silent" "$S27" 'kq: ok    narrowed proc ignores fork'
gate_has   "s27: proc widen"      "$S27" 'kq: ok    proc widen'
gate_has   "s27: recovered FORK"  "$S27" 'kq: ok    recovered note is FORK'
gate_has   "s27: proc disable"    "$S27" 'kq: ok    proc disable'
gate_has   "s27: disabled silent" "$S27" 'kq: ok    disabled proc silent'
gate_has   "s27: proc enable"     "$S27" 'kq: ok    proc enable'
gate_has   "s27: disabled recovers" "$S27" 'kq: ok    disabled proc recovers'
gate_has   "s27: watch exec"      "$S27" 'kq: ok    proc watch exec'
gate_has   "s27: exec watch ok"   "$S27" 'kq: ok    exec watch child ok'
gate_has   "s27: fires on exec"   "$S27" 'kq: ok    proc fires on exec'
gate_has   "s27: exec fflags"     "$S27" 'kq: ok    exec fflags'
gate_has   "s27: exec udata"      "$S27" 'kq: ok    exec udata'
gate_has   "s27: exec ident"      "$S27" 'kq: ok    exec ident is child'
gate_has   "s27: proc delete"     "$S27" 'kq: ok    proc delete'
gate_has   "s27: proc del ENOENT" "$S27" 'kq: ok    proc double delete ENOENT'
gate_has   "s27: proc gone quiet" "$S27" 'kq: ok    proc gone is silent'
# EVFILT_SIGNAL gates. The filter-number ones matter as much as the
# behavioural ones: NetBSD numbers AIO=2, VNODE=3, PROC=4, SIGNAL=5, so
# skipping AIO silently renumbers every later filter and a probe using the
# wrong constants still passes every behavioural check. `knote suppresses
# SIGUSR1 death` is the one that needs a real kernel fix -- without it the
# watched signal takes its default action and kills the watcher.
gate_has   "s27: signal 0 EINVAL" "$S27" 'kq: ok    signal 0 EINVAL'
gate_has   "s27: signal oob EINVAL" "$S27" 'kq: ok    signal oob EINVAL'
gate_has   "s27: signal add"    "$S27" 'kq: ok    signal add'
gate_has   "s27: signal silent" "$S27" 'kq: ok    signal silent until raised'
gate_has   "s27: self raise"    "$S27" 'kq: ok    self raise ok'
gate_has   "s27: signal fires"  "$S27" 'kq: ok    signal fires'
gate_has   "s27: signal filter" "$S27" 'kq: ok    signal filter is SIGNAL'
gate_has   "s27: signal ident"  "$S27" 'kq: ok    signal ident roundtrips'
gate_has   "s27: signal udata"  "$S27" 'kq: ok    signal udata'
gate_has   "s27: signal data"   "$S27" 'kq: ok    signal data is sig'
gate_has   "s27: not level-trig signal" "$S27" 'kq: ok    signal not level-triggered'
gate_has   "s27: signal 17 add" "$S27" 'kq: ok    signal 17 add'
gate_has   "s27: sig10 fires"   "$S27" 'kq: ok    sig10 still fires'
gate_has   "s27: sig17 isolated" "$S27" 'kq: ok    sig17 not woken by 10'
gate_has   "s27: signal disable" "$S27" 'kq: ok    signal disable'
gate_has   "s27: disabled silent" "$S27" 'kq: ok    disabled signal silent'
gate_has   "s27: signal enable" "$S27" 'kq: ok    signal enable'
gate_has   "s27: signal recovers" "$S27" 'kq: ok    disabled signal recovers'
gate_has   "s27: recovered 17"  "$S27" 'kq: ok    recovered data is 17'
gate_has   "s27: knote saves USR1" "$S27" 'kq: ok    knote suppresses SIGUSR1 death'
gate_has   "s27: aio ENOSYS"    "$S27" 'kq: ok    aio ENOSYS'
gate_has   "s27: signal delete" "$S27" 'kq: ok    signal delete'
gate_has   "s27: signal del ENOENT" "$S27" 'kq: ok    signal delete ENOENT'
# EVFILT_TIMER gates. The three that carry the weight:
# `timer ends a long park` (an EVFILT_TIMER is a WAKEUP SOURCE -- kevent
# must return when it expires rather than at the caller's timeout),
# `slot reported` (a slot-keyed registration the caller cannot name is
# unusable, so the kernel writes the assigned slot back into `data`), and
# `nsec clamps to one tick` (a sub-resolution period is clamped, not
# refused -- a timer that is under-ticked still has to be able to fire).
gate_has   "s27: timer zero EINVAL" "$S27" 'kq: ok    timer zero EINVAL'
gate_has   "s27: timer negative EINVAL" "$S27" 'kq: ok    timer negative EINVAL'
gate_has   "s27: timer bad unit EINVAL" "$S27" 'kq: ok    timer bad unit EINVAL'
gate_has   "s27: timer stray flag"    "$S27" 'kq: ok    timer stray flag EINVAL'
gate_has   "s27: abstime refused"     "$S27" 'kq: ok    abstime refused'
gate_has   "s27: timer add"           "$S27" 'kq: ok    timer add'
gate_has   "s27: slot reported"       "$S27" 'kq: ok    slot reported'
gate_has   "s27: timer not ready"     "$S27" 'kq: ok    timer not ready yet'
gate_has   "s27: timer add fast"      "$S27" 'kq: ok    timer add fast'
gate_has   "s27: timer add seconds"   "$S27" 'kq: ok    timer add seconds'
gate_has   "s27: slots differ"        "$S27" 'kq: ok    slots differ'
gate_has   "s27: timer ends a park"   "$S27" 'kq: ok    timer ends a long park'
gate_has   "s27: timer filter"        "$S27" 'kq: ok    timer filter is TIMER'
gate_has   "s27: fast timer delivered" "$S27" 'kq: ok    fast timer delivered'
gate_has   "s27: timer data nonzero"  "$S27" 'kq: ok    timer data nonzero'
gate_has   "s27: unfired withheld"    "$S27" 'kq: ok    unfired timers withheld'
gate_has   "s27: oneshot consumed"    "$S27" 'kq: ok    oneshot timer consumed'
gate_has   "s27: timer delete"        "$S27" 'kq: ok    timer delete'
gate_has   "s27: timer del twice"     "$S27" 'kq: ok    timer double delete ENOENT'
gate_has   "s27: timer del ENOENT"    "$S27" 'kq: ok    timer delete ENOENT'
gate_has   "s27: nsec accepted"       "$S27" 'kq: ok    nsec accepted'
gate_has   "s27: nsec clamps"         "$S27" 'kq: ok    nsec clamps to one tick'
gate_has   "s27: timer add usec"      "$S27" 'kq: ok    timer add usec'
gate_has   "s27: usec fires"          "$S27" 'kq: ok    usec fires fast'
gate_has   "s27: timer add repeat"    "$S27" 'kq: ok    timer add repeat'
gate_has   "s27: repeat not due"      "$S27" 'kq: ok    repeat not due yet'
gate_has   "s27: repeating fires"     "$S27" 'kq: ok    repeating timer fires'
gate_has   "s27: repeating EV_CLEAR"  "$S27" 'kq: ok    repeating timer is EV_CLEAR'
gate_has   "s27: repeat delete"       "$S27" 'kq: ok    repeat delete'
# The last four filters. EVFILT_EMPTY is attached to nothing and is always
# ready. EVFILT_USER fires when the CALLER sets NOTE_TRIGGER -- a userspace
# wakeup with no kernel object behind it -- and `user masks trigger bit` is
# the one that matters: NOTE_TRIGGER lives above NOTE_FFLAGSMASK, so a
# kernel that stored the request verbatim would echo it back as state.
# AIO and FS are ENOSYS, not EINVAL: the filter NUMBERS are valid (AIO has
# NULL filter ops even upstream), it is the objects behind them this OS
# lacks. `unknown filter EINVAL` proves the two are distinguishable.
gate_has   "s27: empty add"       "$S27" 'kq: ok    empty add'
gate_has   "s27: empty always ready" "$S27" 'kq: ok    empty always ready'
gate_has   "s27: empty filter"     "$S27" 'kq: ok    empty filter is EMPTY'
gate_has   "s27: empty udata"      "$S27" 'kq: ok    empty udata'
gate_has   "s27: empty delete"     "$S27" 'kq: ok    empty delete'
gate_has   "s27: empty del ENOENT" "$S27" 'kq: ok    empty del ENOENT'
gate_has   "s27: user add"         "$S27" 'kq: ok    user add'
gate_has   "s27: user no trigger"  "$S27" 'kq: ok    user silent without trigger'
gate_has   "s27: user trigger"     "$S27" 'kq: ok    user trigger'
gate_has   "s27: user fires"       "$S27" 'kq: ok    user fires on trigger'
gate_has   "s27: user filter"      "$S27" 'kq: ok    user filter is USER'
gate_has   "s27: user stored"      "$S27" 'kq: ok    user reports stored'
gate_has   "s27: trigger masked"   "$S27" 'kq: ok    user masks trigger bit'
gate_has   "s27: top bits FFNOP"   "$S27" 'kq: ok    user top bits are FFNOP'
gate_has   "s27: user udata"       "$S27" 'kq: ok    user udata'
gate_has   "s27: user ffor"        "$S27" 'kq: ok    user ffor'
gate_has   "s27: user ffor widen"  "$S27" 'kq: ok    user ffor widened'
gate_has   "s27: user ffand"       "$S27" 'kq: ok    user ffand'
gate_has   "s27: user ffand narrow" "$S27" 'kq: ok    user ffand narrowed'
gate_has   "s27: user delete"      "$S27" 'kq: ok    user delete'
gate_has   "s27: aio ENOSYS again" "$S27" 'kq: ok    aio ENOSYS again'
gate_has   "s27: fs ENOSYS"        "$S27" 'kq: ok    fs ENOSYS'
gate_has   "s27: unknown EINVAL"   "$S27" 'kq: ok    unknown filter EINVAL'
gate_has   "s27: all ok"          "$S27" 'kq: all ok'
gate_has   "s27: exit 0"          "$S27" 'sh: kqtest exited 0'
gate_count "s27: no panic"        "$S27" 'panic' 0
gate_count "s27: no unknown syscall" "$S27" 'unknown syscall' 0
gate_has   "s27: clean exit"      "$S27" 'proc: pid 0 exited \(0\)'
gate_bad   "s27" "$S27"

echo "== session 28: NetBSD identity + length (getppid/uname/ftruncate)"
S28="$T/s28.log"
# uname is the substance: NetBSD's struct utsname is 1280 bytes of five
# 256-byte fields, not Linux's 390. A Linux-shaped writer returns 0 and
# still leaves every field at the wrong offset, so these gates read the
# bytes. `field tails zeroed` catches a writer that stores only the string
# and leaves the rest of each 256-byte field as stack garbage.
( sleep 5
  printf 'idtest\n'; sleep 6
  printf 'exit\n'; sleep 3
) | timeout 29 ./tools/run.sh >"$S28" 2>&1
gate_has   "s28: ppid not self"   "$S28" 'idt: ok   ppid differs from pid'
gate_has   "s28: ppid sane"       "$S28" 'idt: ok   ppid sane'
gate_has   "s28: ppid stable"     "$S28" 'idt: ok   ppid is stable'
gate_has   "s28: uname succeeds"  "$S28" 'idt: ok   uname succeeds'
gate_has   "s28: sysname"         "$S28" 'idt: ok   sysname is NetBSD'
gate_has   "s28: nodename"        "$S28" 'idt: ok   nodename'
gate_has   "s28: release"         "$S28" 'idt: ok   release'
gate_has   "s28: machine"         "$S28" 'idt: ok   machine is aarch64'
gate_has   "s28: all terminated"  "$S28" 'idt: ok   all fields terminated'
gate_has   "s28: sysname len 6"   "$S28" 'idt: ok   sysname len 6'
gate_has   "s28: machine len 7"   "$S28" 'idt: ok   machine len 7'
gate_has   "s28: field tails zero" "$S28" 'idt: ok   field tails zeroed'
gate_has   "s28: not Linux"       "$S28" 'idt: ok   not Linux'
gate_has   "s28: version present" "$S28" 'idt: ok   version present'
gate_has   "s28: shrink"          "$S28" 'idt: ok   ftruncate to 4'
gate_has   "s28: size after shrink" "$S28" 'idt: ok   size after shrink'
gate_has   "s28: extend"          "$S28" 'idt: ok   ftruncate to 12'
gate_has   "s28: size after extend" "$S28" 'idt: ok   size after extend'
gate_has   "s28: zero len"        "$S28" 'idt: ok   size zeroed'
gate_has   "s28: read after zero" "$S28" 'idt: ok   read after zero'
gate_has   "s28: zero-fill"       "$S28" 'idt: ok   extending zeroes'
gate_has   "s28: ro refused"      "$S28" 'idt: ok   ftruncate ro refused'
gate_has   "s28: badfd EBADF"     "$S28" 'idt: ok   ftruncate badfd EBADF'
gate_has   "s28: truncate path"   "$S28" 'idt: ok   truncate path to 3'
gate_has   "s28: truncate size"   "$S28" 'idt: ok   size after truncate'
gate_has   "s28: truncate ENOENT" "$S28" 'idt: ok   truncate missing ENOENT'
gate_has   "s28: truncate EISDIR" "$S28" 'idt: ok   truncate dir EISDIR'
gate_has   "s28: cleanup"         "$S28" 'idt: ok   unlink scratch'
gate_has   "s28: all ok"          "$S28" 'idt: all ok'
gate_has   "s28: exit 0"          "$S28" 'sh: idtest exited 0'
gate_count "s28: no panic"        "$S28" 'panic' 0
gate_count "s28: no unknown syscall" "$S28" 'unknown syscall' 0
gate_has   "s28: clean exit"      "$S28" 'proc: pid 0 exited \(0\)'
gate_bad   "s28" "$S28"

echo "== session 29: NetBSD ioctl (tty request encoding)"
S29="$T/s29.log"
# The substance is the ENCODING. NetBSD's TIOCGWINSZ is 0x80087468 and
# Linux's is 0x5413 -- same name, same 't' group, same param size. The
# Linux-request gates are the half that matters: a kernel which merely ADDED
# the NetBSD table would pass every positive check while answering Linux
# numbers too, and would have no boundary between the two personalities.
( sleep 5
  printf 'ioctltest\n'; sleep 6
  printf 'exit\n'; sleep 3
) | timeout 29 ./tools/run.sh >"$S29" 2>&1
gate_has   "s29: gwinsz"          "$S29" 'io: ok   gwinsz succeeds'
gate_has   "s29: winsz rows"      "$S29" 'io: ok   winsz rows'
gate_has   "s29: winsz cols"      "$S29" 'io: ok   winsz cols'
gate_has   "s29: swinsz accepted" "$S29" 'io: ok   swinsz accepted'
gate_has   "s29: winsz unchanged" "$S29" 'io: ok   winsz unchanged'
gate_has   "s29: geta"            "$S29" 'io: ok   geta succeeds'
gate_has   "s29: NetBSD ICANON"   "$S29" 'io: ok   lflag has ICANON'
gate_has   "s29: NetBSD ECHO"     "$S29" 'io: ok   lflag has ECHO'
gate_has   "s29: not Linux ICANON" "$S29" 'io: ok   lflag not Linux ICANON'
gate_has   "s29: not Linux ECHO"  "$S29" 'io: ok   lflag not Linux ECHO'
gate_has   "s29: byte 43 written" "$S29" 'io: ok   byte 43 written'
gate_has   "s29: speeds match"    "$S29" 'io: ok   speeds match'
gate_has   "s29: seta accepted"   "$S29" 'io: ok   seta accepted'
gate_has   "s29: glined N_TTY"    "$S29" 'io: ok   glined is N_TTY'
gate_has   "s29: gpgrp succeeds"  "$S29" 'io: ok   gpgrp succeeds'
gate_has   "s29: spgrp roundtrip" "$S29" 'io: ok   gpgrp roundtrips'
gate_has   "s29: spgrp neg EINVAL" "$S29" 'io: ok   spgrp rejects negative'
gate_has   "s29: EFAULT on ptr"   "$S29" 'io: ok   gwinsz bad ptr EFAULT'
gate_has   "s29: EBADF on fd"     "$S29" 'io: ok   bad fd EBADF'
gate_has   "s29: LNX TCGETS"      "$S29" 'io: ok   linux TCGETS refused'
gate_has   "s29: LNX TCSETS"      "$S29" 'io: ok   linux TCSETS refused'
gate_has   "s29: LNX GWINSZ"      "$S29" 'io: ok   linux GWINSZ refused'
gate_has   "s29: LNX GPGRP"       "$S29" 'io: ok   linux GPGRP refused'
gate_has   "s29: LNX SPGRP"       "$S29" 'io: ok   linux SPGRP refused'
gate_has   "s29: refused wrote none" "$S29" 'io: ok   refused write nothing'
gate_has   "s29: other group"     "$S29" 'io: ok   other group refused'
gate_has   "s29: nonsense"        "$S29" 'io: ok   nonsense refused'
gate_has   "s29: sti refused"     "$S29" 'io: ok   sti refused'
gate_has   "s29: all ok"          "$S29" 'io: all ok'
gate_has   "s29: exit 0"          "$S29" 'sh: ioctltest exited 0'
gate_count "s29: no panic"        "$S29" 'panic' 0
gate_count "s29: no unknown syscall" "$S29" 'unknown syscall' 0
gate_has   "s29: clean exit"      "$S29" 'proc: pid 0 exited \(0\)'
gate_bad   "s29" "$S29"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: GREEN — all gates passed"
else
    echo "RESULT: RED — see FAIL lines above (logs in $T)"
fi
exit "$FAIL"
