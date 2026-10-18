# tihkali — agent instructions

Nano BSD-style OS in Rust (+asm): QEMU virt aarch64 + Raspberry Pi 3, NetBSD
syscall ABI with a Linux-ABI personality, COW paging, virtio-blk initramfs,
signals, interactive shell. Single core, no MMU user/kernel VA split (user
space lives at VA 4 GiB, kernel identity-maps all RAM in every address space).

## The one rule

`./tools/check.sh` must exit 0 before calling anything done (0-warning build
+ 20 scripted QEMU sessions / 150 gates; logs land in
`/tmp/tihkali-check/*.log`). A
warning is a failure. Sessions use scripted stdin:

```sh
(sleep 5; printf 'ls\n'; sleep 0.5; printf 'exit\n') | timeout 15 ./tools/run.sh
```

First input must start after **5 s**: run.sh runs `cargo build` first, and a
rebuild (triggered by `sync` rewriting target/initramfs.img in a previous
session) takes ~1.5 s on top of boot — anything earlier races the UART init
and drops the first byte (symptom: `trap` → `rap`). Mid-session sleeps can
stay short.

The margin was **3 s → 5 s** because 3 s proved flaky on a loaded host: with
4 QEMU sessions contending, s3 lost its first byte and reported `rap 15`, and
s17's hostfwd exchange timed out (`s17host: echo=b''`). Each session's
`timeout` is now **3 s larger** than before so the extra margin is paid for,
not stolen from the script's own runtime. Verify the headroom still holds
after editing a session's sleeps:

```sh
# sum each session's host sleeps vs its timeout; s9's `printf 'sleep 100'`
# is a guest command and must not be counted
python3 - <<'PY'
import re
src = open('tools/check.sh').read()
for b in re.split(r'\necho "== session ', src)[1:]:
    to = re.search(r'timeout (\d+) \./tools/run\.sh', b)
    tot = sum(float(x) for x in re.findall(r"sleep ([0-9.]+)", b[:to.start()]))
    print(b.split('"')[0].split(':')[0], tot, to.group(1))
PY
```

Sessions run **sequentially**; running several `run.sh` at once fails with
`Failed to get "write" lock` on `target/initramfs.img` and is not a valid
stress test of the margin.

Two ways to poison a suite run, both of which look like real regressions:

- **A QEMU that survives its session** keeps the initramfs lock, so every
  *later* session dies instantly with `Failed to get "write" lock` and all
  its gates fail. `timeout` sends SIGTERM, which QEMU can ignore; kill any
  leftover by **numeric PID** (`ps -C qemu-system-aarch64 -o pid=`), never
  `pkill -f` — the pattern matches the invoking shell and hangs it.
- **Orphaned host helpers.** s13–s17 background a `python3 -m http.server` or
  a TCP listener. If the suite is interrupted those survive holding ports
  18081/18083/18086, and the next run's s16/s17 fail on `Connection refused`
  with an empty log. Check `ps -eo pid,args | grep "[h]ttp.server 180"` before
  trusting a red run.
- **Never rebuild while the suite is running** — `run.sh` rebuilds per
  session, so replacing `target/` mid-run leaves later sessions booting a
  half-written binary. Build once, then start `check.sh` and leave it alone.
- Long runs need `setsid nohup ... &` or they die with the agent's shell.

## Commands

```sh
cargo build --release                      # QEMU-virt kernel (default board)
./tools/run.sh [args]                      # build + boot virt; --no-drive = embedded initramfs
./tools/run.sh --rpi                       # build -p rpi + boot -M raspi3b (kernel8.img)
cargo build --release --no-default-features --features rpi3   # Pi kernel only
./tools/fetch-linux-toolchain.sh           # REQUIRED once: build.rs compiles kernel/assets/c/*.c
./tools/check.sh                           # full acceptance suite
```

- Boards are cargo features: `qemu-virt ⊕ rpi3` (`kernel/src/hal` selects
  platform constants, IRQ facade, linker script). Never enable both
  (compile_error).
- Extra QEMU args pass through run.sh after `-kernel`; `--rpi`/`--no-drive`
  are consumed by the script, not forwarded.

## Build pipeline (kernel/build.rs does more than link)

- Nested `cargo build -p tihkali-user` with a **private `--target-dir` under
  OUT_DIR** — same target dir would deadlock on the parent's lock. Do NOT
  "fix" this by building user/ from the shell first; build.rs is self-contained.
- Compiles `kernel/assets/c/hello.c` with the musl cross gcc → build fails
  with a pointer to fetch-linux-toolchain.sh if missing.
- Packs `target/initramfs.img` (cpio newc, 64 KiB zero headroom after
  TRAILER!!! — QEMU capacity == file size, headroom is what `sync` writes
  into). The same path is embedded as the no-disk fallback.
- **Editing any file under user/ or kernel/assets/c/ regenerates the image**,
  wiping files created by an earlier `sync` run. Two-boot persistence tests
  require stable sources between runs.

## Layout / entrypoints

- `kernel/src/main.rs` → `kernel_main`: console → gic → tty → timer → trap →
  mmu → pmm → heap → virtio_blk → mount initramfs → create pid0 space →
  load `/bin/sh` → `user::enter`.
- `kernel/src/arch/trap.S` frame layout is **coupled by hand** to
  `TrapFrame` in `arch/trap.rs` (x0-x30, elr, spsr, esr = 272 B). Change both.
- Syscall dispatch: `svc` immediate ≠ 0 → NetBSD (`svc #NR`, error = PSTATE.C
  + positive errno); immediate 0 → Linux (`x8` = number, error = `-errno` in
  x0). Numbers differ per ABI (e.g. getpid 20 vs 172, O_CREAT 0x200 vs 0x40 —
  translate in `linux_abi.rs`, never assume Linux values on the NetBSD path).
- `kernel/src/hal/` board selection: `platform_{virt,raspi}.rs`, `gic.rs`
  facade. `kprint!`/`kprintln!` are `#[macro_export]`ed (crate root) and
  reach submodules via `use crate::{kprint, kprintln};` — `#[macro_use]` on
  `mod hal` does NOT descend into child modules like `arch::trap`.
  Pi has **no GIC**: `gic_rpi::iar()` polls timer/UART; acks are source-side.
- `user/` = userland (sh, hello, greet) — Rust no_std bins linked at
  0x100000000; `kernel/assets/c/` = musl C tests linked there too (`-static
  -no-pie -Wl,-Ttext-segment=0x100000000`; PIE or 0x400000 links are
  rejected).
- **`kernel/src/fb.rs` = the display stack (qemu-virt only).** The framebuffer
  is QEMU's `ramfb`: no MMIO, virtqueue, IRQ or PCI — the guest hands QEMU a
  pointer to its own contiguous RAM (`pmm::alloc_contiguous`) through **fw_cfg
  DMA**, and QEMU maps it as the display surface. Kernel log lines are `fb:`.
  - **`-device ramfb` is mandatory** (run.sh adds it; `NO_GUI=1` omits it) and
    **needs `vgabios-ramfb.bin` in the `-L` datadir** — install it with
    `tools/fetch-vgabios.sh`, or QEMU aborts at startup. `-machine virt` has
    **no PL110**, and this QEMU build ships **no virtio-gpu device at all**.
  - fw_cfg windows: **data base+0, selector base+8, DMA base+16**. All three
    are `DEVICE_BIG_ENDIAN`: the data port accepts an access **only at offset
    0** (multi-byte reads must be one access, never `+i`), every value needs
    `swap_bytes()`, and the DMA trigger store must carry the descriptor
    address **byte-swapped** or the transfer silently does nothing.
    `struct fw_cfg_dma_access` field order is **control, length, address**.
    `struct RAMFBCfg` is **QEMU_PACKED and 28 bytes** — a 32-byte `repr(C)`
    write is rejected with ERROR.
  - Syscall door: NetBSD **481** fb_info / **482** fill_rect / **483** blit
    (Linux **480/481/482**). User space blits *through the kernel* because the
    user window is only 4 MiB (`user::USER_LIMIT`) and the framebuffer is
    contiguous physical memory the MMU already identity-maps.
  - Client is `user/src/gui.rs` → `/bin/gui` (unchanged by the module
    rename; only the kernel side is `fb`), all drawing is user space.
  - Verify pixels, not just logs: QMP `screendump` writes a **binary PPM
    (P6)** even if you name the file `.png`.
- Top level is deliberately flat: 2 workspace crates (`kernel`, `user`) plus
  `tools/`, `vendor/`. `user/` cannot merge — it needs its own `-T` link
  script at 0x100000000 vs the kernel's 0x40080000, and rustc-link-arg is
  package-wide. `vendor/` must sit at the workspace root for
  `.cargo/config.toml` source replacement.

## DNS (in-kernel resolver)

- `net::resolve(name, timeout_ms)` (`kernel/src/net.rs`) resolves in two
  steps: **`/etc/hosts` first** (static, no network), then the
  `nameserver` from **`/etc/resolv.conf`**. Both are BSD-style parsers
  (`<ip> <name>...`, `nameserver <ip>`, `#` comments); only the first
  nameserver is used. Missing/unparseable `/etc/resolv.conf` falls back to
  the built-in 10.0.2.3 (SLIRP). Sources are `kernel/assets/hosts` and
  `kernel/assets/resolv.conf`, packed to `/etc/` by `kernel/build.rs`.
- DNS queries go to a scoped `smoltcp::socket::dns::Socket`. Same
  scoped-socket shape as `dhcp_acquire`: own SocketSet for the call, dropped
  before returning, so it never eats one of the 8 persistent pool slots.
- Reached from userland by **Linux syscall 240** (`tihkali_resolve(const
  char *name, u32 *out_ipv4)`), free on aarch64 Linux. 0 + A record on
  success, `-EFAULT` (14) for a bad pointer, `-ENOENT` (2) for
  NXDOMAIN/timeout. `/bin/dnsprobe` exercises it (check.sh session 19).
- Needs smoltcp feature **`socket-dns`**, not `proto-dns` — the latter only
  compiles the wire codec; the socket type lives behind `socket-dns`.
  `DnsQueryType` (not `wire::dns::Type`, which is `pub(crate)`) is the
  public path.
- `start_query` needs a `ManagedSlice` with **at least one** slot, else
  `NoFreeSlot`; `[None; 1]` is the minimal allocation-free form.
- `get_query_result` **frees the query slot** on completion/failure, so
  `cancel_query` afterwards would panic on a free slot — only call it on
  the timeout path (hence the `settled` flag).
- `ManagedSlice` comes from the `managed` crate directly; smoltcp does not
  re-export it.
- **busybox/musl's resolver works** (`ping example.com`, `wget
  http://example.com` — full name -> A record -> TCP -> body). It is a
  completely separate path from `net::resolve` and needed six kernel fixes
  to function; all are listed below.
  - musl **binds `0.0.0.0:0`** before querying. smoltcp rejects port 0, so
    `sock_bind` must treat 0 as "pick an ephemeral port"
    (`EPHEMERAL_PORT + slot`), or bind fails EINVAL and musl reports a
    lookup failure without ever querying.
  - The ephemeral bind must use **`local_ip()`**, not `UNSPECIFIED`.
    smoltcp takes the packet's source IP from the bound address, so
    `UNSPECIFIED` puts `0.0.0.0` on the wire, SLIRP replies to `0.0.0.0`,
    and the reply is silently dropped.
  - UDP `sendto` must call **`service_iface()`** after queueing, like
    `sock_send` does for TCP. Without it the query sits in the smoltcp tx
    ring until an unrelated idle `poll_tick`, so a process that sends then
    blocks in `poll(2)` waits on a packet that never left.
  - `poll(2)` must **`poll_tick()` once before sampling fds** — a datagram
    that landed since the last tick is in the rx queue, not the socket
    buffer, so `sock_poll` reports "not ready" and the caller sleeps
    through the arrival. Do it once per ppoll, not per fd: `poll_tick`
    wakes sleepers, and per-fd would wake the caller mid-iteration.
  - musl opens its socket **`SOCK_NONBLOCK`** and expects `EAGAIN` from
    `recvmsg`/`recvfrom`, not a sleep. `socket(2)` must honour the flag
    (masked off by `& 0xf` for type detection) and `fcntl(F_SETFL)` must
    stop ignoring it, or the resolver blocks forever on an empty socket.
  - `recvmsg` must **not zero `msg_iovlen`**. musl walks the iovec array
    advancing that field; clearing it makes it discard a perfectly good
    reply and report `bad address`. Do write back `msg_name`/`msg_namelen`
    (the reply source) and zero `msg_controllen`/`msg_flags`.
- **No IPv6 stack, so `strip_ipv6_records` removes AAAA RRs** from every
  port-53 reply on the way to user space. musl hands userland *every*
  address it resolved and busybox commits to the first: without this,
  `ping example.com` and `wget http://example.com` resolve fine and then
  die on `socket(AF_INET6)`. Dropping the AAAA *query* is not enough — the
  address comes back in the A reply too. The rewrite is in place: records
  are compacted, ANCOUNT is fixed, and name-compression pointers stay
  valid because the copy never moves the message start.
  - The DNS header is `id[0..2] flags[2..4] qdcount[4..6] ancount[6..8]`.
    **QR is bit 15 of the 16-bit flags at bytes 2-3**, not byte 1 — testing
    `buf[1] & 0x80` reads the transaction ID and silently skips every
    reply. This cost an hour; check the offset against a hexdump, not the
    header shape.
- The two resolvers coexist: `dnsprobe` exercises the in-kernel socket,
  busybox exercises musl. check.sh session 19 gates both.

## Memory-map facts (easy to get wrong)

| | QEMU virt | Raspberry Pi 3 |
|---|---|---|
| kernel load | 0x40080000 | 0x80000 (raw kernel8.img) |
| UART0 (PL011) | 0x09000000 | 0x3F201000 |
| interrupt ctrl | GICv3 @0x08000000 | BCM2835 IC @**0x3F00B200** (NOT the INTE 0x2000 window!) + control @0x40000000 (timercontrol bit1 = route CNTPNSIRQ) |
| RAM | 256 MB @0x40000000 | 1 GiB @0x0 (peri window shadows top) |
| user VA | 0x1_0000_0000..+4 MiB (same both boards) | |

First16 MiB of RAM are reserved (kernel + DTB). MMU: one L2 per 1 GiB slot,
RAM identity + device overlays in the same slot; kernel slots shared,
only L1[4] (user) + L3s are private per process.

## Debugging

- Sync exceptions dump ESR/ELR/FAR/x0-x30 then halt — read ESR as:
  EC = bits[31:26], **WnR = bit 6, FSC = bits[5:0]** (bit 24 is ISV).
  Getting WnR wrong classifies every COW fault as a read.
- For hangs inside asm before Rust: write bytes straight to UARTDR
  (virt 0x09000000 / Pi 0x3F201000) as markers.
- `mrs cntp_tval_el0` zero-extends — test expiry as `(tval as i32) < 0`.
- QEMU virtio-mmio needs `-global virtio-mmio.force-legacy=false` (run.sh
  has it); first device lands on the HIGHEST of 32 slots — always probe all.
- **A 2 MiB block descriptor's address must be the ALIGNED block base**, not
  the device address. Devices sharing a block collide (UART0 0x09000000 and
  fw_cfg 0x09020000 both land in L2 index 72) and the misaligned entry maps
  nothing, so the access faults as "outside user space".
- `tools/boot-test.sh` runs one headless session and always reaps QEMU by
  numeric PID — use it for quick iteration instead of hand-rolling a
  `(sleep …; printf …) | timeout … run.sh` pipeline, which leaves QEMU
  holding `target/initramfs.img` when it is killed and makes the *next* run
  die with `Failed to get "write" lock`.
- GNU `objcopy` cannot read aarch64 ELF here — use `llvm-objcopy-19`.
- QEMU's `-nographic` stdio mux swallows piped input; run.sh uses
  `-display none -serial stdio -monitor none` instead.

## Environment

- No sudo anywhere: vendor with `apt-get download` + `dpkg-deb -x` into
  `.toolchain/` (gitignored) + `LD_LIBRARY_PATH`/`-L` (run.sh handles QEMU).
- Project memory (decisions, ABI tables, past gotchas):
  `~/.local/share/mimocode/memory/projects/global/MEMORY.md` — read the
  tihkali entries before re-deriving anything ABI- or board-related.
- Git: commit locally with `git -c user.name=... -c user.email=...`; never
  edit git config, never push. `.toolchain`, `target`, `.mimocode` ignored.
- Rust edition 2024: `#[unsafe(no_mangle)]`, explicit `unsafe` blocks in
  `unsafe fn` bodies, `static mut` access needs `unsafe`.

## Session layout

**One instance, one worktree.** The second agent session and its `side-b`
worktree/branch were removed on purpose (2026-10-17) — do not recreate
them, and do not push to `side-b`. `master` is the only branch.

```sh
mimoa                      # create-or-attach the session (~/projects/tihkali)
tmux ls                    # list live sessions
```

`mimoa` is a launcher at `~/.local/bin/mimoa` (on PATH, **outside the repo —
not tracked by git**). It inspects the existing session and picks one of three
paths: a live pane already running `mimo` → attach; a pane that died or runs
something else → kill the husk and relaunch; no session → create and attach.
Re-running it is always safe and never double-launches.

Detach without killing: `Ctrl-b` then `d`.

The `target/`-lock and orphaned-helper hazards above still apply, but they
are now only self-inflicted: there is no second instance to blame.
