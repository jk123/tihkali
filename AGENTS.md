# tihkali — agent instructions

Nano BSD-style OS in Rust (+asm): QEMU virt aarch64 + Raspberry Pi 3, NetBSD
syscall ABI with a Linux-ABI personality, COW paging, virtio-blk initramfs,
signals, interactive shell. Single core, no MMU user/kernel VA split (user
space lives at VA 4 GiB, kernel identity-maps all RAM in every address space).

## The one rule

`./tools/check.sh` must exit 0 before calling anything done (0-warning build
+ 17 scripted QEMU sessions / 106 gates; logs land in
`/tmp/tihkali-check/*.log`). A
warning is a failure. Sessions use scripted stdin:

```sh
(sleep 3; printf 'ls\n'; sleep 0.5; printf 'exit\n') | timeout 12 ./tools/run.sh
```

First input must start after **3 s**: run.sh runs `cargo build` first, and a
rebuild (triggered by `sync` rewriting target/initramfs.img in a previous
session) takes ~1.5 s on top of boot — anything earlier races the UART init
and drops the first byte (symptom: `trap` → `rap`). Mid-session sleeps can
stay short.

## Commands

```sh
cargo build --release                      # QEMU-virt kernel (default board)
./tools/run.sh [args]                      # build + boot virt; --no-drive = embedded initramfs
./tools/run.sh --rpi                       # build -p rpi + boot -M raspi3b (kernel8.img)
cargo build --release --no-default-features --features rpi3   # Pi kernel only
./tools/fetch-linux-toolchain.sh           # REQUIRED once: build.rs compiles linux/*.c with it
./tools/check.sh                           # full acceptance suite
```

- Boards are cargo features: `qemu-virt ⊕ raspi3` (hal selects platform
  constants, IRQ facade, linker script). Never enable both (compile_error).
- Extra QEMU args pass through run.sh after `-kernel`; `--rpi`/`--no-drive`
  are consumed by the script, not forwarded.

## Build pipeline (kernel/build.rs does more than link)

- Nested `cargo build -p tihkali-user` with a **private `--target-dir` under
  OUT_DIR** — same target dir would deadlock on the parent's lock. Do NOT
  "fix" this by building user/ from the shell first; build.rs is self-contained.
- Compiles `linux/hello.c` with the musl cross gcc → build fails with a
  pointer to fetch-linux-toolchain.sh if missing.
- Packs `target/initramfs.img` (cpio newc, 64 KiB zero headroom after
  TRAILER!!! — QEMU capacity == file size, headroom is what `sync` writes
  into). The same path is embedded as the no-disk fallback.
- **Editing any file under user/ or linux/ regenerates the image**, wiping
  files created by an earlier `sync` run. Two-boot persistence tests require
  stable sources between runs.

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
- `hal/` board selection: `platform_{virt,raspi}.rs`, `gic.rs` facade.
  Pi has **no GIC**: `gic_rpi::iar()` polls timer/UART; acks are source-side.
- `user/` = userland (sh, hello, greet) — Rust no_std bins linked at
  0x100000000; `linux/` = musl C tests linked there too (`-static -no-pie
  -Wl,-Ttext-segment=0x100000000`; PIE or 0x400000 links are rejected).

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
