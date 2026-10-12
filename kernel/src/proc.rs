//! Process table and round-robin scheduler (single core).
//!
//! All EL0 exceptions are handled on one shared kernel stack; scheduling
//! works by swapping the trap frame + SP_EL0 + TTBR0 in `schedule()` and
//! letting the asm `RESTORE_FRAME`/`eret` land in the next process.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::string::String;
use alloc::vec::Vec;
use tihkali_hal::kprintln;

use crate::arch::trap::TrapFrame;
use crate::file::{self, FdTarget, EACCES, EBADF, EFAULT, EINTR, ESRCH};
use crate::user;
use crate::vm;

const NO_PARENT: usize = usize::MAX;

pub const ECHILD: u8 = 10;
pub const EPERM_L: u8 = 1;
pub const EPIPE_L: u8 = 32;
pub const ENOMEM: u8 = 12;
pub const EINVAL: u8 = 22;

/// Signal support (v1): no masks, no SA_* flags, synchronous delivery at
/// every return-to-EL0 boundary.
pub const NSIG: usize = 33; // signals 1..32 (canonical SIGPWR=32)
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
const SIGKILL: usize = 9;

fn align_up(v: u64) -> u64 {
    (v + 0xfff) & !0xfff
}

/// Signals whose default action is process termination.
fn default_is_term(sig: usize) -> bool {
    // All canonical signals whose default action is terminate:
    // HUP INT QUIT ILL TRAP ABRT EMT FPE KILL BUS SEGV SYS PIPE ALRM TERM
    // (1..=15) + XCPU XFSZ VTALRM PROF (24..=27) + USR1 USR2 PWR (30..=32).
    // STOP/TSTP/CONT/TTIN/TTOU (17..=22) and URG/IO/CHLD/WINCH are not
    // terminate; stop signals are unimplemented v1 and fall through to
    // the discard path in deliver_signals.
    sig <= 15 || (24..=27).contains(&sig) || (30..=32).contains(&sig)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Runnable,
    Sleeping, // blocked in wait4
    Zombie,   // exited, awaiting reap
}

pub struct Process {
    pub pid: usize,
    pub parent: usize,
    pub state: State,
    pub exit_code: i32,
    /// Saved EL0 context (valid while off-CPU).
    pub frame: TrapFrame,
    pub sp_el0: u64,
    /// [l0, l1, l2_ram, l2_user, l3_text, l3_stack] — owned table frames;
    /// tables[0] is the TTBR0 value.
    pub tables: Vec<usize>,
    /// fd table: 0 = stdin (tty), 1/2 = stdout/stderr (tty), 3+ = files.
    pub fds: Vec<Option<FdTarget>>,
    /// Pending signal bitmask (bit N = signal N).
    pub pending: u64,
    /// Disposition per signal: 0 = SIG_DFL, 1 = SIG_IGN, else handler address.
    pub handlers: [usize; NSIG],
    /// Killed by a signal (selects the wait4 status encoding).
    pub signaled: bool,
    /// sigprocmask block set (bit N = signal N; bit 9 never set).
    pub blocked: u64,
    /// brk arena: [brk_start, MMAP_FLOOR) inside the text window.
    pub brk_start: u64,
    pub brk: u64,
    /// mmap bump pointer (0 = unused); arena = [MMAP_FLOOR, mmap_next).
    pub mmap_next: u64,
    /// Dispositions were installed via the Linux ABI (signal numbers seen
    /// by the handler must be converted back from canonical/NetBSD).
    pub sig_linux: bool,
    /// Process group (job control); children inherit it. ^C targets the
    /// tty's foreground group.
    pub pgrp: usize,
    /// Absolute tick deadline while sleeping in a timed syscall
    /// (ppoll/nanosleep); None for untimed sleeps.
    pub wake_at: Option<u64>,
    /// Saved TPIDR_EL0 (user TLS anchor). musl CRTs rewrite the register
    /// on exec; without per-process save/restore a child's exec leaves
    /// every other process reading TLS through a dangling pointer.
    pub tpidr: u64,
}

struct ProcTable(UnsafeCell<Vec<Option<Process>>>);
unsafe impl Sync for ProcTable {}

// Vec::new() is const: the table grows on the kernel heap at first fork.
static PROCS: ProcTable = ProcTable(UnsafeCell::new(Vec::new()));
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static NEXT_PID: AtomicUsize = AtomicUsize::new(1);
/// True while the CPU spins in `kernel_idle` (no process context to save).
static IDLE: AtomicBool = AtomicBool::new(false);

pub fn set_idle(v: bool) {
    IDLE.store(v, Ordering::Relaxed);
}

pub fn is_idle() -> bool {
    IDLE.load(Ordering::Relaxed)
}

fn table() -> &'static mut Vec<Option<Process>> {
    unsafe { &mut *PROCS.0.get() }
}

/// Process group of the running process.
pub fn current_pgrp() -> usize {
    table()[CURRENT.load(Ordering::Relaxed)]
        .as_ref()
        .map(|p| p.pgrp)
        .unwrap_or(0)
}

pub fn current_pid() -> usize {
    table()[CURRENT.load(Ordering::Relaxed)].as_ref().map_or(0, |p| p.pid)
}

fn read_sp_el0() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, sp_el0", out(reg) v, options(nomem, nostack)) };
    v
}

fn write_sp_el0(v: u64) {
    unsafe { core::arch::asm!("msr sp_el0, {}", in(reg) v) }
}

fn switch_ttbr(ttbr: usize) {
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr as u64);
        core::arch::asm!("dsb sy");
        core::arch::asm!("tlbi vmalle1");
        core::arch::asm!("dsb sy", "isb");
    }
}

/// Register the initial (pid 0) process before entering EL0.
/// `tables` must already be active (`mmu::activate`).
pub fn init(entry: usize, image_end: usize, tables: Vec<usize>) {
    let brk = align_up(image_end as u64);
    let t = table();
    t.clear();
    t.push(Some(Process {
        pid: 0,
        parent: NO_PARENT,
        state: State::Runnable,
        exit_code: 0,
        frame: TrapFrame {
            x: [0; 31],
            elr: entry as u64,
            spsr: 0,
            esr: 0,
        },
        sp_el0: user::USER_LIMIT as u64,
        tables,
        fds: alloc::vec![
            Some(FdTarget::TtyIn),
            Some(FdTarget::TtyOut),
            Some(FdTarget::TtyOut),
        ],
        pending: 0,
        handlers: [SIG_DFL; NSIG],
        signaled: false,
        blocked: 0,
        brk_start: brk,
        brk,
        mmap_next: 0,
        sig_linux: false,
        pgrp: 0,
        wake_at: None,
        tpidr: crate::user::TPIDR_VAL,
    }));
    CURRENT.store(0, Ordering::Relaxed);
    NEXT_PID.store(1, Ordering::Relaxed);
}

/// Save the outgoing context (held in `frame`) into its process, pick the
/// next Runnable process round-robin, and load its context. Returns false
/// when nothing is runnable (caller enters kernel idle).
fn read_tpidr() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) v, options(nomem, nostack));
    }
    v
}

fn write_tpidr(v: u64) {
    unsafe {
        core::arch::asm!("msr tpidr_el0, {}", "isb", in(reg) v, options(nomem, nostack));
    }
}

pub fn schedule(frame: &mut TrapFrame) -> bool {
    schedule_ex(frame, true)
}

/// `save = false` is used from kernel idle: `frame` holds a kernel context
/// that must NOT be written into the current process slot.
pub fn schedule_ex(frame: &mut TrapFrame, save: bool) -> bool {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    if save {
        if let Some(p) = &mut t[cur] {
            p.frame = *frame;
            p.sp_el0 = read_sp_el0();
            // Capture the live TLS anchor (a child exec's CRT may have
            // rewritten TPIDR_EL0 since our last switch-out).
            p.tpidr = read_tpidr();
        }
    }

    let n = t.len();
    for k in 1..=n {
        let idx = (cur + k) % n;
        let runnable = t[idx].as_ref().is_some_and(|p| p.state == State::Runnable);
        if !runnable {
            continue;
        }
        if idx == cur && save {
            return true; // same context already in `frame`
        }
        CURRENT.store(idx, Ordering::Relaxed);
        let p = t[idx].as_mut().unwrap();
        write_sp_el0(p.sp_el0);
        write_tpidr(p.tpidr);
        switch_ttbr(p.tables[0]);
        *frame = p.frame;
        IDLE.store(false, Ordering::Relaxed);
        return true;
    }
    false
}

/// Signals that are pending AND not blocked (what delivery would act on).
/// True when a pending signal would actually do something at the next
/// return choke: run a handler, or terminate (DFL+term). Ignored and
/// DFL-ignore signals are discarded there — they must NOT cause EINTR
/// (that was a real bug: a pending SIGCHLD with no handler would
/// interrupt read/ppoll with EINTR even though nothing observable runs).
pub fn has_deliverable() -> bool {
    let cur = CURRENT.load(Ordering::Relaxed);
    let Some(p) = table().get(cur).and_then(|p| p.as_ref()) else {
        return false;
    };
    let deliv = p.pending & !p.blocked;
    (0..NSIG).any(|s| {
        let bit = 1u64 << s;
        deliv & bit != 0
            && (p.handlers[s] > SIG_IGN || (p.handlers[s] == SIG_DFL && default_is_term(s)))
    })
}

/// Block the current process until someone wakes it (rewind-on-wake).
pub fn sleep_current(frame: &mut TrapFrame) {
    sleep_inner(frame, None);
}

/// Sleep until an absolute tick deadline; the re-executed syscall observes
/// the expiry via `deadline_passed`.
pub fn sleep_timed(frame: &mut TrapFrame, deadline: u64) {
    sleep_inner(frame, Some(deadline));
}

fn sleep_inner(frame: &mut TrapFrame, deadline: Option<u64>) {
    let cur = CURRENT.load(Ordering::Relaxed);
    {
        let p = table()[cur].as_mut().unwrap();
        p.state = State::Sleeping;
        p.wake_at = deadline;
    }
    if !schedule(frame) {
        let idle: extern "C" fn() -> ! = crate::kernel_idle;
        frame.elr = idle as *const () as u64;
        frame.spsr = 0x345;
    }
}

/// True (and clears) when the current process's sleep deadline has passed.
pub fn deadline_passed() -> bool {
    let cur = CURRENT.load(Ordering::Relaxed);
    let now = crate::arch::timer::now();
    let Some(p) = table()[cur].as_mut() else { return false };
    match p.wake_at {
        Some(at) if now >= at => {
            p.wake_at = None;
            true
        }
        _ => false,
    }
}

/// Clear a stale deadline (syscall completed without timing out).
pub fn deadline_clear() {
    if let Some(p) = table()[CURRENT.load(Ordering::Relaxed)].as_mut() {
        p.wake_at = None;
    }
}

/// Current sleep deadline, if one is armed.
pub fn deadline() -> Option<u64> {
    table()[CURRENT.load(Ordering::Relaxed)]
        .as_ref()
        .and_then(|p| p.wake_at)
}

/// Wake sleepers whose deadline expired (timer IRQ path).
pub fn wake_expired() {
    let now = crate::arch::timer::now();
    let t = table();
    for o in t.iter_mut() {
        if let Some(p) = o {
            if p.state == State::Sleeping && p.wake_at.is_some_and(|at| now >= at) {
                p.state = State::Runnable;
                p.frame.elr = p.frame.elr.wrapping_sub(4);
                // wake_at stays: the re-executed syscall decides and clears.
            }
        }
    }
}

/// Wake every sleeper by rewinding its saved ELR so the blocked syscall
/// re-executes with its original arguments (wait4 re-checks zombies, read
/// re-checks the tty buffer).
pub fn wake_sleeping() {
    let t = table();
    for o in t.iter_mut() {
        if let Some(p) = o {
            if p.state == State::Sleeping {
                p.frame.elr = p.frame.elr.wrapping_sub(4);
                p.state = State::Runnable;
            }
        }
    }
}

pub enum ForkError {
    NoMem, // ENOMEM
}

/// SYS_fork: new empty page tables + share every present parent page as
/// copy-on-write (no stack copy — pages are shared until written).
pub fn sys_fork(frame: &mut TrapFrame) -> Result<usize, ForkError> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    let slot = match t.iter().position(|p| p.is_none()) {
        Some(i) => i,
        None => {
            t.push(None);
            t.len() - 1
        }
    };
    let parent_ttbr = t[cur].as_ref().unwrap().tables[0];
    let child_sp_el0 = read_sp_el0();

    let Some(child_tables) = crate::arch::mmu::create_space() else {
        return Err(ForkError::NoMem);
    };
    if vm::share_user_pages(parent_ttbr, child_tables[0]).is_err() {
        vm::free_space(&child_tables);
        return Err(ForkError::NoMem);
    }

    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let mut cframe = *frame;
    cframe.x[0] = 0; // fork returns 0 in the child
    cframe.spsr &= !(1 << 29);

    // Inherit the fd table; share file descriptions (common offset).
    let fds = t[cur].as_ref().unwrap().fds.clone();
    // POSIX: dispositions and the signal mask inherit across fork
    // (pending does not). Arenas are inherited as-is (pages are shared COW).
    let handlers = t[cur].as_ref().unwrap().handlers;
    let blocked = t[cur].as_ref().unwrap().blocked;
    let brk_start = t[cur].as_ref().unwrap().brk_start;
    let brk = t[cur].as_ref().unwrap().brk;
    let mmap_next = t[cur].as_ref().unwrap().mmap_next;
    let sig_linux = t[cur].as_ref().unwrap().sig_linux;
    for target in fds.iter().flatten() {
        if let FdTarget::File(i) = target {
            file::dup(*i);
        }
    }

    t[slot] = Some(Process {
        pid,
        parent: cur,
        state: State::Runnable,
        exit_code: 0,
        frame: cframe,
        sp_el0: child_sp_el0,
        tables: child_tables,
        fds,
        pending: 0,
        handlers,
        signaled: false,
        blocked,
        brk_start,
        brk,
        mmap_next,
        sig_linux,
        pgrp: t[cur].as_ref().unwrap().pgrp, // children share the group
        wake_at: None,
        // Child shares the parent's live TLS (COW pages keep it valid).
        tpidr: read_tpidr(),
    });
    kprintln!("proc: fork pid {} (parent {})", pid, t[cur].as_ref().unwrap().pid);
    Ok(pid)
}

fn wake_parent(child_slot: usize) {
    let t = table();
    let parent_idx = t[child_slot].as_ref().unwrap().parent;
    if parent_idx == NO_PARENT {
        return;
    }
    if let Some(par) = &mut t[parent_idx] {
        // POSIX: child death raises SIGCHLD on the parent. Handlers get
        // it at the next choke; DFL/IGN is discarded there (and must not
        // EINTR — has_deliverable filters those).
        par.pending |= 1 << 20; // SIGCHLD (canonical)
        if par.state == State::Sleeping {
            // Rewind the saved ELR so wait4 re-executes and re-checks;
            // registers still hold the original wait4 arguments.
            par.frame.elr = par.frame.elr.wrapping_sub(4);
            par.state = State::Runnable;
        }
    }
}

/// SYS_exit: mark zombie, wake a waiting parent, schedule away.
pub fn sys_exit(frame: &mut TrapFrame, code: u64) {
    terminate(frame, code, false);
}

/// EL0 took a fault the kernel could not resolve: kill *only* the
/// offending process (never halt the machine). `sig` is canonical.
pub fn kill_from_fault(frame: &mut TrapFrame, sig: u64) {
    terminate(frame, sig, true);
}

/// Terminate the current process (exit or fatal signal) and schedule away.
fn terminate(frame: &mut TrapFrame, code: u64, signaled: bool) {
    let cur = CURRENT.load(Ordering::Relaxed);
    {
        let p = table()[cur].as_mut().unwrap();
        p.state = State::Zombie;
        p.exit_code = code as i32;
        p.signaled = signaled;
        p.pending = 0;
        file::release_all(&p.fds);
    }
    let pid = table()[cur].as_ref().unwrap().pid;
    if signaled {
        kprintln!("proc: pid {pid} killed by signal {code}");
    } else {
        kprintln!("proc: pid {pid} exited ({code})");
    }
    wake_parent(cur);
    if !schedule(frame) {
        let idle: extern "C" fn() -> ! = crate::kernel_idle;
        frame.elr = idle as *const () as u64;
        frame.spsr = 0x345;
    }
}

pub enum Wait4 {
    Done(i64), // returns child pid via normal epilogue
    Slept,     // scheduled away; do not run epilogue
    Err(u8),   // errno
}

/// SYS___wait450 (449): reap a zombie child or sleep until one exits.
/// `options & 1` = WNOHANG: return 0 instead of blocking.
pub fn sys_wait4(frame: &mut TrapFrame, pid_arg: i64, status_ptr: u64, options: u64) -> Wait4 {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();

    let mut victim: Option<usize> = None;
    for (i, o) in t.iter().enumerate() {
        if let Some(c) = o {
            if c.parent == cur
                && c.state == State::Zombie
                && (pid_arg == -1 || c.pid as i64 == pid_arg)
            {
                victim = Some(i);
                break;
            }
        }
    }

    if let Some(slot) = victim {
        let (pid, status) = {
            let c = t[slot].as_ref().unwrap();
            let st = if c.signaled {
                // Killed-by-signal encoding: the signum must be in the
                // WAITER's numbering — a Linux parent would misread
                // canonical USR1=30 as signal 30 (Linux PWR).
                let sig = c.exit_code as usize;
                let out = if t[cur].as_ref().unwrap().sig_linux {
                    sig_to_user(sig, true) as u32
                } else {
                    sig as u32
                };
                out & 0x7f
            } else {
                ((c.exit_code as u32) & 0xff) << 8
            };
            (c.pid, st as i32)
        };
        if status_ptr != 0 {
            if !write_user_i32(status_ptr as usize, status) {
                return Wait4::Err(14); // EFAULT
            }
        }
        reap(slot);
        return Wait4::Done(pid as i64);
    }

    let has_children = t
        .iter()
        .any(|o| o.as_ref().is_some_and(|c| c.parent == cur));
    if !has_children {
        return Wait4::Err(ECHILD);
    }
    if options & 1 != 0 {
        return Wait4::Done(0); // WNOHANG: nothing ready yet
    }

    if has_deliverable() {
        return Wait4::Err(EINTR); // interrupted before blocking
    }
    sleep_current(frame);
    Wait4::Slept
}

fn reap(slot: usize) {
    let t = table();
    let c = t[slot].take().unwrap();
    vm::free_space(&c.tables);
    kprintln!("proc: reaped pid {}", c.pid);
}

fn write_user_i32(addr: usize, val: i32) -> bool {
    let end = addr.wrapping_add(4);
    if !user_range_ok(addr as u64, 4) || !user_range_ok(end as u64, 1) {
        return false;
    }
    unsafe { (addr as *mut i32).write_volatile(val) };
    true
}

// ---------- user-memory helpers ----------

pub fn user_range_ok(addr: u64, len: usize) -> bool {
    let s = addr as usize;
    let Some(e) = s.checked_add(len) else { return false };
    (user::USER_BASE..user::USER_LIMIT).contains(&s)
        && (user::USER_BASE..user::USER_LIMIT).contains(&e)
}

pub fn read_user_cstr(addr: u64, max: usize) -> Option<String> {
    let mut out = String::new();
    for i in 0..max {
        if !user_range_ok(addr + i as u64, 1) {
            return None;
        }
        let b = unsafe { *((addr as usize + i) as *const u8) };
        if b == 0 {
            return Some(out);
        }
        out.push(b as char);
    }
    None // not NUL-terminated within max
}

pub fn read_user_u64(addr: u64) -> Option<u64> {
    if !user_range_ok(addr, 8) {
        return None;
    }
    Some(unsafe { (addr as *const u64).read_volatile() })
}

// ---------- execve ----------

const ENOENT: u8 = 2;

/// SYS_execve(path, argv): replace the current process image.
/// On success the trap frame is rebuilt to enter the new program; the
/// syscall epilogue must be skipped (returns Ok).
pub fn sys_execve(frame: &mut TrapFrame, path_ptr: u64, argv_ptr: u64) -> Result<(), u8> {
    let path = read_user_cstr(path_ptr, 128).ok_or(EFAULT)?;
    let mut args: Vec<Vec<u8>> = Vec::new();
    if argv_ptr != 0 {
        for i in 0..16u64 {
            let p = read_user_u64(argv_ptr + 8 * i).ok_or(EFAULT)?;
            if p == 0 {
                break;
            }
            let s = read_user_cstr(p, 64).ok_or(EFAULT)?;
            args.push(s.into_bytes());
        }
    }

    let fs_idx = crate::fs::lookup(&path).ok_or(ENOENT)?;
    if crate::fs::is_dir(fs_idx) {
        return Err(EACCES);
    }

    let cur = CURRENT.load(Ordering::Relaxed);
    let old_tables = table()[cur].as_ref().unwrap().tables.clone();

    let Some(new_tables) = crate::arch::mmu::create_space() else {
        return Err(ENOMEM);
    };

    // Activate the new tables so load()/argv writes land in the new space
    // (stack writes demand-page via the fault handler).
    switch_ttbr(new_tables[0]);
    let loaded = crate::fs::with_bytes(fs_idx, |elf| crate::user::load(elf, new_tables[0]));
    let (entry, image_end) = match loaded {
        Ok(v) => {
            // load() anchored TPIDR_EL0 for the new image — mirror it
            // into the per-process slot so later switch-ins restore it.
            table()[CURRENT.load(Ordering::Relaxed)]
                .as_mut()
                .unwrap()
                .tpidr = crate::user::TPIDR_VAL;
            v
        }
        Err(msg) => {
            kprintln!("exec: load failed: {msg}");
            switch_ttbr(old_tables[0]);
            vm::free_space(&new_tables);
            return Err(EINVAL);
        }
    };

    if crate::user::install_trampoline(new_tables[0]).is_err() {
        switch_ttbr(old_tables[0]);
        vm::free_space(&new_tables);
        return Err(ENOMEM);
    }

    let Some((argc, argv, sp)) = place_argv(&args) else {
        switch_ttbr(old_tables[0]);
        vm::free_space(&new_tables);
        return Err(EFAULT);
    };

    // Release the old address space (now inactive).
    vm::free_space(&old_tables);

    {
        let p = table()[cur].as_mut().unwrap();
        p.tables = new_tables;
        // POSIX: caught dispositions reset to DFL across exec, but
        // *ignored* dispositions survive; pending cleared.
        for h in p.handlers.iter_mut() {
            if *h != SIG_IGN {
                *h = SIG_DFL;
            }
        }
        p.pending = 0;
        p.sig_linux = false;
        let brk = align_up(image_end as u64);
        p.brk_start = brk;
        p.brk = brk;
        p.mmap_next = 0;
    }
    frame.elr = entry as u64;
    frame.spsr = 0; // EL0t, interrupts on
    frame.x[0] = argc;
    frame.x[1] = argv;
    write_sp_el0(sp);
    kprintln!("proc: exec {path} argc={argc} entry={entry:#x}");
    Ok(())
}

/// Lay out the user stack head for BOTH ABIs:
///   sp -> argc, argv[0..argc-1], NULL, NULL (empty envp),
///         auxv {AT_PAGESZ, AT_RANDOM}, {0,0}, then argv strings above.
/// NetBSD-style entry uses registers (x0=argc, x1=argv); musl's aarch64
/// crt reads argc/argv/envp/auxv straight off the stack.
fn place_argv(args: &[Vec<u8>]) -> Option<(u64, u64, u64)> {
    if args.len() > 16 {
        return None;
    }
    let mut cursor: u64 = user::USER_LIMIT as u64;
    let mut ptrs = [0u64; 17];
    // Strings plus 16 AT_RANDOM canary bytes at the very top.
    cursor -= 16;
    let random_ptr = cursor;
    unsafe {
        for i in 0..16u64 {
            *((cursor + i) as *mut u8) = 0x5a;
        }
    }
    for (i, a) in args.iter().enumerate() {
        cursor = cursor.checked_sub(a.len() as u64 + 1)?;
        unsafe {
            core::ptr::copy_nonoverlapping(a.as_ptr(), cursor as *mut u8, a.len());
            *((cursor as usize + a.len()) as *mut u8) = 0;
        }
        ptrs[i] = cursor;
    }

    let argc = args.len() as u64;
    // slots: argc + argv ptrs + argv NULL + envp NULL + 3 auxv pairs
    let slots = argc as usize + 9;
    let raw = cursor.checked_sub((slots * 8) as u64)?;
    let base = raw & !0xfu64; // 16-byte stack alignment
    unsafe {
        let p = base as *mut u64;
        p.add(0).write_volatile(argc);
        for i in 0..argc as usize {
            p.add(1 + i).write_volatile(ptrs[i]);
        }
        p.add(1 + argc as usize).write_volatile(0); // argv NULL
        p.add(2 + argc as usize).write_volatile(0); // envp NULL
        p.add(3 + argc as usize).write_volatile(6); // AT_PAGESZ
        p.add(4 + argc as usize).write_volatile(4096);
        p.add(5 + argc as usize).write_volatile(25); // AT_RANDOM
        p.add(6 + argc as usize).write_volatile(random_ptr);
        p.add(7 + argc as usize).write_volatile(0); // AT_NULL
        p.add(8 + argc as usize).write_volatile(0);
    }
    let argv = base + 8;
    Some((argc, argv, base))
}

// ---------- file-descriptor I/O ----------

pub enum Io {
    Val(i64),  // value returned in x0 (success)
    Err(u8),   // errno (carry set)
    Slept,     // blocked; skip the syscall epilogue
}

pub fn current_target(fd: usize) -> Option<FdTarget> {
    let t = table();
    let cur = CURRENT.load(Ordering::Relaxed);
    t[cur].as_ref().and_then(|p| p.fds.get(fd).copied().flatten())
}

/// SYS_read: tty-in blocks (IRQ-masked sleep), file reads never sleep.
pub fn sys_read(frame: &mut TrapFrame, fd: usize, buf: u64, len: usize) -> Io {
    let Some(target) = current_target(fd) else { return Io::Err(EBADF) };
    if len == 0 {
        return Io::Val(0);
    }
    if !user_range_ok(buf, len) {
        return Io::Err(EFAULT);
    }
    match target {
        FdTarget::TtyIn => {
            // Mask IRQs across the empty-check → sleep window so an RX can't
            // slip in and get lost; eret restores EL0 PSTATE from the frame.
            unsafe { core::arch::asm!("msr daifset, #2") };
            match crate::tty::read_user(buf, len) {
                Some(n) => {
                    unsafe { core::arch::asm!("msr daifclr, #2") };
                    Io::Val(n as i64)
                }
                None => {
                    // A deliverable signal must not be swallowed by a nap:
                    // fail the syscall; the return choke delivers it.
                    if has_deliverable() {
                        unsafe { core::arch::asm!("msr daifclr, #2") };
                        return Io::Err(EINTR);
                    }
                    sleep_current(frame);
                    Io::Slept
                }
            }
        }
        FdTarget::TtyOut => Io::Err(EBADF),
        FdTarget::File(i) => match file::read_to_user(i, buf, len) {
            Ok(n) => Io::Val(n as i64),
            Err(e) => Io::Err(e),
        },
        FdTarget::Pipe { slot, write_end: false } => {
            // Single-core: no writer can run while we're in-kernel, so an
            // empty pipe is a stable state — EOF once all write ends are gone.
            match file::pipe_read(slot, buf, len) {
                Ok(file::PipeRead::Data(n)) => Io::Val(n as i64),
                Ok(file::PipeRead::WouldBlock) => {
                    if pipe_end_count(slot, true) == 0 {
                        Io::Val(0) // no writers left: EOF
                    } else if has_deliverable() {
                        Io::Err(EINTR)
                    } else {
                        sleep_current(frame);
                        Io::Slept
                    }
                }
                Err(e) => Io::Err(e),
            }
        }
        FdTarget::Pipe { write_end: true, .. } => Io::Err(EBADF),
    }
}

/// SYS_write: tty-out writes the console; O_WRONLY/O_RDWR file fds grow
/// the node and mark it dirty.
pub fn sys_write(fd: usize, buf: u64, len: usize) -> Result<i64, u8> {
    let Some(target) = current_target(fd) else { return Err(EBADF) };
    if len == 0 {
        return Ok(0);
    }
    match target {
        FdTarget::TtyOut => {
            if !user_range_ok(buf, len) {
                return Err(EFAULT);
            }
            let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
            tihkali_hal::console::write_bytes(bytes);
            Ok(len as i64)
        }
        FdTarget::Pipe { slot, write_end: true } => {
            if pipe_end_count(slot, false) == 0 {
                // POSIX: EPIPE + SIGPIPE to the writer. The signal is
                // pending; the return choke terminates (DFL) or the
                // caller observes EPIPE (IGN/blocked).
                let cur = CURRENT.load(Ordering::Relaxed);
                table()[cur].as_mut().unwrap().pending |= 1 << 13; // SIGPIPE canonical
                return Err(EPIPE_L);
            }
            match file::pipe_write(slot, buf, len) {
                Ok(n) => {
                    // A reader may be asleep on this pipe.
                    wake_sleeping();
                    Ok(n as i64)
                }
                Err(e) => Err(e),
            }
        },
        FdTarget::Pipe { write_end: false, .. } => Err(EBADF),
        FdTarget::File(i) => {
            if !user_range_ok(buf, len) {
                return Err(EFAULT);
            }
            file::write_from_user(i, buf, len).map(|n| n as i64)
        }
        FdTarget::TtyIn => Err(EBADF),
    }
}

/// SYS_unlink(path): remove a regular file.
pub fn sys_unlink(path: &str) -> Result<(), u8> {
    crate::fs::remove_file(path)
}

/// SYS_rmdir(path): remove an empty directory.
pub fn sys_rmdir(path: &str) -> Result<(), u8> {
    crate::fs::remove_dir(path)
}

/// SYS_mkdir(path, mode): mode is accepted for ABI shape; FS uses 0755.
pub fn sys_mkdir(path: &str) -> Result<(), u8> {
    crate::fs::create_dir(path).map(|_| ())
}

/// SYS_sync: write-back every dirty node through the block device.
pub fn sys_sync() -> Result<(), u8> {
    match crate::fs::sync_to_disk() {
        Ok(0) => {
            kprintln!("sync: nothing dirty");
            Ok(())
        }
        Ok(n) => {
            kprintln!("sync: wrote {n} sectors to disk");
            Ok(())
        }
        Err(e) => {
            kprintln!("sync: failed (errno {e})");
            Err(e)
        }
    }
}

/// SYS_open(path, flags): O_RDONLY / O_WRONLY / O_RDWR with
/// O_CREAT/O_TRUNC/O_APPEND/O_EXCL (NetBSD values, verified).
pub fn sys_open(path: &str, flags: u64) -> Result<usize, u8> {
    let file_idx = file::open(path, flags)?;
    let t = table();
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = t[cur].as_mut().unwrap();
    let slot = match p.fds.iter().position(|f| f.is_none()) {
        Some(i) => i,
        None => {
            p.fds.push(None);
            p.fds.len() - 1
        }
    };
    p.fds[slot] = Some(FdTarget::File(file_idx));
    Ok(slot)
}

/// SYS___getdents30(fd, buf, len): directory enumeration.
pub fn sys_getdents(fd: usize, buf: u64, len: usize) -> Result<usize, u8> {
    let Some(FdTarget::File(i)) = current_target(fd) else { return Err(EBADF) };
    if len == 0 {
        return Ok(0);
    }
    if !user_range_ok(buf, len) {
        return Err(EFAULT);
    }
    file::getdents_to_user(i, buf, len)
}

/// Linux getdents64(61).
pub fn sys_getdents64(fd: usize, buf: u64, len: usize) -> Result<usize, u8> {
    let Some(FdTarget::File(i)) = current_target(fd) else { return Err(EBADF) };
    if len == 0 {
        return Ok(0);
    }
    if !user_range_ok(buf, len) {
        return Err(EFAULT);
    }
    file::getdents64_to_user(i, buf, len)
}

/// SYS_close(fd).
pub fn sys_close(fd: usize) -> Result<(), u8> {
    let t = table();
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = t[cur].as_mut().unwrap();
    let slot = p.fds.get_mut(fd).ok_or(EBADF)?;
    let Some(target) = slot.take() else { return Err(EBADF) };
    if let FdTarget::File(i) = target {
        file::close(i)?;
    }
    Ok(())
}

// ---------- signals ----------

pub fn write_user_u64(addr: u64, val: u64) -> bool {
    if !user_range_ok(addr, 8) {
        return false;
    }
    unsafe { (addr as *mut u64).write_volatile(val) };
    true
}

/// SYS_kill(pid, sig): set a pending signal; default-termination of a
/// sleeping target happens immediately (it would never reach a return
/// boundary otherwise).
pub fn sys_kill(pid: i64, sig: u64) -> Result<(), u8> {
    if !(1..NSIG as u64).contains(&sig) {
        return Err(EINVAL);
    }
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    // POSIX group semantics: pid 0 = caller's group, pid < 0 = pgrp -pid.
    let group: Option<usize> = if pid == 0 {
        Some(t[cur].as_ref().unwrap().pgrp)
    } else if pid < 0 {
        Some(-pid as usize)
    } else {
        None
    };
    let slots: alloc::vec::Vec<usize> = match group {
        Some(pgrp) => t
            .iter()
            .enumerate()
            .filter(|(_, o)| {
                o.as_ref()
                    .is_some_and(|p| p.pgrp == pgrp && p.state != State::Zombie)
            })
            .map(|(i, _)| i)
            .collect(),
        None => {
            let Some(slot) = t.iter().position(|o| {
                o.as_ref().is_some_and(|p| p.pid as i64 == pid && p.state != State::Zombie)
            }) else {
                return Err(ESRCH);
            };
            alloc::vec![slot]
        }
    };
    if slots.is_empty() {
        return Err(ESRCH);
    }
    for slot in slots {
        signal_one(slot, cur, sig);
    }
    Ok(())
}

/// Queue `sig` on `slot` with kill(2) semantics: running targets get the
/// pending bit (delivered at their return boundary), sleeping targets are
/// woken (catchable) or zombified at once (default-terminate) — otherwise
/// a sleeper would never reach a return boundary to notice.
fn signal_one(slot: usize, cur: usize, sig: u64) {
    let t = table();
    if slot == cur {
        t[cur].as_mut().unwrap().pending |= 1 << sig;
        return;
    }
    let action = t[slot].as_ref().unwrap().handlers[sig as usize];
    let term = sig == SIGKILL as u64 || (action == SIG_DFL && default_is_term(sig as usize));
    let pid = t[slot].as_ref().unwrap().pid;
    let p = t[slot].as_mut().unwrap();
    p.pending |= 1 << sig;
    let masked = (p.blocked >> sig) & 1 == 1;
    if p.state == State::Sleeping {
        if term && !masked {
            p.state = State::Zombie;
            p.exit_code = sig as i32;
            p.signaled = true;
            p.pending = 0;
            file::release_all(&p.fds);
            kprintln!("proc: pid {pid} killed by signal {sig}");
            wake_parent(slot);
        } else if action > SIG_IGN {
            // Catchable handler: wake so delivery happens on resume;
            // rewind ELR so the interrupted syscall re-executes after
            // the handler's sigreturn (restart semantics).
            p.frame.elr = p.frame.elr.wrapping_sub(4);
            p.state = State::Runnable;
        } else if !masked {
            // Unblocked but ignorable (SIG_IGN or DFL-ignore): discard
            // now — a sleeper would never reach a choke to clear it.
            p.pending &= !(1 << sig);
        }
        // Blocked + not terminating: keep pending, stay asleep; the
        // signal becomes deliverable when sigprocmask unblocks it.
    }
}

// ---------- job control: process groups + tty foreground ----------

/// tty foreground process group; None = never set via TIOCSPGRP.
/// ^C is dropped while unset (our own shell never establishes one).
static FG_PGRP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn fg_pgrp() -> Option<usize> {
    let v = FG_PGRP.load(Ordering::Relaxed);
    (v != usize::MAX).then_some(v)
}

pub fn set_fg_pgrp(pgrp: usize) {
    FG_PGRP.store(pgrp, Ordering::Relaxed);
}

/// tty ^C: SIGINT (canonical 2 — identical in both ABIs) to the
/// foreground process group. No-op while no group is established.
pub fn sigint_foreground() {
    let Some(fg) = fg_pgrp() else { return };
    let cur = CURRENT.load(Ordering::Relaxed);
    let slots: alloc::vec::Vec<usize> = table()
        .iter()
        .enumerate()
        .filter(|(_, o)| {
            o.as_ref()
                .is_some_and(|p| p.pgrp == fg && p.state != State::Zombie)
        })
        .map(|(i, _)| i)
        .collect();
    for slot in slots {
        signal_one(slot, cur, 2); // SIGINT
    }
}

/// Linux setpgid(pid, pgid): pid 0 = self, pgid 0 = make `pid` the leader.
/// V1: may change self or own children only (POSIX session checks skipped).
pub fn sys_setpgid(pid: i64, pgid: i64) -> Result<(), u8> {
    if pgid < 0 {
        return Err(EINVAL);
    }
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    let target_pid = if pid == 0 { t[cur].as_ref().unwrap().pid } else { pid as usize };
    let Some(slot) = t
        .iter()
        .position(|o| o.as_ref().is_some_and(|p| p.pid == target_pid && p.state != State::Zombie))
    else {
        return Err(ESRCH);
    };
    if slot != cur && t[slot].as_ref().unwrap().parent != cur {
        return Err(EPERM_L);
    }
    let new_pgrp = if pgid == 0 { target_pid } else { pgid as usize };
    t[slot].as_mut().unwrap().pgrp = new_pgrp;
    Ok(())
}

/// Linux getpgid(pid): pid 0 = self.
pub fn sys_getpgid(pid: i64) -> Result<usize, u8> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    let target = if pid == 0 { t[cur].as_ref().unwrap().pid } else { pid as usize };
    t.iter()
        .find(|o| o.as_ref().is_some_and(|p| p.pid == target && p.state != State::Zombie))
        .map(|o| o.as_ref().unwrap().pgrp)
        .ok_or(ESRCH)
}

/// Linux setsid(2): become session + group leader (v1: no session state,
/// just take own pgrp). EPERM if already a group leader.
pub fn sys_setsid() -> Result<usize, u8> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    let p = t[cur].as_mut().unwrap();
    if p.pgrp == p.pid {
        return Err(EPERM_L);
    }
    p.pgrp = p.pid;
    Ok(p.pid)
}

/// SYS___sigaction_sigtramp (340): install/inspect a handler.
/// `act` points at a NetBSD struct sigaction whose FIRST field is
/// sa_handler (verified layout); sa_mask/sa_flags ignored in v1, as are
/// the sigtramp arguments (we use our own trampoline page).
pub fn sys_sigaction(sig: u64, act: u64, oact: u64) -> Result<usize, u8> {
    if !(1..NSIG as u64).contains(&sig) {
        return Err(EINVAL);
    }
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    let old = t[cur].as_ref().unwrap().handlers[sig as usize];
    if oact != 0 && !write_user_u64(oact, old as u64) {
        return Err(EFAULT);
    }
    if act != 0 {
        let handler = read_user_u64(act).ok_or(EFAULT)?;
        if handler > 1 && !user_range_ok(handler, 1) {
            return Err(EFAULT); // handler must point into user space
        }
        t[cur].as_mut().unwrap().handlers[sig as usize] = handler as usize;
    }
    Ok(old)
}

/// SYS___sigprocmask14 (293): POSIX signal mask (sigset_t's first 8 bytes
/// cover signals 1..31; SIG_BLOCK=1, SIG_UNBLOCK=2, SIG_SETMASK=3).
pub fn sys_sigprocmask(how: i64, set: u64, oset: u64) -> Result<(), u8> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    let old = t[cur].as_ref().unwrap().blocked;
    if oset != 0 && !write_user_u64(oset, old) {
        return Err(EFAULT);
    }
    if set != 0 {
        let m = read_user_u64(set).ok_or(EFAULT)?;
        let new = match how {
            1 => old | m,        // SIG_BLOCK
            2 => old & !m,       // SIG_UNBLOCK
            3 => m,              // SIG_SETMASK
            _ => return Err(EINVAL),
        };
        // SIGKILL is never blockable; bit0 is unused.
        t[cur].as_mut().unwrap().blocked = new & !((1 << 9) | 1);
    }
    Ok(())
}

/// SYS_sigreturn (295 / 103): restore the frame pushed by delivery.
/// Frame: x0..x30, elr, spsr (264 bytes) at the user SP.
pub fn sys_sigreturn(frame: &mut TrapFrame) {
    // Layout coupled by hand to install_handler_frame (34 slots).
    const SAVED: usize = 34 * 8;
    let sp = read_sp_el0() as usize;
    if !user_range_ok(sp as u64, SAVED) {
        terminate(frame, SIGKILL as u64, true);
        return;
    }
    let saved_blocked = unsafe { *((sp + 33 * 8) as *const u64) };
    unsafe {
        let src = sp as *const u64;
        for i in 0..31 {
            frame.x[i] = src.add(i).read_volatile();
        }
        frame.elr = src.add(31).read_volatile();
        let spsr = src.add(32).read_volatile();
        frame.spsr = spsr & !0xf; // sanitize: force EL0t
    }
    write_sp_el0((sp + SAVED) as u64);
    let cur = CURRENT.load(Ordering::Relaxed);
    if let Some(p) = table()[cur].as_mut() {
        // Restore the mask the signal interrupted (SIGKILL never blockable).
        p.blocked = saved_blocked & !((1 << 9) | 1);
    }
}

/// Deliver pending signals to the current process. Called at every
/// return-to-EL0 choke point; `frame` may be replaced (handler entry) or
/// scheduled away (termination).
pub fn deliver_signals(frame: &mut TrapFrame) {
    if frame.spsr & 0xf != 0 {
        return; // kernel context, not EL0
    }
    for _ in 0..NSIG {
        let cur = CURRENT.load(Ordering::Relaxed);
        let Some(p) = table()[cur].as_ref() else { return };
        let deliverable = p.pending & !p.blocked;
        if deliverable == 0 {
            return;
        }
        let sig = deliverable.trailing_zeros() as usize;
        if sig == 0 || sig >= NSIG {
            return;
        }
        let action = p.handlers[sig];

        if sig == SIGKILL || (action == SIG_DFL && default_is_term(sig)) {
            terminate(frame, sig as u64, true);
            return;
        }
        if action == SIG_DFL || action == SIG_IGN {
            // Default-ignore (e.g. USR-less signals) or explicit IGN.
            table()[cur].as_mut().unwrap().pending &= !(1 << sig);
            continue;
        }
        install_handler_frame(frame, sig, action);
        return;
    }
}

// ---------- signal-number ABI mapping (canonical = NetBSD) ----------

/// Linux signo -> canonical (NetBSD) index; None = unsupported.
/// Divergent pairs (asm-generic vs NetBSD signal.h): BUS 7<->10,
/// USR1 10<->30, USR2 12<->31, SYS 31<->12, CHLD 17<->20, CONT 18<->19,
/// STOP 19<->17, TSTP 20<->18, URG 23<->16, IO 29<->23, PWR 30<->32.
/// Linux STKFLT(16) has no NetBSD counterpart -> EINVAL.
pub fn sig_from_user(sig: i64, linux: bool) -> Option<usize> {
    if !linux {
        return if (1..NSIG as i64).contains(&sig) {
            Some(sig as usize)
        } else {
            None
        };
    }
    let c = match sig {
        7 => 10,  // BUS
        10 => 30, // USR1
        12 => 31, // USR2
        16 => return None, // STKFLT: no NetBSD equivalent
        17 => 20, // CHLD
        18 => 19, // CONT
        19 => 17, // STOP
        20 => 18, // TSTP
        23 => 16, // URG
        29 => 23, // IO
        30 => 32, // PWR
        31 => 12, // SYS
        s if (1..NSIG as i64).contains(&s) => s as _,
        _ => return None,
    };
    Some(c)
}

/// canonical -> Linux signo (for handler entry / wait4 status / oldact).
pub fn sig_to_user(canonical: usize, linux: bool) -> i64 {
    if !linux {
        return canonical as i64;
    }
    match canonical {
        10 => 7,  // BUS
        30 => 10, // USR1
        31 => 12, // USR2
        12 => 31, // SYS
        20 => 17, // CHLD
        19 => 18, // CONT
        17 => 19, // STOP
        18 => 20, // TSTP
        16 => 23, // URG
        23 => 29, // IO
        32 => 30, // PWR
        // Identity for the rest; canonical EMT(7) maps to Linux BUS —
        // no Linux EMT exists and the kernel never raises it.
        s => s as i64,
    }
}

/// Record that the process talks the Linux signal ABI (set on every
/// Linux svc entry and by rt_sigaction).
pub fn note_signal_abi(linux: bool) {
    let cur = CURRENT.load(Ordering::Relaxed);
    if let Some(p) = table()[cur].as_mut() {
        if p.sig_linux != linux {
            p.sig_linux = linux;
        }
    }
}

/// Push the interrupted context onto the user stack and enter the handler:
/// x0 = signal, x30 = sigreturn trampoline, fresh EL0 context.
fn install_handler_frame(frame: &mut TrapFrame, sig: usize, handler: usize) {
    // Layout (coupled by hand to sys_sigreturn): x0..x30 (slots 0..30),
    // elr (31), spsr (32), caller's `blocked` mask (33).
    const SAVED: usize = 34 * 8;
    let cur = CURRENT.load(Ordering::Relaxed);
    let sp = read_sp_el0() as usize;
    let Some(new_sp) = sp.checked_sub(SAVED) else {
        terminate(frame, SIGKILL as u64, true);
        return;
    };
    if !user_range_ok(new_sp as u64, SAVED) {
        terminate(frame, SIGKILL as u64, true);
        return;
    }
    let old_blocked = table()[cur].as_ref().unwrap().blocked;
    unsafe {
        let dst = new_sp as *mut u64;
        for i in 0..31 {
            dst.add(i).write_volatile(frame.x[i]);
        }
        dst.add(31).write_volatile(frame.elr);
        dst.add(32).write_volatile(frame.spsr);
        dst.add(33).write_volatile(old_blocked);
    }
    write_sp_el0(new_sp as u64);
    {
        let p = table()[cur].as_mut().unwrap();
        p.pending &= !(1 << sig);
        // POSIX default: the delivered signal is blocked while its
        // handler runs (SA_NODEFER unsupported v1) — prevents the same
        // signal from recursively re-entering the handler.
        p.blocked |= 1 << sig;
    }
    let linux_abi = table()[cur].as_mut().unwrap().sig_linux;

    let mut x = [0u64; 31];
    x[0] = sig_to_user(sig, linux_abi) as u64;
    x[30] = crate::user::TRAMPOLINE as u64;
    *frame = TrapFrame {
        x,
        elr: handler as u64,
        spsr: 0, // EL0t, interrupts enabled in the handler
        esr: 0,
    };
}

// ---------- brk / mmap (Linux ABI arenas) ----------

/// (brk, mmap_next) of the running process — consulted by the page-fault
/// handler to demand-map arena growth in the text window.
pub fn current_arenas() -> (u64, u64) {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_ref().expect("no current process");
    (p.brk, p.mmap_next)
}

/// Linux brk(214): x0 == 0 queries; otherwise request a new break inside
/// [brk_start, MMAP_FLOOR). Returns the current break on refusal.
pub fn sys_brk(addr: u64) -> u64 {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().unwrap();
    if addr == 0 {
        return p.brk;
    }
    let ok = addr >= p.brk_start && addr <= user::MMAP_FLOOR as u64;
    tihkali_hal::kprintln!("sys_brk: req={addr:#x} start={:#x} floor={:#x} ok={ok}", p.brk_start, user::MMAP_FLOOR);
    if ok {
        p.brk = addr;
    }
    p.brk
}

/// Linux mmap(222): anonymous bumps only (v1) — returns the arena base;
/// pages materialize on first touch via the fault handler.
pub fn sys_mmap(len: u64) -> Result<u64, u8> {
    let pages = len.checked_add(0xfff).map(|v| v & !0xfff).ok_or(EINVAL)?;
    if pages == 0 {
        return Err(EINVAL);
    }
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().unwrap();
    let base = if p.mmap_next == 0 {
        user::MMAP_FLOOR as u64
    } else {
        p.mmap_next
    };
    let end = base + pages;
    if end > user::USER_TEXT_LIMIT as u64 {
        return Err(ENOMEM);
    }
    p.mmap_next = end;
    Ok(base)
}

/// Linux munmap(215): drop present pages in [addr, addr+len) of the text
/// window; the arena bump pointer is not shrunk (v1).
pub fn sys_munmap(addr: u64, len: u64) -> Result<(), u8> {
    if addr % 4096 != 0 || len == 0 {
        return Err(EINVAL);
    }
    let ttbr: usize;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nomem, nostack));
    }
    vm::unmap(ttbr, addr, len).map_err(|_| EINVAL)
}

/// Linux mprotect(226): adjust perms of present pages in the range.
pub fn sys_mprotect(addr: u64, len: u64, prot: u64) -> Result<(), u8> {
    if addr % 4096 != 0 || len == 0 {
        return Err(EINVAL);
    }
    let ttbr: usize;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nomem, nostack));
    }
    vm::set_perms(ttbr, addr, len, prot as u32).map_err(|_| EINVAL)
}

// ---------- pipes / dup3 / misc (Linux personality entry points) ----------

/// How many live fds reference this pipe's read or write ends?
pub fn pipe_end_count(slot: usize, write_end: bool) -> usize {
    let t = table();
    t.iter()
        .flatten()
        .flat_map(|p| p.fds.iter())
        .filter(|f| matches!(f, Some(FdTarget::Pipe { slot: s, write_end: w }) if *s == slot && *w == write_end))
        .count()
}

/// pipe2(2): create an anonymous pipe; returns the two fds.
pub fn sys_pipe2(pipefd: u64) -> Result<(), u8> {
    if !user_range_ok(pipefd, 8) {
        return Err(EFAULT);
    }
    let slot = file::pipe_create()?;
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().unwrap();
    let take_fd = |p: &mut crate::proc::Process| -> usize {
        match p.fds.iter().position(|f| f.is_none()) {
            Some(i) => i,
            None => {
                p.fds.push(None);
                p.fds.len() - 1
            }
        }
    };
    let r = take_fd(p);
    p.fds[r] = Some(FdTarget::Pipe { slot, write_end: false });
    let w = take_fd(p);
    p.fds[w] = Some(FdTarget::Pipe { slot, write_end: true });
    unsafe {
        (pipefd as *mut i32).add(0).write_volatile(r as i32);
        (pipefd as *mut i32).add(1).write_volatile(w as i32);
    }
    Ok(())
}

/// dup3(oldfd, newfd, flags): copy an fd into slot `newfd` (closing it).
pub fn sys_dup3(oldfd: i64, newfd: i64) -> Result<usize, u8> {
    if newfd < 0 || newfd > 1024 {
        return Err(EINVAL);
    }
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().unwrap();
    let target = p
        .fds
        .get(oldfd as usize)
        .copied()
        .flatten()
        .ok_or(EBADF)?;
    if oldfd == newfd {
        return Ok(newfd as usize);
    }
    while p.fds.len() <= newfd as usize {
        p.fds.push(None);
    }
    if let Some(old) = p.fds[newfd as usize].take() {
        if let FdTarget::File(i) = old {
            let _ = file::close(i);
        }
    }
    if let FdTarget::File(i) = target {
        file::dup(i);
    }
    p.fds[newfd as usize] = Some(target);
    Ok(newfd as usize)
}

/// fcntl(F_DUPFD): duplicate into the lowest free slot >= min.
pub fn sys_dupfd(oldfd: i64, min: i64) -> Result<usize, u8> {
    if min < 0 || min > 1024 {
        return Err(EINVAL);
    }
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().unwrap();
    let target = p.fds.get(oldfd as usize).copied().flatten().ok_or(EBADF)?;
    while p.fds.len() <= min as usize {
        p.fds.push(None);
    }
    let slot = (min as usize..p.fds.len())
        .find(|&i| p.fds[i].is_none())
        .ok_or(EINVAL)?;
    if let FdTarget::File(i) = target {
        file::dup(i);
    }
    p.fds[slot] = Some(target);
    Ok(slot)
}

/// Parent pid for getppid (0 when init).
pub fn current_ppid() -> i64 {
    let t = table();
    let cur = CURRENT.load(Ordering::Relaxed);
    match t[cur].as_ref() {
        Some(p) if p.parent != NO_PARENT && p.parent < t.len() => {
            t[p.parent].as_ref().map_or(0, |q| q.pid as i64)
        }
        _ => 0,
    }
}
