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
pub const ENOMEM: u8 = 12;
pub const EINVAL: u8 = 22;

/// Signal support (v1): no masks, no SA_* flags, synchronous delivery at
/// every return-to-EL0 boundary.
pub const NSIG: usize = 32; // signals 1..31
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
const SIGKILL: usize = 9;

/// Signals whose default action is process termination.
fn default_is_term(sig: usize) -> bool {
    matches!(sig, 1 | 2 | 3 | 9 | 15 | 30 | 31) // HUP INT QUIT KILL TERM USR1 USR2
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
pub fn init(entry: usize, tables: Vec<usize>) {
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
    }));
    CURRENT.store(0, Ordering::Relaxed);
    NEXT_PID.store(1, Ordering::Relaxed);
}

/// Save the outgoing context (held in `frame`) into its process, pick the
/// next Runnable process round-robin, and load its context. Returns false
/// when nothing is runnable (caller enters kernel idle).
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
        switch_ttbr(p.tables[0]);
        *frame = p.frame;
        IDLE.store(false, Ordering::Relaxed);
        return true;
    }
    false
}

/// Signals that are pending AND not blocked (what delivery would act on).
fn has_deliverable() -> bool {
    let cur = CURRENT.load(Ordering::Relaxed);
    table()
        .get(cur)
        .and_then(|p| p.as_ref())
        .is_some_and(|p| (p.pending & !p.blocked) != 0)
}

/// Block the current process until someone wakes it (rewind-on-wake).
pub fn sleep_current(frame: &mut TrapFrame) {
    table()[CURRENT.load(Ordering::Relaxed)]
        .as_mut()
        .unwrap()
        .state = State::Sleeping;
    if !schedule(frame) {
        let idle: extern "C" fn() -> ! = crate::kernel_idle;
        frame.elr = idle as *const () as u64;
        frame.spsr = 0x345;
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
    // (pending does not).
    let handlers = t[cur].as_ref().unwrap().handlers;
    let blocked = t[cur].as_ref().unwrap().blocked;
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
                (c.exit_code as u32) & 0x7f // killed-by-signal encoding
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
    let entry = match loaded {
        Ok(e) => e,
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
        // POSIX: caught dispositions reset to DFL across exec; pending cleared.
        p.handlers = [SIG_DFL; NSIG];
        p.pending = 0;
    }
    frame.elr = entry as u64;
    frame.spsr = 0; // EL0t, interrupts on
    frame.x[0] = argc;
    frame.x[1] = argv;
    write_sp_el0(sp);
    kprintln!("proc: exec {path} argc={argc} entry={entry:#x}");
    Ok(())
}

/// Lay out argv strings + NULL-terminated pointer array at the top of the
/// user stack region. Returns (argc, argv_ptr, initial_sp).
fn place_argv(args: &[Vec<u8>]) -> Option<(u64, u64, u64)> {
    if args.len() > 16 {
        return None;
    }
    let mut cursor: u64 = user::USER_LIMIT as u64;
    let mut ptrs = [0u64; 17];
    for (i, a) in args.iter().enumerate() {
        cursor = cursor.checked_sub(a.len() as u64 + 1)?;
        unsafe {
            core::ptr::copy_nonoverlapping(a.as_ptr(), cursor as *mut u8, a.len());
            *((cursor as usize + a.len()) as *mut u8) = 0;
        }
        ptrs[i] = cursor;
    }
    let arr_len = 8 * (args.len() + 1);
    cursor = cursor.checked_sub(arr_len as u64)?;
    cursor &= !0xfu64; // 16-byte stack alignment
    unsafe {
        let base = cursor as *mut u64;
        for i in 0..=args.len() {
            base.add(i).write_volatile(ptrs[i]);
        }
    }
    Some((args.len() as u64, cursor, cursor))
}

// ---------- file-descriptor I/O ----------

pub enum Io {
    Val(i64),  // value returned in x0 (success)
    Err(u8),   // errno (carry set)
    Slept,     // blocked; skip the syscall epilogue
}

fn current_target(fd: usize) -> Option<FdTarget> {
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
    let Some(slot) = t
        .iter()
        .position(|o| o.as_ref().is_some_and(|p| p.pid as i64 == pid && p.state != State::Zombie))
    else {
        return Err(ESRCH);
    };

    if slot == cur {
        t[cur].as_mut().unwrap().pending |= 1 << sig;
        return Ok(()); // delivered at this syscall's return boundary
    }

    let action = t[slot].as_ref().unwrap().handlers[sig as usize];
    let term = sig == SIGKILL as u64 || (action == SIG_DFL && default_is_term(sig as usize));
    {
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
                wake_parent(slot);
            } else if action > SIG_IGN {
                // Catchable signal: wake so delivery happens on resume.
                // Rewind ELR so an interrupted syscall re-executes after
                // the handler's sigreturn (restart semantics).
                p.frame.elr = p.frame.elr.wrapping_sub(4);
                p.state = State::Runnable;
            } else {
                p.state = State::Runnable; // IGN by default: wake on resume
                p.frame.elr = p.frame.elr.wrapping_sub(4);
            }
        }
    }
    Ok(())
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
    const SAVED: usize = 33 * 8;
    let sp = read_sp_el0() as usize;
    if !user_range_ok(sp as u64, SAVED) {
        terminate(frame, SIGKILL as u64, true);
        return;
    }
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

/// Push the interrupted context onto the user stack and enter the handler:
/// x0 = signal, x30 = sigreturn trampoline, fresh EL0 context.
fn install_handler_frame(frame: &mut TrapFrame, sig: usize, handler: usize) {
    const SAVED: usize = 33 * 8; // x0..x30, elr, spsr
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
    unsafe {
        let dst = new_sp as *mut u64;
        for i in 0..31 {
            dst.add(i).write_volatile(frame.x[i]);
        }
        dst.add(31).write_volatile(frame.elr);
        dst.add(32).write_volatile(frame.spsr);
    }
    write_sp_el0(new_sp as u64);
    table()[cur].as_mut().unwrap().pending &= !(1 << sig);

    let mut x = [0u64; 31];
    x[0] = sig as u64;
    x[30] = crate::user::TRAMPOLINE as u64;
    *frame = TrapFrame {
        x,
        elr: handler as u64,
        spsr: 0, // EL0t, interrupts enabled in the handler
        esr: 0,
    };
}
