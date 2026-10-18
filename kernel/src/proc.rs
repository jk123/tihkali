//! Process table and round-robin scheduler (single core).
//!
//! All EL0 exceptions are handled on one shared kernel stack; scheduling
//! works by swapping the trap frame + SP_EL0 + TTBR0 in `schedule()` and
//! letting the asm `RESTORE_FRAME`/`eret` land in the next process.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::string::String;
use alloc::vec::Vec;
use crate::kprintln;

use crate::arch::trap::TrapFrame;
use crate::file::{self, FdTarget, EACCES, EBADF, EFAULT, EINTR, ESRCH};
use crate::fs;
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
    /// Working directory, always absolute and normalized. Relative paths
    /// resolve against it; getcwd reports it.
    pub cwd: String,
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
    /// PROT_* requested for each mmap'd range. The pages themselves are
    /// demand-paged, so the permissions cannot live in the PTEs until the
    /// first touch -- they are recorded here and applied by
    /// `vm::map_page` when the page is built.
    pub mmap_perms: Vec<(u64, u64, u32)>,
    /// Dispositions were installed via the Linux ABI (signal numbers seen
    /// by the handler must be converted back from canonical/NetBSD).
    pub sig_linux: bool,
    /// Process group (job control); children inherit it. ^C targets the
    /// tty's foreground group.
    pub pgrp: usize,
    /// Real/effective uid and gid, plus the saved set-uid values. Single
    /// user, but recorded per process so chown/seteuid have somewhere real
    /// to write and getuid cannot be answered by a constant.
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    /// Supplementary group list (getgroups/setgroups).
    pub groups: Vec<u32>,
    /// umask applied to newly created files/dirs. Reported by umask(2),
    /// which returns the PREVIOUS value.
    pub umask: u16,
    /// Session id; set by setsid, otherwise the pid at exec time.
    pub sess: usize,
    /// Real counters getrusage(2) can report. Counting these means the
    /// struct carries measured values rather than a row of plausible
    /// zeros -- which is indistinguishable from "not measured".
    pub nvcsw: u64,
    pub nivcsw: u64,
    pub nsignals: u64,
    pub inblock: u64,
    pub oublock: u64,
    /// RLIMIT_NOFILE (and the rest): soft/hard pairs, 12 resources per
    /// RLIM_NLIMITS. Stored per process so setrlimit has somewhere real to
    /// write and getrlimit does not have to answer from a constant.
    pub rlimits: [[u64; 2]; 12],
    /// Absolute tick deadline while sleeping in a timed syscall
    /// (ppoll/nanosleep); None for untimed sleeps.
    pub wake_at: Option<u64>,
    /// Saved TPIDR_EL0 (user TLS anchor). musl CRTs rewrite the register
    /// on exec; without per-process save/restore a child's exec leaves
    /// every other process reading TLS through a dangling pointer.
    pub tpidr: u64,
    /// setitimer(ITIMER_REAL): absolute tick deadline, armed when the
    /// process's own timer fires SIGALRM. None = no timer set.
    pub itimer_at: Option<u64>,
    /// setitimer(ITIMER_REAL) repeat period in ticks, from it_interval.
    /// Some(0) = one-shot (interval zero); None = no timer set.
    pub itimer_iv: Option<u64>,
    /// kqueue registrations owned by this process. Execve clears it.
    pub kregs: Vec<Kevent>,
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

// ---------- credentials (single-user, but per-process so the setters
// have somewhere real to write) ----------

pub fn set_credentials(uid: u32, gid: u32) {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().expect("no current process");
    p.uid = uid;
    p.euid = uid;
    p.gid = gid;
    p.egid = gid;
}

pub fn set_reuid(ruid: u32, euid: u32) {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().expect("no current process");
    p.uid = ruid;
    p.euid = euid;
}

pub fn set_regid(rgid: u32, egid: u32) {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().expect("no current process");
    p.gid = rgid;
    p.egid = egid;
}

pub fn set_fchown_credentials(uid: u32, gid: u32) {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut().expect("no current process");
    if uid != u32::MAX {
        p.uid = uid;
    }
    if gid != u32::MAX {
        p.gid = gid;
    }
}

pub fn get_credential(which: u32) -> u32 {
    let cur = CURRENT.load(Ordering::Relaxed);
    match table()[cur].as_ref() {
        Some(p) => match which {
            0 => p.uid,
            1 => p.euid,
            2 => p.gid,
            _ => p.egid,
        },
        None => 0,
    }
}

/// getgroups(2): writes the supplementary list and returns its length, or
/// -1 if the buffer is too small. A caller that sizes the buffer wrong gets
/// an error rather than a silently truncated list.
pub fn get_groups(buf: u64, len: usize) -> Result<usize, u8> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let n = table()[cur].as_ref().map(|p| p.groups.len()).unwrap_or(0);
    if len < n {
        return Err(34); // EINVAL
    }
    if n == 0 {
        return Ok(0);
    }
    if !user_range_ok(buf, n * 4) {
        return Err(EFAULT);
    }
    let gs = table()[cur].as_ref().unwrap().groups.clone();
    for (i, g) in gs.iter().enumerate() {
        if !write_user_i32((buf + (i * 4) as u64) as usize, *g as i32) {
            return Err(EFAULT);
        }
    }
    Ok(n)
}

pub fn set_groups(buf: u64, len: usize) -> Result<(), u8> {
    let cur = CURRENT.load(Ordering::Relaxed);
    if !user_range_ok(buf, len.saturating_mul(4)) {
        return Err(EFAULT);
    }
    let mut gs = Vec::new();
    for i in 0..len {
        match read_user_i32(buf + (i * 4) as u64) {
            Some(v) => gs.push(v as u32),
            None => return Err(EFAULT),
        }
    }
    table()[cur].as_mut().unwrap().groups = gs;
    Ok(())
}

/// umask(2) returns the PREVIOUS mask and installs the new one.
pub fn sys_umask(new_mask: u16) -> u16 {
    let cur = CURRENT.load(Ordering::Relaxed);
    match table()[cur].as_mut() {
        Some(p) => {
            let old = p.umask;
            p.umask = new_mask & 0o777;
            old
        }
        None => 0,
    }
}

pub fn current_umask() -> u16 {
    let cur = CURRENT.load(Ordering::Relaxed);
    table()[cur].as_ref().map(|p| p.umask).unwrap_or(0)
}

pub fn set_pgrp(pid: usize) {
    let cur = CURRENT.load(Ordering::Relaxed);
    if let Some(p) = table()[cur].as_mut() {
        p.pgrp = pid;
    }
}

/// Process group of the running process.
pub fn current_pgrp() -> usize {
    table()[CURRENT.load(Ordering::Relaxed)]
        .as_ref()
        .map(|p| p.pgrp)
        .unwrap_or(0)
}

/// RLIM_NLIMITS = 12. Unlimited is (u64::MAX, u64::MAX), matching the
/// RLIM_INFINITY a caller would pass.
fn default_rlimits() -> [[u64; 2]; 12] {
    [[u64::MAX; 2]; 12]
}

/// Give up the CPU without a deadline. The process is marked Sleeping
/// then made Runnable again, so `schedule` skips it and picks someone
/// else; when it comes back round the syscall re-executes.
pub fn yield_now(frame: &mut TrapFrame) {
    sleep_current(frame);
    let cur = CURRENT.load(Ordering::Relaxed);
    if let Some(p) = table().get_mut(cur).and_then(|s| s.as_mut()) {
        p.state = State::Runnable;
    }
    let _ = frame;
}

/// The kernel's hostname. Single core, and every access is from a
/// syscall with interrupts masked, so the same UnsafeCell pattern the
/// pipe and socket pools use is sufficient here.
struct HostnameCell(UnsafeCell<String>);
unsafe impl Sync for HostnameCell {}
static HOSTNAME: HostnameCell = HostnameCell(UnsafeCell::new(String::new()));

pub fn hostname() -> String {
    unsafe { (*HOSTNAME.0.get()).clone() }
}

pub fn set_hostname(name: String) {
    unsafe { *HOSTNAME.0.get() = name };
}

pub fn session_of(pid: usize) -> usize {
    table().get(pid).and_then(|s| s.as_ref()).map_or(0, |p| p.sess)
}

/// Count a voluntary context switch for the process being switched out.
fn count_nvcsw(pid: usize) {
    if let Some(p) = table().get_mut(pid).and_then(|s| s.as_mut()) {
        p.nvcsw += 1;
    }
}

/// Count a signal delivery against the process receiving it.
pub fn count_signal(pid: usize) {
    if let Some(p) = table().get_mut(pid).and_then(|s| s.as_mut()) {
        p.nsignals += 1;
    }
}

/// Snapshot of the counters getrusage reports, as (nvcsw, nivcsw,
/// nsignals, inblock, oublock).
pub fn usage_of(pid: usize) -> (u64, u64, u64, u64, u64) {
    match table().get(pid).and_then(|s| s.as_ref()) {
        Some(p) => (p.nvcsw, p.nivcsw, p.nsignals, p.inblock, p.oublock),
        None => (0, 0, 0, 0, 0),
    }
}

/// getrlimit/setrlimit on the current process. `which` outside
/// RLIM_NLIMITS is EINVAL rather than silently ignored -- a caller that
/// set RLIMIT_NOFILE and read back a different resource would never know.
pub fn get_rlimit(which: usize) -> Result<(u64, u64), u8> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_ref().ok_or(3)?; // ESRCH
    let r = p.rlimits.get(which).ok_or(22)?;
    Ok((r[0], r[1]))
}

pub fn set_rlimit(which: usize, cur: u64, max: u64) -> Result<(), u8> {
    let cur_slot = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur_slot].as_mut().ok_or(3)?;
    let Some(slot) = p.rlimits.get_mut(which) else {
        return Err(22); // EINVAL
    };
    // The hard limit cannot be raised by an unprivileged caller, and the
    // soft limit may never exceed the hard one. Both are checked so a
    // later getrlimit cannot report a limit the kernel would not honour.
    if cur > max {
        return Err(22); // EINVAL
    }
    if max > slot[1] {
        return Err(EPERM_L);
    }
    *slot = [cur, max];
    Ok(())
}

pub fn current_pid() -> usize {
    table()[CURRENT.load(Ordering::Relaxed)].as_ref().map_or(0, |p| p.pid)
}

/// Table index of the running process (the proc-table slot, not the
/// guest-visible pid).
pub fn current_slot() -> usize {
    CURRENT.load(Ordering::Relaxed)
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
        cwd: String::from("/"),
        pending: 0,
        handlers: [SIG_DFL; NSIG],
        signaled: false,
        blocked: 0,
        brk_start: brk,
        brk,
        mmap_next: 0,
        mmap_perms: Vec::new(),
        sig_linux: false,
        pgrp: 0,
        // Single-user kernel: everyone is uid/gid 0, which is also what
        // every existing arm already reported.
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        groups: Vec::new(),
        umask: 0o022,
        sess: 0,
        nvcsw: 0,
        nivcsw: 0,
        nsignals: 0,
        inblock: 0,
        oublock: 0,
        rlimits: default_rlimits(),
        wake_at: None,
        tpidr: crate::user::TPIDR_VAL,
        itimer_at: None,
        itimer_iv: None,
        // fork(2) does not inherit kqueue registrations.
        kregs: Vec::new(),
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
            // `cur` was found RUNNABLE, so this really is the same context
            // already in `frame` and nothing was switched. `sleep_inner`
            // has already set State::Sleeping, so this branch only runs
            // when the caller is NOT sleeping -- a genuine no-op yield.
            return true;
        }
        // A real switch: this process gave up the CPU and will be woken
        // by someone else. That is exactly what ru_nvcsw counts, and
        // without this getrusage reports a structurally plausible row of
        // zeros.
        count_nvcsw(cur);
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

/// Queue `sig` (1..32) as pending on pid `pid` (no delivery here — the
/// delivery boundary `deliver_signals` / next svc tail picks it up).
#[allow(dead_code)]
pub fn raise(pid: usize, sig: u8) {
    let t = table();
    let p = t.get_mut(pid).and_then(|slot| slot.as_mut());
    if let Some(p) = p {
        p.pending |= 1u64 << sig;
    }
}

/// Set `sig` pending on the current process (delivery at the next
/// svc-tail / tick boundary, like `raise`).
#[allow(dead_code)]
pub fn self_raise(sig: u8) {
    let cur = CURRENT.load(Ordering::Relaxed);
    raise(cur, sig);
}

/// Arm or clear the current process's ITIMER_REAL deadline. `None`
/// disarms. `iv` is the repeat period in ticks: `Some(0)` one-shots,
/// `Some(n)` re-arms n ticks after each SIGALRM. Returns the previous
/// deadline (for the setitimer out-param).
/// The armed itimer as (deadline_ticks, interval_ticks), for getitimer(2).
pub fn proc_get_itimer(pid: usize) -> (Option<u64>, Option<u64>) {
    match table().get(pid).and_then(|slot| slot.as_ref()) {
        Some(p) => (p.itimer_at, p.itimer_iv),
        None => (None, None),
    }
}

pub fn proc_set_itimer(pid: usize, at: Option<u64>, iv: Option<u64>) -> Option<u64> {
    let t = table();
    let p = t.get_mut(pid).and_then(|slot| slot.as_mut()).expect("process exists");
    let prev = p.itimer_at;
    p.itimer_at = at;
    p.itimer_iv = if at.is_some() { iv } else { None };
    prev
}

/// Absolute timer ticks now (wraps to i64 at the 2^62 boundary, ~5.8e11
/// ticks at 62.5 MHz — the EL1 time rule: use the raw counter, not TICKS).
pub fn arch_timer_now() -> u64 {
    crate::arch::timer::now()
}

/// Ticks per second (the timer frequency).
pub fn arch_timer_hz() -> u64 {
    crate::arch::timer::hz()
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

/// True when a sleep deadline is armed and has not yet expired. A poll-like
/// caller uses this to arm ONCE and keep the deadline across the many
/// re-entries an event-driven sleep produces, instead of re-arming to
/// `now + timeout` on every wake -- which would postpone the timeout
/// indefinitely under a steady event rate.
pub fn deadline_pending() -> bool {
    let cur = CURRENT.load(Ordering::Relaxed);
    table()[cur].as_ref().map(|p| p.wake_at.is_some()).unwrap_or(false)
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

/// Re-arm the timer in `slot` after its event was DELIVERED. Called from
/// the harvest loop, never from the readiness test: re-arming inside
/// `kq_timer_ready` would reset the deadline before the event was ever
/// reported, so a caller that parks would be woken by a timer that had
/// already been accounted for and would never see it. Re-armed from NOW,
/// not from the old deadline, so a caller that slept for many periods gets
/// one event rather than a burst of catch-ups.
pub fn kq_timer_fired(slot: usize) {
    let cur = CURRENT.load(Ordering::Relaxed);
    let now = arch_timer_now();
    if let Some(p) = table()[cur].as_mut() {
        if let Some(k) = p.kregs.get_mut(slot) {
            if k.filter == EVFILT_TIMER {
                k.timer_at = now;
            }
        }
    }
}

/// Earliest pending EVFILT_TIMER deadline for the current process, as an
/// absolute tick. Used to cap how long kevent parks: a timer that is due
/// sooner than the caller's timeout must be able to wake it.
pub fn kq_next_timer() -> Option<u64> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_ref()?;
    let now = arch_timer_now();
    p.kregs
        .iter()
        .filter(|k| k.filter == EVFILT_TIMER && k.flags & EV_DISABLE == 0)
        .map(|k| k.timer_at.saturating_add(k.timer_period).max(now))
        .min()
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

/// Fire SIGALRM on every process whose setitimer(ITIMER_REAL) deadline
/// has passed; the tick IRQ calls this alongside `wake_expired`.
pub fn wake_itimers() {
    let now = crate::arch::timer::now();
    let t = table();
    for o in t.iter_mut() {
        if let Some(p) = o {
            if let Some(at) = p.itimer_at {
                if now >= at {
                    // Re-arm by the interval so periodic alarms keep
                    // firing; a zero interval is a true one-shot.
                    p.itimer_at = match p.itimer_iv {
                        Some(iv) if iv > 0 => Some(at + iv),
                        _ => None,
                    };
                    p.pending |= 1u64 << 14; // SIGALRM (canonical 14)
                    // A deliverable signal must resume a process blocked in
                    // a syscall, or the handler never runs: a timer alarm
                    // that lands on a sleeping process would otherwise sit in
                    // `pending` until unrelated I/O happened to wake it.
                    if p.state == State::Sleeping {
                        p.state = State::Runnable;
                        p.frame.elr = p.frame.elr.wrapping_sub(4);
                    }
                }
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
        #[cfg(feature = "net")]
        if let FdTarget::Socket(slot) = target {
            crate::net::sock_ref_inc(*slot);
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
        cwd: t[cur].as_ref().unwrap().cwd.clone(),
        pending: 0,
        handlers,
        signaled: false,
        blocked,
        brk_start,
        brk,
        mmap_next,
        // COPIED, not cleared: these describe the address space the child
        // just inherited, and `arena_prot` is consulted on the child's
        // own page-table entries. Clearing them makes a PROT_READ page
        // look unmapped, and the COW path then hands the child a writable
        // copy — silently defeating the protection.
        mmap_perms: t[cur].as_ref().unwrap().mmap_perms.clone(),
        sig_linux,
        pgrp: t[cur].as_ref().unwrap().pgrp, // children share the group
        uid: t[cur].as_ref().unwrap().uid,
        euid: t[cur].as_ref().unwrap().euid,
        gid: t[cur].as_ref().unwrap().gid,
        egid: t[cur].as_ref().unwrap().egid,
        // POSIX: a child's supplementary groups are its OWN until it calls
        // setgroups, and a set-uid program drops them on exec -- not on
        // fork. Copied here; sys_execve clears.
        groups: t[cur].as_ref().unwrap().groups.clone(),
        umask: t[cur].as_ref().unwrap().umask,
        sess: t[cur].as_ref().unwrap().sess,
        // Usage counters belong to the process itself, not inherited.
        nvcsw: 0,
        nivcsw: 0,
        nsignals: 0,
        inblock: 0,
        oublock: 0,
        // A child INHERITS its limits -- that is what makes a setrlimit in
        // a parent mean anything to the work it spawns. Usage counters
        // above deliberately do NOT inherit.
        rlimits: t[cur].as_ref().unwrap().rlimits,
        wake_at: None,
        // Child shares the parent's live TLS (COW pages keep it valid).
        tpidr: read_tpidr(),
        itimer_at: None, // ITIMER_REAL does not survive fork()
        itimer_iv: None,
        // fork(2) does not inherit kqueue registrations.
        kregs: Vec::new(),
    });
    let parent_pid = t[cur].as_ref().unwrap().pid;
    kprintln!("proc: fork pid {} (parent {})", pid, parent_pid);
    // NOTE_FORK is reported on the PARENT, with the new pid in the low bits
    // of `data` (see kevent_arm).
    proc_notify(parent_pid, pid, NOTE_FORK);
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
    // Raised here, before reap() frees the slot. The event is keyed by pid
    // so it survives the slot going away.
    proc_notify(pid, pid, NOTE_EXIT);
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
    // Only reclaims the event entry if no EVFILT_PROC registration still
    // wants this pid's pending NOTE_EXIT.
    proc_events_drop(c.pid);
}

fn write_user_i32(addr: usize, val: i32) -> bool {
    let end = addr.wrapping_add(4);
    if !user_range_ok(addr as u64, 4) || !user_range_ok(end as u64, 1) {
        return false;
    }
    unsafe { (addr as *mut i32).write_volatile(val) };
    true
}

fn read_user_i32(addr: u64) -> Option<i32> {
    if !user_range_ok(addr, 4) {
        return None;
    }
    Some(unsafe { *((addr as usize) as *const i32) })
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
        // Registrations do not survive exec: the descriptors they name are
        // kept across exec, but a caller re-registers after any change.
        // Cleared on THIS process only -- the list is per-process, so a
        // child's exec cannot take the parent's watchers with it.
        p.kregs.clear();
    }
    frame.elr = entry as u64;
    frame.spsr = 0; // EL0t, interrupts on
    frame.x[0] = argc;
    frame.x[1] = argv;
    write_sp_el0(sp);
    // NOTE_EXEC is reported like NOTE_FORK: raised against the process's
    // own pid, which for exec is unchanged.
    let exec_pid = table()[CURRENT.load(Ordering::Relaxed)]
        .as_ref()
        .map(|p| p.pid)
        .unwrap_or(0);
    proc_notify(exec_pid, exec_pid, NOTE_EXEC);
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
        FdTarget::Kqueue => Io::Val(0),
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
        #[cfg(feature = "net")]
        FdTarget::Socket(slot) => {
            if has_deliverable() {
                return Io::Err(EINTR);
            }
            #[cfg(feature = "net")]
            crate::net::poll_tick(); // service the NIC before checking the queue
            let user = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
            match crate::net::sock_recv(slot, user, None) {
                Ok(0) => Io::Val(0), // TCP FIN → EOF
                Ok(n) => Io::Val(n as i64),
                Err(crate::net::EAGAIN_L) => {
                    sleep_current(frame);
                    Io::Slept
                }
                Err(e) => Io::Err(e),
            }
        }
        #[cfg(not(feature = "net"))]
        FdTarget::Socket(_) => Io::Err(EBADF),
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
        // Reading a kqueue fd is not meaningful; report 0 rather than
        // pretending. Readiness is harvested by kevent(2).
        FdTarget::Kqueue => Ok(0),
        FdTarget::TtyOut => {
            if !user_range_ok(buf, len) {
                return Err(EFAULT);
            }
            let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
            crate::hal::console::write_bytes(bytes);
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
        #[cfg(feature = "net")]
        FdTarget::Socket(slot) => {
            if !user_range_ok(buf, len) {
                return Err(EFAULT);
            }
            let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
            // Raw/ICMP fds write to their connected peer (datagram,
            // transmitted inline); TCP/UDP fds go through the queue+flush
            // path.
            if crate::net::sock_kind_is_raw(slot) {
                crate::net::sock_send_raw(slot, bytes).map(|n| n as i64)
            } else {
                crate::net::sock_send(slot, bytes).map(|n| n as i64)
            }
        }
        #[cfg(not(feature = "net"))]
        FdTarget::Socket(_) => Err(EBADF),
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

/// Install `target` into the current process's fd table, reusing the
/// lowest free slot. Shared by open(2) and socket(2).
pub fn install_fd(target: FdTarget) -> Result<usize, u8> {
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
    p.fds[slot] = Some(target);
    Ok(slot)
}

/// SYS_open(path, flags): O_RDONLY / O_WRONLY / O_RDWR with
/// O_CREAT/O_TRUNC/O_APPEND/O_EXCL (NetBSD values, verified).
pub fn sys_open(path: &str, flags: u64) -> Result<usize, u8> {
    let file_idx = file::open(path, flags)?;
    install_fd(FdTarget::File(file_idx))
}

/// open(2) with the caller's mode argument, for the *at variants.
pub fn sys_open_mode(path: &str, flags: u64, mode: u16) -> Result<usize, u8> {
    let file_idx = file::open_with_mode(path, flags, mode)?;
    install_fd(FdTarget::File(file_idx))
}


/// pread(2): read at an absolute offset WITHOUT moving the file position.
/// Going through sys_read would move it, which silently breaks every
/// caller that interleaves read and pread on one descriptor.
pub fn read_at(fd: usize, buf: u64, len: usize, offset: u64) -> Result<usize, u8> {
    let Some(FdTarget::File(i)) = current_target(fd) else { return Err(EBADF) };
    if len == 0 {
        return Ok(0);
    }
    if !user_range_ok(buf, len) {
        return Err(EFAULT);
    }
    let node = file::node_of(i)?;
    let pos = offset as usize;
    Ok(fs::read_to_user(node, pos, buf, len))
}

/// pwrite(2): write at an absolute offset without moving the position.
pub fn write_at(fd: usize, buf: u64, len: usize, offset: u64) -> Result<usize, u8> {
    let Some(FdTarget::File(i)) = current_target(fd) else { return Err(EBADF) };
    if len == 0 {
        return Ok(0);
    }
    if !user_range_ok(buf, len) {
        return Err(EFAULT);
    }
    // A read-only description must refuse, not silently discard the write.
    file::fd_is_writable(fd)?;
    let node = file::node_of(i)?;
    Ok(fs::write_at(node, offset as usize, buf, len))
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
    match target {
        FdTarget::File(i) => file::close(i)?,
        #[cfg(feature = "net")]
        // N5: socket pool slots carry a refcount; close drops one ref and
        // tears down the slot only when the last fd is closed.
        FdTarget::Socket(slot) => {
            crate::net::sock_ref_dec(slot);
        }
        _ => {}
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
        // Watched by this process's own EVFILT_SIGNAL registrations. Only
        // the self-raise is watched: the filter attaches to the caller's
        // knote list, so a signal this process sends to ANOTHER pid is not
        // an event for it.
        sig_notify(sig);
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

/// setsid(2): become session + group leader. EPERM if already a group
/// leader. The session id is recorded so `getlogin`-style state and any
/// later job-control work have somewhere real to read.
pub fn sys_setsid() -> Result<usize, u8> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    let p = t[cur].as_mut().unwrap();
    if p.pgrp == p.pid {
        return Err(EPERM_L);
    }
    p.pgrp = p.pid;
    p.sess = p.pid;
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
        // Counted here, at the moment delivery is decided, so ru_nsignals
        // tracks signals actually acted on.
        count_signal(cur);

        // A signal with an ACTIVE EVFILT_SIGNAL knote belongs to the
        // knote list, not to the handler: it is delivered by kevent, and
        // taking its default action here would kill the process that
        // registered the filter to watch it. This is why the filter is
        // checked before SIGKILL too -- an explicit handler cannot change
        // SIGKILL, but a knote can intercept anything.
        if sig != SIGKILL && kq_signal_watching(sig) {
            // Leave it pending: kevent drains it. Clearing here would
            // make the event uncollectable.
            if action != SIG_IGN {
                table()[cur].as_mut().unwrap().pending &= !(1 << sig);
            }
            continue;
        }

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
/// PROT_* recorded for the arena page at `va`, or None if it is outside
/// every mapping. Consulted by `vm::map_page` when it builds a
/// demand-paged page.
pub fn arena_prot(va: u64) -> Option<u32> {
    let cur = CURRENT.load(Ordering::Relaxed);
    // `table()` is empty until `init` builds pid 0, and `map_page` also
    // runs for kernel pages before that — indexing would panic. Same
    // guard as `current_pgrp`.
    let p = table().get(cur)?.as_ref()?;
    p.mmap_perms
        .iter()
        .find(|(base, len, _)| va >= *base && va < base + len)
        .map(|(_, _, prot)| *prot)
}

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
    crate::kprintln!("sys_brk: req={addr:#x} start={:#x} floor={:#x} ok={ok}", p.brk_start, user::MMAP_FLOOR);
    if ok {
        p.brk = addr;
    }
    p.brk
}

/// Linux mmap(222): anonymous bumps only (v1) — returns the arena base;
/// pages materialize on first touch via the fault handler.
/// PROT_* (sys/mman.h). Identical on NetBSD and Linux, which is the rare
/// case where the two ABIs agree on an encoding.
pub const PROT_NONE: u32 = 0x0;
pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;

/// Anonymous mapping. `prot` is applied to the new pages, which matters
/// immediately: demand-paged pages are created on first TOUCH, so without
/// this a `PROT_READ` mapping is writable from the moment it is returned
/// and `mprotect`'s read-only flag has nothing to protect.
pub fn sys_mmap(len: u64, prot: u32) -> Result<u64, u8> {
    let pages = len.checked_add(0xfff).map(|v| v & !0xfff).ok_or(EINVAL)?;
    if pages == 0 {
        return Err(EINVAL);
    }
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(EINVAL);
    }
    if prot == PROT_NONE {
        // PROT_NONE is legal but useless to reserve here: an unmapped
        // VA is not distinguishable from one that was never asked for,
        // so reserving it would silently consume address space.
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
    // No PTEs yet -- these are demand-paged. Mark the whole range so the
    // first touch builds the page with the right access permissions.
    p.mmap_perms.push((base, pages, prot));
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
    if prot & (PROT_READ | PROT_WRITE | PROT_EXEC) as u64 != prot {
        return Err(EINVAL);
    }
    let start = addr & !0xfff;
    let end = (addr + len + 0xfff) & !0xfff;
    // `vm::set_perms` only rewrites PTEs that are already present, and
    // this kernel demand-pages -- so a page mprotect has not yet
    // materialised would come back with the prot mmap recorded for it.
    // Overwrite the recorded range so a later fault agrees with mprotect.
    let cur = CURRENT.load(Ordering::Relaxed);
    if let Some(p) = table()[cur].as_mut() {
        let mut merged: Vec<(u64, u64, u32)> = Vec::new();
        for (base, rng, old) in p.mmap_perms.drain(..) {
            let hi = base + rng;
            // Disjoint: keep the whole mapping as it was. Comparing the
            // mapping's END ADDRESS against `start` matters -- comparing
            // its LENGTH silently skipped any mapping that happened to
            // start above `addr`, leaving it unprotected.
            if hi <= start || base >= end {
                merged.push((base, rng, old));
                continue;
            }
            if base < start {
                merged.push((base, start - base, old));
            }
            merged.push((base.max(start), hi.min(end) - base.max(start), prot as u32));
            if hi > end {
                merged.push((end, hi - end, old));
            }
        }
        p.mmap_perms = merged;
    }
    // Every page in the range must belong to a mapping we hold a record
    // of. Without this, mprotect on an address nobody mapped walks no
    // present PTE, changes nothing, and returns success -- a silent
    // no-op the caller cannot detect.
    if !covers_range(start, end) {
        return Err(ENOMEM);
    }
    vm::set_perms(ttbr, addr, len, prot as u32).map_err(|_| EINVAL)
}

/// Whether `mmap_perms` covers every page of [start, end).
fn covers_range(start: u64, end: u64) -> bool {
    let mut va = start;
    while va < end {
        if arena_prot(va).is_none() {
            return false;
        }
        va += 0x1000;
    }
    true
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
        match old {
            FdTarget::File(i) => {
                let _ = file::close(i);
            }
            #[cfg(feature = "net")]
            FdTarget::Socket(s) => {
                crate::net::sock_ref_dec(s);
            }
            _ => {}
        }
    }
    if let FdTarget::File(i) = target {
        file::dup(i);
    }
    #[cfg(feature = "net")]
    if let FdTarget::Socket(s) = target {
        crate::net::sock_ref_inc(s);
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
    // The table only grows when min is past the end, so a full table with
    // min below the end used to report EINVAL even though every caller
    // expects a free slot to be found or created. Grow first, then search.
    let slot = match (min as usize..p.fds.len()).find(|&i| p.fds[i].is_none()) {
        Some(i) => i,
        None => {
            if p.fds.len() > 1024 {
                return Err(24); // EMFILE
            }
            p.fds.push(None);
            p.fds.len() - 1
        }
    };
    if let FdTarget::File(i) = target {
        file::dup(i);
    }
    #[cfg(feature = "net")]
    if let FdTarget::Socket(s) = target {
        crate::net::sock_ref_inc(s);
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

/// The current process's working directory. Always absolute.
pub fn cwd() -> String {
    let cur = CURRENT.load(Ordering::Relaxed);
    table()[cur].as_ref().map(|p| p.cwd.clone()).unwrap_or_else(|| String::from("/"))
}

/// Set the working directory. `path` must already be absolute+normalized.
pub fn set_cwd(path: &str) {
    let cur = CURRENT.load(Ordering::Relaxed);
    if let Some(p) = table()[cur].as_mut() {
        p.cwd = String::from(path);
    }
}

/// Make `path` absolute against the working directory, and normalize it.
///
/// A relative path is joined onto `cwd`; `.` components are dropped and
/// `..` pops one. Going above `/` clamps to `/` rather than escaping, so
/// `../../..` from anywhere is `/`.

/// True when this process is not already a session leader.
pub fn can_setsid() -> bool {
    let cur = CURRENT.load(Ordering::Relaxed);
    let t = table();
    match &t[cur] { Some(p) => p.sess != p.pid, None => false }
}

/// setsid(2): start a new session, becoming its leader. Returns the new
/// session id, which is also the new process id.
pub fn setsid() -> u32 {
    let cur = CURRENT.load(Ordering::Relaxed);
    let sid;
    {
        let t = table();
        let p = t[cur].as_mut().unwrap();
        p.sess = p.pid;
        p.pgrp = p.pid;
        sid = p.pid as u32;
    }
    sid
}

pub fn abspath(path: &str) -> String {
    let joined = if path.starts_with('/') {
        String::from(path)
    } else {
        let mut s = cwd();
        if !s.ends_with('/') {
            s.push('/');
        }
        s.push_str(path);
        s
    };
    let mut out: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p),
        }
    }
    let mut r = String::from("/");
    for p in out {
        r.push_str(p);
        r.push('/');
    }
    if r.len() > 1 && r.ends_with('/') {
        r.pop();
    }
    r
}

// ---------- kqueue ----------
//
// NetBSD's native event interface. Unlike poll, which is a one-shot query,
// kqueue returns a descriptor: registrations are held in the kernel and
// kevent(2) either harvests ready ones or parks the caller until one is.
//
// Only EVFILT_READ and EVFILT_WRITE are supported, which is the whole of
// what a libc uses when it is willing to use kqueue. Filters that need
// objects this kernel does not have (EVFILT_VNODE, EVFILT_PROC,
// EVFILT_SIGNAL, EVFILT_TIMER) are rejected at EV_ADD with EINVAL rather
// than silently ignored, so a caller learns immediately instead of
// blocking forever on an event that can never arrive.

/// One registered event. Mirrors the ABI-visible fields.
#[derive(Clone, Copy)]
pub struct Kevent {
    /// For EVFILT_READ/WRITE this is the descriptor; for EVFILT_VNODE it is
    /// the fs node index, because that filter watches a path.
    pub ident: u64,
    /// Node generation observed at registration time. A mismatch means the
    /// node changed since; this is what makes the filter edge-preserving
    /// rather than merely "is there anything pending".
    pub vseq: u32,
    pub filter: u32,
    pub flags: u32,
    pub fflags: u32,
    pub udata: u64,
    /// For EVFILT_TIMER: the absolute tick at which this timer last
    /// delivered. Zero when never delivered. Kept apart from `vseq`,
    /// which is the generation counter for the vnode/proc/signal filters
    /// -- overloading one field for two different clocks is how a timer
    /// ends up comparing against a note sequence.
    pub timer_at: u64,
    /// For EVFILT_TIMER: period in ticks. 0 means one-shot already fired.
    pub timer_period: u64,
}

/// EVFILT_READ / EVFILT_WRITE (sys/sys/event.h).
pub const EVFILT_READ: u32 = 0;
pub const EVFILT_WRITE: u32 = 1;
pub const EVFILT_AIO: u32 = 2;
pub const EVFILT_VNODE: u32 = 3;
pub const EVFILT_PROC: u32 = 4;
pub const EVFILT_SIGNAL: u32 = 5;
pub const EVFILT_TIMER: u32 = 6;
pub const EVFILT_FS: u32 = 7;
pub const EVFILT_USER: u32 = 8;
pub const EVFILT_EMPTY: u32 = 9;

/// A `Kevent` with this filter is a DEAD slot left behind by a one-shot
/// timer or a removed registration. Slots must keep their index: a timer
/// is addressed by position, so compacting the list would silently
/// re-point every later timer at the wrong entry. Dead entries are
/// skipped at harvest and cannot be re-added to.
pub const EVFILT_DEAD: u32 = 0xffff_ffff;

// NOTE_* for EVFILT_PROC (sys/sys/event.h). These are distinct values from
// the vnode notes -- NOTE_EXEC is 0x20000000 here and there is no vnode
// note with that value.
pub const NOTE_EXIT: u32 = 0x8000_0000;
pub const NOTE_FORK: u32 = 0x4000_0000;
pub const NOTE_EXEC: u32 = 0x2000_0000;

/// Pending process events, keyed by pid rather than by table slot.
///
/// A slot cannot be used: reap() frees it, so a NOTE_EXIT recorded against
/// a slot would vanish before a watcher could collect it. The pid outlives
/// the slot, and the entry is reclaimed only once no registration wants it.
///
/// Same shape as the vnode generation counter -- a monotonic `seq` plus a
/// pending bitmap -- so a watcher cannot miss an event that happened while
/// it was not inside a syscall.
struct ProcEvents(UnsafeCell<Vec<ProcEvent>>);
unsafe impl Sync for ProcEvents {}

#[derive(Clone, Copy)]
struct ProcEvent {
    pid: usize,
    seq: u32,
    notes: u32,
    /// The child pid when `notes` carries NOTE_FORK, so the watcher learns
    /// WHICH pid forked. Stored rather than read from a global because two
    /// forks can be pending at once.
    child: usize,
}

static PEVENTS: ProcEvents = ProcEvents(UnsafeCell::new(Vec::new()));

fn pevents() -> &'static mut Vec<ProcEvent> {
    unsafe { &mut *PEVENTS.0.get() }
}

/// Record `notes` against `pid`. `NOTE_FORK` is delivered to the PARENT,
/// so `ident` is the parent while the note is raised on the child.
pub fn proc_notify(parent: usize, child: usize, notes: u32) {
    let v = pevents();
    if let Some(e) = v.iter_mut().find(|e| e.pid == parent) {
        e.seq = e.seq.wrapping_add(1);
        e.notes |= notes;
        if notes & NOTE_FORK != 0 {
            e.child = child;
        }
        return;
    }
    if v.len() >= 256 {
        return;
    }
    v.push(ProcEvent {
        pid: parent,
        seq: 1,
        notes,
        child,
    });
}

/// The generation a new watcher records.
pub fn proc_seq(pid: usize) -> u32 {
    pevents()
        .iter()
        .find(|e| e.pid == pid)
        .map_or(0, |e| e.seq)
}

/// Take the pending notes, clearing them. Restored by `proc_restore` when a
/// filter's fflags do not match -- otherwise narrowing a filter would
/// silently discard events.
/// Read without clearing. The filter decision must not consume the event.
pub fn proc_peek(pid: usize) -> Option<(u32, u32, usize)> {
    pevents()
        .iter()
        .find(|e| e.pid == pid)
        .map(|e| (e.seq, e.notes, e.child))
}

pub fn proc_take(pid: usize) -> Option<(u32, u32, usize)> {
    let v = pevents();
    let e = v.iter_mut().find(|e| e.pid == pid)?;
    let out = e.notes;
    e.notes = 0;
    Some((e.seq, out, e.child))
}


/// Drop any pending history for a pid, so a first-time watcher is not woken
/// by events it never asked about.
pub fn proc_clear(pid: usize) {
    if let Some(e) = pevents().iter_mut().find(|e| e.pid == pid) {
        e.notes = 0;
        e.child = 0;
    }
}

/// Does the pid exist (runnable or zombie)? EVFILT_PROC must refuse a pid
/// that does not exist, rather than registering for an event that can
/// never arrive.
pub fn pid_exists(pid: usize) -> bool {
    table().iter().any(|p| p.as_ref().is_some_and(|q| q.pid == pid))
}


/// Reclaim a pid's event entry once it holds nothing worth delivering.
///
/// The entry is kept while it still carries pending notes OR a watcher:
/// dropping it at reap() time would destroy a NOTE_EXIT for a pid whose
/// registration has not been made yet -- which is precisely the case
/// EVFILT_PROC exists for. A pid can therefore be watched *after* it dies.
pub fn proc_events_drop(pid: usize) {
    if kq_watching_pid(pid) {
        return;
    }
    pevents().retain(|e| e.pid != pid || e.notes != 0);
}

/// NOTE_FF* modifiers, shared by EVFILT_USER and EVFILT_VNODE
/// (sys/sys/event.h). The top two bits of fflags say how the low 24 bits
/// should be applied to -- or compared against -- the STORED value.
// NOTE_FFNOP is 0 -- it is what the top two bits are on OUTPUT, and it is
// the `_` arm of every match below, so it needs no constant of its own.
pub const NOTE_FFAND: u32 = 0x4000_0000;
pub const NOTE_FFOR: u32 = 0x8000_0000;
pub const NOTE_FFCOPY: u32 = 0xc000_0000;
pub const NOTE_FFCTRLMASK: u32 = 0xc000_0000;
pub const NOTE_FFLAGSMASK: u32 = 0x00ff_ffff;

// EVFILT_USER (sys/sys/event.h). The filter is not attached to any kernel
// object -- it fires when the caller SETS NOTE_TRIGGER in fflags, so a
// userspace thread can wake another one. On output the top two fflags
// bits are always NOTE_FFNOP and the low 24 bits are the STORED value.
pub const NOTE_TRIGGER: u32 = 0x0100_0000;

/// Apply an EVFILT_USER fflags update to the STORED value, per the
/// NOTE_FF* modifier in the top two bits (sys/sys/event.h).
pub fn user_fflags_apply(stored: u32, fflags: u32) -> u32 {
    let low = fflags & NOTE_FFLAGSMASK;
    match fflags & NOTE_FFCTRLMASK {
        NOTE_FFAND => stored & low,
        NOTE_FFOR => stored | low,
        NOTE_FFCOPY => low,
        // NOTE_FFNOP (0) and every reserved value: keep what is stored.
        _ => stored,
    }
}

/// Is an EVFILT_USER registration ready? It fires when the caller set
/// NOTE_TRIGGER and the stored value still satisfies the filter's own
/// fflags under the same NOTE_FF* modifier -- the trigger is a request,
/// not a guarantee that something is ready.
pub fn kq_user_ready(k: &Kevent) -> Option<u32> {
    if k.flags & EV_DISABLE != 0 {
        return None;
    }
    if k.fflags & NOTE_TRIGGER == 0 {
        return None;
    }
    let stored = k.vseq;
    let want = k.udata as u32;
    // The filter's own NOTE_FF* modifier decides how `want` is compared
    // against the stored value; NOTE_FFNOP means "any stored value".
    let ok = match want & NOTE_FFCTRLMASK {
        NOTE_FFAND => stored & (want & NOTE_FFLAGSMASK) != 0,
        NOTE_FFOR => stored & (want & NOTE_FFLAGSMASK) != 0,
        NOTE_FFCOPY => stored & NOTE_FFLAGSMASK == want & NOTE_FFLAGSMASK,
        // NOTE_FFNOP (0): no filter, so anything matches.
        _ => true,
    };
    if !ok {
        return None;
    }
    // Report the STORED value, not the request.
    Some(stored)
}

/// A watcher with fflags 0 wants every note; with NOTE_FFAND it wants only
/// the notes it named, and NOTE_FFOR widens to any-of. (NOTE_FF* are
/// shared with EVFILT_USER -- see the definitions above.)

/// Registration flags (sys/sys/event.h).
pub const EV_ADD: u32 = 0x0001;
pub const EV_DELETE: u32 = 0x0002;
pub const EV_ENABLE: u32 = 0x0004;
pub const EV_DISABLE: u32 = 0x0008;
pub const EV_ONESHOT: u32 = 0x0010;
pub const EV_CLEAR: u32 = 0x0020;

/// Registration cap. A caller asking for more is EINVAL, matching poll.
pub const KQUEUE_MAX: usize = 64;

/// The current process's registration list.
///
/// kqueues are not multiplexable here: one registration set per process, so
/// kqueue() hands back a shared descriptor. The list therefore lives in the
/// `Process`, not in a static. A static is only correct while no second
/// process exists, and execve then clears it -- which silently destroyed
/// every OTHER process's watchers the moment any child execed.
pub fn kq_regs() -> &'static mut Vec<Kevent> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let p = table()[cur].as_mut();
    match p {
        Some(p) => &mut p.kregs,
        // No current process (only reachable before pid 0 is installed).
        // Returning a real static keeps the borrow total rather than
        // Option-ing every call site.
        None => unsafe { &mut *UNCLAIMED_KQ.0.get() },
    }
}

/// Holds registrations made before a current process exists. Unreachable in
/// practice; it exists so `kq_regs` need not return an Option.
struct UnclaimedKq(UnsafeCell<Vec<Kevent>>);
unsafe impl Sync for UnclaimedKq {}
static UNCLAIMED_KQ: UnclaimedKq = UnclaimedKq(UnsafeCell::new(Vec::new()));

/// Does ANY process hold an EVFILT_PROC registration for `pid`? Reaping a
/// pid must consult every process, not just the reaper's own list.
pub fn kq_watching_pid(pid: usize) -> bool {
    table()
        .iter()
        .filter_map(|s| s.as_ref())
        .any(|p| p.kregs.iter().any(|k| k.filter == EVFILT_PROC && k.ident == pid as u64))
}

/// Add or update a registration. `ident` is the fd.
pub fn kq_add(k: Kevent) -> Result<(), u8> {
    let v = kq_regs();
    if let Some(e) = v.iter_mut().find(|e| e.ident == k.ident && e.filter == k.filter) {
        *e = k;
        return Ok(());
    }
    if v.len() >= KQUEUE_MAX {
        return Err(24); // EMFILE
    }
    v.push(k);
    Ok(())
}

/// Remove one registration. ENOENT if it was never there, which is what
/// EV_DELETE must report.
pub fn kq_delete(ident: u64, filter: u32) -> Result<(), u8> {
    let v = kq_regs();
    match v.iter().position(|e| e.ident == ident && e.filter == filter) {
        Some(i) => {
            v.remove(i);
            Ok(())
        }
        None => Err(2), // ENOENT
    }
}

/// The NOTE bits a registration should fire on, per its NOTE_FF* modifier.
/// NOTE_FFNOP (fflags 0, no modifier) means "every note".
fn vnode_match(fflags: u32, pending: u32) -> bool {
    match fflags & NOTE_FFCTRLMASK {
        NOTE_FFAND => pending != 0 && pending & (fflags & !NOTE_FFCTRLMASK) != 0,
        NOTE_FFOR => pending & (fflags & !NOTE_FFCTRLMASK) != 0,
        _ => pending != 0,
    }
}

/// Is an EVFILT_VNODE registration ready? The node changed since the
/// recorded generation and the notes match the filter's fflags.
pub fn kq_vnode_ready(k: &Kevent) -> Option<u32> {
    if k.flags & EV_DISABLE != 0 {
        return None;
    }
    let idx = k.ident as usize;
    if idx >= crate::fs::node_count() {
        return None;
    }
    let (seq, notes) = crate::fs::vnode_take_notes(idx);
    if seq == k.vseq || !vnode_match(k.fflags, notes) {
        // Put back what we took: a non-matching note is still pending.
        if seq != k.vseq {
            crate::fs::vnode_restore_notes(idx, notes);
        }
        return None;
    }
    Some(notes)
}

/// Match pending process notes against a filter's fflags, honouring
/// NOTE_FFAND / NOTE_FFOR. `data` bits carry the pid for NOTE_FORK.
fn proc_match(fflags: u32, pending: u32) -> bool {
    match fflags & NOTE_FFCTRLMASK {
        NOTE_FFAND => pending != 0 && pending & (fflags & !NOTE_FFCTRLMASK) != 0,
        NOTE_FFOR => pending & (fflags & !NOTE_FFCTRLMASK) != 0,
        _ => pending != 0,
    }
}

// ---------- EVFILT_SIGNAL ----------
//
// Pending signals per signal number, for the calling process only. Same
// shape as the process-event table: a monotonic `seq` plus a pending
// bitmap, so a signal raised while no watcher exists is still deliverable
// afterwards, and re-enabling a filter does not lose what arrived while
// it was disabled.
//
// Per signal NUMBER rather than per process, because `ident` for this
// filter is the signal, not a pid -- and because it is attached to the
// process's own knote list, so a process cannot watch another's signals.
struct SigEvents(UnsafeCell<[SigEvent; NSIG]>);
unsafe impl Sync for SigEvents {}

#[derive(Clone, Copy)]
struct SigEvent {
    seq: u32,
    /// Set once any instance of this signal has been raised and not yet
    /// consumed. A bitmap would be wrong here: two SIGUSR1s are one
    /// event to a watcher, not two.
    pending: bool,
}

static SIGEVENTS: SigEvents = SigEvents(UnsafeCell::new([SigEvent {
    seq: 0,
    pending: false,
}; NSIG]));

fn sigevents() -> &'static mut [SigEvent; NSIG] {
    unsafe { &mut *SIGEVENTS.0.get() }
}

/// Record that `sig` was raised for the current process.
pub fn sig_notify(sig: u64) {
    if sig == 0 || sig >= NSIG as u64 {
        return;
    }
    let e = &mut sigevents()[sig as usize];
    e.seq = e.seq.wrapping_add(1);
    e.pending = true;
}

/// The generation a new watcher records.
pub fn sig_seq(sig: u64) -> u32 {
    sigevents()
        .get(sig as usize)
        .map_or(0, |e| e.seq)
}

/// Drop history so a first-time watcher is not woken by signals it never
/// asked about.
pub fn sig_clear(sig: u64) {
    if let Some(e) = sigevents().get_mut(sig as usize) {
        e.pending = false;
    }
}

/// Units for EVFILT_TIMER, carried in fflags, not in data
/// (sys/sys/event.h). NOTE_MSECONDS is the HISTORICAL value 0, so a
/// caller that passes fflags == 0 gets MILLISECONDS, not "no unit" --
/// this is the one filter where zero is a real selector.
pub const NOTE_MSECONDS: u32 = 0x0000_0000;
pub const NOTE_SECONDS: u32 = 0x0000_0001;
pub const NOTE_USECONDS: u32 = 0x0000_0002;
pub const NOTE_NSECONDS: u32 = 0x0000_0003;
pub const NOTE_TIMER_UNITMASK: u32 = 0x0000_0003;
pub const NOTE_ABSTIME: u32 = 0x0000_0010;

/// One EVFILT_TIMER registration. NetBSD keys timers on a knote slot, not
/// on an ident, because `data` is the timeout -- the caller may register
/// any number of them and each is independent. A registration here is
/// therefore identified by its index in `kregs`, which `slot` carries.
/// Convert nanoseconds to `arch_timer_now()` units.
///
/// `arch_timer_now()` is a SOFTWARE tick counter incremented once per
/// timer IRQ (`arch::timer::on_tick` does `TICKS.fetch_add(1)`), so it
/// runs at `arch_timer_hz()` -- 100 Hz -- and NOT at the 62.5 MHz
/// CNTFRQ. Reading CNTFRQ here instead made every period ~625000x too
/// long: a 20 ms timer was scheduled 1.25 million ticks out, which at
/// 100 ticks/s is three and a half hours, so it could never fire.
///
/// Every other deadline in this kernel (sleep, ppoll, setitimer) is
/// already in these units, so EVFILT_TIMER must be too.
pub fn ticks_for_nanos(nanos: u64) -> u64 {
    let hz = arch_timer_hz().max(1) as u128;
    let ticks = (nanos as u128 * hz / 1_000_000_000) as u64;
    // A sub-tick timeout still has to be able to fire, so clamp UP to one
    // tick rather than refusing it.
    ticks.max(1)
}

pub fn timer_period_ticks(data: u64, units: u32) -> Option<u64> {
    let nanos = match units & NOTE_TIMER_UNITMASK {
        NOTE_SECONDS => data.checked_mul(1_000_000_000)?,
        NOTE_MSECONDS => data.checked_mul(1_000_000)?,
        NOTE_USECONDS => data.checked_mul(1_000)?,
        NOTE_NSECONDS => data,
        _ => return None,
    };
    // `arch_timer_now()` counts CNTFRQ ticks -- 62.5 MHz on this board --
    // NOT IRQ ticks. `arch_timer_hz()` is the 100 Hz IRQ rate, so dividing
    // by it produced a period ~625000x too long: a 30 ms timer came out
    // as nearly 5 seconds. Convert through the counter frequency.
    // NetBSD refuses a zero period but clamps a sub-resolution one to a
    // single tick -- a timer must always be able to fire.
    Some(ticks_for_nanos(nanos))
}


/// Is the EVFILT_TIMER registration at `slot` ready?
pub fn kq_timer_ready(slot: usize) -> Option<u64> {
    let cur = CURRENT.load(Ordering::Relaxed);
    let regs = table()[cur].as_ref()?.kregs.get(slot)?;
    if regs.filter != EVFILT_TIMER || regs.flags & EV_DISABLE != 0 {
        return None;
    }
    let now = arch_timer_now();
    if now.saturating_sub(regs.timer_at) < regs.timer_period {
        return None;
    }
    Some(now)
}

/// Is the current process holding an enabled EVFILT_SIGNAL knote for
/// `sig`? Read at every delivery boundary, so it must consult the CURRENT
/// process's list only.
pub fn kq_signal_watching(sig: usize) -> bool {
    let cur = CURRENT.load(Ordering::Relaxed);
    table()[cur]
        .as_ref()
        .is_some_and(|p| {
            p.kregs
                .iter()
                .any(|k| k.filter == EVFILT_SIGNAL && k.ident == sig as u64 && k.flags & EV_DISABLE == 0)
        })
}

/// Is an EVFILT_SIGNAL registration ready? Returns the signal number, which
/// kevent reports in `data` (fflags is unused for this filter).
pub fn kq_sig_ready(k: &Kevent) -> Option<u64> {
    if k.flags & EV_DISABLE != 0 {
        return None;
    }
    let sig = k.ident;
    let e = sigevents().get(sig as usize)?;
    if !e.pending || e.seq == k.vseq {
        return None;
    }
    // Consume only now that the filter is known to fire.
    sigevents()[sig as usize].pending = false;
    Some(sig)
}

/// Is an EVFILT_PROC registration ready? Returns the pending notes and, for
/// NOTE_FORK, the child pid they came from.
pub fn kq_proc_ready(k: &Kevent) -> Option<(u32, usize)> {
    if k.flags & EV_DISABLE != 0 {
        return None;
    }
    let pid = k.ident as usize;
    // PEEK, do not take: nothing is consumed unless this registration
    // actually fires. Taking here and restoring on the "not ready" path
    // looked equivalent but was not -- a second poll of the SAME
    // registration would see the notes already gone.
    let (seq, notes, child) = proc_peek(pid)?;
    if seq == k.vseq {
        return None;
    }
    if !proc_match(k.fflags, notes) {
        return None;
    }
    // Consume for real, and only now.
    proc_take(pid);
    Some((notes, child))
}

/// Is any enabled registration currently ready? Lets poll() treat a kqueue
/// descriptor like any other readable fd.
pub fn kq_any_ready() -> bool {
    kq_regs().iter().any(|r| {
        if r.flags & EV_DISABLE != 0 {
            return false;
        }
        let fd = r.ident as i64;
        if fd < 0 {
            return false;
        }
        let Some(target) = current_target(fd as usize) else {
            return false;
        };
        let (recv, send) = match target {
            FdTarget::TtyIn => (crate::tty::has_data(), false),
            FdTarget::TtyOut => (false, true),
            FdTarget::File(_) => (true, true),
            FdTarget::Pipe { slot, write_end: false } => {
                (crate::file::pipe_avail(slot) > 0
                    || pipe_end_count(slot, true) == 0, false)
            }
            FdTarget::Pipe { slot, write_end: true } => (
                false,
                pipe_end_count(slot, false) > 0 && crate::file::pipe_free(slot) > 0,
            ),
            #[cfg(feature = "net")]
            FdTarget::Socket(s) => match crate::net::sock_poll(s) {
                Some((r, w)) => (r, w),
                None => return false,
            },
            #[cfg(not(feature = "net"))]
            FdTarget::Socket(_) => (false, false),
            // Deliberately not ready: a kqueue descriptor must not report
            // its own readiness, and making it call kq_any_ready() here
            // would recurse unboundedly for a kqueue watching a kqueue.
            FdTarget::Kqueue => (false, false),
        };
        match r.filter {
            EVFILT_READ => recv,
            EVFILT_WRITE => send,
            _ => false,
        }
    })
}
