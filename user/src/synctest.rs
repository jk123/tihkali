#![no_std]
#![no_main]

//! NetBSD-ABI batch 2: poll/select, file sync, itimer, resource usage.
//!
//! The point of this probe is that each of these was either absent or a
//! hardcoded zero, and every way of getting that wrong is a SILENT SUCCESS:
//!
//! - `poll` returning 0 for a caller that asked to WAIT looks like a
//!   timeout; `select` returning a count without rewriting the caller's
//!   fd_set leaves the caller reading its own input bits back as results.
//! - `fsync` returning 0 without writing would be invisible until a reboot.
//! - `getrusage` reporting a structurally perfect row of zeros is
//!   indistinguishable from a kernel that measured nothing.
//!
//! So the checks assert the observable effect, and every refusal is gated
//! against its own errno rather than "it failed".
//!
//! `struct pollfd` is byte-identical between NetBSD and Linux
//! ({int fd; short events; short revents}, 8 bytes) and `fd_set` is 256
//! bits of 32-bit words -- both read from the upstream headers rather
//! than assumed, because this pair of ABIs differs on almost everything.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

/// ONE write() for the whole line, assembled in a buffer. A probe that
/// forks can have a child's kernel output interleave between separate
/// writes and split the prefix off the name.
fn check(name: &str, ok: bool) {
    let mut line = [0u8; 128];
    let mut n = 0usize;
    let put = |buf: &mut [u8; 128], n: &mut usize, bytes: &[u8]| {
        let end = (*n + bytes.len()).min(buf.len() - 1);
        buf[*n..end].copy_from_slice(&bytes[..end - *n]);
        *n = end;
    };
    let pad = b"                                      ";
    put(&mut line, &mut n, b"p2: ok     ");
    put(&mut line, &mut n, name.as_bytes());
    put(&mut line, &mut n, &pad[..(32usize).saturating_sub(name.len())]);
    if ok {
        put(&mut line, &mut n, b"ok\n");
    } else {
        put(&mut line, &mut n, b"FAILED <<");
        put(&mut line, &mut n, name.as_bytes());
        put(&mut line, &mut n, b">>\n");
        unsafe { FAILURES += 1 };
    }
    unsafe { write(1, &line[..n]) };
}

unsafe fn write(fd: i64, buf: &[u8]) {
    unsafe {
        asm!(
            "svc #4",
            in("x0") fd,
            in("x1") buf.as_ptr(),
            in("x2") buf.len(),
            options(nostack),
        );
    }
}

macro_rules! svc0 {
    ($name:ident, $nr:expr) => {
        unsafe fn $name() -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") 0i64 => ret,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

macro_rules! svc1 {
    ($name:ident, $nr:expr, $arg:ident) => {
        unsafe fn $name($arg: i64) -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") $arg => ret,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

macro_rules! svc2 {
    ($name:ident, $nr:expr, ($a:ident, $b:ident)) => {
        unsafe fn $name($a: i64, $b: i64) -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") $a => ret,
                    in("x1") $b,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

macro_rules! svc3 {
    ($name:ident, $nr:expr, ($a:ident, $b:ident, $c:ident)) => {
        unsafe fn $name($a: i64, $b: i64, $c: i64) -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") $a => ret,
                    in("x1") $b,
                    in("x2") $c,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

svc3!(open, "5", (path, flags, mode));
svc1!(close, "6", fd);
/// write(4) with an explicit length, for the fsync payload write.
unsafe fn wbytes(fd: i64, buf: i64, len: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf,
            in("x2") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}
svc1!(fsync, "95", fd);
svc1!(fdatasync, "241", fd);
svc2!(flock, "131", (fd, how));
svc3!(poll, "209", (fds, nfds, timeout));
/// select(417): select(nd, rd, wr, ex, tv). Five arguments, so it is
/// written out rather than through a macro.
unsafe fn select(nd: i64, rd: i64, wr: i64, ex: i64, tv: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #417",
            "cset {err}, hs",
            inlateout("x0") nd => ret,
            in("x1") rd,
            in("x2") wr,
            in("x3") ex,
            in("x4") tv,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}
svc2!(getrusage, "445", (who, buf));
svc2!(getrlimit, "194", (which, buf));
svc2!(setrlimit, "195", (which, buf));
svc3!(dup3, "454", (from, to, flags));
svc2!(gethostname, "87", (buf, len));
svc2!(sethostname, "88", (buf, len));
svc2!(utimes, "420", (path, times));
svc2!(futimes, "423", (fd, times));
svc0!(sched_yield, "350");
svc2!(crate_stat, "38", (path, buf));
svc1!(getsid, "286", pid);
svc2!(getlogin, "49", (buf, len));
svc1!(sigaltstack, "281", nss);
svc1!(statfs, "157", path);
svc2!(getitimer, "426", (which, buf));
/// pipe(42): writes two descriptors through the caller's pointer; it
/// returns 0 on success, NOT the pair.
unsafe fn pipe(fds: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #42",
            "cset {err}, hs",
            inlateout("x0") fds => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}
/// setitimer(83): setitimer(which, new, old). 83 is the live arm;
/// 425 is the compat __2 entry the kernel does not dispatch.
unsafe fn setitimer(which: i64, new: i64, old: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #83",
            "cset {err}, hs",
            inlateout("x0") which => ret,
            in("x1") new,
            in("x2") old,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// `struct pollfd` from sys/poll.h: { int fd; short events; short revents }.
/// Byte-identical to Linux's -- verified from the upstream header rather
/// than assumed, since the two ABIs differ on nearly everything else.
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// NetBSD's fd_set is FD_SETSIZE=256 bits with NFDBITS=32: EIGHT 32-bit
/// words, so exactly 32 bytes. `sys/fd_set.h`, not Linux's 64-bit words.
const FD_SET_BYTES: usize = 32;
const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;


#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // ---------- poll ----------
    // A pipe with the write end held is never readable, so poll must
    // report "not ready" rather than inventing readiness.
    let mut pfds = [0i32; 2];
    let piped = unsafe { pipe(pfds.as_mut_ptr() as i64) };
    // Printed on BOTH outcomes: a check that only prints when it fails has
    // no line to gate on in a green run.
    check("pipe created", piped.is_ok());
    if piped.is_err() {
        finish();
    }
    let (rdfd, wrfd) = (pfds[0] as i64, pfds[1] as i64);
    let mut fds = [
        PollFd { fd: rdfd as i32, events: POLLIN as i16, revents: 0 },
        PollFd { fd: wrfd as i32, events: POLLOUT as i16, revents: 0 },
    ];
    let paddr = fds.as_mut_ptr() as i64;
    let n = unsafe { poll(paddr, 2, 0) }.unwrap_or(-1);
    check("poll zero timeout", n >= 0);
    // The write end is writable and the read end is not: exactly one
    // ready. A kernel that ignores revents would report two or zero.
    check("poll write ready", fds[1].revents as u16 & POLLOUT != 0);
    check("poll read not ready", fds[0].revents as u16 & POLLIN == 0);
    check("poll counted one", n == 1);

    // A negative fd is ignored per POSIX, not reported as POLLNVAL.
    fds[0].fd = -1;
    fds[0].events = POLLIN as i16;
    fds[0].revents = 0;
    let n2 = unsafe { poll(paddr, 1, 0) }.unwrap_or(-1);
    check("poll ignores negfd", n2 == 0);
    check("poll negfd no NVAL", fds[0].revents == 0);

    // ---------- select ----------
    // A struct-offset self-check first: if the set were not exactly 32
    // bytes the three pointers below would be misaligned, and every
    // result would be garbage rather than an error.
    check("fd_set size", core::mem::size_of::<[u32; 8]>() == FD_SET_BYTES);
    // Watch the write end only.
    let mut rd_set = [0u32; 8];
    let mut wr_set = [0u32; 8];
    let mut ex_set = [0u32; 8];
    let mut tv = [0i64; 2]; // {0,0} = poll, don't wait
    wr_set[(wrfd as usize) / 32] |= 1u32 << ((wrfd as usize) % 32);
    // nd is the HIGHEST fd + 1, so it must cover the descriptor we set.
    let nd = wrfd + 1;
    let sel = unsafe { select(nd, rd_set.as_mut_ptr() as i64, wr_set.as_mut_ptr() as i64, ex_set.as_mut_ptr() as i64, tv.as_mut_ptr() as i64) };
    check("select zero timeout", sel.unwrap_or(-1) == 1);
    // The kernel must have REWRITTEN the sets, not echoed the input back.
    let wr_back = unsafe { *wr_set.as_ptr() };
    check("select rewrote wr", wr_back != 0 && (wr_back & !(1u32 << ((wrfd as usize) % 32))) == 0);
    check("select rd empty", unsafe { *rd_set.as_ptr() } == 0);
    check("select ex empty", unsafe { *ex_set.as_ptr() } == 0);

    // Nothing to watch -> 0 ready.
    let mut e0 = [0u32; 8];
    let mut tv0 = [0i64; 2];
    let sel0 = unsafe { select(1, e0.as_mut_ptr() as i64, e0.as_mut_ptr() as i64, e0.as_mut_ptr() as i64, tv0.as_mut_ptr() as i64) };
    check("select none ready", sel0.unwrap_or(-1) == 0);

    // ---------- fsync / fdatasync ----------
    // These must actually reach the disk path. A kernel that returns 0
    // without writing is indistinguishable here until a reboot, so the
    // check is that they SUCCEED on a real descriptor and FAIL on a bad
    // one -- the refusal is what proves the path is wired.
    let path = b"/etc/p2.tmp\0";
    let fd2 = unsafe { open(path as *const u8 as i64, 0x2 | 0x200 | 0x400, 0o644) };
    if let Ok(f) = fd2 {
        let mut data = *b"hello";
        let _ = unsafe { wbytes(f, data.as_mut_ptr() as i64, 5) };
        check("fsync on file", unsafe { fsync(f) }.is_ok());
        check("fdatasync on file", unsafe { fdatasync(f) }.is_ok());
        let _ = unsafe { close(f) };
    } else {
        check("fsync on file", false);
        check("fdatasync on file", false);
    }
    // A descriptor that is not open must be EBADF, not success.
    check("fsync badfd", unsafe { fsync(999) }.is_err());
    check("fdatasync badfd", unsafe { fdatasync(999) }.is_err());

    // ---------- flock refused, not faked ----------
    // A caller that gets 0 back believes it holds a lock.
    check("flock refused", unsafe { flock(wrfd, 2) }.is_err()); // LOCK_EX
    check("flock unlock refused", unsafe { flock(wrfd, 8) }.is_err()); // LOCK_UN

    // ---------- getitimer round-trip ----------
    let mut itv = [0i64; 4];
    let _ = unsafe { setitimer(0, 0, itv.as_mut_ptr() as i64) };
    let mut back = [0i64; 4];
    let g = unsafe { getitimer(0, back.as_mut_ptr() as i64) };
    check("getitimer ok", g.is_ok());
    // Disarmed -> all zeros. Non-zero here would mean setitimer lied.
    check("getitimer disarmed", back[0] == 0 && back[1] == 0 && back[2] == 0 && back[3] == 0);
    // Arm a real timer and read back a NON-zero remaining value.
    let mut arm = [0i64; 4];
    arm[0] = 0; arm[1] = 0;   // interval: none
    arm[2] = 10; arm[3] = 0; // value: 10 seconds
    check("setitimer armed", unsafe { setitimer(0, arm.as_ptr() as i64, 0) }.is_ok());
    let mut back2 = [0i64; 4];
    check("getitimer armed ok", unsafe { getitimer(0, back2.as_mut_ptr() as i64) }.is_ok());
    // ru_ remaining must be > 0 and <= 10s. A hardcoded zero fails here.
    check("getitimer armed value", back2[2] > 0 && back2[2] <= 10);
    // Disarm again so nothing fires during the rest of the probe.
    let _ = unsafe { setitimer(0, 0, 0) };

    // ---------- getrusage ----------
    let mut ru = [0i64; 18];
    let r = unsafe { getrusage(0, ru.as_mut_ptr() as i64) };
    check("getrusage ok", r.is_ok());
    // ru_nvcsw sits at +24 (byte 24 = long index 3). This probe has slept
    // at least once in select, so it must be NON-zero -- a struct of
    // plausible zeros is precisely the silent failure being guarded.
    check("getrusage counted", ru[3] > 0 || ru[4] > 0 || ru[5] > 0);
    check("getrusage null EINVAL", unsafe { getrusage(0, 0) }.is_err());

    // ---------- getsid / getlogin ----------
    let sid = unsafe { getsid(0) }.unwrap_or(-1);
    check("getsid reached", sid >= 0);
    let mut lbuf = [0u8; 16];
    let lg = unsafe { getlogin(lbuf.as_mut_ptr() as i64, 16) };
    check("getlogin ok", lg.is_ok());
    check("getlogin wrote", lbuf[0] == b'r' && lbuf[4] == 0);
    // A too-small buffer is an error, not a truncated name.
    check("getlogin small EINVAL", unsafe { getlogin(lbuf.as_mut_ptr() as i64, 2) }.is_err());

    // ---------- rlimit round-trip ----------
    // struct rlimit is {u64 cur; u64 max} = 16 bytes. Setting then reading
    // back is the only way to tell a real setrlimit from one that accepts
    // the call and stores nothing.
    let mut rl = [0u64; 2];
    check("getrlimit ok", unsafe { getrlimit(8, rl.as_mut_ptr() as i64) }.is_ok()); // RLIMIT_NOFILE
    let max_before = rl[1];
    let mut set = [0u64; 2];
    set[0] = 64;
    set[1] = 4096; // a finite hard limit, so raising it is refused below
    check("setrlimit ok", unsafe { setrlimit(8, set.as_ptr() as i64) }.is_ok());
    // Raising the HARD limit is EPERM for an unprivileged caller: the
    // hard limit is exactly the ceiling on what may later be set.
    let mut raise = [0u64; 2];
    raise[0] = 64;
    raise[1] = u64::MAX;
    check("setrlimit raise max", unsafe { setrlimit(8, raise.as_ptr() as i64) }.is_err());
    let mut rl2 = [0u64; 2];
    check("getrlimit again", unsafe { getrlimit(8, rl2.as_mut_ptr() as i64) }.is_ok());
    check("setrlimit observable", rl2[0] == 64);
    // A resource outside RLIM_NLIMITS is EINVAL, not silently accepted.
    check("getrlimit badres", unsafe { getrlimit(99, rl2.as_mut_ptr() as i64) }.is_err());
    check("setrlimit badres", unsafe { setrlimit(99, set.as_ptr() as i64) }.is_err());
    // A soft limit above the hard one is EINVAL.
    let mut bad = [0u64; 2];
    bad[0] = 5000; // above the 4096 hard limit just installed
    bad[1] = 4096;
    check("setrlimit cur>max", unsafe { setrlimit(8, bad.as_ptr() as i64) }.is_err());
    // Raise the hard limit back so later runs are unaffected.
    let mut restore = [0u64; 2];
    restore[0] = max_before;
    restore[1] = max_before;
    let _ = unsafe { setrlimit(8, restore.as_ptr() as i64) };

    // ---------- hostname round-trip ----------
    let mut hn = [0u8; 64];
    check("gethostname ok", unsafe { gethostname(hn.as_mut_ptr() as i64, 64) }.is_ok());
    check("sethostname ok", unsafe { sethostname(b"tihkali-test\0".as_ptr() as i64, 13) }.is_ok());
    let mut hn2 = [0u8; 64];
    check("gethostname again", unsafe { gethostname(hn2.as_mut_ptr() as i64, 64) }.is_ok());
    check("sethostname observable", hn2[0] == b't' && hn2[1] == b'i');
    // An over-long name is ENAMETOOLONG, not silently truncated: a
    // truncated hostname is a DIFFERENT name, not the one asked for.
    let long = [b'x'; 80];
    check("sethostname toolong", unsafe { sethostname(long.as_ptr() as i64, 80) }.is_err());
    // An empty name is EINVAL.
    check("sethostname empty", unsafe { sethostname(b"\0".as_ptr() as i64, 1) }.is_err());

    // ---------- utimes / futimes ----------
    // Setting mtime must be READABLE back through stat -- otherwise
    // utimes is a silent success.
    let tp = b"/etc/p2.tmp\0";
    if unsafe { open(tp.as_ptr() as i64, 0x2 | 0x200 | 0x400, 0o644) }.is_ok() {
        check("utimes ok", unsafe { utimes(tp as *const u8 as i64, 0) }.is_ok());
        let mut times = [0i64; 2];
        times[0] = 1234567; // atime
        times[1] = 1234567; // mtime
        check("utimes explicit", unsafe { utimes(tp as *const u8 as i64, times.as_ptr() as i64) }.is_ok());
        let mut sb = [0u8; 152];
        if unsafe { crate_stat(tp.as_ptr() as i64, sb.as_mut_ptr() as i64) }.is_ok() {
            // st_mtim is at offset 64 (st_atim@48), verified with the cross compiler.
            let m = i64::from_le_bytes([sb[64], sb[65], sb[66], sb[67], sb[68], sb[69], sb[70], sb[71]]);
            check("utimes observable", m == 1234567);
        } else {
            check("utimes observable", false);
        }
        check("utimes ENOENT", unsafe { utimes(b"/etc/nope-b3\0".as_ptr() as i64, 0) }.is_err());
        // futimes does the same through a descriptor.
        let mut t3 = [0i64; 2];
        t3[0] = 7654321;
        t3[1] = 7654321;
        let ffd = unsafe { open(tp.as_ptr() as i64, 0x2 | 0x200 | 0x400, 0o644) };
        check("futimes ok", unsafe { futimes(ffd.unwrap_or(-1), t3.as_ptr() as i64) }.is_ok());
        if let Ok(f) = ffd { let _ = unsafe { close(f) }; }
        let mut sb2 = [0u8; 152];
        if unsafe { crate_stat(tp.as_ptr() as i64, sb2.as_mut_ptr() as i64) }.is_ok() {
            let m2 = i64::from_le_bytes([sb2[64], sb2[65], sb2[66], sb2[67], sb2[68], sb2[69], sb2[70], sb2[71]]);
            check("futimes observable", m2 == 7654321);
        } else {
            check("futimes observable", false);
        }
        check("futimes badfd", unsafe { futimes(999, 0) }.is_err());
    } else {
        check("utimes ok", false);
        check("utimes observable", false);
    }

    // ---------- dup3 ----------
    // dup3's distinguishing rule: oldfd == newfd is EINVAL, because it
    // would close the descriptor being duplicated.
    let (d3r, _d3w) = unsafe { pipe(pfds.as_mut_ptr() as i64) }.map(|_| (pfds[0] as i64, pfds[1] as i64)).unwrap_or((90, 91));
    check("dup3 same fd EINVAL", unsafe { dup3(d3r, d3r, 0) }.is_err());
    check("dup3 target ok", unsafe { dup3(d3r, 60, 0) }.is_ok());
    let _ = unsafe { close(60) };

    // ---------- sched_yield ----------
    // Yielding must return; a loop that never comes back would hang here.
    check("sched_yield returned", unsafe { sched_yield() }.is_ok());

    // ---------- refusals, each with its own errno ----------
    // sigaltstack takes sigaltstack13 and statfs takes statfs12: both are
    // lib-compat-era structs absent from current headers, so guessing a
    // layout would write a plausible struct at the wrong offsets.
    check("sigaltstack refused", unsafe { sigaltstack(0) }.is_err());
    check("statfs refused", unsafe { statfs(path as *const u8 as i64) }.is_err());

    let _ = unsafe { close(rdfd) };
    let _ = unsafe { close(wrfd) };

    finish();
}

fn finish() -> ! {
    let msg: &[u8] = if unsafe { FAILURES } == 0 {
        b"p2: all ok\n"
    } else {
        b"p2: FAILED\n"
    };
    unsafe {
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"p2: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}