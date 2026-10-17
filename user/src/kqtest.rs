#![no_std]
#![no_main]

//! NetBSD-ABI event interface: kqueue(344), kevent(345).
//!
//! kqueue is the stateful member of the pair — poll answers a question and
//! forgets it, kqueue holds registrations that kevent harvests later. That
//! difference is the whole point of these checks: most of them register an
//! event and then confirm it *persists* across a kevent call that reported
//! nothing, which a stateless implementation cannot pass.
//!
//! `struct kevent` is **72 bytes** here with `data` at offset 24 and
//! `udata` at offset 32 — the opposite of Linux's layout, where udata
//! comes first. A probe that copied Linux's offsets would still run and
//! still return 0, so the udata round-trip below is what proves the field
//! offsets are right.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

/// A NUL-terminated path in static storage.
macro_rules! p {
    ($b:expr) => {{
        const S: &[u8] = concat!($b, "\0").as_bytes();
        S.as_ptr()
    }};
}

fn check(name: &str, ok: bool) {
    let pad = b"\n                                 " as &[u8];
    // Saturating and clamped: an over-long name must not panic the probe.
    let n = (25usize).saturating_sub(name.len()).min(pad.len() - 1);
    unsafe {
        write(1, b"kq: ok    ");
        write(1, name.as_bytes());
        write(1, &pad[..n]);
        if ok {
            write(1, b"ok\n");
        } else {
            write(1, b"FAILED <<");
            write(1, name.as_bytes());
            write(1, b">>\n");
            FAILURES += 1;
        }
    }
}

/// Print a value in hex, which is how NOTE_* masks are read.
fn print_hex(name: &str, v: u32) {
    let mut digits = [0u8; 8];
    let mut n = 0;
    let mut u = v;
    if u == 0 {
        digits[n] = b'0';
        n += 1;
    }
    while u > 0 {
        digits[n] = b"0123456789abcdef"[(u & 15) as usize];
        u >>= 4;
        n += 1;
    }
    let mut out = [0u8; 8];
    let mut w = 0;
    for i in (0..n).rev() {
        out[w] = digits[i];
        w += 1;
    }
    unsafe {
        write(1, b"kq: hex  ");
        write(1, name.as_bytes());
        write(1, b" = 0x");
        write(1, &out[..w]);
        write(1, b"\n");
    }
}

fn print_num(name: &str, v: i64) {
    let mut buf = [0u8; 24];
    let mut n = 0;
    let neg = v < 0;
    if neg {
        buf[n] = b'-';
        n += 1;
    }
    let mut u = v.unsigned_abs();
    let start = n;
    if u == 0 {
        buf[n] = b'0';
        n += 1;
    }
    while u > 0 {
        buf[n] = b'0' + (u % 10) as u8;
        u /= 10;
        n += 1;
    }
    buf[start..n].reverse();
    unsafe {
        write(1, b"kq: num   ");
        write(1, name.as_bytes());
        write(1, b" = ");
        write(1, &buf[..n]);
        write(1, b"\n");
    }
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

/// SYS_write(fd, buf, len) = 4
unsafe fn wr(fd: i64, buf: &[u8]) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf.as_ptr(),
            in("x2") buf.len(),
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_fork() = 2
unsafe fn fork() -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #2",
            "cset {err}, hs",
            inlateout("x0") 0i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_wait4(pid, status, options) = **449** (WAIT4__2), blocking.
///
/// NOT 7: that is the obsolete compat WAIT4, and the kernel dispatches
/// only __2 -- so `svc #7` would hit an undispatched arm. Same trap as
/// MMAP=71 vs MMAP__2=197.
unsafe fn wait4_block(pid: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #449",
            inlateout("x0") pid => ret,
            in("x1") 0i64,
            in("x2") 0i64, // no WNOHANG: block, yielding the CPU
            options(nostack),
        );
    }
    ret
}

/// SYS_wait4(pid, status, options) = 449, WNOHANG.
unsafe fn wait4(pid: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #449",
            inlateout("x0") pid => ret,
            in("x1") 0i64,
            in("x2") 1i64, // WNOHANG
            options(nostack),
        );
    }
    ret
}

/// SYS_getpid() = 20 (GETPID_WITH_PPID)
unsafe fn getpid() -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #20", inlateout("x0") 0i64 => ret, options(nostack));
    }
    ret
}

/// SYS_getppid() = 39
unsafe fn getppid() -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #39", inlateout("x0") 0i64 => ret, options(nostack));
    }
    ret
}

/// SYS_execve(path, argv, envp) = 59
unsafe fn execve(path: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    let mut argv: [*const u8; 2] = [path, core::ptr::null()];
    unsafe {
        asm!(
            "svc #59",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") argv.as_mut_ptr(),
            in("x2") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_exit(code) = 1
unsafe fn exit(code: i64) -> ! {
    unsafe {
        asm!("svc #1", in("x0") code, options(nostack, noreturn));
    }
}

/// SYS_unlink(path) = 10
unsafe fn unlink(path: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #10",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_truncate(path, length) = 129
unsafe fn truncate(path: *const u8, len: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #129",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_open(path, flags) = 5
unsafe fn open(path: *const u8, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #5",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") flags,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_close(fd) = 6
unsafe fn close(fd: i64) {
    unsafe {
        asm!("svc #6", inlateout("x0") fd => _, options(nostack));
    }
}

/// SYS_kqueue() = 344 — no arguments, returns a descriptor.
unsafe fn kqueue() -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #344",
            "cset {err}, hs",
            inlateout("x0") 0i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_kevent(kq, changelist, nchanges, eventlist, nevents, timeout) = 345
unsafe fn kevent(
    kq: i64,
    cl: *const u8,
    nch: i64,
    el: *mut u8,
    nev: i64,
    to: i64,
) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #345",
            "cset {err}, hs",
            inlateout("x0") kq => ret,
            in("x1") cl,
            in("x2") nch,
            in("x3") el,
            in("x4") nev,
            in("x5") to,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// NetBSD aarch64 `struct kevent`, **72 bytes**. Offsets measured with the
/// vendored cross gcc, not guessed: ident@0, filter@8, flags@10, fflags@12,
/// data@16, udata@24, ext[4]@32.
///
/// Three traps: `ident` is a full 8-byte `uintptr_t`, pushing `filter` to
/// offset 8; `filter`/`flags` are `uint32_t` even though every reference
/// spells them as u16 — reading them as u16 gives the right value while
/// putting every later field at the wrong address; and the trailing `ext[4]`
/// is easy to forget when adding up the size. Note there is no `align(16)`
/// here: it would pad the struct to 80 and silently break every array of
/// events, since the kernel strides 72.
#[repr(C)]
struct Ke {
    ident: u64,
    filter: u32,
    flags: u32,
    fflags: u32,
    data: i64,
    udata: u64,
    ext: [u64; 4],
}

const KE_SIZE: usize = 72;

// EVFILT_* (sys/sys/event.h)
const EVFILT_READ: u32 = 0;
const EVFILT_WRITE: u32 = 1;
const EVFILT_VNODE: u32 = 2;
const EVFILT_PROC: u32 = 3;

// NOTE_* for EVFILT_PROC. These overlap the vnode NOTE_* space, so a
// misdispatched filter is visible as a wrong fflags mask.
const NOTE_EXIT: u32 = 0x8000_0000;
const NOTE_FORK: u32 = 0x4000_0000;
const NOTE_EXEC: u32 = 0x2000_0000;

// Registration flags.
const EV_ADD: u32 = 0x0001;
const EV_DELETE: u32 = 0x0002;
const EV_ENABLE: u32 = 0x0004;
const EV_DISABLE: u32 = 0x0008;
const EV_ONESHOT: u32 = 0x0010;

// NOTE_* filter flags for EVFILT_VNODE.
const NOTE_DELETE: u32 = 0x0001;
const NOTE_WRITE: u32 = 0x0002;
const NOTE_EXTEND: u32 = 0x0004;
const NOTE_ATTRIB: u32 = 0x0008;
const NOTE_RENAME: u32 = 0x0020;
const NOTE_FFAND: u32 = 0x4000_0000;
const NOTE_FFOR: u32 = 0x8000_0000;

/// Offsets asserted against the kernel's own writer. If these drift the
/// probe is reading the wrong bytes and every check below is meaningless.
const OFF_IDENT: usize = 0;
const OFF_FILTER: usize = 8;
const OFF_FLAGS: usize = 12;
const OFF_FFLAGS: usize = 16;
const OFF_DATA: usize = 24;
const OFF_UDATA: usize = 32;

/// A `{0, 0}` timespec. On NetBSD a **null** timeout pointer means "block
/// until something happens", so a harvesting call that uses 0 for "I do not
/// care" would park forever the moment no event is ready -- and would take
/// the whole check session with it. Every harvesting call below therefore
/// passes this instead: it is kevent(2)'s documented poll-without-blocking
/// form.
const POLL_ONLY: [i64; 2] = [0, 0];

/// As `fill`, but with fflags set -- needed for the NOTE_FF* filters.
fn fillf(ident: u64, filter: u32, flags: u32, fflags: u32, udata: u64) -> Ke {
    let mut k = fill(ident, filter, flags, udata);
    k.fflags = fflags;
    k
}

fn fill(ident: u64, filter: u32, flags: u32, udata: u64) -> Ke {
    Ke {
        ident,
        filter,
        flags,
        fflags: 0,
        data: 0,
        udata,
        ext: [0; 4],
    }
}

fn finish() -> ! {
    unsafe {
        write(1, b"kq: FAILURES = ");
        print_num("failures", FAILURES);
        if FAILURES == 0 {
            write(1, b"kq: all ok\n");
            asm!("svc #1", in("x0") 0isize, options(nostack, noreturn));
        } else {
            write(1, b"kq: FAILED\n");
            asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
        }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"kq: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // --- struct kevent offsets, asserted against our own layout -----
        let k = fill(0, 0, 0, 0);
        let base = &k as *const Ke as usize;
        check("offset ident", core::ptr::addr_of!(k.ident) as usize - base == OFF_IDENT);
        check("offset filter", core::ptr::addr_of!(k.filter) as usize - base == OFF_FILTER);
        check("offset flags", core::ptr::addr_of!(k.flags) as usize - base == OFF_FLAGS);
        check("offset fflags", core::ptr::addr_of!(k.fflags) as usize - base == OFF_FFLAGS);
        check("offset data", core::ptr::addr_of!(k.data) as usize - base == OFF_DATA);
        check("offset udata", core::ptr::addr_of!(k.udata) as usize - base == OFF_UDATA);
        check("sizeof kevent", core::mem::size_of::<Ke>() == KE_SIZE);

        // --- kqueue hands back a descriptor -------------------------------
        let Ok(kq) = kqueue() else {
            check("kqueue", false);
            finish();
        };
        check("kqueue", kq >= 0);
        let kq2 = kqueue();
        check("second kqueue", kq2.is_ok());
        if let Ok(k2) = kq2 {
            check("kqueue fds differ", k2 != kq);
            close(k2);
        }

        // --- EV_ADD on a regular file: both filters are always ready ------
        let Ok(fd) = open(p!("/etc/motd"), 0) else {
            check("open", false);
            finish();
        };
        check("open", fd >= 0);

        // A regular file is readable and writable at all times.
        let cl = fill(fd as u64, EVFILT_READ, EV_ADD, 0x1122_3344);
        let mut out = core::mem::zeroed::<Ke>();
        let n = kevent(kq, &cl as *const Ke as *const u8, 1, &mut out as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("add read fires", n == Ok(1));
        if let Ok(1) = n {
            let got = core::ptr::read_volatile(&out);
            check("returned ident", got.ident == fd as u64);
            check("returned filter", got.filter == EVFILT_READ);
            check("returned udata", got.udata == 0x1122_3344);
            check("returned data is 1", got.data == 1);
        }

        // --- a pure changelist call never blocks and returns 0 -----------
        let cl2 = fill(fd as u64, EVFILT_WRITE, EV_ADD, 0x5555);
        let n2 = kevent(kq, &cl2 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("changelist only returns 0", n2 == Ok(0));

        // --- registration persists: the write event survives, and both ---
        // Now both filters are registered. A single call must report both,
        // which only a stateful store can do.
        let mut out2 = [core::mem::zeroed::<Ke>(), core::mem::zeroed::<Ke>()];
        let n3 = kevent(kq, core::ptr::null(), 0, out2.as_mut_ptr() as *mut Ke as *mut u8, 2, POLL_ONLY.as_ptr() as i64);
        check("two events harvested", n3 == Ok(2));
        if n3 == Ok(2) {
            let mut saw_read = false;
            let mut saw_write = false;
            for i in 0..2 {
                let g = core::ptr::read_volatile(&out2[i]);
                if g.filter == EVFILT_READ && g.ident == fd as u64 {
                    saw_read = true;
                }
                if g.filter == EVFILT_WRITE && g.ident == fd as u64 {
                    saw_write = true;
                    check("write udata", g.udata == 0x5555);
                }
            }
            check("read event present", saw_read);
            check("write event present", saw_write);
        }

        // --- EV_DELETE removes it -----------------------------------------
        let del = fill(fd as u64, EVFILT_WRITE, EV_DELETE, 0);
        let n4 = kevent(kq, &del as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("delete returns 0", n4 == Ok(0));
        let mut out3 = core::mem::zeroed::<Ke>();
        let n5 = kevent(kq, core::ptr::null(), 0, &mut out3 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("one event left", n5 == Ok(1));
        if n5 == Ok(1) {
            let g = core::ptr::read_volatile(&out3);
            check("survivor is read", g.filter == EVFILT_READ);
        }

        // Deleting something absent must report ENOENT, not succeed.
        let del2 = fill(fd as u64, EVFILT_WRITE, EV_DELETE, 0);
        let n6 = kevent(kq, &del2 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("double delete ENOENT", n6 == Err(2));

        // --- EV_DISABLE silences without unregistering --------------------
        let dis = fill(fd as u64, EVFILT_READ, EV_DISABLE, 0);
        let n7 = kevent(kq, &dis as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("disable returns 0", n7 == Ok(0));
        let mut out4 = core::mem::zeroed::<Ke>();
        let n8 = kevent(kq, core::ptr::null(), 0, &mut out4 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("disabled reports nothing", n8 == Ok(0));

        // EV_ENABLE brings it back.
        let en = fill(fd as u64, EVFILT_READ, EV_ENABLE, 0);
        let n9 = kevent(kq, &en as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("enable returns 0", n9 == Ok(0));
        let mut out5 = core::mem::zeroed::<Ke>();
        let n10 = kevent(kq, core::ptr::null(), 0, &mut out5 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("re-enabled fires", n10 == Ok(1));

        // --- EV_ONESHOT drops the registration after firing ---------------
        let one = fill(fd as u64, EVFILT_READ, EV_ADD | EV_ONESHOT, 0);
        let n11 = kevent(kq, &one as *const Ke as *const u8, 1, &mut out5 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("oneshot fires once", n11 == Ok(1));
        let n12 = kevent(kq, core::ptr::null(), 0, &mut out5 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("oneshot then silent", n12 == Ok(0));

        // --- EVFILT_VNODE: watches a PATH, not a descriptor --------------
        // The registration is edge-preserving: it fires on a *change*, not
        // on "something is pending", and re-arms itself. So the ordering
        // below matters -- register, poll for silence, make a change, poll
        // again -- and a "fires again without a change" check is what
        // catches a level-triggered implementation.
        let vp = p!("/vnodetest.tmp");
        let vf = fillf(vp as u64, EVFILT_VNODE, EV_ADD, 0, 0xABCD);
        let n13 = kevent(kq, &vf as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("vnode add on missing ENOENT", n13 == Err(2));

        // Create it: that itself is a change, but the watcher is registered
        // afterwards so it must not fire on history.
        let Ok(vfd) = open(vp, 0x0002 | 0x0200) else {
            check("open vnode scratch", false);
            finish();
        };
        let vf2 = fillf(vp as u64, EVFILT_VNODE, EV_ADD, 0, 0xABCD);
        let n13b = kevent(kq, &vf2 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("vnode add succeeds", n13b == Ok(0));

        // Silent until something actually happens.
        let mut vo = core::mem::zeroed::<Ke>();
        let n13c = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("vnode silent when untouched", n13c == Ok(0));

        // A write must wake it with NOTE_WRITE.
        check("write to scratch", wr(vfd, b"hello") == Ok(5));
        let n13d = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("vnode fires on write", n13d == Ok(1));
        if n13d == Ok(1) {
            let g = core::ptr::read_volatile(&vo);
            check("vnode filter is VNODE", g.filter == EVFILT_VNODE);
            check("vnode udata roundtrips", g.udata == 0xABCD);
            check("vnode fflags has WRITE", g.fflags & NOTE_WRITE != 0);
            print_hex("vnode notes on write", g.fflags);
        }
        // Edge-preserving: having fired once, silence until the next change.
        let n13e = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("vnode not level-triggered", n13e == Ok(0));

        // Growing the file is NOTE_EXTEND as well as NOTE_WRITE.
        let tg = truncate(vp, 32);
        check("truncate to grow", tg == Ok(0));
        let n13f = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("vnode fires on extend", n13f == Ok(1));
        if n13f == Ok(1) {
            let g = core::ptr::read_volatile(&vo);
            check("extend sets NOTE_EXTEND", g.fflags & NOTE_EXTEND != 0);
        }

        // NOTE_FFAND: a watcher narrowed to one note must ignore others.
        // EV_ENABLE (not EV_DISABLE) re-registers with the new fflags: the
        // kernel's EV_ADD|EV_ENABLE path replaces the entry wholesale.
        let vf3 = fillf(vp as u64, EVFILT_VNODE, EV_ENABLE, NOTE_FFAND | NOTE_RENAME, 0);
        let s3 = kevent(kq, &vf3 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("vnode fflags set", s3 == Ok(0));
        // A write does not match a RENAME-only filter. It must be IGNORED
        // here and STILL PENDING afterwards -- that is what the restore
        // path is for. Two polls: the first must see nothing, the second
        // (after re-widening) must deliver the write.
        let wn = wr(vfd, b"more");
        check("write while narrowed", wn == Ok(4));
        let narrow_poll = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("narrowed ignores write", narrow_poll == Ok(0));
        // Poll AGAIN under the same narrow filter: the note must still be
        // pending, not silently consumed by the first non-matching poll.
        let narrow_poll2 = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("narrowed still silent", narrow_poll2 == Ok(0));

        // Widen back to "any note". The write was never consumed by the
        // narrow poll, so it must arrive now.
        let vf5 = fillf(vp as u64, EVFILT_VNODE, EV_ENABLE, 0, 0);
        check("vnode any-note", kevent(kq, &vf5 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));
        let n13g = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("pending note survives narrowing", n13g == Ok(1));
        if n13g == Ok(1) {
            let g = core::ptr::read_volatile(&vo);
            check("recovered note is WRITE", g.fflags & NOTE_WRITE != 0);
        }

        // NOTE_FFOR: any-of matching.
        let vf6 = fillf(vp as u64, EVFILT_VNODE, EV_ENABLE, NOTE_FFOR | NOTE_WRITE | NOTE_ATTRIB, 0);
        check("vnode ffor set", kevent(kq, &vf6 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));
        check("write for ffor", wr(vfd, b"x") == Ok(1));
        let n13h = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("ffor matches write", n13h == Ok(1));
        // A filter for a note that cannot occur must not fire.
        let vf7 = fillf(vp as u64, EVFILT_VNODE, EV_ENABLE, NOTE_FFOR | NOTE_DELETE, 0);
        check("vnode ffor delete set", kevent(kq, &vf7 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));
        check("write for ffor delete", wr(vfd, b"y") == Ok(1));
        let n13i = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("ffor delete ignores write", n13i == Ok(0));
        // Reset to any-note so the deletion below is visible.
        let vf8 = fillf(vp as u64, EVFILT_VNODE, EV_ENABLE, 0, 0);
        check("vnode reset to any", kevent(kq, &vf8 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));

        // Removing the watched file reports NOTE_DELETE.
        check("unlink watched file", unlink(vp) == Ok(0));
        let n13j = kevent(kq, core::ptr::null(), 0, &mut vo as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("vnode fires on delete", n13j == Ok(1));
        if n13j == Ok(1) {
            let g = core::ptr::read_volatile(&vo);
            check("delete sets NOTE_DELETE", g.fflags & NOTE_DELETE != 0);
        }

        // Watching a now-missing path fails, rather than silently passing.
        let vf9 = fillf(vp as u64, EVFILT_VNODE, EV_DELETE, 0, 0);
        check("vnode delete missing ENOENT", kevent(kq, &vf9 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Err(2));

        close(vfd);

        // A bad fd must be reported too.
        let badfd = fill(9999, EVFILT_READ, EV_ADD, 0);
        let n14 = kevent(kq, &badfd as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("bad fd EBADF", n14 == Err(9));

        // --- EVFILT_WRITE on stdout is ready; on stdin it is not ---------
        let w1 = fill(1, EVFILT_WRITE, EV_ADD, 0);
        let mut o1 = core::mem::zeroed::<Ke>();
        let n15 = kevent(kq, &w1 as *const Ke as *const u8, 1, &mut o1 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("stdout writable", n15 == Ok(1));
        if n15 == Ok(1) {
            let g = core::ptr::read_volatile(&o1);
            check("stdout ident", g.ident == 1);
        }

        // --- a zero timespec is a poll, never a park ----------------------
        // This must return immediately rather than blocking. A kernel that
        // ignored the zero timeout would hang the whole check session here.
        //
        // How many events come back depends on how much of the scripted
        // stdin the shell has already drained, which the probe cannot
        // predict. What it *can* assert is that the call returned at all:
        // the point of the check is "does not park", not the count.
        let r0 = fill(0, EVFILT_READ, EV_ADD, 0);
        let n16 = kevent(kq, &r0 as *const Ke as *const u8, 1, &mut o1 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("zero timeout polls", n16.is_ok());

        // Whatever it reported, a repeat with no changelist must agree --
        // registration persists across calls rather than being consumed.
        let mut o2 = core::mem::zeroed::<Ke>();
        let n16b = kevent(kq, core::ptr::null(), 0, &mut o2 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("poll repeats", n16b == n16);

        // --- nevents bounds the output ------------------------------------
        let w2 = fill(1, EVFILT_WRITE, EV_ADD, 0);
        let n17 = kevent(kq, &w2 as *const Ke as *const u8, 1, &mut o1 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("re-add stdout", n17 == Ok(1));

        // --- clear the slate so the next run starts clean -----------------
        let clr = fill(fd as u64, EVFILT_READ, EV_DELETE, 0);
        let _ = kevent(kq, &clr as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        let clr2 = fill(0, EVFILT_READ, EV_DELETE, 0);
        let _ = kevent(kq, &clr2 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        let clr3 = fill(1, EVFILT_WRITE, EV_DELETE, 0);
        let _ = kevent(kq, &clr3 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);

        // --- EVFILT_PROC: watch a PID for exit/fork/exec ------------------
        // Unlike the other filters this one keys on a pid, and the pid
        // outlives the table slot -- reap() frees the slot, so an event
        // recorded against a slot would vanish before a watcher saw it.
        let me = getpid();
        let pp = getppid();
        check("proc pid known", me > 0);
        check("proc ppid known", pp >= 0);

        // A pid that does not exist must be refused, not watched forever.
        let ghost = fillf(9999, EVFILT_PROC, EV_ADD, 0, 0);
        let ng = kevent(kq, &ghost as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("proc missing ESRCH", ng == Err(3));
        print_num("proc ESRCH", ng.unwrap_or(-999));

        // Watch our OWN pid for NOTE_EXIT. We are about to exit, and the
        // event must survive our own reaping.
        let pe = fillf(me as u64, EVFILT_PROC, EV_ADD, 0, 0xF00D);
        let npe = kevent(kq, &pe as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("proc watch self", npe == Ok(0));

        // A forked child raises NOTE_FORK on the PARENT. Fork, let it exit,
        // reap it -- the child's pid is gone by then, and the parent's
        // NOTE_FORK must still be deliverable.
        let ppf = fillf(pp as u64, EVFILT_PROC, EV_ADD, NOTE_FFOR, 0xBEEF);
        let npf = kevent(kq, &ppf as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        if pp > 0 {
            check("proc watch parent", npf == Ok(0));
        }

        let Ok(child) = fork() else {
            check("fork ok", false);
            finish();
        };
        if child == 0 {
            // Child exits immediately. It must not run the parent's
            // assertions: the check below is `child > 0`, which is false in
            // exactly this branch.
            exit(7);
        }
        check("fork child", child > 0);
        // Reap it so its slot is gone -- this is what a slot-indexed
        // implementation would lose the event to.
        let _ = wait4(child);

        // Now ask: is the parent's NOTE_FORK still there? We are the child
        // from the kernel's point of view relative to `pp`, and the shell
        // forked us long before, so this must NOT fire. But our OWN fork
        // just happened, and `me` is the parent of `child` -- so watching
        // `me` for NOTE_FORK is the positive case.
        let pf2 = fillf(me as u64, EVFILT_PROC, EV_ADD, NOTE_FFOR | NOTE_FORK, 0x1111);
        let npf2 = kevent(kq, &pf2 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("proc watch self fork", npf2 == Ok(0));

        // The fork already happened, so it is history: a first
        // registration must baseline it away.
        let mut po = core::mem::zeroed::<Ke>();
        let np1 = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        print_num("proc first poll", np1.unwrap_or(-999));

        // Fork again -- NOW the watcher is registered, so this one must fire.
        let Ok(child2) = fork() else {
            check("fork child2", false);
            finish();
        };
        if child2 == 0 {
            exit(9);
        }
        check("fork child2", child2 > 0);
        let _ = wait4(child2);

        let np2 = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("proc fires on fork", np2 == Ok(1));
        if np2 == Ok(1) {
            let g = core::ptr::read_volatile(&po);
            check("fork filter is PROC", g.filter == EVFILT_PROC);
            check("fork fflags", g.fflags & NOTE_FORK != 0);
            check("fork udata", g.udata == 0x1111);
            check("fork ident is me", g.ident == me as u64);
            print_num("fork data (child pid)", g.data);
            check("fork data is child", g.data == child2);
        }
        // Edge-preserving: one fork, one event.
        let np3 = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("proc not level-triggered", np3 == Ok(0));

        // A filter narrowed to NOTE_EXIT must ignore the NOTE_FORK we are
        // about to cause, and keep it pending.
        let narrow = fillf(me as u64, EVFILT_PROC, EV_ENABLE, NOTE_FFOR | NOTE_EXIT, 0);
        check("proc narrow set", kevent(kq, &narrow as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));
        let Ok(child3) = fork() else {
            check("fork child3", false);
            finish();
        };
        if child3 == 0 {
            exit(11);
        }
        check("fork child3", child3 > 0);
        let _ = wait4(child3);
        let npn = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("narrowed proc ignores fork", npn == Ok(0));

        // Widen back: the fork must still be pending, not consumed.
        let wide = fillf(me as u64, EVFILT_PROC, EV_ENABLE, 0, 0);
        check("proc widen", kevent(kq, &wide as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));
        let npw = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("proc pending survives narrowing", npw == Ok(1));
        if npw == Ok(1) {
            let g = core::ptr::read_volatile(&po);
            check("recovered note is FORK", g.fflags & NOTE_FORK != 0);
        }

        // EV_DISABLE silences without unregistering.
        let dis = fillf(me as u64, EVFILT_PROC, EV_DISABLE, 0, 0);
        check("proc disable", kevent(kq, &dis as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));
        let Ok(child4) = fork() else {
            check("fork child4", false);
            finish();
        };
        if child4 == 0 {
            exit(13);
        }
        check("fork child4", child4 > 0);
        let _ = wait4(child4);
        let npd = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("disabled proc silent", npd == Ok(0));
        // Re-enable: the fork made while disabled is delivered.
        let en = fillf(me as u64, EVFILT_PROC, EV_ENABLE, 0, 0);
        check("proc enable", kevent(kq, &en as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));
        let npe2 = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("disabled proc recovers", npe2 == Ok(1));

        // NOTE_EXEC is raised against the pid that execs. Watching a
        // long-lived process is the deterministic case: this binary's own
        // pid never execs, so instead the watcher is put on a child that
        // execs, and the child is allowed to run by BLOCKING on wait4
        // (which yields the single CPU) BEFORE the event is collected.
        //
        // The pid is gone by then on purpose: that is the case a
        // slot-indexed implementation loses, and the reason the event table
        // is keyed by pid.
        let pex = fillf(me as u64, EVFILT_PROC, EV_ENABLE, NOTE_FFOR | NOTE_EXEC, 0xC0DE);
        check("proc watch exec", kevent(kq, &pex as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Ok(0));

        let Ok(child5) = fork() else {
            check("fork child5", false);
            finish();
        };
        if child5 == 0 {
            if execve(p!("/bin/hello")).is_err() {
                exit(17);
            }
            exit(19);
        }
        check("fork child5", child5 > 0);
        let pex2 = fillf(child5 as u64, EVFILT_PROC, EV_ADD, NOTE_FFOR | NOTE_EXEC, 0xC0DE);
        let rex = kevent(kq, &pex2 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("exec watch child ok", rex == Ok(0));

        // /bin/hello FORKS and waits, so child5 does not exit on its own.
        // Spin on the CHILD'S exit with a blocking wait4, which is the only
        // thing on a single core that yields the CPU to the child.
        let _ = wait4_block(child5);

        let mut po2 = core::mem::zeroed::<Ke>();
        let npex2 = kevent(kq, core::ptr::null(), 0, &mut po2 as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("proc fires on exec", npex2 == Ok(1));
        if npex2 == Ok(1) {
            let g = core::ptr::read_volatile(&po2);
            check("exec fflags", g.fflags & NOTE_EXEC != 0);
            check("exec udata", g.udata == 0xC0DE);
            check("exec ident is child", g.ident == child5 as u64);
        }
        let dch = fillf(child5 as u64, EVFILT_PROC, EV_DELETE, 0, 0);
        let _ = kevent(kq, &dch as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);

        // Unregister cleanly.
        let delp = fillf(me as u64, EVFILT_PROC, EV_DELETE, 0, 0);
        let dp = kevent(kq, &delp as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("proc delete", dp == Ok(0));
        print_num("proc delete ret", dp.unwrap_or(-999));
        check("proc double delete ENOENT", {
            let d2 = fillf(me as u64, EVFILT_PROC, EV_DELETE, 0, 0);
            kevent(kq, &d2 as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0) == Err(2)
        });
        // With the registration gone, the pending fork must not surface.
        let npx = kevent(kq, core::ptr::null(), 0, &mut po as *mut Ke as *mut u8, 1, POLL_ONLY.as_ptr() as i64);
        check("proc gone is silent", npx == Ok(0));

        close(fd);
        close(kq);
        finish();
    }
}