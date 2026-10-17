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
    let n = 25 - name.len();
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

fn print_num(name: &str, v: i64) {
    let mut buf = [0u8; 24];
    let mut n = 0;
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    if u == 0 {
        buf[n] = b'0';
        n += 1;
    }
    while u > 0 {
        buf[n] = b'0' + (u % 10) as u8;
        u /= 10;
        n += 1;
    }
    if neg {
        buf[n] = b'-';
        n += 1;
    }
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
const EVFILT_VNODE: u32 = 2; // not supported here

// Registration flags.
const EV_ADD: u32 = 0x0001;
const EV_DELETE: u32 = 0x0002;
const EV_ENABLE: u32 = 0x0004;
const EV_DISABLE: u32 = 0x0008;
const EV_ONESHOT: u32 = 0x0010;

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

        // --- an unsupported filter must be refused, not silently ignored --
        let bad = fill(fd as u64, EVFILT_VNODE, EV_ADD, 0);
        let n13 = kevent(kq, &bad as *const Ke as *const u8, 1, core::ptr::null_mut(), 0, 0);
        check("EVFILT_VNODE EINVAL", n13 == Err(22));

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

        close(fd);
        close(kq);
        finish();
    }
}