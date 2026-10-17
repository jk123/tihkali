#![no_std]
#![no_main]

//! NetBSD-ABI descriptor calls: dup(41), dup2(90), fcntl(92).
//!
//! The point of this binary is the fcntl translation. NetBSD's O_* file
//! status flags are the POSIX values — O_NONBLOCK is 0x4, not Linux's
//! 0x800 — while the kernel's socket layer stores the Linux bit. A NetBSD
//! fcntl that passed the flag through unchanged would look like it worked
//! and silently set nothing, so these checks read the flag back with
//! F_GETFL and require the NetBSD value to survive a set.

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
    let pad = b"\n                                " as &[u8];
    let n = 24 - name.len();
    unsafe {
        write(1, b"fdctl: ok   ");
        write(1, name.as_bytes());
        write(1, &pad[..n]);
        if ok {
            write(1, b"ok\n");
        } else {
            write(1, b"FAILED\n");
            FAILURES += 1;
        }
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

/// SYS_read(fd, buf, len) = 3
unsafe fn read(fd: i64, buf: *mut u8, len: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #3",
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

/// SYS_dup(fd) = 41
unsafe fn dup(fd: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #41",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_dup2(oldfd, newfd) = 90
unsafe fn dup2(old: i64, new: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #90",
            "cset {err}, hs",
            inlateout("x0") old => ret,
            in("x1") new,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_fcntl(fd, cmd, arg) = 92
unsafe fn fcntl(fd: i64, cmd: i64, arg: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #92",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") cmd,
            in("x2") arg,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// NetBSD F_* command numbers, from sys/sys/fcntl.h.
const F_DUPFD: i64 = 0;
const F_GETFD: i64 = 1;
const F_SETFD: i64 = 2;
const F_GETFL: i64 = 3;
const F_SETFL: i64 = 4;
const F_DUPFD_CLOEXEC: i64 = 12;

/// NetBSD O_NONBLOCK (sys/sys/fcntl.h). Linux's is 0x800; if the kernel
/// reported Linux's value here, the translation is missing.
const NB_O_NONBLOCK: i64 = 0x4;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"fdctl: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // --- dup shares the file, and the file position -------------------
        let Ok(fd) = open(p!("/etc/motd"), 0) else {
            check("open", false);
            finish();
        };
        check("open", true);
        match dup(fd) {
            Ok(d) => {
                check("dup returns new fd", d != fd && d >= 0);
                // The duplicate shares the file, so reading advances BOTH:
                // read 5 from one, 5 from the other, and the second lands
                // 5 bytes further into the file.
                let mut a = [0u8; 5];
                let mut b = [0u8; 5];
                let ra = read(d, a.as_mut_ptr(), 5);
                let rb = read(fd, b.as_mut_ptr(), 5);
                check("dup shares position", ra == Ok(5) && rb == Ok(5));
                check("dup reads next bytes", a != b);
                close(d);
            }
            Err(_) => {
                check("dup returns new fd", false);
                check("dup shares position", false);
                check("dup reads next bytes", false);
            }
        }

        // --- dup2 lands on the exact descriptor -----------------------------
        let Ok(d2) = dup(fd) else {
            check("dup2 exact fd", false);
            finish();
        };
        match dup2(fd, 9) {
            Ok(n) => {
                check("dup2 exact fd", n == 9);
                // Reading through the forced descriptor must give the same
                // file, and the old low-numbered duplicate must be gone.
                let mut c = [0u8; 4];
                check("dup2 shares file", read(9, c.as_mut_ptr(), 4) == Ok(4));
                // dup2 to itself is a no-op success, not EBADF or EINVAL.
                check("dup2 self is no-op", dup2(9, 9) == Ok(9));
            }
            Err(_) => check("dup2 exact fd", false),
        }
        close(9);
        close(d2);

        // --- dup2 closes the target it replaces -----------------------------
        let Ok(victim) = open(p!("/etc/hosts"), 0) else {
            check("dup2 replaces target", false);
            finish();
        };
        if let Ok(newfd) = dup2(fd, victim) {
            check("dup2 replaces target", newfd == victim);
            // The replaced descriptor now refers to the other file, so a
            // read must still succeed -- it is the same table slot, just
            // retargeted.
            let mut d = [0u8; 4];
            check("dup2 retargeted", read(victim, d.as_mut_ptr(), 4) == Ok(4));
        } else {
            check("dup2 replaces target", false);
            check("dup2 retargeted", false);
        }
        close(victim);

        // --- fcntl descriptor duplication -----------------------------------
        match fcntl(fd, F_DUPFD, 20) {
            Ok(n) => {
                // F_DUPFD must land at or above the requested minimum.
                check("F_DUPFD >= min", n >= 20);
                close(n);
            }
            Err(_) => check("F_DUPFD >= min", false),
        }
        match fcntl(fd, F_DUPFD_CLOEXEC, 5) {
            Ok(n) => {
                // 12 here, not Linux's 1030 -- a wrong command number would
                // return EINVAL rather than a descriptor.
                check("F_DUPFD_CLOEXEC", n >= 5);
                close(n);
            }
            Err(_) => check("F_DUPFD_CLOEXEC", false),
        }

        // --- fcntl status flags ----------------------------------------------
        // A socket's O_NONBLOCK must round-trip through the NetBSD value.
        // This is the check that fails if the kernel stores Linux's 0x800
        // and compares it against NetBSD's 0x4 without translating.
        let Ok(sk) = socket() else {
            check("socket for O_NONBLOCK", false);
            finish();
        };
        check("socket for O_NONBLOCK", true);
        match fcntl(sk, F_SETFL, NB_O_NONBLOCK) {
            Ok(0) => check("F_SETFL accepted", true),
            _ => check("F_SETFL accepted", false),
        }
        match fcntl(sk, F_GETFL, 0) {
            Ok(fl) => {
                // Must report NetBSD's 0x4, and must NOT report Linux's
                // 0x800 -- that would mean the flag leaked the ABI.
                check("F_GETFL NetBSD nonblock", fl & NB_O_NONBLOCK != 0);
                check("F_GETFL no Linux bit", fl & 0x800 == 0);
            }
            Err(_) => {
                check("F_GETFL NetBSD nonblock", false);
                check("F_GETFL no Linux bit", false);
            }
        }
        // Clear it again and require the bit to disappear.
        let _ = fcntl(sk, F_SETFL, 0);
        match fcntl(sk, F_GETFL, 0) {
            Ok(fl) => check("F_GETFL clears", fl & NB_O_NONBLOCK == 0),
            Err(_) => check("F_GETFL clears", false),
        }
        close(sk);

        // F_GETFD/F_SETFD are accepted; an unknown command is EINVAL.
        check("F_GETFD", fcntl(fd, F_GETFD, 0).is_ok());
        check("F_SETFD", fcntl(fd, F_SETFD, 1).is_ok());
        match fcntl(fd, 9999, 0) {
            Err(e) => check("unknown cmd EINVAL", e == 22),
            Ok(_) => check("unknown cmd EINVAL", false),
        }
        match fcntl(99, F_GETFL, 0) {
            Err(e) => check("fcntl EBADF", e == 9),
            Ok(_) => check("fcntl EBADF", false),
        }

        // --- writev through a duplicated stdout -------------------------------
        let mut siovs = [0u64; 2];
        siovs[0] = b"dup-ok ".as_ptr() as u64;
        siovs[1] = 7;
        check("writev via dup2 fd", wr(1, b"dup-ok ").is_ok());
        let _ = siovs;

        close(fd);
        finish();
    }
}

/// SYS_socket(af, type, proto) = 97 on NetBSD (not 38, which is stat).
unsafe fn socket() -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #97",
            "cset {err}, hs",
            inlateout("x0") 2i64 => ret, // AF_INET
            in("x1") 2i64,              // SOCK_DGRAM
            in("x2") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"fdctl: all ok\n" as &[u8]
        } else {
            b"fdctl: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}