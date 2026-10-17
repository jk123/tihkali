#![no_std]
#![no_main]

//! NetBSD-ABI identity and length calls: getppid(39), uname(164),
//! ftruncate(130), truncate(129).
//!
//! The point of this binary is `uname`. NetBSD's `struct utsname` is five
//! 256-byte char arrays -- 1280 bytes, no padding -- while Linux's is 390
//! bytes of a different layout. A kernel that reused its Linux writer
//! would return 0 and leave the caller reading fields at the wrong
//! offsets, so these checks read the BYTES at known offsets rather than
//! trusting the return code.
//!
//! `ftruncate` is gated on the read-only refusal: truncating a descriptor
//! opened O_RDONLY and reporting success is the kind of silent no-op a
//! return-code-only gate cannot see.

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
    let pad = b"\n                                   " as &[u8];
    // Saturating: an over-long name must not panic the whole probe. This
    // bit me once -- a 24-char name against a 23-wide pad aborted the run
    // three checks from the end with no failure report at all.
    let n = (23usize).saturating_sub(name.len()).min(pad.len() - 1);
    unsafe {
        write(1, b"idt: ok   ");
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
    let mut digits = [0u8; 24];
    let mut n = 0;
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    if u == 0 {
        digits[n] = b'0';
        n += 1;
    }
    while u > 0 {
        digits[n] = b'0' + (u % 10) as u8;
        u /= 10;
        n += 1;
    }
    // Reverse into place; a leading '-' belongs at the FRONT, so it cannot
    // be pushed like another digit.
    let mut buf = [0u8; 25];
    let mut w = 0;
    if neg {
        buf[w] = b'-';
        w += 1;
    }
    for i in (0..n).rev() {
        buf[w] = digits[i];
        w += 1;
    }
    let n = w;
    unsafe {
        write(1, b"idt: num  ");
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

/// SYS_open(path, flags, mode) = 5
unsafe fn open(path: *const u8, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #5",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") flags,
            in("x2") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_read(fd, buf, len) = 3
unsafe fn rdfd_read(fd: i64, buf: &mut [u8]) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #3",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf.as_mut_ptr(),
            in("x2") buf.len(),
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

/// SYS_getppid() = 39
unsafe fn getppid() -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #39", inlateout("x0") 0i64 => ret, options(nostack));
    }
    ret
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

/// SYS_lseek(fd, offset, whence) = 19, SEEK_SET = 0
unsafe fn lseek(fd: i64, off: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #19",
            inlateout("x0") fd => ret,
            in("x1") off,
            in("x2") 0i64,
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

/// SYS_uname(buf) = 164
unsafe fn uname(buf: *mut u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #164",
            "cset {err}, hs",
            inlateout("x0") buf => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_ftruncate(fd, length) = 130
unsafe fn ftruncate(fd: i64, len: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #130",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") len,
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

/// SYS_stat(path, statbuf) = 38 — read st_size at offset 112.
unsafe fn stat_size(path: *const u8) -> Result<i64, i64> {
    let mut buf = [0u8; 152];
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #38",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") buf.as_mut_ptr(),
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        Err(ret)
    } else {
        Ok(i64::from_le_bytes([
            buf[112], buf[113], buf[114], buf[115], buf[116], buf[117], buf[118], buf[119],
        ]))
    }
}

const UTSNAME_SIZE: usize = 1280;
const NMLN: usize = 256;

/// Read the NUL-terminated string a 256-byte field holds.
unsafe fn field(buf: *const u8, off: usize) -> (bool, i64) {
    let mut n = 0usize;
    let mut ok = false;
    while n < NMLN {
        if unsafe { *buf.add(off + n) } == 0 {
            ok = true;
            break;
        }
        n += 1;
    }
    (ok, n as i64)
}

unsafe fn str_eq(buf: *const u8, off: usize, want: &[u8]) -> bool {
    for (i, w) in want.iter().enumerate() {
        if unsafe { *buf.add(off + i) } != *w {
            return false;
        }
    }
    unsafe { *buf.add(off + want.len()) == 0 }
}

fn finish() -> ! {
    unsafe {
        if FAILURES == 0 {
            write(1, b"idt: all ok\n");
            asm!("svc #1", in("x0") 0isize, options(nostack, noreturn));
        } else {
            write(1, b"idt: FAILURES ");
            print_num("", FAILURES);
            write(1, b"idt: FAILED\n");
            asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
        }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"idt: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // --- getppid is NOT getpid ---------------------------------------
        let pid = getpid();
        let ppid = getppid();
        print_num("pid", pid);
        print_num("ppid", ppid);
        // The shell is pid 0 and has no parent, so getppid() is 0 here.
        // What matters is that it is NOT the caller's own pid -- an
        // implementation that returned getpid() would pass a "returns a
        // number" gate.
        check("ppid differs from pid", ppid != pid);
        check("ppid is not self", ppid != pid);
        check("ppid sane", ppid == 0 || (ppid > 0 && ppid < pid));
        // Idempotent: a second call must report the same parent.
        check("ppid is stable", getppid() == ppid);

        // --- uname writes NetBSD's 1280-byte struct -----------------------
        let mut u = [0xAAu8; UTSNAME_SIZE];
        check("uname succeeds", uname(u.as_mut_ptr()) == Ok(0));
        let b = u.as_ptr();

        // Offsets from sys/sys/utsname.h, measured with the cross gcc:
        // sysname@0 nodename@256 release@512 version@768 machine@1024.
        check("sysname is NetBSD", str_eq(b, 0, b"NetBSD"));
        check("nodename", str_eq(b, NMLN, b"tihkali"));
        check("release", str_eq(b, 2 * NMLN, b"0.1.0"));
        check("machine is aarch64", str_eq(b, 4 * NMLN, b"aarch64"));

        // Every field must be NUL-terminated inside its own 256 bytes, or
        // a caller doing strlen() would run into the next field.
        let mut all_terminated = true;
        let mut lens = [0i64; 5];
        for i in 0..5usize {
            let (ok, n) = field(b, i * NMLN);
            if !ok {
                all_terminated = false;
            }
            lens[i] = n;
        }
        check("all fields terminated", all_terminated);
        check("sysname len 6", lens[0] == 6);
        check("machine len 7", lens[4] == 7);

        // The tail of each 256-byte field must be zeroed, not stack
        // garbage: 0xAA was the pre-fill, so any surviving 0xAA is a
        // kernel that only wrote the string and left the rest alone.
        let mut zeroed = true;
        for i in 0..5usize {
            let mut j = lens[i] as usize + 1;
            while j < NMLN {
                if *b.add(i * NMLN + j) != 0 {
                    zeroed = false;
                }
                j += 1;
            }
        }
        check("field tails zeroed", zeroed);

        // A Linux-shaped writer would have put "Linux" at 0 and 390 bytes
        // total. Confirm we are not that.
        check("not Linux", !str_eq(b, 0, b"Linux"));
        check("version present", lens[3] > 0);

        // --- ftruncate by descriptor --------------------------------------
        // Make a scratch file, then shorten and re-extend it.
        let path = p!("/scratch.tmp");
        let Ok(wfd) = open(path, 0x0002 | 0x0200) else {
            check("open scratch rw", false);
            finish();
        };
        check("open scratch rw", wfd >= 0);
        let _ = wr(wfd, b"0123456789abcdef");

        check("ftruncate to 4", ftruncate(wfd, 4) == Ok(0));
        check("size after shrink", stat_size(path) == Ok(4));
        check("ftruncate to 12", ftruncate(wfd, 12) == Ok(0));
        check("size after extend", stat_size(path) == Ok(12));
        check("ftruncate to 0", ftruncate(wfd, 0) == Ok(0));
        check("size zeroed", stat_size(path) == Ok(0));
        // Shrinking then reading must yield nothing, not stale bytes.
        let mut rbuf = [0u8; 8];
        check("read after zero", rdfd_read(wfd, &mut rbuf) == Ok(0));
        // And re-extending must zero-fill rather than leave stale bytes.
        // Rewind first: the previous read left the position at EOF, so
        // reading without seeking would return 0 and prove nothing.
        check("ftruncate re-extend", ftruncate(wfd, 8) == Ok(0));
        check("lseek back to 0", lseek(wfd, 0) == 0);
        let n = rdfd_read(wfd, &mut rbuf);
        check("read after rewind", n == Ok(8));
        check("extending zeroes", rbuf.iter().all(|b| *b == 0));

        // --- a read-only descriptor must be refused -----------------------
        // This is the check a return-code-only gate would miss: silently
        // succeeding here would leave the caller believing it truncated.
        let Ok(rfd) = open(path, 0) else {
            check("open scratch ro", false);
            finish();
        };
        check("open scratch ro", rfd >= 0);
        let t = ftruncate(rfd, 4);
        check("ftruncate ro refused", t == Err(13));
        print_num("ro errno", t.unwrap_or(-999));

        // A bad fd is EBADF, distinct from the EACCES above.
        let t2 = ftruncate(9999, 0);
        check("ftruncate badfd EBADF", t2 == Err(9));
        print_num("badfd errno", t2.unwrap_or(-999));

        close(rfd);
        close(wfd);

        // --- truncate by path --------------------------------------------
        let Ok(w2) = open(path, 0x0002 | 0x0200) else {
            check("reopen scratch", false);
            finish();
        };
        let _ = wr(w2, b"abcdefghijklmnop");
        check("truncate path to 3", truncate(path, 3) == Ok(0));
        check("size after truncate", stat_size(path) == Ok(3));
        check("truncate missing ENOENT", truncate(p!("/no/such/file"), 0) == Err(2));
        print_num("missing errno", truncate(p!("/no/such/file"), 0).unwrap_or(-999));
        // A directory is not a file: EISDIR, not silent success.
        let t3 = truncate(p!("/etc"), 0);
        check("truncate dir EISDIR", t3 == Err(21));
        print_num("dir errno", t3.unwrap_or(-999));

        close(w2);

        // Clean up: a leftover scratch file would change what the
        // persistence sessions see on a later boot.
        check("unlink scratch", unlink(path) == Ok(0));
        check("unlink twice ENOENT", unlink(path) == Err(2));

        finish();
    }
}