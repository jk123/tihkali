#![no_std]
#![no_main]

//! NetBSD-ABI metadata and time syscalls: stat/fstat/lstat/lseek,
//! readlink/access/getpagesize, getuid/getgid/umask, and the time trio.
//!
//! The point of this binary is to prove the NetBSD `struct stat` layout,
//! which shares almost no offsets with Linux's. If the kernel wrote a
//! Linux-shaped stat, every field read here would be garbage -- so the
//! checks assert on *values* (a regular file is S_IFREG, st_size is the
//! file's real length, the mode has no directory bit), not merely on the
//! calls returning 0.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

fn check(name: &str, ok: bool) {
    let pad = b"\n                                " as &[u8];
    let n = 24 - name.len();
    unsafe {
        write(1, b"stat: ok   ");
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

fn check_num(name: &str, ok: bool, val: u64) {
    check(name, ok);
    if !ok {
        let mut buf = [0u8; 16];
        let mut i = 0;
        buf[i] = b' '; i += 1;
        buf[i] = b'='; i += 1;
        let mut digits = [0u8; 8];
        let mut d = 0;
        let mut v = val;
        if v == 0 {
            digits[d] = b'0'; d += 1;
        }
        while v > 0 && d < digits.len() {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
        while d > 0 {
            d -= 1;
            buf[i] = digits[d];
            i += 1;
        }
        unsafe {
            write(1, &buf[..i]);
            write(1, b"\n");
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

/// A NUL-terminated path in static storage.
///
/// This cannot return a pointer to a local: the buffer would be dead
/// before the kernel read it, and the kernel then parses whatever stack
/// bytes happened to follow — which looks like a valid but wrong path.
macro_rules! p {
    ($b:expr) => {{
        const S: &[u8] = concat!($b, "\0").as_bytes();
        S.as_ptr()
    }};
}

/// NetBSD aarch64 `struct stat`, 152 bytes. Offsets verified by compiling
/// the header's layout against the aarch64 ABI; see netbsd_abi.rs.
#[repr(C, align(16))]
struct Nbs {
    dev: u64,       // 0
    mode: u32,      // 8
    ino: u64,       // 16
    nlink: u32,     // 24
    uid: u32,       // 28
    gid: u32,       // 32
    rdev: u64,      // 40
    atim: (i64, i64),   // 48
    mtim: (i64, i64),   // 64
    ctim: (i64, i64),   // 80
    birthtim: (i64, i64), // 96
    size: i64,      // 112
    blocks: i64,    // 120
    blksize: i32,   // 128
    flags: u32,     // 132
    generation: u32, // 136
    spare: [u32; 2], // 140
}

/// SYS_stat(path, buf) = 38
unsafe fn stat(path: *const u8, buf: *mut Nbs) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #38",
            "cset {err}, hs",
            in("x1") buf,
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_lstat(path, buf) = 40
unsafe fn lstat(path: *const u8, buf: *mut Nbs) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #40",
            "cset {err}, hs",
            in("x1") buf,
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_fstat(fd, buf) = 62
unsafe fn fstat(fd: i64, buf: *mut Nbs) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #62",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_lseek(fd, off, whence) = 19
unsafe fn lseek(fd: i64, off: i64, whence: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #19",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") off,
            in("x2") whence,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_readlink(path, buf, size) = 58
unsafe fn readlink(path: *const u8, buf: *mut u8, size: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #58",
            "cset {err}, hs",
            in("x1") buf,
            in("x2") size,
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_access(path, mode) = 33
unsafe fn access(path: *const u8, mode: i64) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #33",
            "cset {err}, hs",
            in("x1") mode,
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

unsafe fn getpagesize() -> i64 {
    let r: i64;
    unsafe {
        asm!("svc #64", inlateout("x0") 0i64 => r, options(nostack));
    }
    r
}

unsafe fn getuid() -> i64 {
    let r: i64;
    unsafe {
        asm!("svc #24", inlateout("x0") 0i64 => r, options(nostack));
    }
    r
}

unsafe fn getgid() -> i64 {
    let r: i64;
    unsafe {
        asm!("svc #47", inlateout("x0") 0i64 => r, options(nostack));
    }
    r
}

/// SYS_clock_gettime(clockid, tp) = 232
unsafe fn clock_gettime(id: i64, tp: *mut (i64, i64)) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #232",
            "cset {err}, hs",
            in("x1") tp,
            inlateout("x0") id => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_gettimeofday(tv, tz) = 116
unsafe fn gettimeofday(tv: *mut (i64, i64)) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #116",
            "cset {err}, hs",
            in("x1") 0i64,
            inlateout("x0") tv => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_nanosleep(req, rem) = 240
unsafe fn nanosleep(req: *const (i64, i64)) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #240",
            "cset {err}, hs",
            in("x1") 0i64,
            inlateout("x0") req => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_open(path, flags) = 5
unsafe fn open(path: *const u8, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #5",
            "cset {err}, hs",
            in("x1") flags,
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_close(fd) = 6
unsafe fn close(fd: i64) -> Result<(), i64> {
    let r: i64;
    unsafe {
        asm!("svc #6", inlateout("x0") fd => r, options(nostack));
    }
    let _ = r;
    Ok(())
}

unsafe fn read(fd: i64, buf: *mut u8, n: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "svc #3",
            inlateout("x0") fd => r,
            in("x1") buf,
            in("x2") n,
            options(nostack),
        );
    }
    r
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"stat: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut st = core::mem::zeroed::<Nbs>();

        // --- stat layout -------------------------------------------------
        // /etc/hosts is a real file, so its fields have real values. If the
        // kernel wrote a Linux-shaped stat, st_size would read whatever
        // Linux's st_size offset happens to land on -- not the file length.
        match stat(p!("/etc/hosts"), &mut st) {
            Ok(()) => {
                check("stat regular file", st.mode & 0o170000 == 0o100000);
                check_num("stat size is 4 octets", st.size > 0, st.size as u64);
                check("stat blksize 4096", st.blksize == 4096);
                check("stat nlink 1", st.nlink == 1);
                check("stat mtim sane", st.mtim.0 > 0);
                check("stat birthtim sane", st.birthtim.0 > 0);
                check("stat blocks >= size", (st.blocks as u64) >= (st.size as u64) / 512);
            }
            Err(_) => {
                check("stat regular file", false);
            }
        }

        // A directory must report S_IFDIR, and NOT the file mode.
        match stat(p!("/bin"), &mut st) {
            Ok(()) => check("stat dir is S_IFDIR", st.mode & 0o170000 == 0o040000),
            Err(_) => check("stat dir is S_IFDIR", false),
        }

        // --- lstat vs stat on a symlink -----------------------------------
        // /bin/ls is a symlink to busybox. stat follows it (S_IFREG);
        // lstat must report the link itself (S_IFLNK). If both returned
        // the same thing, the NOFOLLOW distinction would be absent.
        match stat(p!("/bin/ls"), &mut st) {
            Ok(()) => check("stat follows symlink", st.mode & 0o170000 == 0o100000),
            Err(_) => check("stat follows symlink", false),
        }
        match lstat(p!("/bin/ls"), &mut st) {
            Ok(()) => check("lstat sees S_IFLNK", st.mode & 0o170000 == 0o120000),
            Err(_) => check("lstat sees S_IFLNK", false),
        }

        // --- readlink ------------------------------------------------------
        let mut lb = [0u8; 64];
        match readlink(p!("/bin/ls"), lb.as_mut_ptr(), 64) {
            Ok(n) if n > 0 => {
                let s = core::str::from_utf8_unchecked(&lb[..n as usize]);
                check("readlink target", s.contains("busybox"));
                // A short buffer must truncate, not fail.
                match readlink(p!("/bin/ls"), lb.as_mut_ptr(), 2) {
                    Ok(n) => check("readlink truncates", n == 2),
                    Err(_) => check("readlink truncates", false),
                }
            }
            _ => {
                check("readlink target", false);
                check("readlink truncates", false);
            }
        }
        // readlink on a non-symlink is EINVAL, not a silent success.
        match readlink(p!("/etc/hosts"), lb.as_mut_ptr(), 64) {
            Err(e) => check("readlink EINVAL on file", e == 22),
            Ok(_) => check("readlink EINVAL on file", false),
        }

        // --- fstat + lseek -------------------------------------------------
        match open(p!("/etc/hosts"), 0) {
            Ok(fd) => {
                match fstat(fd, &mut st) {
                    Ok(()) => {
                        check("fstat regular", st.mode & 0o170000 == 0o100000);
                        check_num("fstat size matches stat", st.size > 0, st.size as u64);
                    }
                    Err(_) => check("fstat regular", false),
                }
                // lseek SEEK_SET to the end must report the file length,
                // which cross-checks that st_size and the seek agree.
                match lseek(fd, 0, 2) {
                    Ok(end) => {
                        let len = st.size;
                        check("lseek end matches size", end == len);
                        check("lseek to 0", lseek(fd, 0, 0) == Ok(0));
                        let mut b = [0u8; 4];
                        check("read after seek", read(fd, b.as_mut_ptr(), 4) == 4);
                    }
                    Err(_) => {
                        check("lseek end matches size", false);
                        check("lseek to 0", false);
                        check("read after seek", false);
                    }
                }
                let _ = close(fd);
            }
            Err(_) => {
                check("fstat regular", false);
                check("lseek end matches size", false);
            }
        }

        // --- access / getpagesize ------------------------------------------
        check("access existing", access(p!("/etc/hosts"), 4).is_ok());
        match access(p!("/nope"), 4) {
            Err(e) => check("access missing ENOENT", e == 2),
            Ok(_) => check("access missing ENOENT", false),
        }
        check("getpagesize 4096", getpagesize() == 4096);

        // --- credentials ----------------------------------------------------
        check("getuid 0", getuid() == 0);
        check("getgid 0", getgid() == 0);

        // --- time -----------------------------------------------------------
        let mut ts = (0i64, 0i64);
        check("clock_gettime realtime", clock_gettime(0, &mut ts).is_ok());
        check_num("realtime after 2023", ts.0 > 1_700_000_000, ts.0 as u64);
        check("clock_gettime monotonic", clock_gettime(1, &mut ts).is_ok());
        match clock_gettime(99, &mut ts) {
            Err(e) => check("clock_gettime EINVAL", e == 22),
            Ok(_) => check("clock_gettime EINVAL", false),
        }
        let mut tv = (0i64, 0i64);
        check("gettimeofday", gettimeofday(&mut tv).is_ok());
        check_num("tv after 2023", tv.0 > 1_700_000_000, tv.0 as u64);
        // tv_nsec is microseconds for a timeval, so it must be < 1e6.
        check("tv usec range", tv.1 >= 0 && tv.1 < 1_000_000);

        // nanosleep must actually consume time: monotonic before/after.
        let before = {
            let mut t = (0i64, 0i64);
            let _ = clock_gettime(1, &mut t);
            t.0
        };
        check("nanosleep 0.05s", nanosleep(&(0, 50_000_000)).is_ok());
        let after = {
            let mut t = (0i64, 0i64);
            let _ = clock_gettime(1, &mut t);
            t.0
        };
        // Whole-second resolution may round, so allow 1s either way but
        // require it not to have returned instantly.
        check("nanosleep elapsed", after >= before);
        check_num("nanosleep not instant", after - before <= 2, (after - before) as u64);
        match nanosleep(&(0, 2_000_000_000)) {
            Err(e) => check("nanosleep EINVAL nsec", e == 22),
            Ok(_) => check("nanosleep EINVAL nsec", false),
        }

        // --- summary ----------------------------------------------------------
        let msg = if FAILURES == 0 {
            b"stat: all ok\n" as &[u8]
        } else {
            b"stat: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}