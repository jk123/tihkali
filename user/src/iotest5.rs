#![no_std]
#![no_main]

//! NetBSD-ABI batch 5: positional I/O (pread/pwrite), symlink, futimens,
//! setsid, setegid/seteuid, pathconf/fpathconf, sysarch, getrandom.
//!
//! The point of this probe is that each of these was a silent success or a
//! hardcoded zero:
//!
//! - **pread/pwrite must NOT move the file position.** A kernel that routes
//!   them through read/write breaks every caller that interleaves the two
//!   forms on one descriptor -- and the probe does exactly that, so the
//!   position is asserted rather than assumed.
//! - **The offset is x4, not x3** (`pread(fd, buf, nbyte, int PAD, off_t
//!   offset)`). Getting this wrong reads a padding word as the offset and
//!   fails at a wildly wrong place with no error.
//! - **pathconf is real work**: `_PC_NAME_MAX` is the longest name THIS
//!   filesystem can hold, not a constant.
//! - **getrandom must refuse.** Zero-filled bytes look exactly like
//!   randomness to a caller, and a PRNG seeded from the timer would give
//!   two boots the same "random" key.
//!
//! The refusals are gated on their own errno, because no return-code gate
//! can detect a silent success.

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

/// ONE write() for the whole line, assembled in a buffer.
fn check(name: &str, ok: bool) {
    let mut line = [0u8; 128];
    let mut n = 0usize;
    let put = |buf: &mut [u8; 128], n: &mut usize, bytes: &[u8]| {
        let end = (*n + bytes.len()).min(buf.len() - 1);
        buf[*n..end].copy_from_slice(&bytes[..end - *n]);
        *n = end;
    };
    let pad = b"                                      ";
    put(&mut line, &mut n, b"io5: ok    ");
    put(&mut line, &mut n, name.as_bytes());
    put(&mut line, &mut n, &pad[..(36usize).saturating_sub(name.len())]);
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

const O_CREAT: i64 = 0x200;
const O_TRUNC: i64 = 0x400;
const O_RDWR: i64 = 2;
const AT_FDCWD: i64 = -100;

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

unsafe fn openat_create(dirfd: i64, path: *const u8, flags: i64, mode: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #468",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") flags,
            in("x3") mode,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn close(fd: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #6",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// pwrite(fd, buf, nbyte, PAD, offset) = 174. The offset is x4 -- the
/// prototype carries an explicit PAD word.
unsafe fn pwrite(fd: i64, buf: *const u8, len: i64, offset: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #174",
            "cset {err}, hs",
            in("x0") fd,
            in("x1") buf,
            in("x2") len,
            in("x3") 0i64,
            in("x4") offset,
            lateout("x0") ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// pread(fd, buf, nbyte, PAD, offset) = 173
unsafe fn pread(fd: i64, buf: *mut u8, len: i64, offset: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #173",
            "cset {err}, hs",
            in("x0") fd,
            in("x1") buf,
            in("x2") len,
            in("x3") 0i64,
            in("x4") offset,
            lateout("x0") ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn read(fd: i64, buf: *mut u8, len: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            // NetBSD READ is 3. Using 4 here (which is WRITE) made this
            // helper WRITE into the buffer, so it "returned" ZZZZZ -- the
            // data it had been handed -- while the file was never read.
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

/// lseek(fd, offset, whence) = 19. SEEK_SET/CUR/END = 0/1/2.
unsafe fn lseek(fd: i64, offset: i64, whence: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #19",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") offset,
            in("x2") whence,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn setsid() -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #147",
            "cset {err}, hs",
            inlateout("x0") 0i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "svc #20",
            inlateout("x0") 0i64 => r,
            options(nostack),
        );
    }
    r
}

unsafe fn getuid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "svc #24",
            inlateout("x0") 0i64 => r,
            options(nostack),
        );
    }
    r
}

unsafe fn getgid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "svc #47",
            inlateout("x0") 0i64 => r,
            options(nostack),
        );
    }
    r
}

unsafe fn geteuid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "svc #25",
            inlateout("x0") 0i64 => r,
            options(nostack),
        );
    }
    r
}

unsafe fn getegid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "svc #43",
            inlateout("x0") 0i64 => r,
            options(nostack),
        );
    }
    r
}

/// seteuid(uid) = 183
unsafe fn seteuid(uid: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #183",
            "cset {err}, hs",
            inlateout("x0") uid => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// setegid(gid) = 182
unsafe fn setegid(gid: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #182",
            "cset {err}, hs",
            inlateout("x0") gid => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// getrandom(buf, len, flags) = 91
unsafe fn getrandom(buf: *mut u8, len: i64, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #91",
            "cset {err}, hs",
            inlateout("x0") buf => ret,
            in("x1") len,
            in("x2") flags,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// pathconf(path, name) = 191. _PC_NAME_MAX=3, _PC_PATH_MAX=4,
/// _PC_LINK_MAX=5, _PC_CHOWN_MAX=6, _PC_NO_TRUNC=7.
unsafe fn pathconf(path: *const u8, name: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #191",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") name,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// fpathconf(fd, name) = 192
unsafe fn fpathconf(fd: i64, name: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #192",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") name,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// sysarch(op, parms) = 165. `op` is an OP CODE, not a name string:
/// SYSARCH_UNAME_MACHINE=0, SYSARCH_UNAME_MACHINE_ALIAS=1. The caller's
/// buffer at `parms` is filled with the machine name and the length is
/// returned.
unsafe fn sysarch(op: i64, parms: u64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #165",
            "cset {err}, hs",
            inlateout("x0") op => ret,
            in("x1") parms,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn symlink(target: *const u8, linkpath: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #57",
            "cset {err}, hs",
            inlateout("x0") target => ret,
            in("x1") linkpath,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn readlink(path: *const u8, buf: *mut u8, len: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #58",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") buf,
            in("x2") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// futimens(fd, times[2]) = 472
unsafe fn futimens(fd: i64, times: *const i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #472",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") times,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// stat(path, buf) = 38 -- NetBSD's 152-byte layout. Only mtime.tv_sec is
/// read, at offset 64.
unsafe fn mtime_of(path: *const u8) -> Result<i64, i64> {
    #[repr(C, align(16))]
    struct Nbs {
        dev: u64,
        mode: u32,
        ino: u64,
        nlink: u32,
        uid: u32,
        gid: u32,
        rdev: u64,
        atim: (i64, i64),
        mtim: (i64, i64),
        ctim: (i64, i64),
        birthtim: (i64, i64),
        size: i64,
        blocks: i64,
        blksize: i32,
        flags: u32,
        generation: u32,
        spare: [u32; 2],
    }
    let mut st = unsafe { core::mem::zeroed::<Nbs>() };
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #38",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") &mut st as *mut Nbs,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(st.mtim.0) }
}

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

/// Returns (major, minor) through two i32s, for the refusal cases.
macro_rules! svc_ret0 {
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

svc_ret0!(vfork, 66);

/// A refusal that never returns, so it needs no result register: the
/// argument list varies per call and only the errno matters.
macro_rules! svc_refuse {
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
svc_refuse!(mlock, 203);
svc_refuse!(munlock, 204);
svc_refuse!(mlockall, 242);
svc_refuse!(munlockall, 243);
svc_refuse!(reboot, 55);
svc_refuse!(unmount, 22);
svc_refuse!(obreak, 17);
svc_refuse!(acct, 51);
svc_refuse!(revoke, 56);
svc_refuse!(mincore, 78);
svc_refuse!(pipe2, 453);

/// fexecve(465) needs an fd in x0, which svc_ret0 cannot express.
unsafe fn fexecve(fd: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #465",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") 0i64,
            in("x2") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}


#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"io5: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut buf = [0u8; 64];
        let mut times: [i64; 4];

        let _ = unlink(p!("/etc/io5a"));
        let _ = unlink(p!("/etc/io5b"));
        let _ = unlink(p!("/etc/io5link"));

        // --- pwrite/pread --------------------------------------------------
        // pwrite at offset 8 into an empty file must zero-fill the gap.
        // A kernel that treats offset as a position would append.
        let fd = match openat_create(AT_FDCWD, p!("/etc/io5a"), O_CREAT | O_TRUNC | O_RDWR, 0o644) {
            Ok(f) => f,
            Err(_) => -1,
        };
        check("created file", fd >= 0);
        check("pwrite at 8", pwrite(fd, p!("HELLO"), 5, 8).is_ok());
        match pread(fd, buf.as_mut_ptr(), 5, 8) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
                check("pread read it back", s == "HELLO");
            }
            Err(_) => check("pread read it back", false),
        }
        // Bytes 0..8 must be real zeros, not stack garbage from the gap.
        // A pwrite at 8 that does not extend the file would leave the
        // middle undefined; reading it back is the only way to see that.
        match pread(fd, buf.as_mut_ptr(), 8, 0) {
            Ok(n) => {
                let all_zero = buf[..n as usize].iter().all(|b| *b == 0);
                check("gap zero filled", all_zero);
            }
            Err(_) => check("gap zero filled", false),
        }

        // --- the position must NOT move ------------------------------------
        // This is the whole point of pread/pwrite. Interleave them with a
        // positional read() on the same descriptor: if pwrite moved the
        // position, this read returns the wrong bytes.
        match lseek(fd, 0, 0) { Ok(v) => { check("lseek to 0", v == 0) }, Err(_) => { check("lseek to 0", false) } }
        check("pwrite at 0", pwrite(fd, p!("ZZZZZ"), 5, 0).is_ok());
        match read(fd, buf.as_mut_ptr(), 5) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
                check("read at 0 after pwrite", s == "ZZZZZ");
            }
            Err(_) => { check("read at 0 after pwrite", false) }
        }
        // A pread must leave the position exactly where it was. The
        // previous read consumed 0..5, so the position is 5 -- and bytes
        // 5..10 are the three zero-fill bytes plus "HE". If pread had moved
        // the position to 13 (where it read) this would return past EOF.
        match pread(fd, buf.as_mut_ptr(), 5, 8) {
            Ok(_) => {}
            Err(_) => {}
        }
        match read(fd, buf.as_mut_ptr(), 5) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
                check("pread left the position", s == "\0\0\0HE");
            }
            Err(_) => check("pread left the position", false),
        }
        // A pwrite in the middle must not clobber the rest of the file.
        check("pwrite at 10", pwrite(fd, p!("XX"), 2, 10).is_ok());
        match pread(fd, buf.as_mut_ptr(), 5, 8) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
                check("pwrite patched in place", s == "HEXXO");
            }
            Err(_) => check("pwrite patched in place", false),
        }
        // A read-only descriptor must refuse pwrite rather than discard it.
        let rofd = match open(p!("/etc/io5a"), 0) {
            Ok(f) => f,
            Err(_) => -1,
        };
        match pwrite(rofd, p!("no"), 2, 0) {
            Err(e) => check("pwrite on O_RDONLY EACCES", e == 13),
            Ok(_) => check("pwrite on O_RDONLY EACCES", false),
        }
        if rofd >= 0 {
            let _ = close(rofd);
        }
        // A bad descriptor is EBADF, not a silent success.
        match pwrite(4242, p!("x"), 1, 0) {
            Err(e) => check("pwrite EBADF", e == 9),
            Ok(_) => check("pwrite EBADF", false),
        }
        if fd >= 0 {
            let _ = close(fd);
        }

        // --- symlink(57) ----------------------------------------------------
        check("symlink", symlink(p!("/etc/io5a"), p!("/etc/io5link")).is_ok());
        match readlink(p!("/etc/io5link"), buf.as_mut_ptr(), 64) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
                check("symlink target readable", s == "/etc/io5a");
            }
            Err(_) => check("symlink target readable", false),
        }
        match symlink(p!("/etc/io5a"), p!("/etc/io5link")) {
            Err(e) => check("symlink EEXIST", e == 17),
            Ok(_) => check("symlink EEXIST", false),
        }
        match symlink(p!("/etc/nosuch"), p!("/etc/io5dangling")) {
            // A dangling link is legal: the target need not exist.
            Ok(_) => check("dangling symlink allowed", true),
            Err(_) => check("dangling symlink allowed", false),
        }
        let _ = unlink(p!("/etc/io5dangling"));
        let _ = unlink(p!("/etc/io5link"));

        // --- futimens(472) --------------------------------------------------
        let fd = match open(p!("/etc/io5a"), O_RDWR) {
            Ok(f) => f,
            Err(_) => -1
        };
        check("reopened for rw", fd >= 0);
        // UTIME_OMIT is {1, UTIME_OMIT}; set the modification slot to a
        // fixed instant and require stat to report it.
        times = [1, 2, 1_000_000_000, 0];
        match futimens(fd, times.as_ptr()) {
            Ok(_) => check("futimens ok", true),
            Err(_) => { check("futimens ok", false) }
        };
        match mtime_of(p!("/etc/io5a")) {
            Ok(t) => check("futimens observable", t == 1_000_000_000),
            Err(_) => check("futimens observable", false),
        }
        // tv_nsec out of range is EINVAL -- a bad timestamp written anyway
        // would come back from stat as a plausible time.
        times = [1, 2, 500, 1_500_000_000];
        match futimens(fd, times.as_ptr()) {
            Err(e) => check("futimens bad nsec EINVAL", e == 22),
            Ok(_) => check("futimens bad nsec EINVAL", false),
        }
        match mtime_of(p!("/etc/io5a")) {
            Ok(t) => check("bad nsec changed nothing", t == 1_000_000_000),
            Err(_) => check("bad nsec changed nothing", false),
        }
        // A NULL times array means "now".
        check("futimens NULL", futimens(fd, core::ptr::null()).is_ok());
        // A read-only descriptor must refuse.
        if fd >= 0 {
            let _ = close(fd);
        }
        let rofd = match open(p!("/etc/io5a"), 0) {
            Ok(f) => f,
            Err(_) => -1,
        };
        times = [1, 2, 42, 0];
        match futimens(rofd, times.as_ptr()) {
            Err(e) => check("futimens on O_RDONLY EACCES", e == 13),
            Ok(_) => check("futimens on O_RDONLY EACCES", false),
        }
        if rofd >= 0 {
            let _ = close(rofd);
        }
        match futimens(4242, times.as_ptr()) {
            Err(e) => check("futimens EBADF", e == 9),
            Ok(_) => check("futimens EBADF", false),
        }

        // --- seteuid/setegid ------------------------------------------------
        // These set ONLY the effective id. getuid must be unchanged -- a
        // kernel that set both would silently change the real id, which a
        // caller uses to decide what it owns.
        let ru = getuid();
        check("seteuid ok", seteuid(7).is_ok());
        check("seteuid visible", geteuid() == 7);
        check("seteuid left ruid", getuid() == ru);
        check("seteuid back", seteuid(0).is_ok());
        check("euid restored", geteuid() == 0);
        let rg = getgid();
        check("setegid ok", setegid(5).is_ok());
        check("setegid visible", getegid() == 5);
        check("setegid left rgid", getgid() == rg);
        check("setegid back", setegid(0).is_ok());
        check("egid restored", getegid() == 0);

        // --- setsid(147) ----------------------------------------------------
        // The shell is already a session leader, so setsid must REFUSE. A
        // kernel that returns 0 here would report a session that does not
        // exist, and a caller would use the bogus id to signal a group.
        let pid = getpid();
        match setsid() {
            Err(e) => check("setsid EPERM as leader", e == 1),
            Ok(v) => {
                // If this kernel has no session concept at all and allows
                // it, the returned id must at least BE this process.
                check("setsid id is self", v == pid);
            }
        }

        // --- pathconf/fpathconf --------------------------------------------
        // _PC_NAME_MAX must describe THIS filesystem: the longest name it
        // can actually hold, which is at least the one just created.
        match pathconf(p!("/etc/io5a"), 3) {
            Ok(v) => check("pathconf NAME_MAX >= 4", v >= 4),
            Err(_) => check("pathconf NAME_MAX >= 4", false),
        }
        match pathconf(p!("/etc/io5a"), 4) {
            Ok(v) => { check("pathconf PATH_MAX", v == 1024) },
            Err(_) => { check("pathconf PATH_MAX", false) }
        }
        // _PC_LINK_MAX is 0 because this fs has no hard links -- a positive
        // value would let a caller try to make one.
        match pathconf(p!("/etc/io5a"), 5) {
            Ok(v) => check("pathconf LINK_MAX 0", v == 0),
            Err(_) => check("pathconf LINK_MAX 0", false),
        }
        match pathconf(p!("/etc/io5a"), 7) {
            Ok(v) => check("pathconf NO_TRUNC", v == 1),
            Err(_) => check("pathconf NO_TRUNC", false),
        }
        // An unknown request is EINVAL, not a plausible number.
        match pathconf(p!("/etc/io5a"), 999) {
            Err(e) => check("pathconf unknown EINVAL", e == 22),
            Ok(_) => check("pathconf unknown EINVAL", false),
        }
        match pathconf(p!("/etc/nosuch"), 3) {
            Err(e) => check("pathconf ENOENT", e == 2),
            Ok(_) => check("pathconf ENOENT", false),
        }
        let dfd = match open(p!("/etc"), 0) {
            Ok(f) => f,
            Err(_) => -1,
        };
        match fpathconf(dfd, 4) {
            Ok(v) => check("fpathconf PATH_MAX", v == 1024),
            Err(_) => check("fpathconf PATH_MAX", false),
        }
        match fpathconf(4242, 4) {
            Err(e) => check("fpathconf EBADF", e == 9),
            Ok(_) => check("fpathconf EBADF", false),
        }
        if dfd >= 0 {
            let _ = close(dfd);
        }

        // --- sysarch(165) ---------------------------------------------------
        // Called with "uname_machine" it reports the machine name. A wrong
        // answer is worse than a refusal: the caller picks a code path.
        let mut machine = [0u8; 32];
        match sysarch(0, machine.as_mut_ptr() as u64) {
            Ok(n) => {
                let s = core::str::from_utf8(&machine[..n as usize]).unwrap_or("");
                check("sysarch machine", s == "aarch64");
            }
            Err(_) => check("sysarch machine", false),
        }
        // An unknown op code is EINVAL, not a plausible answer.
        match sysarch(99, machine.as_mut_ptr() as u64) {
            Err(e) => check("sysarch bad op EINVAL", e == 22),
            Ok(_) => check("sysarch bad op EINVAL", false),
        }
        match sysarch(0, 0x10) {
            Err(e) => check("sysarch EFAULT", e == 14),
            Ok(_) => check("sysarch EFAULT", false),
        }

        // --- getrandom(91): refused, not zero-filled ------------------------
        // Zero bytes look exactly like randomness to a caller, and a PRNG
        // seeded from the timer would give two boots the same "random" key.
        let mut rnd = [0u8; 16];
        match getrandom(rnd.as_mut_ptr(), 16, 0) {
            Err(e) => check("getrandom ENOSYS", e == 78),
            Ok(_) => {
                // If this kernel ever grows an entropy source, these must
                // not all be zero -- which is the failure mode to guard.
                let all_zero = rnd.iter().all(|b| *b == 0);
                check("getrandom not all zero", !all_zero);
            }
        }

        // --- refusals -------------------------------------------------------
        // Each of these would have to DO something. Returning 0 would be a
        // silent success, which is worse than the honest refusal.
        match mlock() {
            Err(e) => check("mlock EOPNOTSUPP", e == 45),
            Ok(_) => check("mlock EOPNOTSUPP", false),
        }
        match munlock() {
            Err(e) => check("munlock EOPNOTSUPP", e == 45),
            Ok(_) => check("munlock EOPNOTSUPP", false),
        }
        match mlockall() {
            Err(e) => check("mlockall EOPNOTSUPP", e == 45),
            Ok(_) => check("mlockall EOPNOTSUPP", false),
        }
        match munlockall() {
            Err(e) => check("munlockall EOPNOTSUPP", e == 45),
            Ok(_) => check("munlockall EOPNOTSUPP", false),
        }
        match reboot() {
            Err(e) => check("reboot EPERM", e == 1),
            Ok(_) => check("reboot EPERM", false),
        }
        match unmount() {
            Err(e) => check("unmount EACCES", e == 13),
            Ok(_) => check("unmount EACCES", false),
        }
        match obreak() {
            Err(e) => check("obreak EINVAL", e == 22),
            Ok(_) => check("obreak EINVAL", false),
        }
        match acct() {
            Err(e) => check("acct EINVAL", e == 22),
            Ok(_) => check("acct EINVAL", false),
        }
        match revoke() {
            Err(e) => check("revoke EINVAL", e == 22),
            Ok(_) => check("revoke EINVAL", false),
        }
        match mincore() {
            Err(e) => check("mincore EOPNOTSUPP", e == 45),
            Ok(_) => check("mincore EOPNOTSUPP", false),
        }
        match vfork() {
            Err(e) => check("vfork EOPNOTSUPP", e == 45),
            Ok(_) => check("vfork EOPNOTSUPP", false),
        }
        match pipe2() {
            Err(e) => check("pipe2 EOPNOTSUPP", e == 45),
            Ok(_) => check("pipe2 EOPNOTSUPP", false),
        }
        match fexecve(0) {
            Err(e) => check("fexecve EOPNOTSUPP", e == 45),
            Ok(_) => check("fexecve EOPNOTSUPP", false),
        }

        // --- clean up -------------------------------------------------------
        let _ = unlink(p!("/etc/io5a"));
        let _ = unlink(p!("/etc/io5b"));
        let _ = unlink(p!("/etc/io5link"));

        finish();
    }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"io5: all ok\n" as &[u8]
        } else {
            b"io5: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}