#![no_std]
#![no_main]

//! NetBSD-ABI batch 4: the *at() family, fchdir, and the path-call refusals.
//!
//! Two things make this probe worth its own binary.
//!
//! **The AT_* flag values are not Linux's.** NetBSD has AT_EACCESS=0x100,
//! AT_SYMLINK_NOFOLLOW=0x200, AT_SYMLINK_FOLLOW=0x400 and AT_REMOVEDIR=0x800
//! (sys/sys/fcntl.h), where Linux's AT_SYMLINK_NOFOLLOW is 0x100 and there
//! is no AT_REMOVEDIR at all. A kernel that reuses Linux's constants here
//! treats AT_EACCESS as "do not follow" and follows the link instead -- so
//! the probe passes NetBSD's 0x200 and a Linux-shaped kernel misreads it.
//!
//! **There is no rmdirat.** NetBSD asks for a directory removal by passing
//! AT_REMOVEDIR to unlinkat. A kernel that wired unlinkat to unlink only
//! would silently refuse a legitimate call and, worse, unlink a directory
//! when asked to rmdir it.
//!
//! The refusals matter as much as the work: `link` succeeding without
//! creating a second name, and `mkfifo` succeeding by creating a regular
//! file, are both silent successes. Each is gated on its own errno.

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
    put(&mut line, &mut n, b"at: ok     ");
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

/// open(path, flags, ...) = 5
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

/// close(fd) = 6
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

/// NetBSD O_CREAT is 0x200 and O_RDONLY is 0. (Linux's O_CREAT is 0x40 --
/// a third instance of "same name, different encoding".)
const O_CREAT: i64 = 0x200;
const O_TRUNC: i64 = 0x400;

/// A 3-argument open via openat(fd=-100, ...) is how this probe creates a
/// file with a mode, which plain open(2) would need a variadic third word
/// for. It doubles as the first openat check.
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

/// mkdirat(fd, path, mode) = 461
unsafe fn mkdirat(dirfd: i64, path: *const u8, mode: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #461",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") mode,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// unlinkat(fd, path, flag) = 471. NetBSD's flag is AT_REMOVEDIR=0x800.
unsafe fn unlinkat(dirfd: i64, path: *const u8, flag: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #471",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") flag,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: i64 = 0x200;
const AT_SYMLINK_FOLLOW: i64 = 0x400;
const AT_REMOVEDIR: i64 = 0x800;
const AT_EACCESS: i64 = 0x100;

/// symlinkat(path1, fd, path2) = 470
unsafe fn symlinkat(target: *const u8, dirfd: i64, linkpath: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #470",
            "cset {err}, hs",
            inlateout("x0") target => ret,
            in("x1") dirfd,
            in("x2") linkpath,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// readlinkat(fd, path, buf, bufsize) = 469
unsafe fn readlinkat(dirfd: i64, path: *const u8, buf: *mut u8, bufsize: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #469",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") buf,
            in("x3") bufsize,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// fstatat(fd, path, buf, flag) = 466 -- NetBSD's 152-byte stat.
unsafe fn fstatat_mode(dirfd: i64, path: *const u8, flag: i64) -> Result<u32, i64> {
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
            "svc #466",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") &mut st as *mut Nbs,
            in("x3") flag,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(st.mode) }
}

/// faccessat(fd, path, amode, flag) = 462
unsafe fn faccessat(dirfd: i64, path: *const u8, amode: i64, flag: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #462",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") amode,
            in("x3") flag,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// fchdir(fd) = 13
unsafe fn fchdir(fd: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #13",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// chdir(path) = 12
unsafe fn chdir(path: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #12",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// __getcwd(buf, len) = 296
unsafe fn getcwd(buf: *mut u8, len: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #296",
            "cset {err}, hs",
            inlateout("x0") buf => ret,
            in("x1") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// unlink(path) = 10
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

/// rmdir(path) = 137
unsafe fn rmdir(path: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #137",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// renameat(fromfd, from, tofd, to) = 458
unsafe fn renameat(ffd: i64, from: *const u8, tfd: i64, to: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #458",
            "cset {err}, hs",
            inlateout("x0") ffd => ret,
            in("x1") from,
            in("x2") tfd,
            in("x3") to,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// stat(path, buf) = 38 -- used to confirm a file is really gone.
unsafe fn exists(path: *const u8) -> bool {
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
    let err: isize;
    unsafe {
        asm!(
            "svc #38",
            "cset {err}, hs",
            in("x0") path,
            in("x1") &mut st as *mut Nbs,
            err = out(reg) err,
            options(nostack),
        );
    }
    err == 0
}

/// linkat(fd1, name1, fd2, name2, flags) = 457
unsafe fn linkat(f1: i64, n1: *const u8, f2: i64, n2: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #457",
            "cset {err}, hs",
            inlateout("x0") f1 => ret,
            in("x1") n1,
            inlateout("x2") f2 => _,
            in("x3") n2,
            in("x4") 0,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// mkfifo(path, mode) = 132
unsafe fn mkfifo(path: *const u8, mode: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #132",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") mode,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// setpriority(which, who, prio) = 96
unsafe fn setpriority(which: i64, who: i64, prio: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #96",
            "cset {err}, hs",
            inlateout("x0") which => ret,
            in("x1") who,
            in("x2") prio,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// getpriority(which, who) = 100
unsafe fn getpriority(which: i64, who: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #100",
            "cset {err}, hs",
            inlateout("x0") which => ret,
            in("x1") who,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// chroot(path) = 61
unsafe fn chroot(path: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #61",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"at: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut cwd = [0u8; 64];
        let mut target = [0u8; 64];

        // Leftovers from a previous interrupted run must not make a check
        // fail for a reason that has nothing to do with the kernel.
        let _ = unlink(p!("/etc/at1"));
        let _ = unlink(p!("/etc/at2"));
        let _ = unlink(p!("/etc/atdir/f"));
        let _ = rmdir(p!("/etc/atdir"));
        let _ = rmdir(p!("/etc/atdir2"));
        let _ = unlink(p!("/etc/atlink"));
        let _ = unlink(p!("/etc/at600"));

        // --- openat: AT_FDCWD resolves against the cwd ------------------------
        check("chdir /etc", chdir(p!("/etc")).is_ok());
        match openat_create(AT_FDCWD, p!("at1"), O_CREAT | O_TRUNC, 0o644) {
            Ok(fd) => {
                check("openat AT_FDCWD create", true);
                let _ = close(fd);
            }
            Err(_) => check("openat AT_FDCWD create", false),
        }
        check("openat made the file", exists(p!("/etc/at1")));

        // The same call with a relative path but a dirfd pointing at "/"
        // must land in /etc -- i.e. resolve against the DIR, not the cwd.
        check("open /", open(p!("/"), 0).map(|fd| {
            let _ = close(fd);
        }).is_ok());
        let rootfd = match open(p!("/"), 0) {
            Ok(fd) => fd,
            Err(_) => -1,
        };
        // Relative to /, "at2" must NOT be the /etc one. Unlink it there so
        // the "must not exist" check below is meaningful.
        let _ = unlink(p!("/at2"));
        match openat_create(rootfd, p!("at2"), O_CREAT | O_TRUNC, 0o644) {
            Ok(fd) => {
                check("openat dirfd creates", true);
                let _ = close(fd);
            }
            Err(_) => check("openat dirfd creates", false),
        }
        let _ = unlink(p!("/at2"));
        if rootfd >= 0 {
            let _ = close(rootfd);
        }

        // A bad dirfd is EBADF, not a silent success against the cwd.
        match openat_create(9999, p!("at2"), O_CREAT, 0o644) {
            Err(e) => check("openat bad dirfd EBADF", e == 9),
            Ok(_) => check("openat bad dirfd EBADF", false),
        }

        // --- mkdirat + unlinkat ----------------------------------------------
        check("mkdirat", mkdirat(AT_FDCWD, p!("atdir"), 0o755).is_ok());
        check("mkdirat made dir", exists(p!("/etc/atdir")));
        match fstatat_mode(AT_FDCWD, p!("atdir"), 0) {
            Ok(m) => check("mkdirat made a DIRECTORY", m & 0o170000 == 0o40000),
            Err(_) => check("mkdirat made a DIRECTORY", false),
        }
        // Creating it again is EEXIST -- a second mkdirat must not silently
        // succeed on an existing directory.
        match mkdirat(AT_FDCWD, p!("atdir"), 0o755) {
            Err(e) => check("mkdirat EEXIST", e == 17),
            Ok(_) => check("mkdirat EEXIST", false),
        }
        // A file inside it, created through the directory's own fd. This has
        // to come BEFORE any rmdirat attempt: rmdir on an EMPTY directory
        // correctly succeeds, so checking ENOTEMPTY first would be
        // asserting that the kernel refuses a legitimate call -- and it
        // would remove the directory the rest of this block depends on.
        let dirfd = match open(p!("/etc/atdir"), 0) {
            Ok(fd) => fd,
            Err(_) => -1
        };
        match openat_create(dirfd, p!("f"), O_CREAT | O_TRUNC, 0o644) {
            Ok(fd) => {
                check("openat dirfd-relative", true);
                let _ = close(fd);
            }
            Err(_) => check("openat dirfd-relative", false),
        }
        check("file landed in dirfd dir", exists(p!("/etc/atdir/f")));

        // rmdir must refuse: the directory is not empty. This is the
        // check that catches a kernel treating AT_REMOVEDIR as unlink.
        match unlinkat(AT_FDCWD, p!("atdir"), AT_REMOVEDIR) {
            Err(e) => { check("rmdirat ENOTEMPTY", e == 66); },
            Ok(_) => check("rmdirat ENOTEMPTY", false),
        }
        check("dir still there", exists(p!("/etc/atdir")));

        // The same name with flag 0 must unlink the FILE, not the directory.
        match unlinkat(dirfd, p!("f"), 0) {
            Ok(_) => check("unlinkat removes the file", true),
            Err(_) => check("unlinkat removes the file", false),
        }
        check("file gone", !exists(p!("/etc/atdir/f")));
        check("dir survived file unlink", exists(p!("/etc/atdir")));

        // An unknown unlinkat flag is EINVAL rather than being ignored --
        // ignoring it would make AT_REMOVEDIR untypeable.
        match unlinkat(AT_FDCWD, p!("atdir"), 0x40) {
            Err(e) => check("unlinkat bad flag EINVAL", e == 22),
            Ok(_) => check("unlinkat bad flag EINVAL", false),
        }
        check("dir survived bad flag", exists(p!("/etc/atdir")));

        // AT_REMOVEDIR on a FILE is ENOTDIR, and must not remove the file.
        match openat_create(AT_FDCWD, p!("at2"), O_CREAT | O_TRUNC, 0o644) {
            Ok(fd) => {
                let _ = close(fd);
            }
            Err(_) => {}
        }
        match unlinkat(AT_FDCWD, p!("at2"), AT_REMOVEDIR) {
            Err(e) => check("rmdirat on a file ENOTDIR", e == 20),
            Ok(_) => check("rmdirat on a file ENOTDIR", false),
        }
        check("file survived ENOTDIR", exists(p!("/etc/at2")));

        // Now the directory really is empty and AT_REMOVEDIR must work.
        match unlinkat(AT_FDCWD, p!("atdir"), AT_REMOVEDIR) {
            Ok(_) => check("rmdirat removes empty dir", true),
            Err(_) => check("rmdirat removes empty dir", false),
        }
        check("dir gone", !exists(p!("/etc/atdir")));
        if dirfd >= 0 {
            let _ = close(dirfd);
        }

        // --- symlinkat + readlinkat ------------------------------------------
        check("symlinkat", symlinkat(p!("/etc/at1"), AT_FDCWD, p!("atlink")).is_ok());
        match readlinkat(AT_FDCWD, p!("atlink"), target.as_mut_ptr(), 64) {
            Ok(n) => {
                let s = core::str::from_utf8(&target[..n as usize]).unwrap_or("");
                check("readlinkat target", s == "/etc/at1");
            }
            Err(_) => check("readlinkat target", false),
        }
        // A buffer too small is ENOSPC, not a truncated target that looks
        // complete -- a caller acting on half a path does the wrong thing
        // with no error anywhere.
        match readlinkat(AT_FDCWD, p!("atlink"), target.as_mut_ptr(), 3) {
            Err(e) => check("readlinkat ENOSPC", e == 28),
            Ok(_) => check("readlinkat ENOSPC", false),
        }
        // A zero-length buffer is EINVAL.
        match readlinkat(AT_FDCWD, p!("atlink"), target.as_mut_ptr(), 0) {
            Err(e) => check("readlinkat zero buf EINVAL", e == 22),
            Ok(_) => check("readlinkat zero buf EINVAL", false),
        }
        // readlinkat on a regular file is EINVAL, not the file's contents.
        match readlinkat(AT_FDCWD, p!("at1"), target.as_mut_ptr(), 64) {
            Err(e) => check("readlinkat on a file EINVAL", e == 22),
            Ok(_) => check("readlinkat on a file EINVAL", false),
        }

        // --- fstatat's AT_SYMLINK_NOFOLLOW -----------------------------------
        // The link points at /etc/at1, a regular file. Following and
        // not-following therefore differ in st_mode: regular vs symlink.
        match fstatat_mode(AT_FDCWD, p!("atlink"), 0) {
            Ok(m) => check("fstatat follows by default", m & 0o170000 == 0o100000),
            Err(_) => check("fstatat follows by default", false),
        }
        match fstatat_mode(AT_FDCWD, p!("atlink"), AT_SYMLINK_NOFOLLOW) {
            Ok(m) => check("fstatat NOFOLLOW", m & 0o170000 == 0o120000),
            Err(_) => check("fstatat NOFOLLOW", false),
        }
        // NetBSD's AT_SYMLINK_FOLLOW is 0x400 and 0x200 is NOFOLLOW, so a
        // kernel wired to Linux's numbers would read 0x200 as EACCESS and
        // follow -- which is exactly the check above catching it.
        match fstatat_mode(AT_FDCWD, p!("atlink"), AT_SYMLINK_FOLLOW) {
            Ok(m) => check("fstatat FOLLOW follows", m & 0o170000 == 0o100000),
            Err(_) => check("fstatat FOLLOW follows", false),
        }

        // --- faccessat --------------------------------------------------------
        // The mode must actually be consulted, so the file has to be one
        // whose permission bits genuinely REFUSE something. 0600 does not:
        // the owner write bit is set, and uid 0 owns the file, so a 0600
        // file correctly grants W_OK. Asserting EACCES on 0600 asserts a
        // falsehood about correct behaviour. 0444 has no write bit at all,
        // so W_OK is refused for the real reason.
        match openat_create(AT_FDCWD, p!("at600"), O_CREAT | O_TRUNC, 0o444) {
            Ok(fd) => {
                let _ = close(fd);
            }
            Err(_) => {}
        }
        match fstatat_mode(AT_FDCWD, p!("at600"), 0) {
            Ok(m) => check("mode argument honoured", m & 0o7777 == 0o444),
            Err(_) => check("mode argument honoured", false),
        }
        check("faccessat F_OK", faccessat(AT_FDCWD, p!("at600"), 0, 0).is_ok());
        check("faccessat R_OK on 444", faccessat(AT_FDCWD, p!("at600"), 4, 0).is_ok());
        match faccessat(AT_FDCWD, p!("at600"), 2, 0) {
            Err(e) => check("faccessat W_OK on 444", e == 13),
            Ok(_) => check("faccessat W_OK on 444", false),
        }
        match faccessat(AT_FDCWD, p!("at600"), 6, 0) {
            Err(e) => check("faccessat RW on 444", e == 13),
            Ok(_) => check("faccessat RW on 444", false),
        }
        // A directory is always searchable here, so X_OK must pass on one
        // even at 0444 -- the check that stops a kernel from applying the
        // file-mode test blindly to every node type.
        check("mkdirat for X_OK", mkdirat(AT_FDCWD, p!("atdir2"), 0o755).is_ok());
        check("faccessat X_OK on a dir", faccessat(AT_FDCWD, p!("atdir2"), 1, 0).is_ok());
        // AT_EACCESS is accepted and changes nothing here (one uid), which
        // is better than refusing a flag real callers pass.
        check("faccessat AT_EACCESS ok", faccessat(AT_FDCWD, p!("at600"), 4, AT_EACCESS).is_ok());
        match faccessat(AT_FDCWD, p!("at600"), 4, 0x40) {
            Err(e) => check("faccessat bad flag EINVAL", e == 22),
            Ok(_) => check("faccessat bad flag EINVAL", false),
        }
        // An unknown amode bit is EINVAL -- 0x8 is not a permission.
        match faccessat(AT_FDCWD, p!("at600"), 8, 0) {
            Err(e) => check("faccessat bad amode EINVAL", e == 22),
            Ok(_) => check("faccessat bad amode EINVAL", false),
        }
        match faccessat(AT_FDCWD, p!("atnosuch"), 0, 0) {
            Err(e) => check("faccessat ENOENT", e == 2),
            Ok(_) => check("faccessat ENOENT", false),
        }
        // faccessat NOFOLLOW on the symlink checks the LINK itself. Both the
        // link (0777) and its target are readable, so this asserts the call
        // succeeds -- its purpose is to catch a kernel that REFUSES
        // AT_SYMLINK_NOFOLLOW, which is a real caller's flag.
        check("faccessat NOFOLLOW ok", faccessat(AT_FDCWD, p!("atlink"), 4, AT_SYMLINK_NOFOLLOW).is_ok());

        // --- fchdir ------------------------------------------------------------
        // fchdir through a descriptor must move the cwd, and getcwd must
        // agree. A fchdir that returns 0 without moving anything is a
        // silent success that corrupts every later relative path.
        check("open /etc", open(p!("/etc"), 0).is_ok());
        let etcfd = match open(p!("/etc"), 0) {
            Ok(fd) => fd,
            Err(_) => -1,
        };
        match fchdir(etcfd) {
            Ok(_) => check("fchdir ok", true),
            Err(_) => check("fchdir ok", false),
        }
        match getcwd(cwd.as_mut_ptr(), 64) {
            Ok(n) => {
                let s = core::str::from_utf8(&cwd[..n as usize - 1]).unwrap_or("");
                check("fchdir moved the cwd", s == "/etc");
            }
            Err(_) => check("fchdir moved the cwd", false),
        }
        // A relative openat after fchdir must land in /etc, proving the
        // fchdir changed the cwd and not merely the reported string.
        match openat_create(AT_FDCWD, p!("at2"), O_CREAT | O_TRUNC, 0o644) {
            Ok(fd) => {
                check("cwd change is real", true);
                let _ = close(fd);
            }
            Err(_) => check("cwd change is real", false),
        }
        check("file is in /etc", exists(p!("/etc/at2")));
        if etcfd >= 0 {
            let _ = close(etcfd);
        }
        // fchdir on a plain file is ENOTDIR -- accepting it would silently
        // leave the cwd pointing at something that is not a directory.
        match open(p!("/etc/at1"), 0) {
            Ok(fd) => {
                match fchdir(fd) {
                    Err(e) => check("fchdir on a file ENOTDIR", e == 20),
                    Ok(_) => check("fchdir on a file ENOTDIR", false),
                }
                let _ = close(fd);
            }
            Err(_) => check("fchdir on a file ENOTDIR", false),
        }
        // fchdir on a closed descriptor is EBADF.
        match fchdir(4242) {
            Err(e) => check("fchdir EBADF", e == 9),
            Ok(_) => check("fchdir EBADF", false),
        }
        check("chdir / restores cwd", chdir(p!("/")).is_ok());

        // --- renameat ----------------------------------------------------------
        // The names are RELATIVE, so they resolve against the cwd -- which
        // `chdir /` above just set to "/". /etc/at1 is not /at1, so this
        // would be ENOENT for a reason that has nothing to do with
        // renameat. Use absolute names.
        match renameat(AT_FDCWD, p!("/etc/at1"), AT_FDCWD, p!("/etc/at2")) {
            Ok(_) => check("renameat", true),
            Err(_) => check("renameat", false),
        }
        check("renameat moved it", exists(p!("/etc/at2")) && !exists(p!("/etc/at1")));
        match renameat(AT_FDCWD, p!("/etc/at2"), AT_FDCWD, p!("/etc/at1")) {
            Ok(_) => check("renameat back", true),
            Err(_) => check("renameat back", false),
        }
        match renameat(AT_FDCWD, p!("/etc/atnosuch"), AT_FDCWD, p!("/etc/atx")) {
            Err(e) => check("renameat ENOENT", e == 2),
            Ok(_) => check("renameat ENOENT", false),
        }

        // --- linkat: refused, and refused for the right reason ----------------
        // A hard link needs a link count this filesystem does not keep.
        // Returning 0 would create no second name at all, and the caller
        // would believe it had one.
        match linkat(AT_FDCWD, p!("at1"), AT_FDCWD, p!("atlink2")) {
            Err(e) => check("linkat EOPNOTSUPP", e == 95),
            Ok(_) => check("linkat EOPNOTSUPP", false),
        }
        check("linkat made no file", !exists(p!("/etc/atlink2")));

        // --- mkfifo: refused, and it must not create a regular file ----------
        match mkfifo(p!("/etc/atfifo"), 0o644) {
            Err(e) => check("mkfifo EOPNOTSUPP", e == 95),
            Ok(_) => check("mkfifo EOPNOTSUPP", false),
        }
        check("mkfifo made no node", !exists(p!("/etc/atfifo")));

        // --- chroot: refused ---------------------------------------------------
        // One always-mounted root and no way to change it. EPERM is what a
        // caller without CAP_SYS_CHROOT gets on a real system.
        match chroot(p!("/etc")) {
            Err(e) => check("chroot EPERM", e == 1),
            Ok(_) => check("chroot EPERM", false),
        }
        check("root unmoved", getcwd(cwd.as_mut_ptr(), 64).is_ok());

        // --- setpriority / getpriority ----------------------------------------
        // NetBSD's range is 0..MAXPRIORITY (255), not Linux's -20..20.
        check("setpriority 0 ok", setpriority(0, 0, 0).is_ok());
        check("setpriority 255 ok", setpriority(0, 0, 255).is_ok());
        match setpriority(0, 0, 256) {
            Err(e) => check("setpriority 256 EINVAL", e == 22),
            Ok(_) => check("setpriority 256 EINVAL", false),
        }
        // A negative value is out of range here. x2 arrives as a u64 sign
        // extension, so a kernel that compared it as unsigned would accept
        // it as a huge positive and report success.
        match setpriority(0, 0, -1) {
            Err(e) => check("setpriority -1 EINVAL", e == 22),
            Ok(_) => check("setpriority -1 EINVAL", false),
        }
        check("getpriority ok", getpriority(0, 0).is_ok());
        // A negative return would collide with the error flag, so the value
        // must be a real priority, not an errno-shaped -1.
        match getpriority(0, 0) {
            Ok(v) => check("getpriority nonnegative", v >= 0),
            Err(_) => check("getpriority nonnegative", false),
        }

        // --- clean up ----------------------------------------------------------
        let _ = unlink(p!("/etc/at1"));
        let _ = unlink(p!("/etc/at2"));
        let _ = unlink(p!("/etc/atlink"));
        let _ = unlink(p!("/etc/at600"));
        let _ = rmdir(p!("/etc/atdir"));
        let _ = rmdir(p!("/etc/atdir2"));

        finish();
    }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"at: all ok\n" as &[u8]
        } else {
            b"at: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}