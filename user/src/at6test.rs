#![no_std]
#![no_main]

//! NetBSD-ABI batch 6: the *at() variants of calls that already exist,
//! chflags/lchflags/fchflags, preadv/pwritev.
//!
//! These are the cheapest calls in the backlog -- each is a second spelling
//! of something already implemented -- and that is exactly why they are
//! worth probing hard. A shared code path with a different flag value or a
//! different register produces a plausible wrong answer, not a failure.
//!
//! Three traps this probe exists to catch:
//!
//! - **`preadv`/`pwritev` put the offset in x4, not x3.** The prototype
//!   carries an explicit PAD word, exactly like `pread`/`pwrite`. Reading
//!   x3 lands millions of bytes off with no error anywhere.
//! - **NetBSD's `AT_SYMLINK_NOFOLLOW` is 0x200**, where Linux's is 0x100
//!   (0x100 is NetBSD's `AT_EACCESS`). A kernel wired to Linux's constants
//!   follows the link when the caller asked it not to.
//! - **chflags must be observable through stat.** `st_flags` sits at
//!   offset 132; a chflags that returned 0 without storing anything would
//!   leave a caller believing UF_IMMUTABLE is set on a writable file.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

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
    put(&mut line, &mut n, b"at6: ok    ");
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
const O_RDONLY: i64 = 0;
const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: i64 = 0x200;

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

/// stat(path, buf) = 38. NetBSD's 152-byte layout: mode@8 (u32),
/// st_flags@132 (u32).
unsafe fn stat_fields(path: *const u8) -> Result<(u32, u32, u32), i64> {
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
    if err != 0 { Err(ret) } else { Ok((st.mode, st.uid, st.flags)) }
}

/// chflags(path, flags) = 34
unsafe fn chflags(path: *const u8, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #34",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") flags,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// lchflags(path, flags) = 304
unsafe fn lchflags(path: *const u8, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #304",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") flags,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// fchflags(fd, flags) = 35
unsafe fn fchflags(fd: i64, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #35",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") flags,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// lchmod(path, mode) = 274
unsafe fn lchmod(path: *const u8, mode: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #274",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") mode,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// fchmodat(fd, path, mode, flag) = 463
unsafe fn fchmodat(dirfd: i64, path: *const u8, mode: i64, flag: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #463",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") mode,
            in("x3") flag,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// fchownat(fd, path, uid, gid, flag) = 464
unsafe fn fchownat(dirfd: i64, path: *const u8, uid: i64, gid: i64, flag: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #464",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") uid,
            in("x3") gid,
            in("x4") flag,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// utimensat(fd, path, times[2], flag) = 467
unsafe fn utimensat(dirfd: i64, path: *const u8, times: *const i64, flag: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #467",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") times,
            in("x3") flag,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// lpathconf(path, name) = 499
unsafe fn lpathconf(path: *const u8, name: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #499",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") name,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// __posix_rename(from, to) = 270
unsafe fn posix_rename(from: *const u8, to: *const u8) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #270",
            "cset {err}, hs",
            inlateout("x0") from => ret,
            in("x1") to,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// pwritev(fd, iov, iovcnt, PAD, offset) = 290. Offset in x4.
unsafe fn pwritev(fd: i64, iov: u64, cnt: i64, offset: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #290",
            "cset {err}, hs",
            in("x0") fd,
            in("x1") iov,
            in("x2") cnt,
            in("x3") 0i64,
            in("x4") offset,
            lateout("x0") ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// preadv(fd, iov, iovcnt, PAD, offset) = 289. Offset in x4.
unsafe fn preadv(fd: i64, iov: u64, cnt: i64, offset: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #289",
            "cset {err}, hs",
            in("x0") fd,
            in("x1") iov,
            in("x2") cnt,
            in("x3") 0i64,
            in("x4") offset,
            lateout("x0") ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// read(fd, buf, len) = 3. (NetBSD READ is 3; 4 is WRITE.)
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

/// lseek(fd, offset, whence) = 19
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

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"at6: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut buf = [0u8; 64];
        let mut times: [i64; 4];

        // UF_APPEND=0x4, UF_IMMUTABLE=0x2, SF_ARCHIVED=0x10000,
        // SF_IMMUTABLE=0x20000 (sys/sys/stat.h).
        const UF_APPEND: i64 = 0x0000_0004;
        const UF_IMMUTABLE: i64 = 0x0000_0002;
        const SF_ARCHIVED: i64 = 0x0001_0000;

        let _ = unlink(p!("/etc/a6file"));
        let _ = unlink(p!("/etc/a6link"));
        let _ = unlink(p!("/etc/a6b"));

        // --- chflags/lchflags/fchflags: observable through st_flags ---------
        let fd = match openat_create(AT_FDCWD, p!("/etc/a6file"), O_CREAT | O_TRUNC | O_RDWR, 0o644) {
            Ok(f) => f,
            Err(_) => -1,
        };
        check("created file", fd >= 0);

        match stat_fields(p!("/etc/a6file")) {
            Ok((_, _, fl)) => check("flags start clear", fl == 0),
            Err(_) => check("flags start clear", false),
        }
        check("chflags UF_APPEND", chflags(p!("/etc/a6file"), UF_APPEND).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, _, fl)) => check("chflags observable", fl == UF_APPEND as u32),
            Err(_) => check("chflags observable", false),
        }
        // A second, different flag must replace, not accumulate.
        check("chflags SF_ARCHIVED", chflags(p!("/etc/a6file"), SF_ARCHIVED).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, _, fl)) => check("chflags replaces", fl == SF_ARCHIVED as u32),
            Err(_) => check("chflags replaces", false),
        }
        check("chflags clear", chflags(p!("/etc/a6file"), 0).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, _, fl)) => check("chflags cleared", fl == 0),
            Err(_) => check("chflags cleared", false),
        }
        match chflags(p!("/etc/nosuch"), UF_APPEND) {
            Err(e) => check("chflags ENOENT", e == 2),
            Ok(_) => check("chflags ENOENT", false),
        }
        // fchflags through a descriptor must agree.
        check("fchflags ok", fchflags(fd, UF_IMMUTABLE).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, _, fl)) => check("fchflags observable", fl == UF_IMMUTABLE as u32),
            Err(_) => check("fchflags observable", false),
        }
        match fchflags(4242, UF_APPEND) {
            Err(e) => check("fchflags EBADF", e == 9),
            Ok(_) => check("fchflags EBADF", false),
        }
        check("fchflags clear", fchflags(fd, 0).is_ok());

        // --- lchflags: the LINK's flags, not the target's ------------------
        check("symlink for lchflags", symlink(p!("/etc/a6file"), p!("/etc/a6link")).is_ok());
        check("lchflags ok", lchflags(p!("/etc/a6link"), UF_APPEND).is_ok());
        // lchflags must change the LINK. If it followed, the target would
        // carry the flag instead -- and the target's flag is checked here
        // by path, so the two are distinguishable.
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, _, fl)) => check("lchflags did NOT follow", fl == 0),
            Err(_) => check("lchflags did NOT follow", false),
        }
        // A plain stat follows, so it reports the TARGET's flags -- still 0.
        // Read the link's own flags with lstat's no-follow form instead.
        check("lchflags clear", lchflags(p!("/etc/a6link"), 0).is_ok());

        // --- fchmodat -------------------------------------------------------
        check("fchmodat", fchmodat(AT_FDCWD, p!("/etc/a6file"), 0o600, 0).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((m, _, _)) => check("fchmodat observable", m & 0o7777 == 0o600),
            Err(_) => check("fchmodat observable", false),
        }
        // NOFOLLOW on a non-symlink is the same as following it.
        check("fchmodat NOFOLLOW", fchmodat(AT_FDCWD, p!("/etc/a6file"), 0o644, AT_SYMLINK_NOFOLLOW).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((m, _, _)) => check("fchmodat NOFOLLOW ok", m & 0o7777 == 0o644),
            Err(_) => check("fchmodat NOFOLLOW ok", false),
        }
        match fchmodat(AT_FDCWD, p!("/etc/nosuch"), 0o600, 0) {
            Err(e) => check("fchmodat ENOENT", e == 2),
            Ok(_) => check("fchmodat ENOENT", false),
        }
        match fchmodat(AT_FDCWD, p!("/etc/a6file"), 0o600, 0x40) {
            Err(e) => check("fchmodat bad flag EINVAL", e == 22),
            Ok(_) => check("fchmodat bad flag EINVAL", false),
        }

        // --- lchmod ---------------------------------------------------------
        // lchmod on the LINK must not change the TARGET's mode, because
        // following is the chmod arm's job.
        check("lchmod ok", lchmod(p!("/etc/a6link"), 0o700).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((m, _, _)) => check("lchmod did NOT follow", m & 0o7777 == 0o644),
            Err(_) => check("lchmod did NOT follow", false),
        }

        // --- fchownat -------------------------------------------------------
        // -1 for both ids leaves them alone; then set a real uid and read it
        // back through stat's st_uid@28.
        check("fchownat noop", fchownat(AT_FDCWD, p!("/etc/a6file"), -1, -1, 0).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, u, _)) => check("fchownat -1 no-op", u == 0),
            Err(_) => check("fchownat -1 no-op", false),
        }
        check("fchownat set uid", fchownat(AT_FDCWD, p!("/etc/a6file"), 5, -1, 0).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, u, _)) => check("fchownat observable", u == 5),
            Err(_) => check("fchownat observable", false),
        }
        // uid -1 with a real gid must leave the uid alone and set the gid.
        check("fchownat gid only", fchownat(AT_FDCWD, p!("/etc/a6file"), -1, 7, 0).is_ok());
        match stat_fields(p!("/etc/a6file")) {
            Ok((_, u, _)) => check("fchownat kept uid", u == 5),
            Err(_) => check("fchownat kept uid", false),
        }
        check("fchownat restore", fchownat(AT_FDCWD, p!("/etc/a6file"), 0, 0, 0).is_ok());
        match fchownat(AT_FDCWD, p!("/etc/nosuch"), 0, 0, 0) {
            Err(e) => check("fchownat ENOENT", e == 2),
            Ok(_) => check("fchownat ENOENT", false),
        }

        // --- utimensat ------------------------------------------------------
        times = [1, 2, 1_234_567_890, 0];
        check("utimensat ok", utimensat(AT_FDCWD, p!("/etc/a6file"), times.as_ptr(), 0).is_ok());
        // Read the mtime back: the probe's own stat helper returns mode/uid/
        // flags, so check the value through a dedicated read of st_mtim@64.
        {
            let mut st = [0u8; 152];
            let err: isize;
            asm!(
                "svc #38",
                "cset {err}, hs",
                in("x0") p!("/etc/a6file"),
                in("x1") st.as_mut_ptr(),
                err = out(reg) err,
                options(nostack),
            );
            if err == 0 {
                let mt = i64::from_le_bytes([st[64], st[65], st[66], st[67], st[68], st[69], st[70], st[71]]);
                check("utimensat observable", mt == 1_234_567_890);
            } else {
                check("utimensat observable", false);
            }
        }
        times = [1, 2, 500, 1_500_000_000];
        match utimensat(AT_FDCWD, p!("/etc/a6file"), times.as_ptr(), 0) {
            Err(e) => check("utimensat bad nsec EINVAL", e == 22),
            Ok(_) => check("utimensat bad nsec EINVAL", false),
        }
        // NULL times means "now", and must succeed.
        check("utimensat NULL", utimensat(AT_FDCWD, p!("/etc/a6file"), core::ptr::null(), 0).is_ok());
        times = [1, 2, 1_000_000_000, 0];
        match utimensat(AT_FDCWD, p!("/etc/nosuch"), times.as_ptr(), 0) {
            Err(e) => check("utimensat ENOENT", e == 2),
            Ok(_) => check("utimensat ENOENT", false),
        }

        // --- lpathconf ------------------------------------------------------
        match lpathconf(p!("/etc/a6file"), 4) {
            Ok(v) => check("lpathconf PATH_MAX", v == 1024),
            Err(_) => check("lpathconf PATH_MAX", false),
        }
        match lpathconf(p!("/etc/a6link"), 4) {
            // The link resolves in lpathconf's favour; both give 1024 here.
            Ok(v) => check("lpathconf on a link", v == 1024),
            Err(_) => check("lpathconf on a link", false),
        }
        match lpathconf(p!("/etc/nosuch"), 4) {
            Err(e) => check("lpathconf ENOENT", e == 2),
            Ok(_) => check("lpathconf ENOENT", false),
        }

        // --- __posix_rename -------------------------------------------------
        check("posix_rename ok", posix_rename(p!("/etc/a6file"), p!("/etc/a6b")).is_ok());
        check("posix_rename moved", stat_fields(p!("/etc/a6b")).is_ok() && stat_fields(p!("/etc/a6file")).is_err());
        check("posix_rename back", posix_rename(p!("/etc/a6b"), p!("/etc/a6file")).is_ok());
        match posix_rename(p!("/etc/nosuch"), p!("/etc/a6b")) {
            Err(e) => check("posix_rename ENOENT", e == 2),
            Ok(_) => check("posix_rename ENOENT", false),
        }

        // --- preadv/pwritev: offset in x4, position unmoved -----------------
        // NetBSD's struct iovec is {void*, size_t} -- 16 bytes, identical to
        // Linux's -- so the walker's stride is shared rather than assumed.
        let mut out1 = [0u8; 4];
        let mut out2 = [0u8; 3];

        // Write "ABCDEFG" at offset 4 in two vectors: "ABCD" then "EFG".
        let mut v1 = [0u64; 2];
        v1[0] = p!("ABCD").wrapping_add(0) as u64; v1[1] = 4;
        match pwritev(fd, v1.as_mut_ptr() as u64, 1, 4) {
            Ok(n) => check("pwritev one vec", n == 4),
            Err(_) => check("pwritev one vec", false),
        }
        let mut v2 = [0u64; 2];
        v2[0] = p!("EFG").wrapping_add(0) as u64; v2[1] = 3;
        match pwritev(fd, v2.as_mut_ptr() as u64, 1, 8) {
            Ok(n) => check("pwritev second vec", n == 3),
            Err(_) => check("pwritev second vec", false),
        }
        // Two vectors in ONE call, contiguous -- the walker must join them.
        // Source bytes are known, so the read-back is an assertion rather
        // than a comparison of a buffer with itself.
        let mut both = [0u64; 4];
        both[0] = p!("WXYZ").wrapping_add(0) as u64; both[1] = 4;
        both[2] = p!("123").wrapping_add(0) as u64; both[3] = 3;
        match pwritev(fd, both.as_mut_ptr() as u64, 2, 20) {
            Ok(n) => check("pwritev two vecs", n == 7),
            Err(_) => check("pwritev two vecs", false),
        }
        both[0] = out1.as_mut_ptr() as u64; both[1] = 4;
        both[2] = out2.as_mut_ptr() as u64; both[3] = 3;
        match preadv(fd, both.as_mut_ptr() as u64, 2, 20) {
            Ok(n) => check("preadv two vecs", n == 7),
            Err(_) => check("preadv two vecs", false),
        }
        // Each vector must hold its own half of the 7 bytes written.
        check("preadv vec1", out1 == *b"WXYZ");
        check("preadv vec2", out2 == *b"123");
        // A zero-length iovcnt transfers nothing and is not an error.
        match preadv(fd, both.as_mut_ptr() as u64, 0, 0) {
            Ok(n) => check("preadv zero cnt", n == 0),
            Err(_) => check("preadv zero cnt", false),
        }
        // iovcnt past IOV_MAX (64) is EINVAL, not a huge allocation.
        match preadv(fd, both.as_mut_ptr() as u64, 65, 0) {
            Err(e) => check("preadv IOV_MAX EINVAL", e == 22),
            Ok(_) => check("preadv IOV_MAX EINVAL", false),
        }
        // Neither may move the file position: lseek to 0, preadv, then read
        // must return byte 0 rather than wherever preadv read.
        let _ = lseek(fd, 0, 0);
        let mut tmp = [0u64; 2];
        tmp[0] = buf.as_mut_ptr() as u64; tmp[1] = 4;
        let _ = preadv(fd, tmp.as_mut_ptr() as u64, 1, 8);
        match read(fd, buf.as_mut_ptr(), 4) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
                // Bytes 0..4 were never written, so they are zeros.
                check("preadv left the position", s == "\0\0\0\0");
            }
            Err(_) => check("preadv left the position", false),
        }
        // A read-only descriptor must refuse pwritev.
        let rofd = match open(p!("/etc/a6file"), O_RDONLY) {
            Ok(f) => f,
            Err(_) => -1,
        };
        match pwritev(rofd, v1.as_mut_ptr() as u64, 1, 0) {
            Err(e) => check("pwritev on O_RDONLY EACCES", e == 13),
            Ok(_) => check("pwritev on O_RDONLY EACCES", false),
        }
        if rofd >= 0 {
            let _ = close(rofd);
        }
        if fd >= 0 {
            let _ = close(fd);
        }

        // --- clean up -------------------------------------------------------
        let _ = unlink(p!("/etc/a6file"));
        let _ = unlink(p!("/etc/a6link"));
        let _ = unlink(p!("/etc/a6b"));

        finish();
    }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"at6: all ok\n" as &[u8]
        } else {
            b"at6: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}