#![no_std]
#![no_main]

//! NetBSD-ABI batch 7: extended attributes (setxattr/getxattr/listxattr/
//! removexattr and their l- and f- spellings).
//!
//! Twelve calls over one storage path, and every way of getting it wrong
//! is a SILENT SUCCESS: a setxattr that returns 0 without storing anything
//! is indistinguishable from one that worked until the caller reads the
//! value back.
//!
//! Two argument-order facts, both different from Linux's:
//!
//! - **NetBSD's `setxattr` is `(path, name, value, size, flags)` -- `size`
//!   BEFORE `flags`.** Linux's is `(path, name, value, size, flags)` too,
//!   but a caller written from the Linux man page for a five-argument
//!   NetBSD prototype gets the flag value read as the size.
//! - **A `size` of 0 on the get/list calls asks for the LENGTH and writes
//!   nothing.** A buffer too small is ERANGE, not a truncated value the
//!   caller would act on as complete.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

/// A NUL-terminated literal as an i64 address. Nearly every helper in this
/// probe takes register-width integers; the three that want a real pointer
/// cast at the call site.
macro_rules! p {
    ($b:expr) => {{
        const S: &[u8] = concat!($b, "\0").as_bytes();
        S.as_ptr()
    }};
}

/// The same literal as an i64 address, for the xattr helpers, which take
/// register-width integers rather than pointers.
macro_rules! pa {
    ($b:expr) => {{
        const S: &[u8] = concat!($b, "\0").as_bytes();
        S.as_ptr() as i64
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
    put(&mut line, &mut n, b"xa: ok     ");
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
const XATTR_CREATE: i64 = 1;
const XATTR_REPLACE: i64 = 2;

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

macro_rules! xattr_call {
    ($name:ident, $nr:expr, $nargs:expr) => {
        unsafe fn $name(a0: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") a0 => ret,
                    in("x1") a1,
                    in("x2") a2,
                    in("x3") a3,
                    in("x4") a4,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            let _ = $nargs;
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

xattr_call!(setxattr, 375, 5);
xattr_call!(lsetxattr, 376, 5);
xattr_call!(fsetxattr, 377, 5);
xattr_call!(getxattr, 378, 4);
xattr_call!(lgetxattr, 379, 4);
xattr_call!(fgetxattr, 380, 4);
xattr_call!(listxattr, 381, 3);
xattr_call!(llistxattr, 382, 3);
xattr_call!(flistxattr, 383, 3);
xattr_call!(removexattr, 384, 2);
xattr_call!(lremovexattr, 385, 2);
xattr_call!(fremovexattr, 386, 2);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"xa: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut buf = [0u8; 64];
        let mut list = [0u8; 128];

        let _ = unlink(p!("/etc/xafile"));
        let _ = unlink(p!("/etc/xalink"));

        let fd = match openat_create(AT_FDCWD, p!("/etc/xafile"), O_CREAT | O_TRUNC | O_RDWR, 0o644) {
            Ok(f) => f,
            Err(_) => -1,
        };
        check("created file", fd >= 0);

        // --- set/get round trip -------------------------------------------
        // A value that must come back byte for byte.
        check("setxattr", setxattr(pa!("/etc/xafile"), pa!("user.a"), pa!("hello"), 5, 0).is_ok());
        match getxattr(pa!("/etc/xafile"), pa!("user.a"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(n) => {
                let got = &buf[..n as usize];
                check("getxattr round trip", got == b"hello");
            }
            Err(_) => check("getxattr round trip", false),
        }
        // A second set must REPLACE, not append.
        check("setxattr replace", setxattr(pa!("/etc/xafile"), pa!("user.a"), pa!("bye"), 3, 0).is_ok());
        match getxattr(pa!("/etc/xafile"), pa!("user.a"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(n) => check("setxattr replaced", &buf[..n as usize] == b"bye"),
            Err(_) => check("setxattr replaced", false),
        }
        // An empty value is legal and distinct from absent.
        check("setxattr empty", setxattr(pa!("/etc/xafile"), pa!("user.e"), 0, 0, 0).is_ok());
        match getxattr(pa!("/etc/xafile"), pa!("user.e"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(n) => check("empty value readable", n == 0),
            Err(_) => check("empty value readable", false),
        }

        // --- size 0 asks for the LENGTH, and writes nothing -----------------
        match getxattr(pa!("/etc/xafile"), pa!("user.a"), 0, 0, 0) {
            Ok(n) => check("getxattr size 0 is length", n == 3),
            Err(_) => check("getxattr size 0 is length", false),
        }
        // A buffer too small is ERANGE, not a truncated value.
        match getxattr(pa!("/etc/xafile"), pa!("user.a"), buf.as_mut_ptr() as i64, 2, 0) {
            Err(e) => check("getxattr ERANGE", e == 34),
            Ok(_) => check("getxattr ERANGE", false),
        }
        // An absent name is ENODATA (61), not an empty value.
        match getxattr(pa!("/etc/xafile"), pa!("user.nope"), buf.as_mut_ptr() as i64, 64, 0) {
            Err(e) => check("getxattr ENODATA", e == 89),
            Ok(_) => check("getxattr ENODATA", false),
        }
        match getxattr(pa!("/etc/nosuch"), pa!("user.a"), buf.as_mut_ptr() as i64, 64, 0) {
            Err(e) => check("getxattr ENOENT", e == 2),
            Ok(_) => check("getxattr ENOENT", false),
        }

        // --- XATTR_CREATE / XATTR_REPLACE ----------------------------------
        check("setxattr CREATE", setxattr(pa!("/etc/xafile"), pa!("user.c"), pa!("x"), 1, XATTR_CREATE).is_ok());
        match setxattr(pa!("/etc/xafile"), pa!("user.c"), pa!("y"), 1, XATTR_CREATE) {
            Err(e) => check("CREATE twice EEXIST", e == 17),
            Ok(_) => check("CREATE twice EEXIST", false),
        }
        match setxattr(pa!("/etc/xafile"), pa!("user.zz"), pa!("x"), 1, XATTR_REPLACE) {
            Err(e) => check("REPLACE missing ENODATA", e == 89),
            Ok(_) => check("REPLACE missing ENODATA", false),
        }
        check("REPLACE present", setxattr(pa!("/etc/xafile"), pa!("user.c"), pa!("z"), 1, XATTR_REPLACE).is_ok());
        match getxattr(pa!("/etc/xafile"), pa!("user.c"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(n) => check("REPLACE observable", &buf[..n as usize] == b"z"),
            Err(_) => check("REPLACE observable", false),
        }
        // Both flags at once is EINVAL: they are exclusive.
        match setxattr(pa!("/etc/xafile"), pa!("user.c"), pa!("q"), 1, XATTR_CREATE | XATTR_REPLACE) {
            Err(e) => check("CREATE+REPLACE EINVAL", e == 22),
            Ok(_) => check("CREATE+REPLACE EINVAL", false),
        }
        match setxattr(pa!("/etc/xafile"), pa!("user.c"), pa!("q"), 1, 0x40) {
            Err(e) => check("unknown flag EINVAL", e == 22),
            Ok(_) => check("unknown flag EINVAL", false),
        }
        // A NULL name and a NULL path are EINVAL, not the root.
        match setxattr(pa!("/etc/xafile"), 0, pa!("x"), 1, 0) {
            Err(e) => check("NULL name EINVAL", e == 22),
            Ok(_) => check("NULL name EINVAL", false),
        }
        match setxattr(0, pa!("user.a"), pa!("x"), 1, 0) {
            Err(e) => check("NULL path EINVAL", e == 22),
            Ok(_) => check("NULL path EINVAL", false),
        }
        // A NULL value with a non-zero size is EFAULT.
        match setxattr(pa!("/etc/xafile"), pa!("user.a"), 0, 4, 0) {
            Err(e) => check("NULL value EFAULT", e == 14),
            Ok(_) => check("NULL value EFAULT", false),
        }

        // --- listxattr ------------------------------------------------------
        match listxattr(pa!("/etc/xafile"), 0, 0, 0, 0) {
            Ok(n) => check("listxattr size 0 length", n > 0),
            Err(_) => check("listxattr size 0 length", false),
        }
        match listxattr(pa!("/etc/xafile"), list.as_mut_ptr() as i64, 128, 0, 0) {
            Ok(_) => {
                // Names are NUL-separated; "user.a" must appear whole.
                let mut found = false;
                let mut i = 0usize;
                while i < 128 {
                    if list[i] == 0 { i += 1; continue; }
                    let mut j = i;
                    while j < 128 && list[j] != 0 { j += 1; }
                    let s = core::str::from_utf8(&list[i..j]).unwrap_or("");
                    if s == "user.a" { found = true; }
                    i = j + 1;
                }
                check("listxattr names", found);
            }
            Err(_) => check("listxattr names", false),
        }
        match listxattr(pa!("/etc/xafile"), list.as_mut_ptr() as i64, 2, 0, 0) {
            Err(e) => check("listxattr ERANGE", e == 34),
            Ok(_) => check("listxattr ERANGE", false),
        }

        // --- removexattr ---------------------------------------------------
        check("removexattr", removexattr(pa!("/etc/xafile"), pa!("user.e"), 0, 0, 0).is_ok());
        match getxattr(pa!("/etc/xafile"), pa!("user.e"), buf.as_mut_ptr() as i64, 64, 0) {
            Err(e) => check("removed is ENODATA", e == 89),
            Ok(_) => check("removed is ENODATA", false),
        }
        match removexattr(pa!("/etc/xafile"), pa!("user.e"), 0, 0, 0) {
            Err(e) => check("removexattr ENOENT", e == 2),
            Ok(_) => check("removexattr ENOENT", false),
        }

        // --- the f spelling: through a descriptor ---------------------------
        check("fsetxattr", fsetxattr(fd, pa!("user.f"), pa!("viafd"), 5, 0).is_ok());
        match fgetxattr(fd, pa!("user.f"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(n) => check("fgetxattr round trip", &buf[..n as usize] == b"viafd"),
            Err(_) => check("fgetxattr round trip", false),
        }
        // The same attribute seen through the path spelling must agree:
        // two names for one node, not two copies.
        match getxattr(pa!("/etc/xafile"), pa!("user.f"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(n) => check("fd and path agree", &buf[..n as usize] == b"viafd"),
            Err(_) => check("fd and path agree", false),
        }
        check("fremovexattr", fremovexattr(fd, pa!("user.f"), 0, 0, 0).is_ok());
        match fgetxattr(fd, pa!("user.f"), buf.as_mut_ptr() as i64, 64, 0) {
            Err(e) => check("fremoved is ENODATA", e == 89),
            Ok(_) => check("fremoved is ENODATA", false),
        }
        match fgetxattr(4242, pa!("user.f"), buf.as_mut_ptr() as i64, 64, 0) {
            Err(e) => check("fgetxattr EBADF", e == 9),
            Ok(_) => check("fgetxattr EBADF", false),
        }
        match fsetxattr(4242, pa!("user.f"), pa!("x"), 1, 0) {
            Err(e) => check("fsetxattr EBADF", e == 9),
            Ok(_) => check("fsetxattr EBADF", false),
        }
        match flistxattr(fd, 0, 0, 0, 0) {
            Ok(_) => check("flistxattr ok", true),
            Err(_) => check("flistxattr ok", false),
        }

        // --- the l spelling: on the LINK, not the target -------------------
        // The target gets an attribute; the l-call must NOT see it, which
        // is the only way to tell lgetxattr from getxattr here.
        check("symlink for l", symlink(p!("/etc/xafile"), p!("/etc/xalink")).is_ok());
        match lgetxattr(pa!("/etc/xalink"), pa!("user.a"), buf.as_mut_ptr() as i64, 64, 0) {
            // The link has no attributes of its own, so this is ENODATA.
            Err(e) => check("lgetxattr did NOT follow", e == 89),
            Ok(_) => check("lgetxattr did NOT follow", false),
        }
        // While the following form does see it.
        match getxattr(pa!("/etc/xalink"), pa!("user.a"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(_) => check("getxattr did follow", true),
            Err(_) => check("getxattr did follow", false),
        }
        check("lsetxattr on link", lsetxattr(pa!("/etc/xalink"), pa!("user.link"), pa!("L"), 1, 0).is_ok());
        match lgetxattr(pa!("/etc/xalink"), pa!("user.link"), buf.as_mut_ptr() as i64, 64, 0) {
            Ok(n) => check("lsetxattr observable", &buf[..n as usize] == b"L"),
            Err(_) => check("lsetxattr observable", false),
        }
        // The attribute is on the LINK, so the target must not have it.
        match getxattr(pa!("/etc/xafile"), pa!("user.link"), buf.as_mut_ptr() as i64, 64, 0) {
            Err(e) => check("lsetxattr did NOT follow", e == 89),
            Ok(_) => check("lsetxattr did NOT follow", false),
        }
        check("lremovexattr", lremovexattr(pa!("/etc/xalink"), pa!("user.link"), 0, 0, 0).is_ok());
        match llistxattr(pa!("/etc/xalink"), 0, 0, 0, 0) {
            Ok(n) => check("llistxattr empty after rm", n == 0),
            Err(_) => check("llistxattr empty after rm", false),
        }
        match llistxattr(pa!("/etc/xafile"), 0, 0, 0, 0) {
            Ok(n) => check("llistxattr kept target attrs", n > 0),
            Err(_) => check("llistxattr kept target attrs", false),
        }

        if fd >= 0 {
            let _ = close(fd);
        }
        let _ = unlink(p!("/etc/xafile"));
        let _ = unlink(p!("/etc/xalink"));

        finish();
    }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"xa: all ok\n" as &[u8]
        } else {
            b"xa: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}