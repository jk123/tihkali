#![no_std]
#![no_main]

//! NetBSD-ABI directory and path calls: __getcwd(296), chdir(12),
//! rename(128), chmod(15).
//!
//! The point of this binary is that these four interact. chdir changes the
//! process's working directory, and the other three either report it or
//! resolve a *relative* path against it -- so a getcwd that ignored the
//! chdir, or a rename that resolved both operands against "/", would pass
//! each check in isolation and fail here.

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
    let n = 30 - name.len();
    unsafe {
        write(1, b"pathctl: ok   ");
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

/// SYS_close, NetBSD's unlink is 10.
unsafe fn unlink(path: *const u8) -> Result<(), i64> {
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
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_stat(path, buf) = 38, read back through NetBSD's 152-byte layout.
unsafe fn stat_mode(path: *const u8) -> Result<u32, i64> {
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
    if err != 0 { Err(ret) } else { Ok(st.mode) }
}

/// SYS___getcwd(bufp, length) = 296
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

/// SYS_chdir(path) = 12
unsafe fn chdir(path: *const u8) -> Result<(), i64> {
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
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_rename(from, to) = 128
unsafe fn rename(from: *const u8, to: *const u8) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #128",
            "cset {err}, hs",
            inlateout("x0") from => ret,
            in("x1") to,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_chmod(path, mode) = 15
unsafe fn chmod(path: *const u8, mode: i64) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #15",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") mode,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"pathctl: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut buf = [0u8; 64];

        // --- getcwd at the start ---------------------------------------------
        match getcwd(buf.as_mut_ptr(), 64) {
            Ok(n) => {
                // The length includes the NUL, so it is strlen + 1.
                let s = core::str::from_utf8(&buf[..n as usize - 1]).unwrap_or("");
                check("getcwd is /", s == "/");
                check("getcwd len has NUL", n == 2);
            }
            Err(_) => {
                check("getcwd is /", false);
                check("getcwd len has NUL", false);
            }
        }
        // A too-small buffer is ERANGE (34) and must not write a partial
        // path -- a caller ignoring the error would act on half a path.
        match getcwd(buf.as_mut_ptr(), 1) {
            Err(e) => check("getcwd ERANGE", e == 34),
            Ok(_) => check("getcwd ERANGE", false),
        }

        // --- chdir, then getcwd must agree -----------------------------------
        check("chdir /etc", chdir(p!("/etc")).is_ok());
        match getcwd(buf.as_mut_ptr(), 64) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize - 1]).unwrap_or("");
                check("getcwd tracks chdir", s == "/etc");
            }
            Err(_) => check("getcwd tracks chdir", false),
        }

        // Relative-path resolution is observable through the NetBSD arms
        // themselves: rename takes no dirfd, so both operands are relative
        // and must resolve against the cwd. (open() is deliberately still
        // cwd-unaware -- it is the same helper the Linux path uses, and
        // changing it is a separate decision.)
        check("stat absolute under /etc", stat_mode(p!("/etc/hosts")).is_ok());
        // A relative name resolves against /etc only if the kernel joins
        // it, so a kernel ignoring cwd would report ENOENT here.
        match stat_mode(p!("hosts")) {
            Ok(m) => check("relative stat uses cwd", m & 0o170000 == 0o100000),
            Err(_) => check("relative stat uses cwd", false),
        }
        // The same relative name from "/" must NOT resolve to /etc/hosts.
        check("chdir / for contrast", chdir(p!("/")).is_ok());
        match stat_mode(p!("hosts")) {
            Ok(_) => check("relative stat follows cwd", false),
            Err(_) => check("relative stat follows cwd", true),
        }
        check("chdir /etc again", chdir(p!("/etc")).is_ok());

        // --- ".." must normalize, not escape ----------------------------------
        check("chdir /etc/..", chdir(p!("/etc/..")).is_ok());
        match getcwd(buf.as_mut_ptr(), 64) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize - 1]).unwrap_or("");
                check("chdir normalizes ..", s == "/");
            }
            Err(_) => check("chdir normalizes ..", false),
        }
        // Climbing above the root clamps at "/".
        check("chdir /../../..", chdir(p!("/../../..")).is_ok());
        match getcwd(buf.as_mut_ptr(), 64) {
            Ok(n) => {
                let s = core::str::from_utf8(&buf[..n as usize - 1]).unwrap_or("");
                check("chdir clamps at root", s == "/");
            }
            Err(_) => check("chdir clamps at root", false),
        }

        // --- chdir rejects a non-directory and a missing path ------------------
        match chdir(p!("/etc/hosts")) {
            Err(e) => check("chdir ENOTDIR", e == 20),
            Ok(_) => check("chdir ENOTDIR", false),
        }
        match chdir(p!("/nope")) {
            Err(e) => check("chdir ENOENT", e == 2),
            Ok(_) => check("chdir ENOENT", false),
        }

        // --- chmod, verified through stat --------------------------------------
        // /etc/motd is 0644 as packed; set 0600 and require stat to agree,
        // then restore so a later session sees the packed mode.
        match stat_mode(p!("/etc/motd")) {
            Ok(m) => {
                check("motd perms are 644", m & 0o7777 == 0o644);
                check("chmod 600", chmod(p!("/etc/motd"), 0o600).is_ok());
                match stat_mode(p!("/etc/motd")) {
                    Ok(m2) => check("chmod visible in stat", m2 & 0o7777 == 0o600),
                    Err(_) => check("chmod visible in stat", false),
                }
                let _ = chmod(p!("/etc/motd"), 0o644);
                match stat_mode(p!("/etc/motd")) {
                    Ok(m3) => check("chmod restored", m3 & 0o7777 == 0o644),
                    Err(_) => check("chmod restored", false),
                }
            }
            Err(_) => {
                check("motd perms are 644", false);
                check("chmod 600", false);
                check("chmod visible in stat", false);
                check("chmod restored", false);
            }
        }
        match chmod(p!("/nope"), 0o600) {
            Err(e) => check("chmod ENOENT", e == 2),
            Ok(_) => check("chmod ENOENT", false),
        }

        // --- rename, with both operands relative to the cwd -------------------
        check("chdir /etc", chdir(p!("/etc")).is_ok());
        // motd -> motd.tmp (relative), then back. Both names are relative,
        // so this only works if rename resolves against the cwd.
        check("rename relative", rename(p!("motd"), p!("motd.tmp")).is_ok());
        check("old name gone", stat_mode(p!("motd")).is_err());
        match stat_mode(p!("motd.tmp")) {
            Ok(m) => check("new name present", m & 0o170000 == 0o100000),
            Err(_) => check("new name present", false),
        }
        check("rename back", rename(p!("motd.tmp"), p!("motd")).is_ok());
        match stat_mode(p!("motd")) {
            Ok(_) => check("file restored", true),
            Err(_) => check("file restored", false),
        }
        // Renaming something that does not exist is ENOENT.
        match rename(p!("nope"), p!("nope2")) {
            Err(e) => check("rename ENOENT", e == 2),
            Ok(_) => check("rename ENOENT", false),
        }
        // Clean up anything a failed run left behind.
        let _ = unlink(p!("/etc/motd.tmp"));

        check("chdir back to /", chdir(p!("/")).is_ok());
        finish();
    }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"pathctl: all ok\n" as &[u8]
        } else {
            b"pathctl: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}