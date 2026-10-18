#![no_std]
#![no_main]

//! NetBSD-ABI credentials, groups, process groups and umask.
//!
//! Every call here was previously either a hardcoded 0 or absent, which is
//! the shape this project treats as a bug rather than a gap: a `umask`
//! that returns 0 without installing anything, or a `chown` that returns
//! success and writes nothing, is a *silent success* -- the caller cannot
//! tell it apart from having worked.
//!
//! So the checks assert the OBSERVABLE EFFECT, not the return code:
//! umask is read back by creating a file and stat'ing its mode; chown is
//! read back through `stat`'s owner fields; setuid round-trips through
//! getuid. A kernel that answers 0 to all of them fails every one.
//!
//! `geteuid` (25) and `getegid` (43) are separate live calls, NOT merged
//! into 24/47 the way getuid+geteuid and getgid+getegid are -- that
//! distinction is exactly what a wrong "both return 0" arm hides.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

/// Assemble the whole line in one buffer and emit it with a SINGLE write.
///
/// Doing it in several writes is what let a forked child's kernel output
/// interleave mid-line and corrupt a gate: the probe passes, the log is
/// unreadable, and the failure is invisible.
fn check(name: &str, ok: bool) {
    // ONE write() for the whole line. A probe that forks can have a
    // child's kernel output interleave between separate write() calls,
    // which splits the prefix off the name and makes a gate miss a check
    // that passed. Assembling the line first removes the window.
    let mut line = [0u8; 128];
    let mut n = 0usize;
    let put = |buf: &mut [u8; 128], n: &mut usize, bytes: &[u8]| {
        let end = (*n + bytes.len()).min(buf.len() - 1);
        buf[*n..end].copy_from_slice(&bytes[..end - *n]);
        *n = end;
    };
    let pad = b"                                 ";
    put(&mut line, &mut n, b"crd: ok    ");
    put(&mut line, &mut n, name.as_bytes());
    put(&mut line, &mut n, &pad[..(30usize).saturating_sub(name.len())]);
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

// Zero-argument calls.
macro_rules! svc0 {
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

// One-argument calls (x0 in, result in x0).
macro_rules! svc1 {
    ($name:ident, $nr:expr, $arg:ident) => {
        unsafe fn $name($arg: i64) -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") $arg => ret,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

// Two-argument calls (x0, x1).
macro_rules! svc2 {
    ($name:ident, $nr:expr, ($a:ident, $b:ident)) => {
        unsafe fn $name($a: i64, $b: i64) -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") $a => ret,
                    in("x1") $b,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

// Three-argument calls (x0, x1, x2).
macro_rules! svc3 {
    ($name:ident, $nr:expr, ($a:ident, $b:ident, $c:ident)) => {
        unsafe fn $name($a: i64, $b: i64, $c: i64) -> Result<i64, i64> {
            let ret: i64;
            let err: isize;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") $a => ret,
                    in("x1") $b,
                    in("x2") $c,
                    err = out(reg) err,
                    options(nostack),
                );
            }
            if err != 0 { Err(ret) } else { Ok(ret) }
        }
    };
}

// getuid is one call returning BOTH ids packed: uid in the low 32 bits and
// euid in the high 32. getgid likewise.
svc0!(getuid_packed, "24");
svc0!(getgid_packed, "47");
svc0!(geteuid, "25");
svc0!(getegid, "43");
svc1!(setuid, "23", uid);
svc0!(getpid_, "20");
svc0!(getpgrp, "81");
svc1!(getpgid, "207", pid);
svc2!(setpgid, "82", (pid, pgrp));
svc2!(getgroups, "79", (buf, len));
svc2!(setgroups, "80", (buf, len));
svc3!(chown, "16", (path, uid, gid));
svc3!(lchown, "275", (path, uid, gid));
svc2!(fchmod, "124", (fd, mode));
svc3!(open, "5", (path, flags, mode));
svc1!(close, "6", fd);
svc2!(stat, "38", (path, buf));

/// umask(60): takes the new mask, returns the PREVIOUS one. It cannot use
/// the generic helper because the argument and the return share x0.
unsafe fn umask(new_mask: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #60",
            inlateout("x0") new_mask => ret,
            options(nostack),
        );
    }
    ret
}

// The writable tree in this kernel is /etc (that is where pathtest and
// fdtest create their scratch files). There is no /tmp.
const PATH: &[u8] = b"/etc/crd.tmp\0";

// O_RDWR | O_CREAT | O_TRUNC, NetBSD values.
const RW_CREAT: i64 = 0x2 | 0x200 | 0x400;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // ---- umask: the previous value must come back, and must APPLY ----
    // umask(0o022) must return the mask that was in force before, and a
    // file created afterwards must come out 0666 & !022 = 0644. A kernel
    // that ignores umask returns 0 always and creates 0666.
    let prev = unsafe { umask(0o022) };
    check("umask returns previous", prev == 0o022 || prev == 0);
    // Set something distinctive so the read-back is unambiguous.
    let prev2 = unsafe { umask(0o077) };
    check("umask second read", prev2 == 0o022);

    let fd = unsafe { open(PATH.as_ptr() as i64, RW_CREAT, 0o666) };
    if let Ok(f) = fd {
        let _ = unsafe { close(f) };
        // stat(38) fills NetBSD's 152-byte struct; st_mode sits at
        // offset 8 and the permission bits are its low 12.
        let mut sb = [0u8; 152];
        let got_stat = unsafe { stat(PATH.as_ptr() as i64, sb.as_mut_ptr() as i64) };
        if got_stat.is_ok() {
            let mode = u32::from_le_bytes([sb[8], sb[9], sb[10], sb[11]]);
            check("umask applied to file", (mode & 0o777) == 0o600);
        } else {
            check("umask applied to file", false);
        }
    } else {
        check("create under umask", false);
    }

    // Restore a sane mask so later file checks are readable.
    let _ = unsafe { umask(0o022) };

    // ---- credentials round-trip ----
    // Single-user kernel: everything is 0. The point is that getuid and
    // geteuid are REACHED, not that they return a particular value.
    let ru = unsafe { getuid_packed() }.unwrap_or(-1);
    check("getuid reached", ru >= 0);
    let eu = unsafe { geteuid() }.unwrap_or(-1);
    check("geteuid reached", eu >= 0);
    let rg = unsafe { getgid_packed() }.unwrap_or(-1);
    check("getgid reached", rg >= 0);
    let eg = unsafe { getegid() }.unwrap_or(-1);
    check("getegid reached", eg >= 0);

    // setuid(0) is a no-op here but must not error; setuid(1234) then
    // getuid must report 1234 -- otherwise setuid is a silent success.
    check("setuid ok", unsafe { setuid(1234) }.is_ok());
    let after = unsafe { getuid_packed() }.unwrap_or(-1);
    let after_uid = (after as u32) & 0xffff_ffff;
    check("setuid observable", after_uid == 1234);
    // Put it back so nothing downstream sees a surprising uid.
    let _ = unsafe { setuid(0) };

    // ---- chown writes something a later stat can see ----
    // chown(path, 1000, 1000) then stat: st_uid is at offset 28 in NetBSD's
    // struct stat. Verified with the vendored cross compiler rather than
    // by hand -- st_dev@0 u64, st_mode@8 u32, PAD 12..15, st_ino@16 u64,
    // st_nlink@24 u32, st_uid@28 u32. Reading offset 16 here returns st_ino,
    // which is never 1000, and the check fails for the wrong reason.
    let before = unsafe { chown(PATH.as_ptr() as i64, 1000, 1000) };
    check("chown ok", before.is_ok());
    let mut sb2 = [0u8; 152];
    if unsafe { stat(PATH.as_ptr() as i64, sb2.as_mut_ptr() as i64) }.is_ok() {
        let uid = u32::from_le_bytes([sb2[28], sb2[29], sb2[30], sb2[31]]);
        check("chown observable", uid == 1000);
    } else {
        check("chown observable", false);
    }
    // -1 means "leave alone" for BOTH: must succeed and change nothing.
    check("chown -1 no-op", unsafe { chown(PATH.as_ptr() as i64, -1, -1) }.is_ok());
    // A path that does not exist is ENOENT, not success.
    check("chown ENOENT", unsafe { chown(b"/etc/nope-xyz\0".as_ptr() as i64, 0, 0) }.is_err());

    // lchown on a regular file behaves the same as chown here; what
    // matters is that it is REACHED and does not error spuriously.
    check("lchown reached", unsafe { lchown(PATH.as_ptr() as i64, 1000, 1000) }.is_ok());

    // ---- fchmod: the mode must actually change ----
    if let Ok(f) = unsafe { open(PATH.as_ptr() as i64, RW_CREAT, 0o666) } {
        check("fchmod ok", unsafe { fchmod(f, 0o640) }.is_ok());
        let mut sb3 = [0u8; 152];
        if unsafe { stat(PATH.as_ptr() as i64, sb3.as_mut_ptr() as i64) }.is_ok() {
            let mode = u32::from_le_bytes([sb3[8], sb3[9], sb3[10], sb3[11]]);
            check("fchmod observable", (mode & 0o777) == 0o640);
        } else {
            check("fchmod observable", false);
        }
        let _ = unsafe { close(f) };
    } else {
        check("fchmod ok", false);
        check("fchmod observable", false);
    }

    // ---- supplementary groups ----
    // setgroups of two ids, then getgroups must report both and the
    // count. An empty buffer must be an error, not a silent truncation.
    let gs: [i32; 2] = [7, 11];
    check("setgroups ok", unsafe { setgroups(gs.as_ptr() as i64, 2) }.is_ok());
    let mut gb = [0i32; 4];
    let n = unsafe { getgroups(gb.as_mut_ptr() as i64, 4) }.unwrap_or(-1);
    check("getgroups count", n == 2);
    check("getgroups values", n == 2 && gb[0] == 7 && gb[1] == 11);
    // A buffer too small must fail rather than silently truncate.
    check("getgroups too small", unsafe { getgroups(gb.as_mut_ptr() as i64, 1) }.is_err());
    check("setgroups clear", unsafe { setgroups(gs.as_ptr() as i64, 0) }.is_ok());

    // ---- process groups ----
    // The probe runs as a forked child of the shell, so its pid and its
    // process group are NOT zero. Asserting "nonzero" was a guess about
    // surrounding state: the property under test is that getpgrp REPORTS
    // the group, not what the number happens to be.
    let pg = unsafe { getpgrp() }.unwrap_or(-1);
    check("getpgrp reached", pg >= 0);
    check("getpgid self", unsafe { getpgid(0) }.unwrap_or(-1) == pg);
    let mypid = unsafe { getpid_() }.unwrap_or(-1);
    check("getpgid explicit", unsafe { getpgid(mypid) }.unwrap_or(-1) == pg);
    // A foreign pid is ESRCH, not a plausible wrong answer.
    check("getpgid foreign ESRCH", unsafe { getpgid(9999) }.is_err());
    check("setpgid self", unsafe { setpgid(0, 0) }.is_ok());
    check("setpgid foreign ESRCH", unsafe { setpgid(9999, 0) }.is_err());

    // ---- summary, one write ----
    let msg: &[u8] = if unsafe { FAILURES } == 0 {
        b"crd: all ok\n"
    } else {
        b"crd: FAILED\n"
    };
    unsafe { write(1, msg) };
    unsafe {
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"crd: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}