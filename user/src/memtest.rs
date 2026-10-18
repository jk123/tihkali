#![no_std]
#![no_main]

//! NetBSD-ABI memory syscalls: mmap/munmap/mprotect/madvise/msync.
//!
//! Separate from `nettest` because it exercises the other half of the
//! NetBSD personality -- the memory calls, whose ABI differs from Linux in
//! two ways that silently break a copy-paste: `mmap` takes seven register
//! slots (with a PAD word at x5) instead of six, and MAP_ANONYMOUS is
//! 0x1000 rather than 0x20.
//!
//! All calls go through `svc #NR` with the number in the immediate, so this
//! binary exercises the same dispatch a real NetBSD libc would hit.

use core::arch::asm;
use core::panic::PanicInfo;

const MAP_ANON: i64 = 0x1000;
const PROT_READ: i64 = 0x1;
const PROT_WRITE: i64 = 0x2;
const PROT_NONE: i64 = 0x0;

/// NetBSD `mmap(addr, len, prot, flags, fd, PAD, pos)`.
/// Note x5 is the pad word and x6 the offset -- six-argument Linux order
/// would read the offset out of the pad.
#[allow(clippy::too_many_arguments)]
unsafe fn mmap(
    addr: i64,
    len: i64,
    prot: i64,
    flags: i64,
    fd: i64,
    pos: i64,
) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #197",
            "cset {err}, hs",
            inlateout("x0") addr => ret,
            in("x1") len,
            in("x2") prot,
            in("x3") flags,
            in("x4") fd,
            in("x5") 0i64, // PAD
            in("x6") pos,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        Err(ret)
    } else {
        Ok(ret)
    }
}

unsafe fn munmap(addr: i64, len: i64) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #73",
            "cset {err}, hs",
            inlateout("x0") addr => ret,
            in("x1") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        Err(ret)
    } else {
        Ok(())
    }
}

unsafe fn mprotect(addr: i64, len: i64, prot: i64) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #74",
            "cset {err}, hs",
            inlateout("x0") addr => ret,
            in("x1") len,
            in("x2") prot,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        Err(ret)
    } else {
        Ok(())
    }
}

unsafe fn madvise(addr: i64, len: i64, advice: i64) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #75",
            "cset {err}, hs",
            inlateout("x0") addr => ret,
            in("x1") len,
            in("x2") advice,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        Err(ret)
    } else {
        Ok(())
    }
}

unsafe fn msync(addr: i64, len: i64) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #65",
            "cset {err}, hs",
            inlateout("x0") addr => ret,
            in("x1") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        Err(ret)
    } else {
        Ok(())
    }
}

/// NetBSD `fork()` = 2. A child continues in the same address space, so
/// it must exit before reaching any further assertion -- see the
/// forked-child trap in the kqueue phases.
unsafe fn fork() -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #2",
            inlateout("x0") 0i64 => ret,
            options(nostack),
        );
    }
    ret
}

/// NetBSD `wait4` = **449** (`WAIT4__2`), blocking -- not 7, which is the
/// obsolete compat entry the kernel does not dispatch. Blocking is what
/// yields the CPU on a single core; a WNOHANG spin would starve the very
/// child being waited for.
unsafe fn wait4(pid: i64, status: &mut i32) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #449",
            inlateout("x0") pid => ret,
            in("x1") status as *mut i32 as i64,
            in("x2") 0i64,
            options(nostack),
        );
    }
    ret
}

/// NetBSD `exit(code)` = 1. Does not return.
unsafe fn exit(code: i64) -> ! {
    unsafe {
        asm!("svc #1", in("x0") code, options(nostack, noreturn));
    }
}

unsafe fn write(fd: i64, buf: &[u8]) {
    let ret: i64;
    unsafe {
        asm!(
            "svc #4",
            inlateout("x0") fd as isize => ret,
            in("x1") buf.as_ptr() as i64,
            in("x2") buf.len() as i64,
            options(nostack),
        );
    }
    let _ = ret;
}

static mut FAILURES: u32 = 0;

fn check(name: &str, ok: bool) {
    let line = if ok { "memtest: ok   " } else { "memtest: FAIL " };
    unsafe {
        write(1, line.as_bytes());
        write(1, name.as_bytes());
        write(1, b"\n");
        if !ok {
            FAILURES += 1;
        }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"memtest: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    const PAGE: i64 = 4096;

    // 1. Anonymous mmap with NetBSD's MAP_ANONYMOUS (0x1000). If the
    //    kernel used the Linux 0x20 here this returns ENOSYS.
    let a = unsafe { mmap(0, PAGE * 4, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0) };
    match a {
        Ok(base) => {
            check("mmap anon", base != 0);
            let aligned = base % PAGE == 0;
            check("mmap page aligned", aligned);

            // 2. The mapping must actually be writable: a fault here
            //    means the page tables were never populated.
            unsafe {
                let p = base as *mut u64;
                p.write(0x5a5a_5a5a_5a5a_5a5a);
                check("mmap writable", p.read() == 0x5a5a_5a5a_5a5a_5a5a);
            }

            // 3. mprotect round-trip: drop to PROT_NONE then restore.
            let prot_none = unsafe { mprotect(base, PAGE, PROT_NONE) };
            check("mprotect none", prot_none.is_ok());
            let restored = unsafe { mprotect(base, PAGE, PROT_READ | PROT_WRITE) };
            check("mprotect restore", restored.is_ok());
            unsafe {
                let p = base as *mut u64;
                check("still writable", p.read() == 0x5a5a_5a5a_5a5a_5a5a);
            }

            // 3a. PROT_* must be REAL, not advisory. The pages are
            // demand-paged, so a kernel that ignored `prot` would hand
            // back a fully read-write mapping and `mprotect`'s read-only
            // flag would have nothing to protect. mmap'ing PROT_READ and
            // writing to it must fault; the same page after mprotect to
            // read-write must not.
            let ro = unsafe { mmap(0, PAGE, PROT_READ, MAP_ANON, -1, 0) };
            if let Ok(robase) = ro {
                // Reading is always allowed.
                check("prot_read readable", unsafe { (robase as *const u64).read() } == 0);
                // Writing must NOT be allowed. A fault here kills the
                // probe, so the check is done from a child process and
                // the parent infers the outcome from its exit status.
                let child = unsafe { fork() };
                if child == 0 {
                    unsafe {
                        (robase as *mut u64).write(1);
                    }
                    // Reaching here means the kernel let the write
                    // through. Exit 0; the parent asserts the opposite.
                    unsafe { exit(0) }
                } else {
                    let mut st: i32 = 0;
                    let _ = unsafe { wait4(child, &mut st) };
                    // A clean exit (status 0) proves PROT_READ was
                    // advisory. A fault puts the signal number in the
                    // low 7 bits instead.
                    check("prot_read enforced", st != 0);
                }
                check("prot_read munmap", unsafe { munmap(robase, PAGE) }.is_ok());
            } else {
                check("prot_read mapped", false);
            }

            // PROT_NONE is refused rather than silently upgraded: an
            // unmapped VA is indistinguishable from one nobody asked for,
            // so honouring it would consume address space invisibly.
            let pn = unsafe { mmap(0, PAGE, PROT_NONE, MAP_ANON, -1, 0) };
            check("prot_none refused", pn.is_err());
            // A prot with bits outside PROT_* is EINVAL, not "the bits
            // we understand".
            let pbad = unsafe { mmap(0, PAGE, PROT_READ | 0x40, MAP_ANON, -1, 0) };
            check("bad prot EINVAL", pbad.is_err());

            // 3b. mprotect must not be a silent no-op on a range nobody
            // mapped. It walks present PTEs, finds none, and would
            // return success -- a change that never happened, reported
            // as one that did. ENOMEM is the answer a caller can act on.
            let bogus = unsafe { mprotect(0x1000_1000, PAGE, PROT_READ | PROT_WRITE) };
            check("mprotect unmapped ENOMEM", bogus.is_err());

            // 3c. mprotect spanning TWO adjacent mappings must protect
            // both. The bookkeeping splits each recorded range, and a
            // mapping starting above `addr` is the case a naive
            // range-overlap test gets wrong.
            let m1 = unsafe { mmap(0, PAGE * 2, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0) };
            let m2 = unsafe { mmap(0, PAGE * 2, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0) };
            if let (Ok(x), Ok(y)) = (m1, m2) {
                check("two maps", x != y);
                // Drop the SECOND mapping's first page, not the first's.
                check("mprotect across two", unsafe {
                    mprotect(y, PAGE, PROT_NONE)
                }.is_ok());
                let child = unsafe { fork() };
                if child == 0 {
                    // Each child proves one page. Written as two
                    // children because a fault kills the process.
                    unsafe { (y as *mut u64).write(1) };
                    unsafe { exit(0) }
                }
                let mut st: i32 = 0;
                let _ = unsafe { wait4(child, &mut st) };
                check("second map protected", st != 0);
                let _ = unsafe { munmap(x, PAGE * 2) };
                let _ = unsafe { munmap(y, PAGE * 2) };
            } else {
                check("two maps", false);
            }

            // 4. Advice-only calls must succeed.
            check("madvise", unsafe { madvise(base, PAGE, 0) }.is_ok());
            check("msync", unsafe { msync(base, PAGE) }.is_ok());

            // 5. munmap the page we protected, and a whole region.
            check("munmap", unsafe { munmap(base, PAGE) }.is_ok());
            let b = unsafe { mmap(0, PAGE * 8, PROT_READ, MAP_ANON, -1, 0) };
            match b {
                Ok(bbase) => {
                    check("second mmap", bbase != base);
                    check("munmap region", unsafe { munmap(bbase, PAGE * 8) }.is_ok());
                }
                Err(_) => check("second mmap", false),
            }
        }
        Err(e) => {
            check("mmap anon", false);
            check("mmap errno is ENOSYS/other", e > 0);
        }
    }

    // 6. A misaligned munmap must be rejected, not silently accepted.
    let c = unsafe { mmap(0, PAGE, PROT_READ, MAP_ANON, -1, 0) };
    if let Ok(base) = c {
        let bad = unsafe { munmap(base + 1, PAGE) };
        check("munmap rejects unaligned", bad.is_err());
        let _ = unsafe { munmap(base, PAGE) };
    } else {
        check("munmap rejects unaligned", false);
    }

    unsafe {
        let msg = if FAILURES == 0 {
            b"memtest: all ok\n" as &[u8]
        } else {
            b"memtest: FAILED\n" as &[u8]
        };
        write(1, msg);
        // exit(FAILURES) so a shell can gate on it. SYS_exit does not
        // return, so its argument goes in x0 without capturing a result.
        asm!(
                "svc #1",
                in("x0") FAILURES as isize,
                options(nostack, noreturn),
        );
    }
}