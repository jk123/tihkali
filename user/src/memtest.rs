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