#![no_std]
#![no_main]

//! tihkali test program: NetBSD aarch64 syscall ABI, fork/wait4 demo.
//!
//! ABI (verified against NetBSD lib/libc/arch/aarch64/SYS.h):
//!   - syscall number is encoded in the SVC immediate: `svc #NR`
//!   - arguments in x0..x3 (AAPCS), result in x0
//!   - error: PSTATE.C = 1 on return, errno in x0
//!   - flags must be sampled immediately after svc (cset in same asm block)

use core::arch::asm;
use core::panic::PanicInfo;

unsafe fn write(fd: usize, msg: &str) -> (isize, bool) {
    let ret: isize;
    let err: u64;
    unsafe {
        asm!(
            "svc #4", // SYS_write
            "cset {err}, hs",
            inlateout("x0") fd as isize => ret,
            in("x1") msg.as_ptr(),
            in("x2") msg.len(),
            err = out(reg) err,
            options(nostack),
        );
    }
    (ret, err != 0)
}

unsafe fn fork() -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #2", // SYS_fork
            "cset {err}, hs",
            inlateout("x0") 0i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

unsafe fn getpid() -> i64 {
    let ret: i64;
    unsafe { asm!("svc #20", inlateout("x0") 0i64 => ret, options(nostack)) };
    ret
}

unsafe fn wait4(pid: i64, status: *mut i32) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #449", // SYS___wait450
            "cset {err}, hs",
            inlateout("x0") pid => ret,
            in("x1") status as i64,
            in("x2") 0i64,
            in("x3") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

unsafe fn exit(code: usize) -> ! {
    unsafe { asm!("svc #1", in("x0") code, options(noreturn)) }
}

/// execve(path, argv): on success this never returns.
unsafe fn execve(path: &str, argv: &[&str]) -> i64 {
    // Kernel reads path as a C string: copy + NUL into a stack buffer.
    let mut pbuf = [0u8; 64];
    let n = path.len().min(62);
    pbuf[..n].copy_from_slice(&path.as_bytes()[..n]);
    pbuf[n] = 0;

    // NULL-terminated pointer array; each arg is already NUL-free &str,
    // but the kernel uses read_user_cstr → needs NULs: copy args too.
    let mut sbuf = [[0u8; 64]; 8];
    let mut ptrs = [0u64; 9];
    for (i, a) in argv.iter().enumerate().take(8) {
        let len = a.len().min(62);
        sbuf[i][..len].copy_from_slice(&a.as_bytes()[..len]);
        sbuf[i][len] = 0;
        ptrs[i] = sbuf[i].as_ptr() as u64;
    }
    ptrs[argv.len().min(8)] = 0;

    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #59", // SYS_execve
            "cset {err}, hs",
            inlateout("x0") pbuf.as_ptr() as i64 => ret,
            in("x1") ptrs.as_ptr() as i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

/// Format n into buf; returns the digit slice (borrows buf).
fn utoa<'a>(n: u64, buf: &'a mut [u8; 20]) -> &'a str {
    if n == 0 {
        buf[19] = b'0';
        return core::str::from_utf8(&buf[19..]).unwrap_or("?");
    }
    let mut m = n;
    let mut i = 20;
    while m > 0 {
        i -= 1;
        buf[i] = b'0' + (m % 10) as u8;
        m /= 10;
    }
    core::str::from_utf8(&buf[i..]).unwrap_or("?")
}

fn say(parts: &[&str]) {
    for p in parts {
        let (n, err) = unsafe { write(1, p) };
        if err || n < 0 {
            unsafe { exit(9) }
        }
    }
}

fn spin(iters: u64) {
    let mut i: u64 = 0;
    while i < iters {
        unsafe { core::ptr::read_volatile(&i) };
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut b1 = [0u8; 20];
    let mut b2 = [0u8; 20];

    let pid = unsafe { getpid() };
    say(&["proc ", utoa(pid as u64, &mut b1), ": forking\n"]);

    let child = unsafe { fork() };
    let mut status: i32 = 0;

    if child == 0 {
        // Replace our image with /bin/greet; only returns on failure.
        let r = unsafe { execve("/bin/greet", &["greet", "from-init"]) };
        let mut b = [0u8; 20];
        say(&["child: execve failed (", utoa(r as u64, &mut b), ")\n"]);
        unsafe { exit(1) }
    } else if child > 0 {
        for i in 0..4u64 {
            say(&["parent ", utoa(pid as u64, &mut b1), " round ", utoa(i, &mut b2), "\n"]);
            spin(25_000_000);
        }
        let reaped = unsafe { wait4(-1, &mut status) };
        if reaped > 0 {
            say(&["parent: reaped child ", utoa(reaped as u64, &mut b1),
                  " status ", utoa((status >> 8) as u64, &mut b2), "\n"]);
            unsafe { exit(0) }
        }
        unsafe { exit(3) }
    } else {
        unsafe { exit(1) }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { exit(99) }
}
