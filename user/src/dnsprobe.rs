#![no_std]
#![no_main]

//! tihkali `/bin/dnsprobe`: in-kernel DNS resolver probe (Linux door 240).
//!
//! Resolves a name through the kernel's smoltcp `dns::Socket` against the
//! SLIRP resolver at 10.0.2.3 and prints the A record. Also checks that a
//! bogus name fails rather than hanging.

use core::arch::asm;
use core::panic::PanicInfo;

fn puts(s: &str) {
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") 1i64 => _,      // write
            in("x1") s.as_ptr() as i64,
            in("x2") s.len() as i64,
            in("x8") 64i64,                // sys_write
            options(nostack),
        );
    }
}

unsafe fn exit(code: i64) -> ! {
    unsafe {
        asm!("mov x8, #93", "svc #0", in("x0") code, options(noreturn));
    }
}

fn dec(n: u32) {
    let mut buf = [0u8; 12];
    let mut i = buf.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    unsafe { puts(core::str::from_utf8_unchecked(&buf[i..])) }
}

fn fail(msg: &str, code: i64) -> ! {
    puts(msg);
    unsafe { exit(code) }
}

/// `tihkali_resolve(const char *name, u32 *out)` (svc #0, nr 240).
/// Returns 0 on success with the A record written to `out`, else -errno.
///
/// `name` must be NUL-terminated: the kernel reads it with
/// `read_user_cstr`, so a bare `&str` literal would run past the string
/// into whatever follows it in .rodata.
unsafe fn resolve(name: &str, out: &mut u32) -> i64 {
    let mut buf = [0u8; 64];
    if name.len() >= buf.len() {
        return -22; // EINVAL, same as the kernel's EFAULT-on-overflow
    }
    buf[..name.len()].copy_from_slice(name.as_bytes());
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") buf.as_ptr() as i64 => ret,
            in("x1") out as *mut u32 as i64,
            in("x8") 240i64,
            options(nostack),
        );
    }
    ret
}

/// Run one resolution and print `dns: <name> = a.b.c.d`.
fn try_resolve(name: &str, want_ok: bool) {
    // Out-param must sit low in the user frame: `user_range_ok` requires
    // all 4 bytes strictly below USER_LIMIT, and this runs after the boot
    // stack has already grown.
    let mut out: u32 = 0;
    let r = unsafe { resolve(name, &mut out) };
    if want_ok {
        if r != 0 {
            fail("dnsprobe: resolve failed\n", 10);
        }
        let o = out.to_le_bytes();
        puts("dns: ");
        puts(name);
        puts(" = ");
        dec(o[0] as u32);
        puts(".");
        dec(o[1] as u32);
        puts(".");
        dec(o[2] as u32);
        puts(".");
        dec(o[3] as u32);
        puts("\n");
    } else {
        if r == 0 {
            fail("dnsprobe: bogus name resolved\n", 11);
        }
        puts("dns: bogus name rejected (");
        dec(-r as u32);
        puts(")\n");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64, _: u64) -> ! {
    try_resolve("gateway", true);
    try_resolve("example.com", true);
    try_resolve("tihkali.invalid", false);
    puts("dnsprobe: ok\n");
    unsafe { exit(0) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe { exit(90) }
}