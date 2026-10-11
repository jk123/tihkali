#![no_std]
#![no_main]

//! tihkali `/bin/greet`: demonstrates execve argv handoff.
//! Entry ABI: x0 = argc, x1 = argv (NULL-terminated pointer array).

use core::arch::asm;
use core::panic::PanicInfo;

unsafe fn write(fd: usize, msg: &str) {
    let ret: isize;
    let err: u64;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd as isize => ret,
            in("x1") msg.as_ptr(),
            in("x2") msg.len(),
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 || ret < 0 {
        unsafe { exit(9) }
    }
}

unsafe fn exit(code: usize) -> ! {
    unsafe { asm!("svc #1", in("x0") code, options(noreturn)) }
}

unsafe fn getpid() -> i64 {
    let ret: i64;
    unsafe { asm!("svc #20", inlateout("x0") 0i64 => ret, options(nostack)) };
    ret
}

/// Write the NUL-terminated string at user address `p`.
unsafe fn write_cstr(p: u64) {
    let base = p as *const u8;
    let mut len = 0usize;
    unsafe {
        while *base.add(len) != 0 && len < 256 {
            len += 1;
        }
        let s = core::str::from_utf8_unchecked(core::slice::from_raw_parts(base, len));
        write(1, s);
    }
}

fn utoa(n: u64, buf: &mut [u8; 20]) -> &str {
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

#[unsafe(no_mangle)]
pub extern "C" fn _start(argc: u64, argv: u64) -> ! {
    let mut buf = [0u8; 20];
    let pid = unsafe { getpid() };

    let mut line = [0u8; 96];
    let mut pos = 0usize;
    let push = |line: &mut [u8; 96], pos: &mut usize, s: &str| {
        for &b in s.as_bytes() {
            if *pos < line.len() {
                line[*pos] = b;
                *pos += 1;
            }
        }
    };
    push(&mut line, &mut pos, "greet: pid=");
    push(&mut line, &mut pos, utoa(pid as u64, &mut buf));
    push(&mut line, &mut pos, " argc=");
    push(&mut line, &mut pos, utoa(argc, &mut buf));
    push(&mut line, &mut pos, "\n");
    unsafe { write(1, core::str::from_utf8(&line[..pos]).unwrap_or("?")) };

    // argv[0..argc], pointers live at `argv` as u64s, NULL-terminated.
    for i in 0..argc {
        let p = unsafe { *((argv + 8 * i) as *const u64) };
        if p == 0 {
            break;
        }
        unsafe { write(1, "greet: argv[") };
        unsafe { write(1, utoa(i, &mut buf)) };
        unsafe { write(1, "] = ") };
        unsafe { write_cstr(p) };
        unsafe { write(1, "\n") };
    }

    unsafe { exit(5) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { exit(99) }
}
