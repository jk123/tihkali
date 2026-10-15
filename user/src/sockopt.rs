#![no_std]
#![no_main]

//! tihkali `/bin/sockopt`: N5c setsockopt/getsockopt probe (Linux door).
//!
//! Exercises the real SO_* option plumbing with no network peer needed:
//! `SO_REUSEADDR`/`SO_KEEPALIVE`/`SO_BROADCAST` round-trip set→get, the
//! `SO_SNDBUF`/`SO_RCVBUF` defaults and overrides report back what was
//! stored, `SO_TYPE` reflects the socket kind, and `SO_ERROR` starts
//! clear and reports-and-clears after a failed connect to a closed port.

use core::arch::asm;
use core::panic::PanicInfo;

// Linux asm-generic/socket.h
const SOL_SOCKET: i64 = 1;
const SO_REUSEADDR: i64 = 2;
const SO_TYPE: i64 = 3;
const SO_ERROR: i64 = 4;
const SO_BROADCAST: i64 = 6;
const SO_SNDBUF: i64 = 7;
const SO_RCVBUF: i64 = 8;
const SO_KEEPALIVE: i64 = 9;

const SOCK_STREAM: i64 = 1;
const AF_INET: i64 = 2;

/// `socket(AF_INET, type, 0)` (svc #0, nr 198).
unsafe fn socket_of(kind: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #198",
            "svc #0",
            inlateout("x0") AF_INET => ret,
            in("x1") kind,
            in("x2") 0i64,
            options(nostack),
        );
    }
    ret
}

/// `setsockopt(fd, level, name, val*, len)` (svc #0, nr 208). `valp` must
/// point at a 4-byte int.
unsafe fn setsockopt(fd: i64, name: i64, valp: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #208",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") SOL_SOCKET,
            in("x2") name,
            in("x3") valp,
            in("x4") 4i64,
            options(nostack),
        );
    }
    ret
}

/// setsockopt with an inline int value; exits via `fail` on error.
fn set(fd: i64, name: i64, v: u32, what: &str, code: i64) {
    let mut cell: u32 = v;
    let r = unsafe { setsockopt(fd, name, &raw mut cell as i64) };
    if r < 0 {
        fail(what, code);
    }
}

/// `getsockopt(fd, level, name, val*, len*)` (svc #0, nr 209).
unsafe fn getsockopt(fd: i64, name: i64, out: i64, lenp: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #209",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") SOL_SOCKET,
            in("x2") name,
            in("x3") out,
            in("x4") lenp,
            options(nostack),
        );
    }
    ret
}

/// `connect(fd, sa, 16)` (svc #0, nr 203; blocking).
unsafe fn connect(fd: i64, sa: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #203",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") sa as i64,
            in("x2") 16i64,
            options(nostack),
        );
    }
    ret
}

/// `close(fd)` (svc #0, nr 57).
unsafe fn close(fd: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #57",
            "svc #0",
            inlateout("x0") fd => ret,
            options(nostack),
        );
    }
    ret
}

unsafe fn write(fd: i64, buf: *const u8, len: usize) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #64",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") buf as i64,
            in("x2") len as i64,
            options(nostack),
        );
    }
    ret
}

unsafe fn exit(code: i64) -> ! {
    unsafe {
        asm!("mov x8, #93", "svc #0", in("x0") code, options(noreturn));
    }
}

fn fail(msg: &str, code: i64) -> ! {
    unsafe {
        write(2, msg.as_ptr(), msg.len());
        exit(code);
    }
}

fn puts(s: &str) {
    unsafe {
        write(1, s.as_ptr(), s.len());
    }
}

/// Print `label=<decimal value>\n`; returns the value read back.
fn report(label: &str, v: u32) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut n = v as u64;
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    puts(label);
    puts(core::str::from_utf8(&buf[i..]).unwrap_or("?"));
    puts("\n");
}

/// getsockopt into a fresh cell; exits via `fail` on a kernel error.
fn get(fd: i64, name: i64, what: &str, code: i64) -> u32 {
    let mut cell: u32 = 0xdead_beef;
    let mut len: u32 = 4;
    let r = unsafe { getsockopt(fd, name, &raw mut cell as i64, &raw mut len as i64) };
    if r < 0 {
        fail(what, code);
    }
    if len != 4 {
        fail("sockopt: short optlen\n", code);
    }
    cell
}

/// Step 6 in its own shallow frame so the scratch int sits well below
/// `USER_LIMIT`.
fn readonly_check() {
    // Fresh socket: SO_TYPE/SO_ERROR are get-only on every slot, but a
    // fresh one keeps the check independent of earlier steps.
    let fd = unsafe { socket_of(SOCK_STREAM) };
    if fd < 0 {
        fail("sockopt: socket failed\n", 30);
    }
    let mut bad: u32 = 0;
    for name in [SO_TYPE, SO_ERROR] {
        let mut cell: u32 = 1;
        let r = unsafe { setsockopt(fd, name, &raw mut cell as i64) };
        if r != -22 {
            bad = if r < 0 { (-r) as u32 } else { r as u32 };
            break;
        }
    }
    report("ro_errno=", bad);
    if bad != 0 {
        fail("sockopt: readonly set not EINVAL\n", 28);
    }
    unsafe { close(fd) };
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64, _: u64) -> ! {
    // 1. TCP socket — SO_TYPE must report SOCK_STREAM.
    let fd = unsafe { socket_of(SOCK_STREAM) };
    if fd < 0 {
        fail("sockopt: socket failed\n", 1);
    }
    report("so_type=", get(fd, SO_TYPE, "sockopt: getsockopt type\n", 2));
    if get(fd, SO_TYPE, "sockopt: getsockopt type\n", 3) != SOCK_STREAM as u32 {
        fail("sockopt: SO_TYPE mismatch\n", 4);
    }

    // 2. Boolean flags: set then read back.
    for (name, label) in [
        (SO_REUSEADDR, "so_reuseaddr="),
        (SO_KEEPALIVE, "so_keepalive="),
        (SO_BROADCAST, "so_broadcast="),
    ] {
        set(fd, name, 1, "sockopt: setsockopt flag failed\n", 5);
        let v = get(fd, name, "sockopt: getsockopt flag\n", 6);
        if v != 1 {
            fail("sockopt: flag not sticky\n", 7);
        }
        report(label, v);
        // Clear it again — 0 must read back as 0.
        set(fd, name, 0, "sockopt: setsockopt clear failed\n", 8);
        let v = get(fd, name, "sockopt: getsockopt flag\n", 9);
        if v != 0 {
            fail("sockopt: flag did not clear\n", 10);
        }
    }

    // 3. SO_SNDBUF/SO_RCVBUF: kernel default is nonzero, then a set round-trips.
    let snd_def = get(fd, SO_SNDBUF, "sockopt: getsockopt sndbuf\n", 11);
    if snd_def == 0 {
        fail("sockopt: SO_SNDBUF default zero\n", 12);
    }
    report("so_sndbuf_def=", snd_def);
    set(fd, SO_SNDBUF, 16384, "sockopt: setsockopt sndbuf failed\n", 13);
    let v = get(fd, SO_SNDBUF, "sockopt: getsockopt sndbuf\n", 14);
    if v != 16384 {
        fail("sockopt: SO_SNDBUF not stored\n", 15);
    }
    report("so_sndbuf=", v);

    let rcv_def = get(fd, SO_RCVBUF, "sockopt: getsockopt rcvbuf\n", 16);
    if rcv_def == 0 {
        fail("sockopt: SO_RCVBUF default zero\n", 17);
    }
    report("so_rcvbuf_def=", rcv_def);
    set(fd, SO_RCVBUF, 32768, "sockopt: setsockopt rcvbuf failed\n", 18);
    let v = get(fd, SO_RCVBUF, "sockopt: getsockopt rcvbuf\n", 19);
    if v != 32768 {
        fail("sockopt: SO_RCVBUF not stored\n", 20);
    }
    report("so_rcvbuf=", v);

    // 4. SO_ERROR starts clear on a fresh, unconnected socket.
    let e = get(fd, SO_ERROR, "sockopt: getsockopt error\n", 21);
    if e != 0 {
        fail("sockopt: SO_ERROR not clear\n", 22);
    }
    report("so_error=", e);

    // 5. SO_ERROR latches a failed connect, then reports-and-clears.
    //    Port 1 on the SLIRP gateway has nothing listening → ECONNREFUSED.
    let cfd = unsafe { socket_of(SOCK_STREAM) };
    if cfd < 0 {
        fail("sockopt: socket failed\n", 23);
    }
    // Linux sockaddr_in: family u16 LE, port u16 BE (10.0.2.2 = SLIRP gw).
    let sa: [u8; 16] = [
        2, 0, // sin_family = AF_INET (LE)
        0, 1, // sin_port = 1 (BE)
        10, 0, 2, 2, // 10.0.2.2
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let r = unsafe { connect(cfd, sa.as_ptr()) };
    puts("connect_r=");
    puts(if r < 0 { "neg\n" } else { "zero\n" });
    let e = get(cfd, SO_ERROR, "sockopt: getsockopt error\n", 24);
    report("so_error_after=", e);
    if e == 0 {
        fail("sockopt: SO_ERROR did not latch\n", 25);
    }
    // Report-and-clear: the second read must come back 0.
    let e2 = get(cfd, SO_ERROR, "sockopt: getsockopt error\n", 26);
    report("so_error_cleared=", e2);
    if e2 != 0 {
        fail("sockopt: SO_ERROR did not clear\n", 27);
    }

    // 6. Setsockopt on SO_TYPE / SO_ERROR is rejected (EINVAL = -22).
    // Run in a fresh shallow frame: `user_range_ok` needs the whole 4-byte
    // cell strictly below USER_LIMIT, and this probe's frame grows high
    // into the user stack after steps 1-5.
    readonly_check();
    puts("sockopt: readonly rejected\n");

    // 7. Bad fd → EBADF (-9).
    let mut scratch: u32 = 0;
    let mut scratch_len: u32 = 4;
    let r = unsafe { getsockopt(99, SO_TYPE, &raw mut scratch as i64, &raw mut scratch_len as i64) };
    if r != -9 {
        fail("sockopt: bad fd not EBADF\n", 29);
    }
    puts("sockopt: ebadf ok\n");

    unsafe {
        close(cfd);
        close(fd);
    }
    puts("sockopt: ok\n");
    unsafe { exit(0) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe { exit(90) }
}