#![no_std]
#![no_main]

//! NetBSD-ABI socket identity: getpeername(31), getsockname(32),
//! socketpair(135).
//!
//! The point of this binary is the sockaddr *layout* and the errno
//! distinction. NetBSD's sockaddr_in stores sa_len and sa_family as **u8**
//! and the port big-endian in the two bytes after them -- nothing like
//! Linux's u16 family. A kernel that wrote the Linux shape would return 0
//! from all three calls and leave every field here garbage, so the checks
//! read the bytes back rather than the return code.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

fn check(name: &str, ok: bool) {
    let pad = b"\n                                  " as &[u8];
    let n = 28 - name.len();
    unsafe {
        write(1, b"sockid: ok   ");
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

/// SYS_socket(af, type, proto) = 97
unsafe fn socket(af: i64, ty: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #97",
            "cset {err}, hs",
            inlateout("x0") af => ret,
            in("x1") ty,
            in("x2") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_bind(fd, sa, salen) = 104
unsafe fn bind(fd: i64, sa: *const u8, salen: i64) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #104",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") sa,
            in("x2") salen,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_getsockname(fd, sa, salen*) = 32
unsafe fn getsockname(fd: i64, sa: *mut u8, salen: *mut i32) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #32",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") sa,
            in("x2") salen,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_getpeername(fd, sa, salen*) = 31
unsafe fn getpeername(fd: i64, sa: *mut u8, salen: *mut i32) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #31",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") sa,
            in("x2") salen,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_socketpair(domain, type, proto, fdp) = 135
unsafe fn socketpair(domain: i64, ty: i64, fdp: *mut i32) -> Result<(), i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #135",
            "cset {err}, hs",
            in("x0") domain,
            in("x1") ty,
            in("x2") 0i64,
            in("x3") fdp,
            lateout("x0") ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(()) }
}

/// SYS_close(fd) = 6
unsafe fn close(fd: i64) {
    unsafe {
        asm!("svc #6", inlateout("x0") fd => _, options(nostack));
    }
}

/// Fill a NetBSD sockaddr_in: sa_len@0 (u8), sa_family@1 (u8),
/// port big-endian @2..4, IPv4 @4..8.
unsafe fn nb_sa(port: u16, ip: [u8; 4]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 16;
    a[1] = 2; // AF_INET as u8 on NetBSD
    a[2] = (port >> 8) as u8;
    a[3] = port as u8;
    a[4..8].copy_from_slice(&ip);
    a
}

/// Read the port back out of a NetBSD sockaddr_in.
fn nb_port(a: &[u8; 16]) -> u16 {
    ((a[2] as u16) << 8) | a[3] as u16
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"sockid: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut sa = [0u8; 16];
        let mut slen: i32 = 16;

        // --- getsockname on an unbound socket ---------------------------------
        // Must succeed and report 0.0.0.0:0 -- not an error, and not the
        // ephemeral port the stack would pick later.
        let Ok(s) = socket(2, 1) else {
            check("socket tcp", false);
            finish();
        };
        check("socket tcp", true);
        match getsockname(s, sa.as_mut_ptr(), &mut slen) {
            Ok(()) => {
                check("getsockname unbound ok", true);
                check("getsockname sa_len", sa[0] == 16);
                check("getsockname family u8", sa[1] == 2);
                check("getsockname port 0", nb_port(&sa) == 0);
                check("getsockname wildcard", sa[4..8] == [0, 0, 0, 0]);
                check("getsockname wrote len", slen == 16);
            }
            Err(_) => {
                check("getsockname unbound ok", false);
                check("getsockname sa_len", false);
                check("getsockname family u8", false);
                check("getsockname port 0", false);
                check("getsockname wildcard", false);
                check("getsockname wrote len", false);
            }
        }

        // getpeername before any connect must be ENOTCONN (57), not a
        // zeroed address a caller could mistake for a real peer.
        match getpeername(s, sa.as_mut_ptr(), &mut slen) {
            Err(e) => check("getpeername ENOTCONN", e == 57),
            Ok(_) => check("getpeername ENOTCONN", false),
        }

        // --- getsockname after an explicit bind -------------------------------
        let port = 31_337;
        match bind(s, nb_sa(port, [0, 0, 0, 0]).as_ptr(), 16) {
            Ok(()) => check("bind tcp", true),
            Err(_) => check("bind tcp", false),
        }
        match getsockname(s, sa.as_mut_ptr(), &mut slen) {
            Ok(()) => {
                check("getsockname bound port", nb_port(&sa) == port);
                // A 0.0.0.0 bind must be reported as the real local address,
                // not as the wildcard: the packet goes out with the iface IP.
                check("getsockname real ip", sa[4] == 10 && sa[5] == 0 && sa[6] == 2);
            }
            Err(_) => {
                check("getsockname bound port", false);
                check("getsockname real ip", false);
            }
        }
        close(s);

        // --- a UDP socket keeps its ephemeral port visible ---------------------
        let Ok(u) = socket(2, 2) else {
            check("socket udp", false);
            finish();
        };
        check("socket udp", true);
        // musl's resolver binds 0.0.0.0:0; the stack picks a real port and
        // getsockname must report THAT, not the 0 that was asked for.
        match bind(u, nb_sa(0, [0, 0, 0, 0]).as_ptr(), 16) {
            Ok(()) => check("bind udp ephemeral", true),
            Err(_) => check("bind udp ephemeral", false),
        }
        match getsockname(u, sa.as_mut_ptr(), &mut slen) {
            Ok(()) => {
                let p = nb_port(&sa);
                check("udp ephemeral nonzero", p != 0);
                check("udp family u8", sa[1] == 2);
            }
            Err(_) => {
                check("udp ephemeral nonzero", false);
                check("udp family u8", false);
            }
        }
        close(u);

        // --- socketpair ---------------------------------------------------------
        // Not implemented, and deliberately so: see net::sock_pair. Both
        // AF_INET and AF_UNIX must be refused with EOPNOTSUPP (45) rather
        // than half-succeeding -- a caller that checks the errno gets a
        // clear reason, where a partial pair would fail later and further
        // from the cause.
        let mut fds = [0i32; 2];
        match socketpair(2, 1, fds.as_mut_ptr()) {
            Err(e) => check("socketpair EOPNOTSUPP", e == 45),
            Ok(_) => check("socketpair EOPNOTSUPP", false),
        }
        match socketpair(1, 1, fds.as_mut_ptr()) {
            Err(e) => check("socketpair AF_UNIX too", e == 45),
            Ok(_) => check("socketpair AF_UNIX too", false),
        }

        finish();
    }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"sockid: all ok\n" as &[u8]
        } else {
            b"sockid: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}