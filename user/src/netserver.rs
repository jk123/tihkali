#![no_std]
#![no_main]

//! tihkali `/bin/netserver`: N4 NetBSD-door TCP listen/accept probe.
//!
//! Listens on 127.0.0.1:PORT (via SLIRP hostfwd the host side connects in),
//! accepts one client, reads a byte, echoes it back, and reports the peer.
//! Exercises the NetBSD arms: `__socket30` 394, `bind` 104, `listen` 106,
//! `accept` 30 (blocking sleep/wake), `read`/`write` on the accepted fd,
//! `close` 6.

use core::arch::asm;
use core::panic::PanicInfo;

const PORT: u16 = 18082;

// ---- NetBSD-door syscall wrappers (cerror: PSTATE.C + positive errno) ----

/// `__socket30(AF_INET, SOCK_STREAM, 0)` → fd, or -errno.
unsafe fn socket_stream() -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #394",
            "cset {err}, hs",
            inlateout("x0") 2i64 => ret, // AF_INET
            in("x1") 1i64, // SOCK_STREAM
            in("x2") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -(err as i64)
    } else {
        ret
    }
}

/// `bind(fd, sa, 16)` → 0 or -errno.
unsafe fn bind(fd: i64, sa: *const u8) -> i64 {
    let err: u64;
    unsafe {
        asm!(
            "svc #104",
            "cset {err}, hs",
            in("x0") fd,
            in("x1") sa as i64,
            in("x2") 16i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -(err as i64)
    } else {
        0
    }
}

/// `listen(fd, backlog)` → 0 or -errno.
unsafe fn listen(fd: i64) -> i64 {
    let err: u64;
    unsafe {
        asm!(
            "svc #106",
            "cset {err}, hs",
            in("x0") fd,
            in("x1") 1i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -(err as i64)
    } else {
        0
    }
}

/// `accept(fd, laddr, laddrp)` → new fd, or -errno (blocks).
unsafe fn accept(fd: i64, addr: *mut u8, addrlen: *mut u8) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #30",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") addr as i64,
            in("x2") addrlen as i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -(err as i64)
    } else {
        ret
    }
}

unsafe fn read(fd: i64, buf: *mut u8, len: i64) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #3",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf as i64,
            in("x2") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -(err as i64)
    } else {
        ret
    }
}

unsafe fn write(fd: i64, buf: *const u8, len: i64) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf as i64,
            in("x2") len,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -(err as i64)
    } else {
        ret
    }
}

unsafe fn close(fd: i64) {
    let err: u64;
    unsafe {
        asm!(
            "svc #6",
            "cset {err}, hs",
            in("x0") fd,
            err = out(reg) err,
            options(nostack),
        );
    }
    let _ = err;
}

unsafe fn exit(code: i64) -> ! {
    unsafe {
        asm!("svc #1", in("x0") code, options(noreturn));
    }
}

fn fail(msg: &str, code: i64) -> ! {
    unsafe {
        write(2, msg.as_ptr(), msg.len() as i64);
        exit(code);
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
pub extern "C" fn _start(_: u64, _: u64) -> ! {
    // 1. AF_INET SOCK_STREAM socket.
    let fd = unsafe { socket_stream() };
    if fd < 0 {
        fail("netserver: socket failed\n", 1);
    }

    // 2. NetBSD sockaddr_in for 0.0.0.0:PORT (bind any, so hostfwd reaches it).
    let mut sa: [u8; 16] = [0; 16];
    sa[0] = 16; // sa_len
    sa[1] = 2; // sa_family = AF_INET
    sa[2] = (PORT >> 8) as u8; // sin_port (BE)
    sa[3] = PORT as u8;
    // sa[4..8] = 0.0.0.0

    // 3. bind + listen.
    if unsafe { bind(fd, sa.as_ptr()) } < 0 {
        fail("netserver: bind failed\n", 2);
    }
    if unsafe { listen(fd) } < 0 {
        fail("netserver: listen failed\n", 3);
    }

    // 4. Blocking accept — the arm sleeps until the SYN/ACK completes.
    // smoltcp serves one connection at a time, so the arm installs a fresh
    // fd for the accepted data socket (the listener keeps listening).
    let mut peer_sa = [0u8; 16];
    let mut peer_len: u8 = 16;
    let cfd = unsafe { accept(fd, peer_sa.as_mut_ptr(), &mut peer_len as *mut u8) };
    if cfd < 0 {
        fail("netserver: accept failed\n", 4);
    }

    // 5. Echo one byte back to the client (data flows on the accepted fd).
    let mut b = [0u8; 1];
    let n = unsafe { read(cfd, b.as_mut_ptr(), 1) };
    if n >= 1 {
        let _ = unsafe { write(cfd, b.as_ptr(), 1) };
    }
    // 6. Report the peer port (byte 2..4 of the accepted sockaddr, BE) plus
    // the read result so host + guest logs disambiguate delivery.
    let peer_port = ((peer_sa[2] as u16) << 8) | peer_sa[3] as u16;
    let mut num = [0u8; 20];
    let s = utoa(peer_port as u64, &mut num);
    let msg = "netserver: peer port ";
    let total = msg.len() + s.len() + 1;
    let mut buf = [0u8; 64];
    let mut p = 0usize;
    for &c in msg.as_bytes() {
        buf[p] = c;
        p += 1;
    }
    for &c in s.as_bytes() {
        buf[p] = c;
        p += 1;
    }
    buf[p] = b'\n';
    p += 1;
    let _ = total;
    let mut dbg = [0u8; 32];
    let mut tmpbuf = [0u8; 20];
    let dpos = {
        let base = "netserver: read=";
        let mut q = 0usize;
        for &c in base.as_bytes() {
            dbg[q] = c;
            q += 1;
        }
        let digits = utoa(n.max(0) as u64, &mut tmpbuf);
        for &c in digits.as_bytes() {
            dbg[q] = c;
            q += 1;
        }
        dbg[q] = b'\n';
        q + 1
    };
    unsafe {
        write(1, buf.as_ptr(), p as i64);
        write(1, dbg.as_ptr(), dpos as i64);
        close(cfd);
        close(fd);
        exit(0);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
