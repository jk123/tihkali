#![no_std]
#![no_main]

//! tihkali `/bin/nettest`: N3 NetBSD-door ICMP ping.
//!
//! Exercises the NetBSD socket arms (`__socket30` 394, connect 98,
//! sendto 133, recvfrom 29) end to end: raw ICMP socket, echo request
//! to the SLIRP gateway 10.0.2.2, blocking recvfrom for the reply.
//! Error convention: PSTATE.C + positive errno in x0 (NetBSD cerror).

use core::arch::asm;
use core::panic::PanicInfo;

const IDENT: u16 = 0x1234;

// ---- NetBSD-door syscall wrappers (cerror: PSTATE.C + positive errno) ----

/// `__socket30(domain, type, proto)` → fd, or -errno.
unsafe fn socket() -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #394",
            "cset {err}, hs",
            inlateout("x0") 2i64 => ret, // AF_INET
            in("x1") 3i64, // SOCK_RAW
            in("x2") 1i64, // IPPROTO_ICMP
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

/// `connect(fd, sa, 16)` → 0 or -errno.
unsafe fn connect(fd: i64, sa: *const u8) -> i64 {
    let err: u64;
    unsafe {
        asm!(
            "svc #98",
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

/// `sendto(fd, buf, 64, 0, NULL, 0)` → bytes or -errno.
unsafe fn sendto(fd: i64, buf: *const u8) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #133",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf as i64,
            in("x2") 64i64,
            in("x3") 0i64,
            in("x4") 0i64,
            in("x5") 0i64,
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

/// `recvfrom(fd, buf, 320, 0, NULL, NULL)` → bytes or -errno (blocks).
unsafe fn recvfrom(fd: i64, buf: *mut u8) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #29",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf as i64,
            in("x2") 320i64,
            in("x3") 0i64,
            in("x4") 0i64,
            in("x5") 0i64,
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

unsafe fn write(fd: i64, msg: &str) {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") msg.as_ptr() as i64,
            in("x2") msg.len() as i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    let _ = (ret, err);
}

unsafe fn exit(code: i64) -> ! {
    unsafe {
        asm!("svc #1", in("x0") code, options(noreturn));
    }
}

/// `shutdown(fd, how)` → 0 or -errno (NetBSD svc #134).
unsafe fn shutdown(fd: i64, how: i64) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #134",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") how,
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

/// `setitimer(ITIMER_REAL, new, old)` → 0 or -errno (NetBSD svc #83,
/// SYS_compat_50_setitimer). x0 = 0 (ITIMER_REAL), x1 = new (null =
/// disarm), x2 = old (null ok). itimerval layout: {u64 sec, u64 usec}
/// for it_value and it_interval (this probe uses it_value only).
unsafe fn setitimer(new: *const u64, old: *mut u64) -> i64 {
    let err: u64;
    unsafe {
        asm!(
            "svc #83",
            "cset {err}, hs",
            in("x0") 0i64,
            in("x1") new as i64,
            in("x2") old as i64,
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

fn fail(msg: &str, code: i64) -> ! {
    unsafe {
        write(2, msg);
        exit(code);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64, _: u64) -> ! {
    // 1. Raw ICMP socket: NetBSD door `__socket30(AF_INET, SOCK_RAW, 1)`.
    let fd = unsafe { socket() };
    if fd < 0 {
        fail("nettest: socket failed\n", 1);
    }

    // 2. 64-byte echo request to 10.0.2.2, identifier 0x1234, seq 1.
    let mut pkt = [0u8; 64];
    pkt[0] = 8;
    pkt[4] = (IDENT >> 8) as u8;
    pkt[5] = (IDENT & 0xff) as u8;
    pkt[7] = 1;
    {
        let mut sum = 0u32;
        for pair in pkt.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        pkt[2] = (cksum >> 8) as u8;
        pkt[3] = (cksum & 0xff) as u8;
    }

    // 3. NetBSD sockaddr_in (sa_family at byte 1, not 0; sa_len at byte 0).
    let sa: [u8; 16] = [
        16, 2, // sa_len, sa_family = AF_INET
        0, 0, // sin_port = 0 (BE)
        10, 0, 2, 2, // sin_addr = 10.0.2.2 (BE)
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // 4. connect() records the peer (no handshake on raw ICMP).
    let r = unsafe { connect(fd, sa.as_ptr()) };
    if r < 0 {
        fail("nettest: connect failed\n", 2);
    }

    // 5. sendto(NULL dest) → routes to the connected peer.
    let n = unsafe { sendto(fd, pkt.as_ptr()) };
    if n != 64 {
        fail("nettest: sendto failed\n", 3);
    }

    // 6. Blocking recvfrom (the arm sleeps + wakes on SocketStateChanged).
    // Raw-socket delivery: 20-byte IPv4 header, then the ICMP message.
    let mut out = [0u8; 320];
    let n = unsafe { recvfrom(fd, out.as_mut_ptr()) } as usize;
    if n < 28 {
        fail("nettest: recvfrom failed\n", 4);
    }
    let hlen = ((out[0] & 0x0f) as usize) * 4;
    let ic = hlen.max(20).min(n - 8);
    if out[ic] != 0
        || out[ic + 4] != (IDENT >> 8) as u8
        || out[ic + 5] != (IDENT & 0xff) as u8
        || out[ic + 7] != 1
    {
        fail("nettest: bad reply\n", 5);
    }

    // 7. N5: shut down the send half of the live socket (svc #134).
    let sh = unsafe { shutdown(fd, 1) };
    if sh < 0 {
        fail("nettest: shutdown failed\n", 6);
    }

    // 8. N5: arm a 3 s ITIMER_REAL deadline via setitimer(83), then
    // disarm it — exercises the proc itimer plumbing. arm → disarming
    // within the window means no SIGALRM is actually delivered.
    let mut itim = [0u64; 4];
    itim[0] = 3; // it_value.tv_sec
    itim[1] = 0; // it_value.tv_usec
    let mut old_itim = [0u64; 4];
    let r = unsafe { setitimer(itim.as_ptr(), old_itim.as_mut_ptr()) };
    if r < 0 {
        fail("nettest: setitimer arm failed\n", 7);
    }
    // It value 0 disarms the pending timer.
    itim[0] = 0;
    itim[1] = 0;
    let r = unsafe { setitimer(itim.as_ptr(), old_itim.as_mut_ptr()) };
    if r < 0 {
        fail("nettest: setitimer disarm failed\n", 7);
    }

    unsafe {
        write(1, "nettest: ok\n");
        exit(0);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
