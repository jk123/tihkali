#![no_std]
#![no_main]

//! tihkali `/bin/netsend`: N5 Linux-door TCP sendmsg/recvmsg/shutdown probe.
//!
//! Listens on guest:PORT (host reaches it via SLIRP hostfwd), accepts the
//! host's connection, then echoes one payload using `sendmsg` (svc #0, nr
//! 211) + `recvmsg` (nr 212) + `shutdown` (nr 210, SHUT_WR) — exercising
//! the iovec msghdr marshalling, blocking recvmsg sleep/wake, and the
//! fd refcount paths (both the listener fd and the accepted data fd
//! drop one socket reference each on close).

use core::arch::asm;
use core::panic::PanicInfo;

const PORT: u16 = 18086;

// Linux aarch64 `struct msghdr` (LE 64-bit, pads elided):
// {msg_name, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen, msg_flags}
// — 7 × u64 = 56 bytes; msg_iovlen at byte 24.

/// Linux-door syscall: x0 holds the return value (negative = -errno on
/// failure). PSTATE.C is NOT set by the Linux epilogue — check x0.

/// `socket(AF_INET, SOCK_STREAM, 0)` (svc #0, nr 198).
unsafe fn socket_stream() -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #198",
            "svc #0",
            inlateout("x0") 2i64 => ret,
            in("x1") 1i64,
            in("x2") 0i64,
            options(nostack),
        );
    }
    ret // kernel puts the fd in x0; negative = -errno
}

/// `bind(fd, sa, 16)` (svc #0, nr 200).
unsafe fn bind(fd: i64, sa: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #200",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") sa as i64,
            in("x2") 16i64,
            options(nostack),
        );
    }
    ret // 0 on success, -errno on failure
}

/// `listen(fd, 1)` (svc #0, nr 201).
unsafe fn listen(fd: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #201",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") 1i64,
            options(nostack),
        );
    }
    ret
}

/// `accept(fd, laddr, addrlenp)` (svc #0, nr 202; blocks).
unsafe fn accept(fd: i64, laddr: *mut u8, addrlen: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #202",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") laddr as i64,
            in("x2") addrlen as i64,
            options(nostack),
        );
    }
    ret // new fd on success, -errno on failure
}

/// `recvmsg(fd, msg, 0)` (svc #0, nr 212; blocks).
unsafe fn recvmsg(fd: i64, msg: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #212",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") msg as i64,
            in("x2") 0i64,
            options(nostack),
        );
    }
    ret
}

/// `sendmsg(fd, msg, 0)` (svc #0, nr 211).
unsafe fn sendmsg(fd: i64, msg: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #211",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") msg as i64,
            in("x2") 0i64,
            options(nostack),
        );
    }
    ret
}

/// `shutdown(fd, SHUT_WR=1)` (svc #0, nr 210).
unsafe fn shutdown(fd: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #210",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") 1i64,
            options(nostack),
        );
    }
    ret
}

unsafe fn write(fd: i64, buf: *const u8, len: i64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x8, #64",
            "svc #0",
            inlateout("x0") fd => ret,
            in("x1") buf as i64,
            in("x2") len,
            options(nostack),
        );
    }
    ret
}

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

unsafe fn exit(code: i64) -> ! {
    unsafe {
        asm!("mov x8, #93", "svc #0", in("x0") code, options(noreturn));
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
    // 1. Listener socket + bind + listen.
    let lfd = unsafe { socket_stream() };
    if lfd < 0 {
        fail("netsend: socket failed\n", 1);
    }
    // Linux sockaddr_in: family u16 LE, port u16 BE, 0.0.0.0.
    let sa: [u8; 16] = [
        2, 0, // sin_family = AF_INET (LE)
        (PORT >> 8) as u8, PORT as u8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    if unsafe { bind(lfd, sa.as_ptr()) } < 0 {
        fail("netsend: bind failed\n", 2);
    }
    if unsafe { listen(lfd) } < 0 {
        fail("netsend: listen failed\n", 3);
    }

    // 2. Blocking accept — host connects via SLIRP hostfwd.
    let mut peer_sa = [0u8; 16];
    let mut peer_len: u8 = 16;
    let cfd = unsafe { accept(lfd, peer_sa.as_mut_ptr(), &mut peer_len as *mut u8) };
    if cfd < 0 {
        fail("netsend: accept failed\n", 4);
    }

    // 3. recvmsg: one iovec, host's payload (up to 16 B).
    let mut rbuf = [0u8; 16];
    let mut riov = [0u64; 2];
    riov[0] = rbuf.as_mut_ptr() as u64;
    riov[1] = rbuf.len() as u64;
    let mut rmsg = [0u64; 7];
    rmsg[2] = riov.as_ptr() as u64;
    rmsg[3] = 1;
    let n = unsafe { recvmsg(cfd, rmsg.as_mut_ptr() as *mut u8) };
    let n_sz = n.max(0) as usize;
    if n_sz < 2 {
        fail("netsend: recvmsg short\n", 5);
    }

    // 4. sendmsg: echo the payload back.
    let mut siov = [0u64; 2];
    siov[0] = rbuf.as_ptr() as u64;
    siov[1] = n_sz as u64;
    let mut smsg = [0u64; 7];
    smsg[2] = siov.as_ptr() as u64;
    smsg[3] = 1;
    let sent = unsafe { sendmsg(cfd, smsg.as_ptr() as *const u8) };
    if sent <= 0 {
        fail("netsend: sendmsg short\n", 6);
    }

    // 5. SHUT_WR: graceful FIN.
    if unsafe { shutdown(cfd) } < 0 {
        fail("netsend: shutdown failed\n", 7);
    }

    // 6. Report + tear down both fds (each drops one socket ref).
    let mut num = [0u8; 20];
    let s = utoa(n_sz as u64, &mut num);
    let mut out = [0u8; 48];
    let p = {
        let base = "netsend: recv=";
        let mut q = 0usize;
        for &c in base.as_bytes() {
            out[q] = c;
            q += 1;
        }
        for &c in s.as_bytes() {
            out[q] = c;
            q += 1;
        }
        out[q] = b'\n';
        q + 1
    };
    unsafe {
        write(1, out.as_ptr(), p as i64);
        close(cfd);
        close(lfd);
        exit(0);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
