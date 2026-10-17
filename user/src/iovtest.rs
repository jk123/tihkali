#![no_std]
#![no_main]

//! NetBSD-ABI vectored I/O: readv(120) and writev(121).
//!
//! NetBSD's `struct iovec` is `{ void *, size_t }` — the same 16 bytes
//! Linux uses — so only the syscall numbers differ (NetBSD 120/121 vs
//! Linux 65/66). This binary proves the numbers and the accounting: the
//! return value is the sum across every vector, and a zero-length vector
//! is skipped rather than treated as EOF.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

/// A NUL-terminated path in static storage. A stack local would be dead
/// before the kernel read it.
macro_rules! p {
    ($b:expr) => {{
        const S: &[u8] = concat!($b, "\0").as_bytes();
        S.as_ptr()
    }};
}

fn check(name: &str, ok: bool) {
    let pad = b"\n                                 " as &[u8];
    let n = 30 - name.len();
    unsafe {
        write(1, b"iov: ok   ");
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

/// SYS_open(path, flags) = 5
unsafe fn open(path: *const u8, flags: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #5",
            "cset {err}, hs",
            inlateout("x0") path => ret,
            in("x1") flags,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_close(fd) = 6
unsafe fn close(fd: i64) {
    unsafe {
        asm!("svc #6", inlateout("x0") fd => _, options(nostack));
    }
}

/// SYS_readv(fd, iov, iovcnt) = 120
unsafe fn readv(fd: i64, iov: *const u64, cnt: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #120",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") iov,
            in("x2") cnt,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

/// SYS_writev(fd, iov, iovcnt) = 121
unsafe fn writev(fd: i64, iov: *const u64, cnt: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #121",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") iov,
            in("x2") cnt,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"iov: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

/// Flattened iovec array: (base, len) pairs, 16 bytes each.
struct Iovecs {
    raw: [u64; 24],
    n: i64,
}

impl Iovecs {
    fn new() -> Self {
        Iovecs { raw: [0; 24], n: 0 }
    }
    fn push(&mut self, base: *const u8, len: usize) {
        self.raw[self.n as usize * 2] = base as u64;
        self.raw[self.n as usize * 2 + 1] = len as u64;
        self.n += 1;
    }
    fn as_ptr(&self) -> *const u64 {
        self.raw.as_ptr()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // --- writev to stdout, readv a real file back -------------------------
        // A pipe would need SYS_pipe (not dispatched on this path yet), so
        // the two directions use separate fds: stdout for writev, a file
        // for readv. That still exercises the same shared fd plumbing.
        let mut wiovs = Iovecs::new();
        wiovs.push(b"abc".as_ptr(), 3);
        wiovs.push(b"de".as_ptr(), 2);
        wiovs.push(b"".as_ptr(), 0);
        wiovs.push(b"fghi".as_ptr(), 4);

        // 3 + 2 + 0 + 4 = 9. A zero-length vector must be skipped, not
        // treated as a short write.
        match writev(1, wiovs.as_ptr(), wiovs.n) {
            Ok(n) => check("writev sums vectors", n == 9),
            Err(_) => check("writev sums vectors", false),
        }

        match open(p!("/etc/motd"), 0) {
            Ok(fd) => {
                // Read in awkward chunks: 1, 0, 4, then the rest. A correct
                // walker skips the zero and keeps filling later vectors.
                let mut a = [0u8; 1];
                let mut c = [0u8; 4];
                let mut d = [0u8; 64];
                let mut riovs = Iovecs::new();
                riovs.push(a.as_mut_ptr(), 1);
                let mut zbuf = [0u8; 1];
                riovs.push(zbuf.as_mut_ptr(), 0);
                riovs.push(c.as_mut_ptr(), 4);
                riovs.push(d.as_mut_ptr(), 64);

                match readv(fd, riovs.as_ptr(), riovs.n) {
                    Ok(n) => {
                        // 1 + 0 + 4 + 64 = 69: every vector filled, so the
                        // zero-length one was skipped rather than ending
                        // the read.
                        check("readv fills vectors", n == 69);
                        check("readv vector 0", a[0] != 0);
                        check("readv skipped 0-len vector", n == 69);
                    }
                    Err(_) => {
                        check("readv fills vectors", false);
                        check("readv vector 0", false);
                        check("readv skipped 0-len vector", false);
                    }
                }
                close(fd);
            }
            Err(_) => {
                check("readv fills vectors", false);
                check("readv vector 0", false);
                check("readv kept going past 0-len", false);
            }
        }

        // --- argument validation --------------------------------------------
        // iovcnt of 0 transfers nothing and succeeds.
        match writev(1, wiovs.as_ptr(), 0) {
            Ok(0) => check("writev zero iovcnt", true),
            _ => check("writev zero iovcnt", false),
        }
        // A huge iovcnt is EINVAL, not a wild read of the array.
        match writev(1, wiovs.as_ptr(), 1_000_000) {
            Err(e) => check("writev EINVAL iovcnt", e == 22),
            Ok(_) => check("writev EINVAL iovcnt", false),
        }
        // An iovec array outside user space is EFAULT.
        match writev(1, 0x10_0000_0000u64 as *const u64, 2) {
            Err(e) => check("writev EFAULT iovec", e == 14),
            Ok(_) => check("writev EFAULT iovec", false),
        }
        // A bad fd is EBADF.
        match writev(99, wiovs.as_ptr(), 1) {
            Err(e) => check("writev EBADF", e == 9),
            Ok(_) => check("writev EBADF", false),
        }

        finish();
    }
}

unsafe fn finish() -> ! {
    unsafe {
        let msg = if FAILURES == 0 {
            b"iov: all ok\n" as &[u8]
        } else {
            b"iov: FAILED\n" as &[u8]
        };
        write(1, msg);
        asm!(
            "svc #1",
            in("x0") FAILURES as isize,
            options(nostack, noreturn),
        );
    }
}