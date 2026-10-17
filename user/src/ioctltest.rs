#![no_std]
#![no_main]

//! NetBSD-ABI `ioctl`(54).
//!
//! The point of this binary is that NetBSD's ioctl request encoding is not
//! Linux's, even though the TIOC names, the 't' group character and the
//! parameter sizes are identical. Linux's `TIOCGWINSZ` is 0x5413; NetBSD's
//! is 0x80087468. A kernel that reused the Linux table would answer every
//! NetBSD request with ENOTTY — and, worse, one that merely *added* the
//! NetBSD values would happily honour a Linux request number on the
//! NetBSD path.
//!
//! So this checks both directions: every NetBSD request works, **and**
//! every Linux one is refused. The negative half is the only thing that
//! distinguishes a translating kernel from one that accepts both.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

fn check(name: &str, ok: bool) {
    let pad = b"\n                                    " as &[u8];
    let n = (24usize).saturating_sub(name.len()).min(pad.len() - 1);
    unsafe {
        write(1, b"io: ok   ");
        write(1, name.as_bytes());
        write(1, &pad[..n]);
        if ok {
            write(1, b"ok\n");
        } else {
            write(1, b"FAILED <<");
            write(1, name.as_bytes());
            write(1, b">>\n");
            FAILURES += 1;
        }
    }
}

fn print_num(name: &str, v: i64) {
    let mut digits = [0u8; 24];
    let mut n = 0;
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    if u == 0 {
        digits[n] = b'0';
        n += 1;
    }
    while u > 0 {
        digits[n] = b'0' + (u % 10) as u8;
        u /= 10;
        n += 1;
    }
    let mut buf = [0u8; 25];
    let mut w = 0;
    if neg {
        buf[w] = b'-';
        w += 1;
    }
    for i in (0..n).rev() {
        buf[w] = digits[i];
        w += 1;
    }
    unsafe {
        write(1, b"io: num  ");
        write(1, name.as_bytes());
        write(1, b" = ");
        write(1, &buf[..w]);
        write(1, b"\n");
    }
}

/// Print a request number in hex, which is how these are written by hand.
fn print_hex(name: &str, v: u64) {
    let mut buf = [0u8; 18];
    let mut n = 0;
    let mut u = v;
    if u == 0 {
        buf[n] = b'0';
        n += 1;
    }
    while u > 0 {
        buf[n] = b"0123456789abcdef"[(u & 15) as usize];
        u >>= 4;
        n += 1;
    }
    buf[n] = b'x';
    n += 1;
    let mut out = [0u8; 18];
    let mut w = 0;
    for i in (0..n).rev() {
        out[w] = buf[i];
        w += 1;
    }
    unsafe {
        write(1, b"io: num  ");
        write(1, name.as_bytes());
        write(1, b" = 0x");
        write(1, &out[..w]);
        write(1, b"\n");
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

/// SYS_ioctl(fd, request, arg) = 54
unsafe fn ioctl(fd: i64, req: u64, arg: u64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #54",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") req,
            in("x2") arg,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

// --- NetBSD request numbers, from sys/sys/ioccom.h + ttycom.h ---
const TIOCEXCL: u64 = 0x2000740d;
const TIOCNXCL: u64 = 0x2000740e;
const TIOCFLUSH: u64 = 0x40047410;
const TIOCGETA: u64 = 0x802c7413;
const TIOCSETA: u64 = 0x402c7414;
const TIOCSETAW: u64 = 0x402c7415;
const TIOCSETAF: u64 = 0x402c7416;
const TIOCGETD: u64 = 0x8004741a;
const TIOCSETD: u64 = 0x4004741b;
const TIOCGLINED: u64 = 0x80047442;
const TIOCSLINED: u64 = 0x40047443;
const TIOCSWINSZ: u64 = 0x40087467;
const TIOCGWINSZ: u64 = 0x80087468;
const TIOCMGET: u64 = 0x8004746a;
const TIOCSTART: u64 = 0x2000746e;
const TIOCSTOP: u64 = 0x2000746f;
const TIOCNOTTY: u64 = 0x20007471;
const TIOCOUTQ: u64 = 0x80047473;
const TIOCSPGRP: u64 = 0x40047476;
const TIOCGPGRP: u64 = 0x80047477;
const TIOCCDTR: u64 = 0x20007478;

// --- Linux request numbers, which must all be refused here ---
const LNX_TCGETS: u64 = 0x5401;
const LNX_TCSETS: u64 = 0x5402;
const LNX_TIOCGWINSZ: u64 = 0x5413;
const LNX_TIOCGPGRP: u64 = 0x540f;
const LNX_TIOCSPGRP: u64 = 0x5410;

/// NetBSD `struct termios` = 4*u32 + c_cc[20] + 2*int = 44 bytes.
/// Linux's is 36 because its NCCS is 19.
const TERMIOS_SIZE: usize = 44;
const NB_ICANON: u32 = 0x100;
const NB_ECHO: u32 = 0x8;

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn finish() -> ! {
    unsafe {
        if FAILURES == 0 {
            write(1, b"io: all ok\n");
            asm!("svc #1", in("x0") 0isize, options(nostack, noreturn));
        } else {
            write(1, b"io: FAILURES ");
            print_num("", FAILURES);
            write(1, b"io: FAILED\n");
            asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
        }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"io: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // --- TIOCGWINSZ: the request whose encoding differs most ----------
        let mut ws = [0xAAu8; 8];
        check("gwinsz succeeds", ioctl(1, TIOCGWINSZ, ws.as_mut_ptr() as u64) == Ok(0));
        check("winsz rows", u16_at(&ws, 0) == 24);
        check("winsz cols", u16_at(&ws, 2) == 80);
        check("winsz xpixel", u16_at(&ws, 4) == 0);
        check("winsz ypixel", u16_at(&ws, 6) == 0);
        // struct winsize is 8 bytes on both ABIs, so a Linux-shaped writer
        // would pass every line above. The request number is the only
        // thing distinguishing them -- hence the refusal checks further on.

        // --- TIOCSWINSZ is accepted and ignored ---------------------------
        let ws2 = [30u16, 100, 0, 0];
        check("swinsz accepted", ioctl(1, TIOCSWINSZ, ws2.as_ptr() as u64) == Ok(0));
        // ...and it must NOT have changed what GET reports: the emulation
        // has one fixed winsize.
        let mut ws3 = [0u8; 8];
        check("gwinsz after swinsz", ioctl(1, TIOCGWINSZ, ws3.as_mut_ptr() as u64) == Ok(0));
        check("winsz unchanged", u16_at(&ws3, 0) == 24 && u16_at(&ws3, 2) == 80);

        // --- TIOCGETA: NetBSD termios is 44 bytes, not 36 ----------------
        let mut t = [0xAAu8; TERMIOS_SIZE];
        check("geta succeeds", ioctl(1, TIOCGETA, t.as_mut_ptr() as u64) == Ok(0));
        // c_lflag @12. NetBSD ICANON is 0x100 where Linux's is 0x2, and
        // ECHO is 0x8 where Linux's is 0x10.
        let lflag = u32_at(&t, 12);
        print_hex("c_lflag", lflag as u64);
        check("lflag has ICANON", lflag & NB_ICANON != 0);
        check("lflag has ECHO", lflag & NB_ECHO != 0);
        check("lflag not Linux ICANON", lflag & 0x2 == 0);
        check("lflag not Linux ECHO", lflag & 0x10 == 0);
        // c_ispeed/c_ospeed @40 and @44-4... i.e. 40 and 44 is past the
        // end, so they are at 40 and 44-4=40? No: 4 flags (16) + 20 cc = 36,
        // then c_ispeed @36 and c_ospeed @40.
        check("ispeed nonzero", u32_at(&t, 36) != 0);
        check("ospeed nonzero", u32_at(&t, 40) != 0);
        // The last 8 bytes are c_ispeed/c_ospeed. Prefilled with 0xAA, so
        // any surviving 0xAA at offset 43 means the kernel wrote only
        // Linux's 36 bytes and left the tail as the caller had it.
        let mut tt = [0xAAu8; TERMIOS_SIZE];
        check("geta again", ioctl(1, TIOCGETA, tt.as_mut_ptr() as u64) == Ok(0));
        check("byte 43 written", tt[43] != 0xAA);
        check("speeds match", u32_at(&tt, 36) == u32_at(&tt, 40));

        // --- TIOCSETA and friends are accepted ---------------------------
        check("seta accepted", ioctl(1, TIOCSETA, t.as_ptr() as u64) == Ok(0));
        check("setaw accepted", ioctl(1, TIOCSETAW, t.as_ptr() as u64) == Ok(0));
        check("setaf accepted", ioctl(1, TIOCSETAF, t.as_ptr() as u64) == Ok(0));

        // --- line discipline ---------------------------------------------
        let mut ld = [0u8; 4];
        check("glined succeeds", ioctl(1, TIOCGLINED, ld.as_mut_ptr() as u64) == Ok(0));
        check("glined is N_TTY", u32_at(&ld, 0) == 1);
        check("slined accepted", ioctl(1, TIOCSLINED, ld.as_mut_ptr() as u64) == Ok(0));
        check("getd is N_TTY", {
            let mut d = [0u8; 4];
            ioctl(1, TIOCGETD, d.as_mut_ptr() as u64) == Ok(0) && u32_at(&d, 0) == 1
        });
        check("setd accepted", ioctl(1, TIOCSETD, ld.as_mut_ptr() as u64) == Ok(0));

        // --- modem state: none, and reported as none ----------------------
        let mut modem = [0xFFu8; 4];
        check("mget succeeds", ioctl(1, TIOCMGET, modem.as_mut_ptr() as u64) == Ok(0));
        check("mget reports zero", u32_at(&modem, 0) == 0);
        check("outq succeeds", ioctl(1, TIOCOUTQ, modem.as_mut_ptr() as u64) == Ok(0));
        check("outq reports zero", u32_at(&modem, 0) == 0);

        // --- process group -----------------------------------------------
        let mut pg = [0u8; 4];
        check("gpgrp succeeds", ioctl(1, TIOCGPGRP, pg.as_mut_ptr() as u64) == Ok(0));
        let cur = u32_at(&pg, 0) as i64;
        check("spgrp accepts own", ioctl(1, TIOCSPGRP, pg.as_mut_ptr() as u64) == Ok(0));
        check("gpgrp roundtrips", {
            let mut q = [0u8; 4];
            ioctl(1, TIOCGPGRP, q.as_mut_ptr() as u64) == Ok(0) && u32_at(&q, 0) as i64 == cur
        });
        // SPGRP takes a POINTER to an int, so the g<0 test needs -1 in
        // memory. Passing the value -1 *as the pointer* is EFAULT, which is
        // a different check and is exercised separately below.
        let mut negpg = [0xFFu8; 4]; // -1 as a little-endian int
        check("spgrp rejects negative", ioctl(1, TIOCSPGRP, negpg.as_mut_ptr() as u64) == Err(22));
        print_num("spgrp neg errno", ioctl(1, TIOCSPGRP, negpg.as_mut_ptr() as u64).unwrap_or(-999));

        // --- the accepted no-ops ------------------------------------------
        check("flush accepted", ioctl(1, TIOCFLUSH, 0) == Ok(0));
        check("excl accepted", ioctl(1, TIOCEXCL, 0) == Ok(0));
        check("nxcl accepted", ioctl(1, TIOCNXCL, 0) == Ok(0));
        check("start accepted", ioctl(1, TIOCSTART, 0) == Ok(0));
        check("stop accepted", ioctl(1, TIOCSTOP, 0) == Ok(0));
        check("notty accepted", ioctl(1, TIOCNOTTY, 0) == Ok(0));
        check("cdtr accepted", ioctl(1, TIOCCDTR, 0) == Ok(0));
        // TIOCSTI (0x40017472) injects a byte into the input queue -- an
        // input-injection primitive NetBSD restricts by privilege. It is
        // deliberately NOT implemented, and must be refused rather than
        // silently ignored.
        check("sti refused", ioctl(1, 0x40017472, 0) == Err(25));

        // --- EFAULT on a bad pointer, EBADF on a bad fd ------------------
        check("gwinsz bad ptr EFAULT", ioctl(1, TIOCGWINSZ, 0xFFFF_FFFF_FFFF) == Err(14));
        print_num("badptr errno", ioctl(1, TIOCGWINSZ, 0xFFFF_FFFF_FFFF).unwrap_or(-999));
        check("bad ptr as ptr EFAULT", ioctl(1, TIOCSPGRP, (-1i64) as u64) == Err(14));
        check("bad fd EBADF", ioctl(9999, TIOCGWINSZ, ws.as_mut_ptr() as u64) == Err(9));
        print_num("badfd errno", ioctl(9999, TIOCGWINSZ, ws.as_mut_ptr() as u64).unwrap_or(-999));

        // --- LINUX request numbers must all be refused --------------------
        // This is the half that proves a translation is happening. A kernel
        // that answers 0x5413 here would hand a NetBSD caller the Linux
        // table's meaning, and one that accepts both has no boundary at all.
        check("linux TCGETS refused", ioctl(1, LNX_TCGETS, t.as_mut_ptr() as u64) == Err(25));
        check("linux TCSETS refused", ioctl(1, LNX_TCSETS, t.as_ptr() as u64) == Err(25));
        check("linux GWINSZ refused", ioctl(1, LNX_TIOCGWINSZ, ws.as_mut_ptr() as u64) == Err(25));
        check("linux GPGRP refused", ioctl(1, LNX_TIOCGPGRP, pg.as_mut_ptr() as u64) == Err(25));
        check("linux SPGRP refused", ioctl(1, LNX_TIOCSPGRP, pg.as_mut_ptr() as u64) == Err(25));
        // And they must not have written anything on the way out.
        let mut untouched = [0xAAu8; 8];
        let _ = ioctl(1, LNX_TIOCGWINSZ, untouched.as_mut_ptr() as u64);
        check("refused write nothing", untouched.iter().all(|b| *b == 0xAA));

        // --- a request from an unrelated group is refused too -------------
        check("other group refused", ioctl(1, 0x802c_7401, 0) == Err(25));
        check("nonsense refused", ioctl(1, 0xDEAD_BEEF, 0) == Err(25));

        finish();
    }
}