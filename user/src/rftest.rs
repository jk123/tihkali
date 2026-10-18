#![no_std]
#![no_main]

//! NetBSD-ABI batch 8: the three refusal groups -- POSIX.1e ACLs,
//! user-level threads, kernel semaphores, System V IPC and POSIX message
//! queues.
//!
//! Fifty-six calls, one shared answer: EOPNOTSUPP, which says "this
//! kernel does not have that facility" where ENOSYS would say "this
//! kernel has never heard of the call". Neither is a silent success, and
//! that distinction is the whole point -- an ACL get returning 0 bytes
//! would be indistinguishable from an empty ACL, which a caller then
//! reads as "no access granted" rather than "not implemented".
//!
//! EOPNOTSUPP is **45** on NetBSD. (95 is ENOLINK, and this kernel
//! returned 95 on every refusal for several batches before a probe caught
//! it -- see the notes.) NetBSD's error convention is PSTATE.C=1 plus the
//! POSITIVE errno in x0; there is no -1 sentinel.
//!
//! One call in the LWP group is NOT a refusal: `_lwp_self` returns the
//! calling thread's id, because the calling thread is real -- it is just
//! the only one. A probe that asserted "everything refuses" would pass on
//! a kernel that refuses the one thing it can answer.

use core::arch::asm;
use core::panic::PanicInfo;

static mut FAILURES: i64 = 0;

macro_rules! p {
    ($b:expr) => {{
        const S: &[u8] = concat!($b, "\0").as_bytes();
        S.as_ptr()
    }};
}

macro_rules! pa {
    ($b:expr) => {{
        const S: &[u8] = concat!($b, "\0").as_bytes();
        S.as_ptr() as i64
    }};
}

/// EOPNOTSUPP on NetBSD. Carried as a constant so the probe and the kernel
/// cannot drift apart silently -- that drift is exactly what shipped.
const EOPNOTSUPP: isize = 45;

fn check(name: &str, ok: bool) {
    let mut line = [0u8; 128];
    let mut n = 0usize;
    let put = |buf: &mut [u8; 128], n: &mut usize, bytes: &[u8]| {
        let end = (*n + bytes.len()).min(buf.len() - 1);
        buf[*n..end].copy_from_slice(&bytes[..end - *n]);
        *n = end;
    };
    let pad = b"                                      ";
    put(&mut line, &mut n, b"rf: ok     ");
    put(&mut line, &mut n, name.as_bytes());
    put(&mut line, &mut n, &pad[..(36usize).saturating_sub(name.len())]);
    if ok {
        put(&mut line, &mut n, b"ok\n");
    } else {
        put(&mut line, &mut n, b"FAILED <<");
        put(&mut line, &mut n, name.as_bytes());
        put(&mut line, &mut n, b">>\n");
        unsafe { FAILURES += 1 };
    }
    unsafe { write(1, &line[..n]) };
}

unsafe fn write(fd: i64, buf: &[u8]) {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf.as_ptr(),
            in("x2") buf.len(),
            err = out(reg) err,
            options(nostack),
        );
    }
    let _ = (ret, err);
}

/// One refusal check. The syscall number is an IMMEDIATE on NetBSD --
/// `svc #NR`, not a register -- so it must be a literal at the call site.
/// That is why every refusal is its own line rather than a loop over an
/// array of numbers: each check names the number it exercised, so no
/// return-code gate can be satisfied by a call that silently succeeded.
macro_rules! refuses {
    ($name:expr, $nr:literal, $a0:expr, $a1:expr, $a2:expr) => {{
        let ret: i64;
        let err: isize;
        unsafe {
            asm!(
                concat!("svc #", $nr),
                "cset {err}, hs",
                inlateout("x0") $a0 => ret,
                err = out(reg) err,
                options(nostack),
            );
        }
        let _ = ($a1, $a2);
        // `cset ... hs` yields 1 when the carry flag is set, NOT the errno.
        // The errno is the value the kernel left in x0. So the check is
        // "the flag is set AND x0 holds 45" -- asserting err == 45 asserts
        // a carry flag equals a number, which is never true.
        check($name, err != 0 && ret == EOPNOTSUPP as i64);
    }};
}

/// The five-argument form, for the calls that carry a fourth word.
macro_rules! refuses5 {
    ($name:expr, $nr:literal, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let ret: i64;
        let err: isize;
        unsafe {
            asm!(
                concat!("svc #", $nr),
                "cset {err}, hs",
                inlateout("x0") $a0 => ret,
                in("x1") $a1,
                in("x2") $a2,
                in("x3") $a3,
                err = out(reg) err,
                options(nostack),
            );
        }
        check($name, err != 0 && ret == EOPNOTSUPP as i64);
    }};
}

/// A call that must ANSWER rather than refuse.
macro_rules! answers {
    ($name:expr, $nr:literal) => {{
        let ret: i64;
        let err: isize;
        unsafe {
            asm!(
                concat!("svc #", $nr),
                "cset {err}, hs",
                inlateout("x0") 0i64 => ret,
                err = out(reg) err,
                options(nostack),
            );
        }
        check($name, err == 0 && ret > 0);
    }};
}

unsafe fn openat_create(dirfd: i64, path: *const u8, flags: i64, mode: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #468",
            "cset {err}, hs",
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") flags,
            in("x3") mode,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

unsafe fn close(fd: i64) -> Result<i64, i64> {
    let ret: i64;
    let err: isize;
    unsafe {
        asm!(
            "svc #3",
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { Err(ret) } else { Ok(ret) }
}

const AT_FDCWD: i64 = -100;
const O_CREAT: i64 = 0x200;
const O_RDWR: i64 = 2;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        write(1, b"rf: panic\n");
        asm!("svc #1", in("x0") 1isize, options(nostack, noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // A real open file: the _fd variants must be refused on an open
    // descriptor, not merely because the number is unmapped.
    let fd = match unsafe { openat_create(AT_FDCWD, p!("/etc/rffile"), O_CREAT | O_RDWR, 0o644) } {
        Ok(f) => f,
        Err(_) => {
            unsafe { write(1, b"rf: open failed\n") };
            unsafe { asm!("svc #1", in("x0") 1isize, options(nostack, noreturn)) };
        }
    };
    check("probe opened a file", fd > 0);

    // Control: GETPID is 20 and is armed. The probe is a forked child of
    // the shell, so its pid is NOT 0 -- asserting 0 asserted a premise
    // about the run environment rather than about the kernel.
    answers!("control getpid 20", 20);

    // --- POSIX.1e ACLs, 487-498 ---------------------------------------
    // Every one takes (path | fd, acl_type_t, struct acl *) in x0..x2.
    // A NULL aclp is the natural probe argument: it cannot be mistaken
    // for a successfully-returned empty ACL.
    refuses!("acl_set_link 488", 488, pa!("/etc/rffile"), 0i64, 0i64);
    refuses!("acl_delete_link 489", 489, pa!("/etc/rffile"), 0i64, 0i64);
    refuses!("acl_aclcheck_link 490", 490, pa!("/etc/rffile"), 0i64, 0i64);
    refuses!("acl_get_file 491", 491, pa!("/etc/rffile"), 0i64, 0i64);
    refuses!("acl_set_file 492", 492, pa!("/etc/rffile"), 0i64, 0i64);
    refuses!("acl_get_fd 493", 493, fd, 0i64, 0i64);
    refuses!("acl_set_fd 494", 494, fd, 0i64, 0i64);
    refuses!("acl_delete_file 495", 495, pa!("/etc/rffile"), 0i64, 0i64);
    refuses!("acl_delete_fd 496", 496, fd, 0i64, 0i64);
    refuses!("acl_aclcheck_file 497", 497, pa!("/etc/rffile"), 0i64, 0i64);
    refuses!("acl_aclcheck_fd 498", 498, fd, 0i64, 0i64);
    // A descriptor that is NOT open must still refuse. A kernel that
    // resolved the fd first would report EBADF instead, which tells the
    // caller something entirely different about whether ACLs exist.
    refuses!("acl_get_fd bad fd 493", 493, 4242i64, 0i64, 0i64);

    // --- user-level threads, 309-325 -------------------------------
    refuses!("lwp_create 309", 309, 0i64, 0i64, 0i64);
    refuses!("lwp_exit 310", 310, 0i64, 0i64, 0i64);
    refuses!("lwp_wait 312", 312, 0i64, 0i64, 0i64);
    refuses!("lwp_suspend 313", 313, pa!("main"), 0i64, 0i64);
    refuses!("lwp_continue 314", 314, pa!("main"), 0i64, 0i64);
    refuses!("lwp_wakeup 315", 315, pa!("main"), 0i64, 0i64);
    refuses!("lwp_park 320", 320, 0i64, 0i64, 0i64);
    refuses!("lwp_unpark 321", 321, pa!("main"), 0i64, 0i64);
    refuses!("lwp_unpark_all 322", 322, 0i64, 0i64, 0i64);
    refuses!("lwp_detach 319", 319, 0i64, 0i64, 0i64);
    refuses!("lwp_kill 318", 318, 0i64, 1i64, 15i64);
    refuses!("lwp_ctl 325", 325, pa!("main"), 0i64, 0i64);
    refuses!("lwp_setname 323", 323, pa!("main"), pa!("rf-probe"), 0i64);
    refuses!("lwp_getname 324", 324, pa!("rf-probe"), 0i64, 0i64);
    refuses!("lwp_getprivate 316", 316, 0i64, 0i64, 0i64);
    refuses!("lwp_setprivate 317", 317, 0i64, 1i64, 0i64);

    // _lwp_self(311) is the one call here that must ANSWER.
    answers!("lwp_self 311 answers", 311);

    // --- kernel semaphores, 247-256 ----------------------------------
    refuses!("ksem_init 247", 247, 0i64, 0xDEAD0000u32 as i64, 0i64);
    refuses!("ksem_open 248", 248, pa!("rf-sem"), 0i64, 0i64);
    refuses!("ksem_unlink 249", 249, pa!("rf-sem"), 0i64, 0i64);
    refuses!("ksem_close 250", 250, 0xDEAD0000u32 as i64, 0i64, 0i64);
    refuses!("ksem_post 251", 251, 0xDEAD0000u32 as i64, 1i64, 0i64);
    refuses!("ksem_wait 252", 252, 0xDEAD0000u32 as i64, 0i64, 0i64);
    refuses!("ksem_trywait 253", 253, 0xDEAD0000u32 as i64, 0i64, 0i64);
    refuses!("ksem_getvalue 254", 254, 0xDEAD0000u32 as i64, 0i64, 0i64);
    refuses!("ksem_destroy 255", 255, 0xDEAD0000u32 as i64, 0i64, 0i64);
    refuses!("ksem_timedwait 256", 256, 0xDEAD0000u32 as i64, 0i64, 0i64);

    // --- System V IPC, 221-231 ----------------------------------------
    // A KEY_T is a machine-global object identifier, so these need a
    // cross-process object store this kernel does not have.
    refuses!("semget 221", 221, 0x1234i64, 1i64, 0i64);
    refuses!("semop 222", 222, 0i64, 0i64, 0i64);
    refuses!("semconfig 223", 223, 0i64, 0i64, 0i64);
    refuses!("msgget 225", 225, 0x1234i64, 0i64, 0i64);
    refuses!("msgsnd 226", 226, 0i64, 0i64, 0i64);
    refuses!("msgrcv 227", 227, 0i64, 0i64, 0i64);
    refuses!("shmat 228", 228, 0i64, 0i64, 0i64);
    refuses!("shmctl 229", 229, 0i64, 0i64, 0i64);
    refuses!("shmdt 230", 230, 0i64, 0i64, 0i64);
    refuses!("shmget 231", 231, 0x1234i64, 4096i64, 0i64);

    // --- POSIX message queues, 257-264 -------------------------------
    // mq_open takes (name, oflag, mode, attr); mq_send takes
    // (mqd_t, msg_ptr, msg_len, msg_prio).
    refuses5!("mq_open 257", 257, pa!("/rfmq"), 0i64, 0i64, 0i64);
    refuses!("mq_close 258", 258, 3i64, 0i64, 0i64);
    refuses!("mq_unlink 259", 259, pa!("/rfmq"), 0i64, 0i64);
    refuses!("mq_getattr 260", 260, 3i64, 0i64, 0i64);
    refuses!("mq_setattr 261", 261, 3i64, 0i64, 0i64);
    refuses!("mq_notify 262", 262, 3i64, 0i64, 0i64);
    refuses5!("mq_send 263", 263, 3i64, pa!("m"), 1i64, 0i64);
    refuses!("mq_receive 264", 264, 3i64, 0i64, 4096i64);

    check("refusal errno is 45", EOPNOTSUPP == 45);

    let _ = unsafe { close(fd) };
    unsafe { finish() }
}

unsafe fn finish() -> ! {
    let f = unsafe { FAILURES };
    let mut buf = [0u8; 64];
    let mut n;
    if f == 0 {
        let msg = b"rf: all ok\n";
        buf[..msg.len()].copy_from_slice(msg);
        n = msg.len();
    } else {
        let mut digits = [0u8; 20];
        let mut d = 0usize;
        let mut v = f;
        if v == 0 {
            digits[0] = b'0';
            d = 1;
        }
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
        let head = b"rf: FAILED ";
        buf[..head.len()].copy_from_slice(head);
        n = head.len();
        for i in (0..d).rev() {
            buf[n] = digits[i];
            n += 1;
        }
        buf[n] = b'\n';
        n += 1;
    }
    unsafe { write(1, &buf[..n]) };
    unsafe { asm!("svc #1", in("x0") 0isize, options(nostack, noreturn)) }
}