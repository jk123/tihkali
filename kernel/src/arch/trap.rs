//! Trap frame, exception dispatch, syscall handling, and register dumps.

use crate::hal::gic;
use crate::netbsd_abi::nr as nbsys;
use crate::{kprint, kprintln};

use crate::arch::timer;

/// Saved exception context. Layout is coupled to `SAVE_FRAME`/`RESTORE_FRAME`
/// in trap.S — keep the two in sync.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
}

unsafe extern "C" {
    static vectors: u8; // opaque: address is what matters, not contents
}

pub fn init() {
    let v = core::ptr::addr_of!(vectors) as usize;
    unsafe { core::arch::asm!("msr vbar_el1, {0}", "isb", in(reg) v) }
}

fn read_far() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) v, options(nomem, nostack)) };
    v
}

/// Synchronous exception entry point (from EL0 or EL1).
/// Returns only for syscalls/resolved faults; fatal paths halt.
/// Pending-signal delivery runs before handing control back to asm.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sync_handler(frame: &mut TrapFrame) {
    let esr = frame.esr;
    match esr >> 26 {
        0x15 => svc_dispatch(frame), // SVC from AArch64
        0x20 | 0x21 => {
            // Instruction abort: nothing is mapped executable on demand.
            if frame.spsr & 0xf == 0 {
                // EL0: kill the offending process (SIGSEGV), keep the
            // kernel alive — a jumping-to-nowhere busybox must not
            // take the machine down.
            let sp: u64;
            unsafe {
                core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nomem, nostack));
            }
            kprintln!(
                "proc: pid {} insn fault at {:#x} esr={:#x} spsr={:#x} sp_el0={:#x} x8={:#x} x10={:#x} x13={:#x}",
                crate::proc::current_pid(),
                frame.elr,
                esr,
                frame.spsr,
                sp,
                frame.x[8],
                frame.x[10],
                frame.x[13]
            );
            {
                for i in 0..30 {
                    kprint!("x{i:<2}={:#018x} ", frame.x[i]);
                    if i % 4 == 3 {
                        kprintln!();
                    }
                }
                kprintln!();
            }
                crate::proc::kill_from_fault(frame, 11); // SIGSEGV (canonical 11)
            } else {
                kprintln!("exec fault at {:#x}", frame.elr);
                fatal(frame)
            }
        }
        0x24 | 0x25 => {
            // Data abort (lower or same EL): demand-zero / copy-on-write.
            let far = read_far() as usize;
            let is_write = (esr >> 6) & 1 == 1; // ISS.WnR (bit 6; bit 24 is ISV)
            let ttbr: u64;
            unsafe {
                core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nomem, nostack));
            }
            match crate::vm::handle_fault(ttbr as usize, far, is_write) {
                Ok(()) => {} // instruction retries (frame untouched)
                Err(msg) => {
                    if frame.spsr & 0xf == 0 {
                        // EL0 fault outside any arena: SIGSEGV the process.
                        kprintln!(
                            "proc: pid {} data fault {msg} (FAR={far:#x} ELR={:#x})",
                            crate::proc::current_pid(),
                            frame.elr
                        );
                        crate::proc::kill_from_fault(frame, 11); // SIGSEGV
                    } else {
                        kprintln!("unhandled data fault: {msg} (FAR={far:#x} WnR={is_write})");
                        fatal(frame)
                    }
                }
            }
        }
        _ => {
            if frame.spsr & 0xf == 0 {
                kprintln!(
                    "proc: pid {} unknown exception ESR={esr:#x} ELR={:#x}",
                    crate::proc::current_pid(),
                    frame.elr
                );
                crate::proc::kill_from_fault(frame, 4); // SIGILL (canonical 4)
            } else {
                fatal(frame)
            }
        }
    }
    // Boundary: svc returns, resolved faults, and any frame a syscall
    // switched to are all eligible for signal delivery. Network servicing
    // runs first so a recv/connect woken by a fresh packet re-runs in the
    // same trap exit (and anything still waiting is woken for the next
    // schedule).
    #[cfg(feature = "net")]
    crate::net::poll_tick();
    crate::proc::deliver_signals(frame);
}

/// Split the two syscall ABIs sharing `svc`:
///   Linux   = svc #0 with the number in x8   → linux_abi::svc
///   NetBSD  = svc #NR (NR never 0)           → immediate dispatch below
fn svc_dispatch(frame: &mut TrapFrame) {
    let imm = frame.esr & 0xffff;
    if imm == 0 {
        crate::linux_abi::svc(frame);
        return;
    }
    let nr = imm;
    let (result, err): (i64, u8) = match imm as u16 {
        nbsys::EXIT => {
            // SYS_exit(code)
            crate::proc::sys_exit(frame, frame.x[0]);
            return;
        }
        nbsys::FORK => match crate::proc::sys_fork(frame) {
            // SYS_fork: parent gets the child pid, child (later) gets 0
            Ok(pid) => (pid as i64, 0),
            Err(crate::proc::ForkError::NoMem) => (-1, crate::proc::ENOMEM),
        },
        nbsys::READ => {
            // SYS_read(fd, buf, len): tty-in sleeps, files read through.
            match crate::proc::sys_read(frame, frame.x[0] as usize, frame.x[1], frame.x[2] as usize)
            {
                crate::proc::Io::Val(n) => (n, 0),
                crate::proc::Io::Err(e) => (-1, e),
                crate::proc::Io::Slept => return,
            }
        }
        nbsys::WRITE => match crate::proc::sys_write(frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Ok(n) => (n, 0),
            Err(e) => (-1, e),
        },
        nbsys::OPEN => {
            // SYS_open(path, flags): O_RDONLY only (read-only initramfs).
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_open(&path, frame.x[1]) {
                    Ok(fd) => (fd as i64, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        nbsys::CLOSE => match crate::proc::sys_close(frame.x[0] as usize) {
            Ok(()) => (0, 0),
            Err(e) => (-1, e),
        },
        nbsys::GETPID_WITH_PPID => (crate::proc::current_pid() as i64, 0), // SYS_getpid
        nbsys::EXECVE => {
            // SYS_execve(path, argv)
            match crate::proc::sys_execve(frame, frame.x[0], frame.x[1]) {
                Ok(()) => return, // frame rebuilt: enter the new image
                Err(e) => (-1, e),
            }
        }
        nbsys::UNLINK => {
            // SYS_unlink(path)
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_unlink(&path) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        nbsys::SYNC => match crate::proc::sys_sync() {
            // SYS_sync: write-back dirty nodes
            Ok(()) => (0, 0),
            Err(e) => (-1, e),
        },
        // --- memory ---
        //
        // NetBSD's mmap takes SEVEN register slots, not Linux's six:
        //   mmap(void *addr, size_t len, int prot, int flags,
        //        int fd, long PAD, off_t pos)
        // x5 is a padding word and x6 is the offset, so `pos` is NOT x5
        // the way Linux has it. Anonymous mappings only (v1), same as the
        // Linux arm: no fd, no file backing, no MAP_FIXED.
        //
        // MAP_ANONYMOUS is 0x1000 on NetBSD (sys/mman.h) -- NOT the Linux
        // 0x20. Using the Linux value here rejects every mmap outright.
        nbsys::MMAP__2 => {
            const MAP_ANON_N: u64 = 0x1000;
            if frame.x[3] & MAP_ANON_N == 0 {
                (-1, 78) // ENOSYS: file-backed mmap is not implemented
            } else if frame.x[0] != 0 {
                (-1, 22) // EINVAL: MAP_FIXED-style hint requests unsupported
            } else {
                match crate::proc::sys_mmap(frame.x[1]) {
                    Ok(base) => (base as i64, 0),
                    Err(e) => (-1, e),
                }
            }
        }
        nbsys::MUNMAP => match crate::proc::sys_munmap(frame.x[0], frame.x[1]) {
            Ok(()) => (0, 0),
            Err(e) => (-1, e),
        },
        nbsys::MPROTECT => {
            // prot is a NetBSD PROT_* bitmask; PROT_NONE is 0 and clears
            // everything, which vm::set_perms already handles.
            match crate::proc::sys_mprotect(frame.x[0], frame.x[1], frame.x[2]) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::MADVISE => (0, 0), // advice-only; always succeeds
        nbsys::MSYNC => (0, 0),  // no swap, nothing to write back
        // --- file metadata ---
        //
        // NetBSD's struct stat is 152 bytes with st_size at offset 112;
        // the Linux one is 128 bytes with st_size at 48. The writer in
        // netbsd_abi::write_stat_node carries the verified offsets --
        // do not reuse the Linux fill_stat here.
        nbsys::STAT | nbsys::LSTAT => {
            // SYS_stat(path, buf) / SYS_lstat(path, buf)
            // lstat does not follow a final symlink; stat does.
            let follow = imm == nbsys::STAT as u64;
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => {
                    // A relative path resolves against the cwd; before
                    // chdir existed this was passed through raw.
                    let abs = crate::proc::abspath(&path);
                    let idx = if follow {
                        crate::fs::lookup(&abs)
                    } else {
                        crate::fs::lookup_nofollow(&abs)
                    };
                    match idx {
                        None => (-1, crate::file::ENOENT),
                        Some(i) => match crate::netbsd_abi::write_stat_node(frame.x[1], i) {
                            Ok(()) => (0, 0),
                            Err(e) => (-1, e),
                        },
                    }
                }
            }
        }
        nbsys::FSTAT => {
            // SYS_fstat(fd, buf)
            match crate::netbsd_abi::write_stat_fd(frame.x[1], frame.x[0] as usize) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::LSEEK => {
            // SYS_lseek(fd, offset, whence). file::lseek indexes the open-
            // file TABLE, so it wants the table index, not the node index
            // node_of_fd returns -- passing the node panics.
            match crate::proc::current_target(frame.x[0] as usize) {
                Some(crate::file::FdTarget::File(i)) => {
                    match crate::file::lseek(i, frame.x[1] as i64, frame.x[2] as u32) {
                        Ok(off) => (off, 0),
                        Err(e) => (-1, e),
                    }
                }
                _ => (-1, crate::file::EBADF),
            }
        }
        nbsys::READLINK => {
            // SYS_readlink(path, buf, bufsiz): no NUL appended, and a
            // short buffer truncates rather than failing.
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14),
                Some(path) => match crate::fs::lookup_nofollow(&crate::proc::abspath(&path)) {
                    None => (-1, crate::file::ENOENT),
                    Some(idx) => {
                        if !crate::fs::is_symlink(idx) {
                            (-1, crate::file::EINVAL) // EINVAL on non-symlink
                        } else {
                            let bufsiz = frame.x[2] as usize;
                            match crate::fs::with_bytes(idx, |b: &[u8]| {
                                let n = b.len().min(bufsiz);
                                if n > 0 {
                                    if !crate::proc::user_range_ok(frame.x[1], n) {
                                        return None;
                                    }
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            b.as_ptr(),
                                            frame.x[1] as *mut u8,
                                            n,
                                        );
                                    }
                                }
                                Some(n)
                            }) {
                                None => (-1, 14),
                                Some(n) => (n as i64, 0),
                            }
                        }
                    }
                },
            }
        }
        nbsys::GETPAGESIZE => (4096, 0),
        // --- vectored I/O ---
        //
        // NetBSD's struct iovec is { void*, size_t } — the same 16 bytes
        // Linux uses — so only the numbers differ (NetBSD 120/121 vs
        // Linux 65/66). Both stop at the first error and return the
        // bytes already transferred, which is what a short write means.
        nbsys::READV => {
            // SYS_readv(fd, iov, iovcnt). A blocking tty read must not
            // report EOF, so the walker signals Slept by returning early
            // through a sentinel the arm turns into a bare return.
            match crate::netbsd_abi::walk_iovecs(frame.x[1], frame.x[2]) {
                Err(e) => (-1, e), // EINVAL or EFAULT
                Ok(iovs) => {
                    let mut total: i64 = 0;
                    let mut err: Option<u8> = None;
                    for (base, len) in iovs {
                        if len == 0 {
                            continue;
                        }
                        match crate::proc::sys_read(
                            frame,
                            frame.x[0] as usize,
                            base,
                            len as usize,
                        ) {
                            crate::proc::Io::Val(n) => {
                                total += n;
                                // Short read: the caller's vectors are full.
                                if (n as u64) < len {
                                    break;
                                }
                            }
                            crate::proc::Io::Err(e) => {
                                err = Some(e);
                                break;
                            }
                            // A blocking tty read slept; the epilogue must
                            // not run, so signal it with a bare return.
                            crate::proc::Io::Slept => return,
                        }
                    }
                    match err {
                        // Report the bytes already read, not -1: POSIX says
                        // a partial read must not be lost to the errno.
                        Some(e) => (total, e),
                        None => (total, 0),
                    }
                }
            }
        }
        nbsys::WRITEV => {
            // SYS_writev(fd, iov, iovcnt)
            match crate::netbsd_abi::walk_iovecs(frame.x[1], frame.x[2]) {
                Err(e) => (-1, e),
                Ok(iovs) => {
                    let mut total: i64 = 0;
                    let mut err: Option<u8> = None;
                    for (base, len) in iovs {
                        if len == 0 {
                            continue;
                        }
                        match crate::proc::sys_write(frame.x[0] as usize, base, len as usize) {
                            Ok(n) => total += n,
                            // Stop at the first error but keep the count:
                            // the bytes already written really were written.
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }
                    match err {
                        Some(e) => (total, e),
                        None => (total, 0),
                    }
                }
            }
        }
        // --- kqueue ---
        nbsys::KQUEUE => {
            // SYS_kqueue(): hand back a descriptor for this process's
            // registration list. There is no descriptor pool for it here --
            // one list per process -- so the fd is a marker, not a real
            // kernel object, and every process gets the same number.
            match crate::proc::install_fd(crate::file::FdTarget::Kqueue) {
                Ok(fd) => (fd as i64, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::KEVENT => {
            // SYS_kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
            match crate::netbsd_abi::kevent_arm(frame) {
                crate::proc::Io::Val(n) => (n, 0),
                crate::proc::Io::Err(e) => (-1, e),
                crate::proc::Io::Slept => return,
            }
        }
        // --- socket identity ---
        #[cfg(feature = "net")]
        nbsys::GETPEERNAME => {
            // SYS_getpeername(fd, sockaddr, socklen_t *addrlen)
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => match crate::net::sock_peer_addr(slot) {
                    // ENOTCONN, not a zeroed address: a caller that ignored
                    // the error would otherwise believe it is talking to
                    // 0.0.0.0:0.
                    None => (-1, 57),
                    Some((ip, port)) => {
                        crate::net::write_netbsd_sockaddr_out(frame.x[1], frame.x[2], ip, port);
                        (0, 0)
                    }
                },
            }
        }
        #[cfg(feature = "net")]
        nbsys::GETSOCKNAME => {
            // SYS_getsockname(fd, sockaddr, socklen_t *addrlen)
            // Unlike getpeername this always succeeds: an unbound socket
            // reports 0.0.0.0:0.
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => {
                    let (ip, port) = crate::net::sock_local_addr(slot);
                    crate::net::write_netbsd_sockaddr_out(frame.x[1], frame.x[2], ip, port);
                    (0, 0)
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::SOCKETPAIR => {
            // SYS_socketpair(domain, type, protocol, fdp[2]): x3 holds fdp.
            //
            // Unsupported for both domains, for the reasons spelled out in
            // net::sock_pair: smoltcp has no unix-socket transport, and the
            // AF_INET loopback substitute cannot complete a handshake
            // inside a syscall. The arm delegates rather than pre-checking
            // the domain, so there is one place that decides the answer.
            crate::net::sock_pair(frame.x[3], frame.x[1] as i64)
        }
        // --- descriptor duplication and control ---
        nbsys::DUP => {
            // SYS_dup(fd): lowest free descriptor, sharing the file.
            match crate::proc::sys_dupfd(frame.x[0] as i64, 0) {
                Ok(n) => (n as i64, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::DUP2 => {
            // SYS_dup2(oldfd, newfd): force onto newfd, closing whatever
            // was there. dup3(old,new,0) already implements this, including
            // the oldfd == newfd no-op.
            match crate::proc::sys_dup3(frame.x[0] as i64, frame.x[1] as i64) {
                Ok(n) => (n as i64, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::FCNTL => {
            // SYS_fcntl(fd, cmd, arg)
            //
            // NetBSD's O_* file-status flags are the POSIX values, not
            // Linux's: O_NONBLOCK is 0x4 here and 0x800 in asm-generic, and
            // O_WRONLY/O_RDWR are 1/2 in both. Passing NetBSD's bit to the
            // socket layer unchanged would silently do nothing, since the
            // stored flag is the Linux one -- so the two are translated.
            match frame.x[1] as i64 {
                0 => match crate::proc::sys_dupfd(frame.x[0] as i64, frame.x[2] as i64) {
                    Ok(n) => (n as i64, 0), // F_DUPFD
                    Err(e) => (-1, e),
                },
                1 | 2 => (0, 0), // F_GETFD / F_SETFD: no cloexec tracking
                3 => match crate::proc::current_target(frame.x[0] as usize) {
                    // F_GETFL
                    Some(crate::file::FdTarget::File(i)) => match crate::file::is_writable(i) {
                        Ok(true) => (2, 0), // O_RDWR
                        Ok(false) => (1, 0), // O_WRONLY
                        Err(e) => (-1, e),
                    },
                    Some(crate::file::FdTarget::Socket(s)) => {
                        #[cfg(feature = "net")]
                        {
                            // Report NetBSD's 0x4, not the stored Linux bit.
                            if crate::net::sock_is_nonblock(s) {
                                (0x4, 0)
                            } else {
                                (0, 0)
                            }
                        }
                        #[cfg(not(feature = "net"))]
                        {
                            let _ = s;
                            (0, 0)
                        }
                    }
                    None => (-1, crate::file::EBADF),
                    _ => (0, 0), // TtyIn/TtyOut/Pipe: no flags tracked
                },
                4 => {
                    // F_SETFL: O_NONBLOCK is load-bearing -- musl's resolver
                    // polls a non-blocking UDP socket and expects EAGAIN.
                    match crate::proc::current_target(frame.x[0] as usize) {
                        Some(crate::file::FdTarget::Socket(s)) => {
                            #[cfg(feature = "net")]
                            crate::net::sock_set_nonblock(s, frame.x[2] & 0x4 != 0);
                            #[cfg(not(feature = "net"))]
                            {
                                let _ = (s, frame.x[2]);
                            }
                            (0, 0)
                        }
                        _ => (0, 0),
                    }
                }
                12 => match crate::proc::sys_dupfd(frame.x[0] as i64, frame.x[2] as i64) {
                    // F_DUPFD_CLOEXEC (12 on NetBSD, 1030 on Linux)
                    Ok(n) => (n as i64, 0),
                    Err(e) => (-1, e),
                },
                _ => (-1, 22), // EINVAL: unknown command
            }
        }
        // --- working directory and path operations ---
        //
        // NetBSD has no plain `getcwd`: the call was folded into the
        // compat-only __getcwd (296). Both numbers dispatch the same
        // body, so either spelling works.
        nbsys::__GETCWD => {
            // SYS___getcwd(bufp, length). POSIX truncation semantics: if
            // the buffer is too small return ERANGE, and do NOT write a
            // partial path -- a caller that ignores the error would
            // otherwise act on half a path.
            let len = frame.x[1] as usize;
            let cwd = crate::proc::cwd();
            // +1 for the NUL, which getcwd must include in the length.
            if len <= cwd.len() {
                (-1, 34) // ERANGE
            } else if !crate::proc::user_range_ok(frame.x[0], cwd.len() + 1) {
                (-1, 14)
            } else {
                unsafe {
                    let p = frame.x[0] as *mut u8;
                    core::ptr::copy_nonoverlapping(cwd.as_ptr(), p, cwd.len());
                    p.add(cwd.len()).write(0);
                }
                (cwd.len() as i64 + 1, 0)
            }
        }
        nbsys::CHDIR => {
            // SYS_chdir(path): must name a directory.
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14),
                Some(path) => {
                    let abs = crate::proc::abspath(&path);
                    match crate::fs::lookup(&abs) {
                        None => (-1, crate::file::ENOENT),
                        Some(idx) => {
                            if !crate::fs::is_dir(idx) {
                                (-1, crate::file::ENOTDIR)
                            } else {
                                crate::proc::set_cwd(&abs);
                                (0, 0)
                            }
                        }
                    }
                }
            }
        }
        nbsys::RENAME => {
            // SYS_rename(from, to). Both resolve against the cwd; the
            // NetBSD signature carries no dirfd.
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14),
                Some(from) => match crate::proc::read_user_cstr(frame.x[1], 128) {
                    None => (-1, 14),
                    Some(to) => {
                        match crate::fs::rename(
                            &crate::proc::abspath(&from),
                            &crate::proc::abspath(&to),
                        ) {
                            Ok(()) => (0, 0),
                            Err(e) => (-1, e),
                        }
                    }
                },
            }
        }
        nbsys::CHMOD => {
            // SYS_chmod(path, mode). Only permission bits are stored; the
            // S_IF* type bits in `mode` are ignored, as POSIX requires.
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14),
                Some(path) => match crate::fs::lookup(&crate::proc::abspath(&path)) {
                    None => (-1, crate::file::ENOENT),
                    Some(idx) => match crate::fs::set_mode(idx, frame.x[1] as u16) {
                        Ok(()) => (0, 0),
                        Err(e) => (-1, e),
                    },
                },
            }
        }
        nbsys::ACCESS => {
            // SYS_access(path, mode): the fs is a readable initramfs, so
            // mode is advisory -- existence is the only real question.
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14),
                Some(path) => match crate::fs::lookup(&crate::proc::abspath(&path)) {
                    None => (-1, crate::file::ENOENT),
                    Some(_) => (0, 0),
                },
            }
        }
        // --- process identity / credentials ---
        nbsys::GETPPID => {
            // SYS_getppid(). Distinct from GETPID_WITH_PPID (20), which
            // merges getpid and getppid onto one number; aarch64 NetBSD
            // keeps a separate getppid at 39.
            (crate::proc::current_ppid(), 0)
        }
        nbsys::FTRUNCATE => {
            // SYS_ftruncate(fd, length): by descriptor, so no path lookup
            // and no cwd involvement. Refuses a read-only descriptor rather
            // than silently truncating -- a caller that ignored the error
            // would believe it had shortened the file.
            match crate::file::fd_is_writable(frame.x[0] as usize) {
                Err(e) => (-1, e),
                Ok(idx) => {
                    let len = frame.x[1];
                    if len > i64::MAX as u64 {
                        (-1, 22) // EINVAL
                    } else {
                        match crate::fs::set_len(idx, len as usize) {
                            Ok(()) => (0, 0),
                            Err(e) => (-1, e),
                        }
                    }
                }
            }
        }
        nbsys::TRUNCATE => {
            // SYS_truncate(path, length)
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14),
                Some(path) => match crate::fs::lookup(&crate::proc::abspath(&path)) {
                    None => (-1, crate::file::ENOENT),
                    Some(idx) => {
                        let len = frame.x[1];
                        if len > i64::MAX as u64 {
                            (-1, 22)
                        } else {
                            match crate::fs::set_len(idx, len as usize) {
                                Ok(()) => (0, 0),
                                Err(e) => (-1, e),
                            }
                        }
                    }
                },
            }
        }
        nbsys::UNAME => {
            // SYS_uname(buf): NetBSD's struct utsname is five 256-byte
            // char arrays = 1280 bytes, with no padding and no fields Linux
            // has. The Linux arm writes 390 bytes of a different layout.
            if !crate::proc::user_range_ok(frame.x[0], crate::netbsd_abi::UTSNAME_SIZE) {
                (-1, 14)
            } else {
                crate::netbsd_abi::write_utsname(frame.x[0]);
                (0, 0)
            }
        }
        // --- process / credential ---
        //
        // NetBSD merges these into single numbered calls: getuid+geteuid
        // share 24 and getgid+getegid share 47, exactly as getpid+getppid
        // share 20. Single user, so both return 0.
        nbsys::GETUID_WITH_EUID => (0, 0),
        nbsys::GETGID_WITH_EGID => (0, 0),
        nbsys::UMASK => (0, 0), // never changes
        // --- time ---
        //
        // NetBSD's timeval and timespec are both { long, long } on aarch64,
        // identical to Linux's, so only the syscall numbers differ.
        nbsys::GETTIMEOFDAY => {
            // SYS_gettimeofday(tv, tz): tv is required, tz never written.
            if frame.x[0] == 0 {
                (-1, 22) // EINVAL
            } else if !crate::proc::user_range_ok(frame.x[0], 16) {
                (-1, 14)
            } else {
                let (mut sec, nsec) = crate::linux_abi::now_parts();
                sec += 1_700_000_000;
                unsafe {
                    let p = frame.x[0] as *mut i64;
                    p.write_unaligned(sec);
                    p.add(1).write_unaligned(nsec / 1000); // timeval is usec
                }
                (0, 0)
            }
        }
        nbsys::CLOCK_GETTIME => {
            // SYS_clock_gettime(clockid, tp): REALTIME(0) and MONOTONIC(1).
            let id = frame.x[0] as i64;
            if id > 1 {
                (-1, 22) // EINVAL
            } else if !crate::proc::user_range_ok(frame.x[1], 16) {
                (-1, 14)
            } else {
                let (mut sec, nsec) = crate::linux_abi::now_parts();
                if id == 0 {
                    sec += 1_700_000_000;
                }
                unsafe {
                    let p = frame.x[1] as *mut i64;
                    p.write_unaligned(sec);
                    p.add(1).write_unaligned(nsec);
                }
                (0, 0)
            }
        }
        nbsys::NANOSLEEP => {
            // SYS_nanosleep(req, rem): relative sleep with EINTR on signal.
            // Same deadline machinery as the Linux arm -- the process is
            // parked, not spun, so a signal can still interrupt it.
            match crate::linux_abi::nanosleep_netbsd(frame, frame.x[0], frame.x[1]) {
                crate::proc::Io::Val(n) => (n, 0),
                crate::proc::Io::Err(e) => (-1, e),
                crate::proc::Io::Slept => return,
            }
        }
        nbsys::MKDIR => {
            // SYS_mkdir(path, mode)
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_mkdir(&path) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        nbsys::RMDIR => {
            // SYS_rmdir(path)
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_rmdir(&path) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        nbsys::KILL => {
            // SYS_kill(pid, sig)
            match crate::proc::sys_kill(frame.x[0] as i64, frame.x[1]) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::SETITIMER => {
            // SYS_compat_50_setitimer(which, new, old): ITIMER_REAL only.
            // NetBSD aarch64 struct itimerval = { it_interval, it_value },
            // each a { time_t tv_sec; suseconds_t tv_usec } of 8 bytes
            // (sys/sys/time.h) — identical to the Linux/musl layout:
            // it_interval at +0, it_value at +16, 32 bytes total.
            let which = frame.x[0] as i32;
            let new = frame.x[1];
            let old = frame.x[2];
            // Zero the old out-param (32 bytes) if non-null and in range.
            if old != 0 && crate::proc::user_range_ok(old, 32) {
                unsafe {
                    (old as *mut u8).write_bytes(0, 32);
                }
            }
            if which != 0 {
                // Not ITIMER_REAL: accept and ignore (v1).
                (0, 0)
            } else if new == 0 {
                // Null new = disarm.
                crate::proc::proc_set_itimer(crate::proc::current_slot(), None, None);
                (0, 0)
            } else if !crate::proc::user_range_ok(new, 32) {
                (-1, 14) // EFAULT
            } else {
                let rd = |off: usize| unsafe {
                    (new as *const u64).add(off / 8).read_unaligned() as u64
                };
                let sec = rd(16);
                let usec = rd(24);
                let isec = rd(0);
                let iusec = rd(8);
                if sec == 0 && usec == 0 {
                    crate::proc::proc_set_itimer(crate::proc::current_slot(), None, None);
                } else {
                    let ticks = crate::proc::arch_timer_hz();
                    let to_ticks = |s: u64, us: u64| s * ticks + us * ticks / 1_000_000;
                    let deadline =
                        crate::proc::arch_timer_now() + to_ticks(sec, usec);
                    let iv = to_ticks(isec, iusec);
                    crate::proc::proc_set_itimer(
                        crate::proc::current_slot(),
                        Some(deadline),
                        Some(iv),
                    );
                }
                (0, 0)
            }
        }
        nbsys::SIGRETURN | nbsys::SIGRETURN__2 => {
            // SYS_sigreturn / __sigreturn14: frame fully rebuilt.
            crate::proc::sys_sigreturn(frame);
            return;
        }
        nbsys::__SIGACTION_SIGTRAMP => {
            // SYS___sigaction_sigtramp(sig, act, oact, sigtramp, sz)
            match crate::proc::sys_sigaction(frame.x[0], frame.x[1], frame.x[2]) {
                Ok(old) => (old as i64, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::GETDENTS__2 => {
            // SYS___getdents30(fd, buf, len)
            match crate::proc::sys_getdents(frame.x[0] as usize, frame.x[1], frame.x[2] as usize)
            {
                Ok(n) => (n as i64, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::SIGPROCMASK__2 => {
            // SYS___sigprocmask14(how, set, oset)
            match crate::proc::sys_sigprocmask(frame.x[0] as i64, frame.x[1], frame.x[2]) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        nbsys::WAIT4__2 => {
            // SYS___wait450(pid, status, options, rusage)
            match crate::proc::sys_wait4(frame, frame.x[0] as i64, frame.x[1], frame.x[2]) {
                crate::proc::Wait4::Done(pid) => (pid, 0),
                crate::proc::Wait4::Slept => return,
                crate::proc::Wait4::Err(e) => (-1, e),
            }
        }
        #[cfg(feature = "qemu-virt")]
        crate::netbsd_abi::fb::INFO => {
            // tihkali: fb_fb_info(out) -> {width, height, stride, pa}
            match crate::fb::sys_fb_info(frame.x[0]) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        #[cfg(feature = "qemu-virt")]
        crate::netbsd_abi::fb::FILL_RECT => {
            // tihkali: fb_fill_rect(x, y, w, h, rgb)
            match crate::fb::sys_fill_rect(
                frame.x[0] as u32,
                frame.x[1] as u32,
                frame.x[2] as u32,
                frame.x[3] as u32,
                frame.x[4] as u32,
            ) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        #[cfg(feature = "qemu-virt")]
        crate::netbsd_abi::fb::BLIT => {
            // tihkali: fb_blit(src, x, y, w, h, src_stride)
            match crate::fb::sys_blit(
                frame.x[0],
                frame.x[1] as u32,
                frame.x[2] as u32,
                frame.x[3] as u32,
                frame.x[4] as u32,
                frame.x[5] as u32,
            ) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        #[cfg(feature = "net")]
        394 | 97 => {
            // SYS___socket30 / SYS_compat_30_socket (domain, type, proto)
            match crate::net::socket_kind(
                (frame.x[1] & 0xf) as u32,
                frame.x[2] as u32,
            ) {
                None => (-1, crate::net::EAFNOSUPPORT),
                Some(kind) => match crate::net::sock_open(kind) {
                    Ok(slot) => match crate::proc::install_fd(
                        crate::file::FdTarget::Socket(slot),
                    ) {
                        Ok(fd) => (fd as i64, 0),
                        Err(e) => {
                            crate::net::sock_ref_dec(slot);
                            (-1, e)
                        }
                    },
                    Err(e) => (-1, e),
                },
            }
        }
        #[cfg(feature = "net")]
        nbsys::CONNECT => {
            // SYS_connect(fd, sockaddr, addrlen): blocking on TCP — each
            // wake re-enters the state machine (same contract as Linux 203).
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => {
                    match crate::net::parse_netbsd_sockaddr_in(frame.x[1], frame.x[2]) {
                        Err(e) => (-1, e),
                        Ok((ip, port)) => {
                            crate::net::poll_tick();
                            match crate::net::sock_connect(slot, ip, port) {
                                Err(e) => (-1, e),
                                Ok(crate::net::Conn::Done) => (0, 0),
                                Ok(crate::net::Conn::Failed) => {
                                    (-1, crate::net::ECONNREFUSED)
                                }
                                Ok(crate::net::Conn::Progress) => {
                                    if crate::proc::has_deliverable() {
                                        (-1, 4) // EINTR
                                    } else {
                                        crate::proc::sleep_current(frame);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::LISTEN => {
            // SYS_listen(fd, backlog)
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => match crate::net::sock_listen(slot, frame.x[1] as i32) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        #[cfg(feature = "net")]
        nbsys::ACCEPT => {
            // SYS_accept(fd, laddr, laddrp): blocking, mirrors Linux 202.
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => {
                    crate::net::poll_tick();
                    match crate::net::sock_accept(slot) {
                        Err(e) => (-1, e),
                        Ok(crate::net::Acc::Done((peer, data_slot))) => {
                            if frame.x[1] != 0 && crate::proc::user_range_ok(frame.x[1], 16) {
                                crate::net::write_netbsd_sockaddr_out(
                                    frame.x[1],
                                    frame.x[2],
                                    peer.0,
                                    peer.1,
                                );
                            }
                            // smoltcp serves one connection per socket: the
                            // accepted connection lives in `data_slot`. Hand
                            // the caller a *fresh fd* for it; the listening
                            // slot keeps listening for the next peer.
                            match crate::proc::install_fd(crate::file::FdTarget::Socket(
                                data_slot,
                            )) {
                                Ok(newfd) => {
                                    crate::net::sock_ref_inc(data_slot);
                                    (newfd as i64, 0)
                                }
                                Err(e) => {
                                    crate::net::sock_ref_dec(data_slot);
                                    (-1, e)
                                }
                            }
                        }
                        Ok(crate::net::Acc::Progress) => {
                            if crate::proc::has_deliverable() {
                                (-1, 4) // EINTR
                            } else {
                                crate::proc::sleep_current(frame);
                                return;
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::SHUTDOWN => {
            // SYS_shutdown(fd, how)
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => match crate::net::sock_shutdown(slot, frame.x[1] as i32) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        #[cfg(feature = "net")]
        nbsys::SENDMSG => {
            // SYS_sendmsg(fd, msg, flags): scatter into one send.
            // `frame.x[1]` is the msghdr: msg_iov at byte 16,
            // msg_iovlen (u32) at byte 28 on NetBSD aarch64 — the pad after
            // msg_iov makes it differ from Linux's byte 24. Do NOT share.
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => {
                    let msg = frame.x[1];
                    if msg == 0 || !crate::proc::user_range_ok(msg, 32) {
                        (-1, 14) // EFAULT
                    } else {
                        let iov = unsafe { (msg as *const u64).add(2).read_unaligned() };
                        let iovlen =
                            unsafe { (msg as *const u32).add(7).read_unaligned() as usize };
                        match crate::net::sock_sendmsg(slot, iov, iovlen) {
                            Ok(n) => (n as i64, 0),
                            Err(e) => (-1, e),
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::RECVMSG => {
            // SYS_recvmsg(fd, msg, flags): one coalesced recv.
            // Same msghdr offsets as arm 28 (msg_iov @16, msg_iovlen @28).
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => {
                    let msg = frame.x[1];
                    if msg == 0 || !crate::proc::user_range_ok(msg, 32) {
                        (-1, 14) // EFAULT
                    } else {
                        let iov = unsafe { (msg as *const u64).add(2).read_unaligned() };
                        let iovlen =
                            unsafe { (msg as *const u32).add(7).read_unaligned() as usize };
                        let mut src = ([0u8; 4], 0u16);
                        let res = if iovlen == 0 {
                            Ok(0)
                        } else {
                            crate::net::sock_recvmsg(slot, iov, iovlen, Some(&mut src))
                        };
                        match res {
                            Ok(n) => {
                                if n > 0 {
                                    crate::net::service_iface();
                                }
                                (n as i64, 0)
                            }
                            Err(crate::net::EAGAIN_L) => {
                                crate::proc::sleep_current(frame);
                                return;
                            }
                            Err(e) => (-1, e),
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::BIND => {
            // SYS_bind(fd, sockaddr, addrlen)
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (-1, crate::file::EBADF),
                Some(slot) => match crate::net::parse_netbsd_sockaddr_in(frame.x[1], frame.x[2]) {
                    Err(e) => (-1, e),
                    Ok((ip, port)) => match crate::net::sock_bind(slot, ip, port) {
                        Ok(()) => (0, 0),
                        Err(e) => (-1, e),
                    },
                },
            }
        }
        #[cfg(feature = "net")]
        nbsys::SETSOCKOPT => {
            // SYS_setsockopt(fd, level, name, value, len)
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (0, crate::file::EBADF),
                Some(slot) => {
                    if frame.x[1] as i32 != crate::net::SOL_SOCKET_N {
                        (0, 0) // unknown level: lenient
                    } else {
                        match crate::net::netbsd_opt(frame.x[2] as i32) {
                            None => (0, 0),
                            Some(opt) => {
                                match crate::net::sock_setopt(
                                    slot,
                                    opt,
                                    frame.x[3],
                                    frame.x[4] as usize,
                                ) {
                                    Ok(()) => (0, 0),
                                    Err(e) => (0, e),
                                }
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::GETSOCKOPT => {
            // SYS_getsockopt(fd, level, name, value, len*)
            match crate::net::sock_slot(frame.x[0] as usize) {
                None => (0, crate::file::EBADF),
                Some(slot) => {
                    if frame.x[1] as i32 != crate::net::SOL_SOCKET_N {
                        (0, 0)
                    } else {
                        match crate::net::netbsd_opt(frame.x[2] as i32) {
                            None => {
                                let optlen_ptr = frame.x[4];
                                if optlen_ptr != 0 && crate::proc::user_range_ok(optlen_ptr, 4) {
                                    unsafe {
                                        (optlen_ptr as *mut u32).write_unaligned(0);
                                    }
                                }
                                (0, 0)
                            }
                            Some(opt) => {
                                match crate::net::sock_getopt(
                                    slot,
                                    opt,
                                    frame.x[3],
                                    frame.x[4],
                                ) {
                                    Ok(()) => (0, 0),
                                    Err(e) => (0, e),
                                }
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::SENDTO => {
            // SYS_sendto(fd, buf, len, flags, to, tolen)
            let len = frame.x[2] as usize;
            if len == 0 {
                (0, 0)
            } else if !crate::proc::user_range_ok(frame.x[1], len) {
                (-1, 14) // EFAULT
            } else {
                match crate::net::sock_slot(frame.x[0] as usize) {
                    None => (-1, crate::file::EBADF),
                    Some(slot) => {
                        let bytes = unsafe {
                            core::slice::from_raw_parts(frame.x[1] as *const u8, len)
                        };
                        // NULL dest → the connected peer; raw/ICMP sockets
                        // send datagram-style to that peer, TCP/UDP to queue.
                        if frame.x[4] == 0 {
                            if crate::net::sock_kind_is_raw(slot) {
                                match crate::net::sock_send_raw(slot, bytes) {
                                    Ok(n) => (n as i64, 0),
                                    Err(e) => (-1, e),
                                }
                            } else {
                                match crate::net::sock_send(slot, bytes) {
                                    Ok(n) => (n as i64, 0),
                                    Err(e) => (-1, e),
                                }
                            }
                        } else {
                            match crate::net::parse_netbsd_sockaddr_in(frame.x[4], frame.x[5]) {
                                Err(e) => (-1, e),
                                Ok((ip, port)) => {
                                    match crate::net::sock_send_to(slot, bytes, ip, port) {
                                        Ok(n) => (n as i64, 0),
                                        Err(e) => (-1, e),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        nbsys::RECVFROM => {
            // SYS_recvfrom(fd, buf, len, flags, from, fromlen): blocking.
            let len = frame.x[2] as usize;
            if len == 0 {
                (0, 0)
            } else if !crate::proc::user_range_ok(frame.x[1], len) {
                (-1, 14) // EFAULT
            } else {
                match crate::net::sock_slot(frame.x[0] as usize) {
                    None => (-1, crate::file::EBADF),
                    Some(slot) => {
                        if crate::proc::has_deliverable() {
                            (-1, 4) // EINTR
                        } else {
                            let want_from = frame.x[4] != 0;
                            let mut src = ([0u8; 4], 0u16);
                            let user = unsafe {
                                core::slice::from_raw_parts_mut(frame.x[1] as *mut u8, len)
                            };
                            let from = if want_from { Some(&mut src) } else { None };
                            match crate::net::sock_recv(slot, user, from) {
                                Ok(n) => {
                                    if want_from {
                                        crate::net::write_netbsd_sockaddr_out(
                                            frame.x[4],
                                            frame.x[5],
                                            src.0,
                                            src.1,
                                        );
                                    }
                                    (n as i64, 0)
                                }
                                Err(crate::net::EAGAIN_L) => {
                                    crate::proc::sleep_current(frame);
                                    return;
                                }
                                Err(e) => (-1, e),
                            }
                        }
                    }
                }
            }
        }
        _ => {
            kprintln!("[user] unknown syscall {nr} at ELR {:#x}", frame.elr);
            (-1, 78) // ENOSYS
        }
    };

    frame.x[0] = result as u64;
    // Error convention: PSTATE.C=1 + positive errno in x0 (NetBSD cerror).
    if err != 0 {
        frame.spsr |= 1 << 29;
        frame.x[0] = err as u64;
    } else {
        frame.spsr &= !(1 << 29);
    }
    // No ELR adjustment: AArch64 SVC's preferred return address already
    // points at the instruction following the svc (same as Linux/NetBSD).
}

/// Unexpected synchronous exception: dump everything we know, then halt.
fn fatal(frame: &mut TrapFrame) -> ! {
    let esr = frame.esr;
    let ec = esr >> 26;
    kprintln!();
    kprintln!("=== sync exception ===");
    kprintln!("ESR_EL1 = {esr:#018x}  (EC {ec:#x}, IL {})", (esr >> 25) & 1);
    kprintln!("ELR_EL1 = {:#018x}  SPSR_EL1 = {:#018x}", frame.elr, frame.spsr);
    kprintln!("FAR_EL1 = {:#018x}", read_far());
    for (i, &v) in frame.x.iter().enumerate() {
        if i % 4 == 0 {
            kprintln!();
        }
        kprint!("x{i:<2}={v:#018x} ");
    }
    kprintln!();
    kprintln!("halting.");
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}

/// IRQ entry: claim from the GIC, dispatch, EOI; preempt EL0 on timer ticks.
#[unsafe(no_mangle)]
pub extern "C" fn rust_irq_handler(frame: &mut TrapFrame) {
    let iar = gic::iar();
    let id = iar & 0x00ff_ffff;
    match id {
        gic::SPURIOUS => return,
        gic::PPI_PHYS_TIMER => {
            timer::on_tick();
            crate::proc::wake_expired();
            crate::proc::wake_itimers();
        }
        crate::tty::UART0_SPI => crate::tty::on_rx(),
        other => kprintln!("[irq] unhandled INTID {other}"),
    }
    gic::eoir(iar);
    // Round-robin when the tick interrupted user mode (SPSR M=EL0t);
    // additionally, any IRQ that lands while the kernel idles gets a
    // schedule chance (that's how a woken reader resumes from idle).
    if id == gic::PPI_PHYS_TIMER && frame.spsr & 0xf == 0 {
        let _ = crate::proc::schedule(frame);
    } else if crate::proc::is_idle() {
        let _ = crate::proc::schedule_ex(frame, false);
    }
    // A tick is also the delivery boundary for running processes.
    crate::proc::deliver_signals(frame);
}
