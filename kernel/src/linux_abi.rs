//! Linux (asm-generic aarch64) syscall personality.
//!
//! Dispatch discriminator: Linux uses `svc #0` with the number in x8;
//! NetBSD encodes the number in the SVC immediate (never 0). Error ABI
//! differs too: Linux returns `-errno` in x0, NetBSD sets PSTATE.C.
//! Numbers verified against torvalds/linux include/uapi/asm-generic/unistd.h.

use alloc::string::String;

use tihkali_hal::kprintln;

use crate::arch::trap::TrapFrame;
use crate::file::{self, FdTarget};
use crate::proc::{self, Io};

const AT_FDCWD: i64 = -100;
const MAP_ANONYMOUS: u64 = 0x20;

// --- netbsd-backed operations shared with the other personality ---
// (write/read/close/exit handled below with Linux numbers.)

/// Handle a `svc #0` (Linux) call. Applies the Linux epilogue itself;
/// early-returns for sleeps/exit/sigreturn where the frame is finished.
pub fn svc(frame: &mut TrapFrame) {
    let nr = (frame.x[8] as u32) & 0xffff;
    // Any process issuing svc#0 is Linux-ABI: wait4 status translation
    // keys off this (set here so waiters need not have called sigaction).
    proc::note_signal_abi(true);
    let (result, err): (i64, u8) = match nr {
        // --- process ---
        93 | 94 => {
            proc::sys_exit(frame, frame.x[0]);
            return;
        }
        96 => (proc::current_pid() as i64, 0), // set_tid_address
        167 => (0, 0),                         // prctl: harmless no-op (v1)
        172 => (proc::current_pid() as i64, 0), // getpid
        129 => match proc::sig_from_user(frame.x[1] as i64, true) {
            // kill: pending bits live in canonical (NetBSD) indexing
            None => (0, 22),
            Some(sig) => match proc::sys_kill(frame.x[0] as i64, sig as u64) {
                Ok(()) => (0, 0),
                Err(e) => (0, e),
            },
        },
        130 => match proc::sig_from_user(frame.x[1] as i64, true) {
            // tkill(tid, sig): single-threaded → kill(tid, sig)
            None => (0, 22),
            Some(sig) => match proc::sys_kill(frame.x[0] as i64, sig as u64) {
                Ok(()) => (0, 0),
                Err(e) => (0, e),
            },
        },
        131 => match proc::sig_from_user(frame.x[2] as i64, true) {
            // tgkill(tgid, tid, sig): single-threaded → kill(tid, sig)
            None => (0, 22),
            Some(sig) => match proc::sys_kill(frame.x[1] as i64, sig as u64) {
                Ok(()) => (0, 0),
                Err(e) => (0, e),
            },
        },
        221 => {
            // execve(path, argv)
            match proc::sys_execve(frame, frame.x[0], frame.x[1]) {
                Ok(()) => return,
                Err(e) => (0, e),
            }
        }
        260 => {
            // wait4(pid, status, options, rusage)
            match proc::sys_wait4(frame, frame.x[0] as i64, frame.x[1], frame.x[2]) {
                proc::Wait4::Done(pid) => (pid, 0),
                proc::Wait4::Slept => return,
                proc::Wait4::Err(e) => (0, e),
            }
        }
        // --- stdio / files ---
        64 => match proc::sys_write(frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Ok(n) => (n, 0),
            Err(e) => (0, e),
        },
        63 => match proc::sys_read(frame, frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Io::Val(n) => (n, 0),
            Io::Err(e) => (0, e),
            Io::Slept => return,
        },
        66 => writev(frame.x[0] as usize, frame.x[1], frame.x[2] as usize),
        57 => match proc::sys_close(frame.x[0] as usize) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        56 => openat(frame.x[0] as i64, frame.x[1], frame.x[2]),
        62 => match proc::current_target(frame.x[0] as usize) {
            None => (0, file::EBADF),
            Some(FdTarget::File(i)) => match file::lseek(i, frame.x[1] as i64, frame.x[2] as u32) {
                Ok(pos) => (pos, 0),
                Err(e) => (0, e),
            },
            Some(_) => (0, file::EBADF), // tty: ESPIPE≈EBADF acceptable v1
        },
        80 => match fstat_fd(frame.x[0] as usize, frame.x[1]) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        79 => newfstatat(frame.x[0] as i64, frame.x[1], frame.x[2]),
        61 => match proc::sys_getdents64(frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Ok(n) => (n as i64, 0),
            Err(e) => (0, e),
        },
        25 => fcntl(frame.x[0] as usize, frame.x[1] as i64, frame.x[2] as i64),
        29 => ioctl(frame.x[0] as usize, frame.x[1], frame.x[2]),
        17 => getcwd(frame.x[0], frame.x[1]), // getcwd(path, size)
        173 => (proc::current_ppid(), 0),     // getppid
        24 => match proc::sys_dup3(frame.x[0] as i64, frame.x[1] as i64) {
            // dup3(old, new, flags)
            Ok(fd) => (fd as i64, 0),
            Err(e) => (0, e),
        },
        59 => match proc::sys_pipe2(frame.x[0]) {
            // pipe2(pipefd, flags)
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        // --- memory ---
        214 => (proc::sys_brk(frame.x[0]) as i64, 0), // brk never fails
        222 => {
            // mmap: anonymous bumps only (v1)
            if frame.x[3] & MAP_ANONYMOUS == 0 {
                (0, 78) // ENOSYS (internal code; translated below)
            } else {
                match proc::sys_mmap(frame.x[1]) {
                    Ok(base) => (base as i64, 0),
                    Err(e) => (0, e),
                }
            }
        }
        215 => match proc::sys_munmap(frame.x[0], frame.x[1]) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        226 => match proc::sys_mprotect(frame.x[0], frame.x[1], frame.x[2]) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        // --- time ---
        113 => clock_gettime(frame.x[0] as i32, frame.x[1]),
        169 => gettimeofday(frame.x[0], frame.x[1]),
        160 => uname(frame.x[0]),
        // --- signals ---
        134 => {
            // rt_sigaction(sig, act, oldact, sigsetsize)
            match proc::sig_from_user(frame.x[0] as i64, true) {
                None => (0, 22), // EINVAL
                Some(sig) => {
                    proc::note_signal_abi(true);
                    match proc::sys_sigaction(sig as u64, frame.x[1], frame.x[2]) {
                        // Linux rt_sigaction returns 0 on success (the old
                        // action goes to *oldact, written by sys_sigaction);
                        // returning the old handler here made the SECOND
                        // sigaction for a signal fail in musl (nonzero = error).
                        Ok(_) => (0, 0),
                        Err(e) => (0, e),
                    }
                }
            }
        }
        139 => {
            // rt_sigreturn: frame fully rebuilt
            proc::sys_sigreturn(frame);
            return;
        }
        220 => {
            // clone(flags, stack, ptid, tls, ctid): plain fork only.
            // threads / shared-mm (CLONE_VM etc.) unsupported in v1.
            if frame.x[0] & !0xff != 0 {
                (0, 22)
            } else {
                match proc::sys_fork(frame) {
                    Ok(pid) => (pid as i64, 0),
                    Err(proc::ForkError::NoMem) => (0, 12),
                }
            }
        }
        71 => sendfile(
            // sendfile(out, in, off, count): regular-file sources only;
            // pipe/tty sources return EINVAL so busybox falls back to read
            frame.x[0] as usize,
            frame.x[1] as usize,
            frame.x[2],
            frame.x[3] as usize,
        ),
        73 => match ppoll(frame, frame.x[0], frame.x[1], frame.x[2]) {
            Io::Val(n) => (n, 0),
            Io::Err(e) => (0, e),
            Io::Slept => return,
        },
        101 => match nanosleep(frame, frame.x[0], frame.x[1]) {
            Io::Val(n) => (n, 0),
            Io::Err(e) => (0, e),
            Io::Slept => return,
        },
        115 => {
            // clock_nanosleep(clockid, flags, req, rem): relative only (v1)
            if frame.x[1] & 1 != 0 {
                (0, 22) // TIMER_ABSTIME unsupported
            } else {
                match nanosleep(frame, frame.x[2], frame.x[3]) {
                    Io::Val(n) => (n, 0),
                    Io::Err(e) => (0, e),
                    Io::Slept => return,
                }
            }
        }
        154 => match proc::sys_setpgid(frame.x[0] as i64, frame.x[1] as i64) {
            // setpgid
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        155 => match proc::sys_getpgid(frame.x[0] as i64) {
            // getpgid
            Ok(g) => (g as i64, 0),
            Err(e) => (0, e),
        },
        157 => match proc::sys_setsid() {
            // setsid
            Ok(pid) => (pid as i64, 0),
            Err(e) => (0, e),
        },
        // Identity: single-user root. Observed from ash/musl startup.
        144 => (0, 0), // setgid
        146 => (0, 0), // setuid
        174 => (0, 0), // getuid
        175 => (0, 0), // geteuid
        176 => (0, 0), // getgid
        177 => (0, 0), // getegid
        178 => (proc::current_pid() as i64, 0), // gettid (tid == pid, 1-thread)
        135 => match proc::sys_sigprocmask(frame.x[0] as i64 + 1, frame.x[1], frame.x[2]) {
            // Linux how 0/1/2 -> NetBSD 1/2/3
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        _ => {
            kprintln!(
                "[linux] ENOSYS nr={nr} x0={:#x} x1={:#x} x2={:#x} elr={:#x}",
                frame.x[0], frame.x[1], frame.x[2], frame.elr
            );
            (0, 78) // ENOSYS
        }
    };

    // Linux epilogue: x0 = value or -errno; carry flags untouched (musl
    // tests with `cmp x0, #-4095` in user space).
    if err == 22 {
        kprintln!(
            "[linux] EINVAL nr={nr} x0={:#x} x1={:#x} x2={:#x} elr={:#x}",
            frame.x[0], frame.x[1], frame.x[2], frame.elr
        );
    }
    if err != 0 {
        frame.x[0] = (-(linux_errno(err) as i64)) as u64;
    } else {
        frame.x[0] = result as u64;
    }
}

// ---------- ppoll / nanosleep (deadline-based sleeps) ----------

const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
const POLLERR: u16 = 0x008;
const POLLHUP: u16 = 0x010;
const POLLNVAL: u16 = 0x020;

/// Readiness of one fd for the events requested in `events`.
fn poll_revents(fd: i32, events: u16) -> u16 {
    if fd < 0 {
        return 0; // negative fds are ignored per POSIX
    }
    let Some(target) = proc::current_target(fd as usize) else {
        return POLLNVAL;
    };
    match target {
        FdTarget::TtyIn => {
            if crate::tty::has_data() {
                events & POLLIN
            } else {
                0
            }
        }
        FdTarget::TtyOut => events & POLLOUT,
        // Regular files never block: always readable/writable.
        FdTarget::File(_) => events & (POLLIN | POLLOUT),
        FdTarget::Pipe { slot, write_end: false } => {
            let data = file::pipe_avail(slot);
            let mut r = events & POLLIN & if data > 0 { !0 } else { 0 };
            if proc::pipe_end_count(slot, true) == 0 {
                r |= POLLHUP; // no writers: hangup is reported unconditionally
                if data == 0 {
                    r |= events & POLLIN; // EOF: read would return 0
                }
            }
            r
        }
        FdTarget::Pipe { slot, write_end: true } => {
            if proc::pipe_end_count(slot, false) == 0 {
                return POLLERR; // no readers
            }
            if file::pipe_free(slot) > 0 {
                events & POLLOUT
            } else {
                0
            }
        }
    }
}

/// ppoll(73): poll(fds, nfds, timeout*, sigmask*). timeout NULL = block
/// until ready; {0,0} = return now; else deadline wake. sigmask ignored.
fn ppoll(frame: &mut TrapFrame, fds: u64, nfds: u64, timeout: u64) -> Io {
    if nfds > 64 {
        return Io::Err(file::EINVAL);
    }
    let bytes = nfds as usize * 8;
    if bytes != 0 && !proc::user_range_ok(fds, bytes) {
        return Io::Err(file::EFAULT);
    }
    let mut nready = 0usize;
    for i in 0..nfds as usize {
        let base = fds + (i as u64) * 8;
        let (fd, events) = unsafe {
            (
                *((base) as *const i32),
                *((base + 4) as *const u16),
            )
        };
        let revents = poll_revents(fd, events);
        unsafe { *((base + 6) as *mut u16) = revents };
        if revents != 0 {
            nready += 1;
        }
    }
    if nready > 0 {
        proc::deadline_clear();
        return Io::Val(nready as i64);
    }
    if proc::has_deliverable() {
        proc::deadline_clear();
        return Io::Err(file::EINTR);
    }
    if timeout == 0 {
        // Infinite: sleep until an event (tty/pipe) rewinds us.
        proc::deadline_clear();
        proc::sleep_current(frame);
        return Io::Slept;
    }
    if !proc::user_range_ok(timeout, 16) {
        proc::deadline_clear();
        return Io::Err(file::EFAULT);
    }
    let (sec, nsec) = unsafe {
        (
            *((timeout) as *const i64),
            *((timeout + 8) as *const i64),
        )
    };
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        proc::deadline_clear();
        return Io::Err(file::EINVAL);
    }
    if sec == 0 && nsec == 0 {
        proc::deadline_clear();
        return Io::Val(0);
    }
    // Reuse the armed deadline across event-driven re-entries so stray
    // wakes can't postpone the timeout indefinitely.
    match proc::deadline() {
        Some(at) => {
            if proc::deadline_passed() {
                return Io::Val(0);
            }
            proc::sleep_timed(frame, at);
            Io::Slept
        }
        None => {
            let dur = deadline_ticks(sec, nsec);
            let at = crate::arch::timer::now().saturating_add(dur);
            proc::sleep_timed(frame, at);
            Io::Slept
        }
    }
}

/// Convert a relative timespec to ticks (at least one, for nonzero input).
fn deadline_ticks(sec: i64, nsec: i64) -> u64 {
    let hz = crate::arch::timer::hz();
    let ticks = sec as u64 * hz + (nsec as u64).div_ceil(1_000_000_000 / hz);
    ticks.max(1)
}

/// nanosleep(101): relative sleep with deadline wake + EINTR semantics.
fn nanosleep(frame: &mut TrapFrame, req: u64, rem: u64) -> Io {
    if !proc::user_range_ok(req, 16) {
        proc::deadline_clear();
        return Io::Err(file::EFAULT);
    }
    let (sec, nsec) = unsafe { (*((req) as *const i64), *((req + 8) as *const i64)) };
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        proc::deadline_clear();
        return Io::Err(file::EINVAL);
    }
    if proc::has_deliverable() {
        write_rem(rem, sec, nsec);
        proc::deadline_clear();
        return Io::Err(file::EINTR);
    }
    if sec == 0 && nsec == 0 {
        proc::deadline_clear();
        return Io::Val(0);
    }
    match proc::deadline() {
        Some(at) => {
            if proc::deadline_passed() {
                return Io::Val(0);
            }
            proc::sleep_timed(frame, at);
            Io::Slept
        }
        None => {
            let at = crate::arch::timer::now().saturating_add(deadline_ticks(sec, nsec));
            proc::sleep_timed(frame, at);
            Io::Slept
        }
    }
}

/// Report remaining time to the caller on EINTR (best effort).
fn write_rem(rem: u64, sec: i64, nsec: i64) {
    if rem == 0 || !proc::user_range_ok(rem, 16) {
        return;
    }
    unsafe {
        *((rem) as *mut i64) = sec;
        *((rem + 8) as *mut i64) = nsec;
    }
}

/// Kernel-internal errnos are NetBSD-coded (the NetBSD ABI is primary);
/// asm-generic Linux diverges on a handful. Translate at the boundary so
/// musl/strerror see the right names (ENOSYS 78-vs-38 showed up as
/// "No error information" in ash).
fn linux_errno(e: u8) -> u8 {
    match e {
        78 => 38, // ENOSYS
        66 => 39, // ENOTEMPTY
        35 => 11, // EAGAIN
        63 => 36, // ENAMETOOLONG
        other => other,
    }
}

// ---------- helpers ----------

/// Translate Linux open flags to NetBSD (values differ for CREAT/TRUNC/...).
fn translate_open_flags(lf: u64) -> u64 {
    let mut nf = lf & 0b11; // access mode: identical
    if lf & 0x0040 != 0 {
        nf |= 0x0200; // O_CREAT
    }
    if lf & 0x0080 != 0 {
        nf |= 0x0800; // O_EXCL
    }
    if lf & 0x0200 != 0 {
        nf |= 0x0400; // O_TRUNC
    }
    if lf & 0x0400 != 0 {
        nf |= 0x0008; // O_APPEND
    }
    // O_DIRECTORY / O_CLOEXEC / O_NOCTTY etc: ignored (v1 semantics).
    nf
}

/// openat(dirfd, path, flags, mode): resolves dirfd by prefixing the
/// directory's path (absolute paths and AT_FDCWD skip it).
fn openat(dirfd: i64, path_ptr: u64, flags: u64) -> (i64, u8) {
    let Some(path) = proc::read_user_cstr(path_ptr, 128) else {
        return (0, 14); // EFAULT
    };
    let resolved: String = if path.starts_with('/') || dirfd == AT_FDCWD {
        path
    } else if dirfd >= 0 {
        match proc::current_target(dirfd as usize) {
            Some(FdTarget::File(i)) => match file::path_of_fd(i) {
                Ok(dir) => {
                    let mut p = String::from(dir);
                    if p != "/" {
                        p.push('/');
                    }
                    p.push_str(&path);
                    p
                }
                Err(e) => return (0, e),
            },
            _ => return (0, file::EBADF),
        }
    } else {
        return (0, 22); // EINVAL: unknown dirfd
    };
    match proc::sys_open(&resolved, translate_open_flags(flags)) {
        Ok(fd) => {
            (fd as i64, 0)
        }
        Err(e) => {
            (0, e)
        }
    }
}

fn writev(fd: usize, iov: u64, cnt: usize) -> (i64, u8) {
    if cnt > 64 {
        return (0, 22);
    }
    let mut total: i64 = 0;
    for i in 0..cnt {
        let Some(base) = proc::read_user_u64(iov + 16 * i as u64) else {
            return (0, 14);
        };
        let Some(len) = proc::read_user_u64(iov + 16 * i as u64 + 8) else {
            return (0, 14);
        };
        if len == 0 {
            continue;
        }
        match proc::sys_write(fd, base, len as usize) {
            Ok(n) => total += n,
            Err(e) => return (total, e),
        }
    }
    (total, 0)
}

/// Fill the asm-generic `struct stat` (128 bytes) at a user address.
fn write_linux_stat(addr: u64, mode: u32, size: u64, ino: u64) -> Result<(), u8> {
    if !proc::user_range_ok(addr, 128) {
        return Err(14);
    }
    unsafe {
        let p = addr as *mut u8;
        core::ptr::write_bytes(p, 0, 128);
        (p as *mut u64).add(0).write_unaligned(1); // st_dev
        (p as *mut u64).add(1).write_unaligned(ino);
        (p as *mut u32).add(4).write_unaligned(mode); // @16
        (p as *mut u32).add(5).write_unaligned(1); // nlink @20
        (p as *mut i64).add(6).write_unaligned(size as i64); // @48
        (p as *mut i32).add(14).write_unaligned(4096); // blksize @56
        (p as *mut i64).add(8).write_unaligned(((size + 511) / 512) as i64); // @64
    }
    Ok(())
}

/// S_IFCHR|0666, S_IFREG|0644, S_IFDIR|0755
const MODE_CHR: u32 = 0x21B6;
const MODE_REG: u32 = 0x81A4;
const MODE_DIR: u32 = 0x41ED;

fn fstat_fd(fd: usize, buf: u64) -> Result<(), u8> {
    match proc::current_target(fd) {
        None => Err(file::EBADF),
        Some(FdTarget::File(i)) => {
            let (is_dir, size) = file::meta(i)?;
            let mode = if is_dir { MODE_DIR } else { MODE_REG };
            let ino = file::ino(i)?;
            write_linux_stat(buf, mode, size as u64, ino as u64)
        }
        Some(_) => write_linux_stat(buf, MODE_CHR, 0, 1),
    }
}

fn newfstatat(dirfd: i64, path_ptr: u64, buf: u64) -> (i64, u8) {
    let Some(path) = proc::read_user_cstr(path_ptr, 128) else {
        return (0, 14);
    };
    if path.is_empty() {
        // AT_EMPTY_PATH: stat the dirfd itself
        return match fstat_fd(dirfd as usize, buf) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        };
    }
    let resolved: String = if path.starts_with('/') || dirfd == AT_FDCWD {
        path
    } else if dirfd >= 0 {
        match proc::current_target(dirfd as usize) {
            Some(FdTarget::File(i)) => match file::path_of_fd(i) {
                Ok(dir) => {
                    let mut p = String::from(dir);
                    if p != "/" {
                        p.push('/');
                    }
                    p.push_str(&path);
                    p
                }
                Err(e) => return (0, e),
            },
            _ => return (0, file::EBADF),
        }
    } else {
        return (0, 22);
    };
    // Open briefly to resolve, stat, close (v1; no fdless lookup yet).
    match proc::sys_open(&resolved, 0) {
        Ok(fd) => {
            let r = fstat_fd(fd, buf);
            let _ = proc::sys_close(fd);
            match r {
                Ok(()) => (0, 0),
                Err(e) => (0, e),
            }
        }
        Err(e) => (0, e),
    }
}

fn fcntl(fd: usize, cmd: i64, arg: i64) -> (i64, u8) {
    match cmd {
        0 => match proc::sys_dupfd(fd as i64, arg) {
            // F_DUPFD
            Ok(n) => (n as i64, 0),
            Err(e) => (0, e),
        },
        1 | 2 => (0, 0),  // F_GETFD / F_SETFD (no cloexec tracking, v1)
        3 => match proc::current_target(fd) {
            // F_GETFL
            Some(FdTarget::File(i)) => match file::is_writable(i) {
                Ok(true) => (2, 0),
                Ok(false) => (0, 0),
                Err(e) => (0, e),
            },
            Some(_) => (0, file::EBADF),
            None => (0, file::EBADF),
        },
        4 => (0, 0), // F_SETFL: ignore
        1030 => match proc::sys_dupfd(fd as i64, arg) {
            // F_DUPFD_CLOEXEC (no cloexec tracking v1 — same as F_DUPFD)
            Ok(n) => (n as i64, 0),
            Err(e) => (0, e),
        },
        1031 | 1032 => match proc::current_target(fd) {
            // F_SETPIPE_SZ / F_GETPIPE_SZ: accept, report the fixed size
            Some(FdTarget::Pipe { .. }) => (file::PIPE_SIZE as i64, 0),
            _ => (0, file::EBADF),
        },
        _ => (0, 22), // EINVAL (unknown commands)
    }
}

/// ioctl: fake terminal state for busybox/musl line I/O.
fn ioctl(fd: usize, cmd: u64, arg: u64) -> (i64, u8) {
    if !proc::current_target(fd).is_some() {
        return (0, file::EBADF);
    }
    match cmd {
        0x5401 => {
            // TCGETS: struct termios = 4*u32 flags + c_line + c_cc[19]
            if !proc::user_range_ok(arg, 36) {
                return (0, 14);
            }
            unsafe {
                let p = arg as *mut u8;
                core::ptr::write_bytes(p, 0, 36);
                // c_lflag @12: ICANON(0x2) | ECHO(0x8)
                (p as *mut u32).add(3).write_unaligned(0x0000_000a);
            }
            (0, 0)
        }
        0x5402 => (0, 0), // TCSETS: accept and ignore
        0x5413 => {
            // TIOCGWINSZ: {rows, cols, xpix, ypix} = u16 x4
            if !proc::user_range_ok(arg, 8) {
                return (0, 14);
            }
            unsafe {
                let p = arg as *mut u16;
                p.add(0).write_unaligned(24);
                p.add(1).write_unaligned(80);
                p.add(2).write_unaligned(0);
                p.add(3).write_unaligned(0);
            }
            (0, 0)
        }
        0x540F => {
            // TIOCGPGRP: report the foreground group (caller's own when
            // none established yet — matches a fresh controlling tty).
            if !proc::user_range_ok(arg, 4) {
                return (0, 14);
            }
            let g = proc::fg_pgrp().unwrap_or_else(proc::current_pgrp) as i32;
            unsafe { (arg as *mut i32).write_volatile(g) };
            (0, 0)
        }
        0x5410 => {
            // TIOCSPGRP: establish the ^C target group.
            if !proc::user_range_ok(arg, 4) {
                return (0, 14);
            }
            let g = unsafe { (arg as *const i32).read_volatile() };
            if g < 0 {
                return (0, 22);
            }
            proc::set_fg_pgrp(g as usize);
            (0, 0)
        }
        _ => {
            kprintln!("[linux] ioctl ENOTTY cmd={:#x} fd={fd}", cmd);
            (0, 25) // ENOTTY
        }
    }
}

fn now_parts() -> (i64, i64) {
    let (ticks, freq): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) ticks, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    let freq = if freq == 0 { 62_500_000 } else { freq };
    ((ticks / freq) as i64, ((ticks % freq) * 1_000_000_000 / freq) as i64)
}

fn clock_gettime(clkid: i32, tp: u64) -> (i64, u8) {
    if !proc::user_range_ok(tp, 16) {
        return (0, 14);
    }
    let (mut sec, nsec) = now_parts();
    match clkid {
        0 => sec += 1_700_000_000, // CLOCK_REALTIME: fixed epoch offset
        1 | 5 | 7 => {}           // MONOTONIC/BOOTTIME/MONOTONIC_RAW: uptime
        _ => return (0, 22),
    }
    unsafe {
        (tp as *mut i64).add(0).write_unaligned(sec);
        (tp as *mut i64).add(1).write_unaligned(nsec);
    }
    (0, 0)
}

fn gettimeofday(tv: u64, tz: u64) -> (i64, u8) {
    if tv == 0 {
        return (0, 22); // EINVAL: kernel always wants the timeval
    }
    if !proc::user_range_ok(tv, 16) {
        return (0, 14);
    }
    let (mut sec, nsec) = now_parts();
    sec += 1_700_000_000; // fixed epoch, plenty for `date`-style reads
    unsafe {
        (tv as *mut i64).add(0).write_unaligned(sec);
        (tv as *mut i64).add(1).write_unaligned(nsec / 1000);
        if tz != 0 && proc::user_range_ok(tz, 8) {
            core::ptr::write_bytes(tz as *mut u8, 0, 8);
        }
    }
    (0, 0)
}

fn uname(buf: u64) -> (i64, u8) {
    if !proc::user_range_ok(buf, 390) {
        return (0, 14);
    }
    unsafe {
        let p = buf as *mut u8;
        core::ptr::write_bytes(p, 0, 390);
        for (off, s) in [
            (0usize, "Linux"),
            (65, "tihkali"),
            (130, "6.6.0-tihkali"),
            (195, "#1 tihkali"),
            (260, "aarch64"),
        ] {
            core::ptr::copy_nonoverlapping(s.as_ptr(), p.add(off), s.len());
        }
    }
    (0, 0)
}

/// getcwd(17): no process cwd yet — report "/" (POSIX root).
/// sendfile(71): bounce a regular file through a kernel buffer. Sources
/// that can block (pipe/tty) return EINVAL — busybox then uses read/write,
/// which owns the sleep/EOF logic.
fn sendfile(out_fd: usize, in_fd: usize, off: u64, count: usize) -> (i64, u8) {
    if off != 0 {
        return (0, 22); // v1: caller-supplied offset unsupported
    }
    let Some(FdTarget::File(src)) = proc::current_target(in_fd) else {
        return (0, 22);
    };
    let Some(dst) = proc::current_target(out_fd) else {
        return (0, 9);
    };
    // Pipe destinations need blocking-write semantics sendfile can't do
    // synchronously; EINVAL sends busybox through the read/write path.
    if !matches!(dst, FdTarget::TtyOut | FdTarget::File(_)) {
        return (0, 22);
    }
    let mut total = 0usize;
    let mut kbuf = [0u8; 1024];
    let kaddr = kbuf.as_mut_ptr() as u64;
    while total < count {
        let want = (count - total).min(kbuf.len());
        let n = match file::read_to_user(src, kaddr, want) {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                return if total > 0 { (total as i64, 0) } else { (0, e) }
            }
        };
        let wrote = match dst {
            FdTarget::TtyOut => {
                let bytes = unsafe { core::slice::from_raw_parts(kaddr as *const u8, n) };
                tihkali_hal::console::write_bytes(bytes);
                n
            }
            FdTarget::File(dst_idx) => {
                match file::write_from_user(dst_idx, kaddr, n) {
                    Ok(w) => w,
                    Err(e) => {
                        return if total > 0 { (total as i64, 0) } else { (0, e) }
                    }
                }
            }
            _ => return (0, 9), // unreachable: dst filtered above
        };
        total += wrote;
        if wrote < n {
            break; // short write: report progress, caller retries
        }
    }
    (total as i64, 0)
}

fn getcwd(path: u64, size: u64) -> (i64, u8) {
    if size < 2 {
        return (0, 34); // ERANGE
    }
    if !proc::user_range_ok(path, 2) {
        return (0, 14);
    }
    unsafe {
        (path as *mut u8).add(0).write(b'/');
        (path as *mut u8).add(1).write(0);
    }
    (0, 0)
}
