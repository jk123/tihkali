//! Linux (asm-generic aarch64) syscall personality.
//!
//! Dispatch discriminator: Linux uses `svc #0` with the number in x8;
//! NetBSD encodes the number in the SVC immediate (never 0). Error ABI
//! differs too: Linux returns `-errno` in x0, NetBSD sets PSTATE.C.
//! Numbers verified against torvalds/linux include/uapi/asm-generic/unistd.h.

use alloc::string::String;

use crate::kprintln;

use crate::arch::trap::TrapFrame;
use crate::file::{self, FdTarget};
use crate::fs;
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
        79 => newfstatat(frame.x[0] as i64, frame.x[1], frame.x[2], frame.x[3]),
        61 => match proc::sys_getdents64(frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Ok(n) => (n as i64, 0),
            Err(e) => (0, e),
        },
        25 => fcntl(frame.x[0] as usize, frame.x[1] as i64, frame.x[2] as i64),
        29 => ioctl(frame.x[0] as usize, frame.x[1], frame.x[2]),
        17 => getcwd(frame.x[0], frame.x[1]), // getcwd(path, size)
        173 => (proc::current_ppid(), 0),     // getppid
        23 => match proc::sys_dup3(frame.x[0] as i64, frame.x[1] as i64) {
            // dup2(old, new) = dup3 without the flags
            Ok(fd) => (fd as i64, 0),
            Err(e) => (0, e),
        },
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
        103 => {
            // setitimer(which, new, old): ITIMER_REAL only — arms a
            // per-process deadline; the tick fires SIGALRM at it (v1).
            // Zero the old struct so callers see "no prior timer".
            let old_ptr = frame.x[2];
            if old_ptr != 0 && proc::user_range_ok(old_ptr, 32) {
                unsafe {
                    (old_ptr as *mut u8).write_bytes(0, 32);
                }
            }
            if frame.x[0] as i32 != 0 {
                // not ITIMER_REAL: accept and ignore
                (0, 0)
            } else {
                // musl aarch64: struct itimerval = { it_interval, it_value },
                // each a { time_t tv_sec; suseconds_t tv_usec } with
                // time_t = long = 8 bytes. it_interval is at +0 and
                // it_value at +16, so the pair spans 32 bytes.
                let new = frame.x[1];
                if new == 0 || !proc::user_range_ok(new, 32) {
                    (0, 0)
                } else {
                    let rd = |off: usize| unsafe {
                        (new as *const u64).add(off / 8).read_unaligned() as u64
                    };
                    let sec = rd(16);
                    let usec = rd(24);
                    let isec = rd(0);
                    let iusec = rd(8);
                    let ticks = proc::arch_timer_hz();
                    let to_ticks = |s: u64, us: u64| s * ticks + us * ticks / 1_000_000;
                    if sec == 0 && usec == 0 {
                        // Disarm: clear the deadline, keep returning 0.
                        proc::proc_set_itimer(proc::current_slot(), None, None);
                    } else {
                        let deadline =
                            proc::arch_timer_now() + to_ticks(sec, usec);
                        // A zero interval is a one-shot alarm; anything else
                        // repeats, which is what periodic tools like
                        // busybox ping rely on to drive their send loop.
                        let iv = to_ticks(isec, iusec);
                        proc::proc_set_itimer(
                            proc::current_slot(),
                            Some(deadline),
                            Some(iv),
                        );
                    }
                    (0, 0)
                }
            }
        }
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
        34 => {
            // mkdirat(dirfd, path, mode)
            match resolve_path(frame.x[0] as i64, read_cstr(frame.x[1])) {
                Err(e) => (0, e),
                Ok(path) => match fs::create_dir(&path) {
                    Ok(idx) => {
                        let _ = fs::set_mode(idx, (frame.x[2] as u16) & 0o7777);
                        (0, 0)
                    }
                    Err(e) => (0, e),
                },
            }
        }
        35 => {
            // unlinkat(dirfd, path, flags): AT_REMOVEDIR selects rmdir
            match resolve_path(frame.x[0] as i64, read_cstr(frame.x[1])) {
                Err(e) => (0, e),
                Ok(path) => {
                    let r = if frame.x[2] & 0x200 != 0 {
                        fs::remove_dir(&path)
                    } else {
                        fs::remove_file(&path)
                    };
                    match r {
                        Ok(()) => (0, 0),
                        Err(e) => (0, e),
                    }
                }
            }
        }
        36 => symlinkat_arm(frame.x[0], frame.x[1] as i64, frame.x[2]),
        38 => renameat_arm(frame.x[0] as i64, frame.x[1], frame.x[2] as i64, frame.x[3]),
        276 => {
            // renameat2: RENAME_NOREPLACE/RENAME_EXCHANGE unsupported v1
            if frame.x[4] != 0 {
                (0, 22)
            } else {
                renameat_arm(
                    frame.x[0] as i64,
                    frame.x[1],
                    frame.x[2] as i64,
                    frame.x[3],
                )
            }
        }
        45 => {
            // truncate(path, len)
            match resolve_path(AT_FDCWD, read_cstr(frame.x[0])) {
                Err(e) => (0, e),
                Ok(path) => match fs::lookup(&path) {
                    None => (0, 2),
                    Some(idx) => match fs::set_len(idx, frame.x[1] as usize) {
                        Ok(()) => (0, 0),
                        Err(e) => (0, e),
                    },
                },
            }
        }
        46 => {
            // ftruncate(fd, len)
            match file::node_of_fd(frame.x[0] as usize) {
                Err(e) => (0, e),
                Ok(node) => match fs::set_len(node, frame.x[1] as usize) {
                    Ok(()) => (0, 0),
                    Err(e) => (0, e),
                },
            }
        }
        52 => {
            // fchmod(fd, mode)
            match file::node_of_fd(frame.x[0] as usize) {
                Err(e) => (0, e),
                Ok(node) => match fs::set_mode(node, frame.x[1] as u16) {
                    Ok(()) => (0, 0),
                    Err(e) => (0, e),
                },
            }
        }
        53 => {
            // fchmodat(dirfd, path, mode, flags)
            match resolve_path(frame.x[0] as i64, read_cstr(frame.x[1])) {
                Err(e) => (0, e),
                Ok(path) => match fs::lookup(&path) {
                    None => (0, 2),
                    Some(idx) => match fs::set_mode(idx, frame.x[2] as u16) {
                        Ok(()) => (0, 0),
                        Err(e) => (0, e),
                    },
                },
            }
        }
        78 => readlinkat_arm(frame.x[0] as i64, frame.x[1], frame.x[2], frame.x[3]),
        81 => {
            // sync: v1 flushes the whole image
            match proc::sys_sync() {
                Ok(()) => (0, 0),
                Err(e) => (0, e),
            }
        }
        82 | 83 => {
            // fsync/fdatasync: v1 syncs the whole image
            if proc::current_target(frame.x[0] as usize).is_none() {
                (0, 9) // EBADF
            } else {
                match proc::sys_sync() {
                    Ok(()) => (0, 0),
                    Err(e) => (0, e),
                }
            }
        }
        48 => {
            // faccessat(dirfd, path, mode): single-user root — R/W always
            // allowed on existing nodes; X_OK needs an execute bit (POSIX
            // exempts only dirs from that). access() follows symlinks.
            match resolve_path(frame.x[0] as i64, read_cstr(frame.x[1])) {
                Err(e) => (0, e),
                Ok(path) => match fs::lookup(&path) {
                    None => (0, 2), // ENOENT
                    Some(i) => {
                        let want = frame.x[2] as u32;
                        let x_ok = fs::is_dir(i) || fs::perms(i) & 0o111 != 0;
                        if want & 1 != 0 && !x_ok {
                            (0, 13) // X_OK denied
                        } else {
                            (0, 0)
                        }
                    }
                },
            }
        }
        88 => utimensat(frame.x[0] as i64, frame.x[1], frame.x[2]),
        // --- sockets (Linux ABI only; NetBSD socket arms land in N3) ---
        // Fall through to the default ENOSYS arm in rpi3 builds (no net).
        #[cfg(feature = "net")]
        198 => {
            // socket(domain, type, proto)
            if frame.x[0] as i64 != 2 {
                (0, crate::net::EAFNOSUPPORT) // AF_INET only
            } else {
                match crate::net::socket_kind(
                    (frame.x[1] & 0xf) as u32,
                    frame.x[2] as u32,
                ) {
                    None => (0, crate::net::EAFNOSUPPORT),
                    Some(kind) => match crate::net::sock_open(kind) {
                        Ok(slot) => {
                            // SOCK_NONBLOCK (0x800) rides in the type word;
                            // musl's resolver opens its UDP socket this way.
                            if frame.x[1] & crate::net::SOCK_NONBLOCK != 0 {
                                crate::net::sock_set_nonblock(slot, true);
                            }
                            match proc::install_fd(FdTarget::Socket(slot)) {
                                Ok(fd) => (fd as i64, 0),
                                Err(e) => {
                                    crate::net::sock_ref_dec(slot);
                                    (0, e)
                                }
                            }
                        }
                        Err(e) => (0, e),
                    },
                }
            }
        }
        #[cfg(feature = "net")]
        200 => {
            // bind(fd, sockaddr, addrlen)
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => match parse_sockaddr_in(frame.x[1], frame.x[2]) {
                    Err(e) => (0, e),
                    Ok((ip, port)) => match crate::net::sock_bind(slot, ip, port) {
                        Ok(()) => (0, 0),
                        Err(e) => (0, e),
                    },
                },
            }
        }
        #[cfg(feature = "net")]
        203 => {
            // connect(fd, sockaddr, addrlen): blocking via sleep/wake —
            // each wake re-enters and re-checks the smoltcp state machine.
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => match parse_sockaddr_in(frame.x[1], frame.x[2]) {
                    Err(e) => (0, e),
                    Ok((ip, port)) => {
                        crate::net::poll_tick(); // flush anything queued
                        match crate::net::sock_connect(slot, ip, port) {
                            Err(e) => (0, e),
                            Ok(crate::net::Conn::Done) => (0, 0),
                            Ok(crate::net::Conn::Failed) => (0, crate::net::ECONNREFUSED),
                            Ok(crate::net::Conn::Progress) => {
                                if proc::has_deliverable() {
                                    (0, 4) // EINTR
                                } else {
                                    proc::sleep_current(frame);
                                    return;
                                }
                            }
                        }
                    }
                },
            }
        }
        #[cfg(feature = "net")]
        201 => {
            // listen(fd, backlog)
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => match crate::net::sock_listen(slot, frame.x[1] as i32) {
                    Ok(()) => (0, 0),
                    Err(e) => (0, e),
                },
            }
        }
        #[cfg(feature = "net")]
        202 => {
            // accept(fd, addr* out, addrlen* out): blocks via sleep/wake —
            // each wake re-enters and re-checks the listener's state.
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => {
                    crate::net::poll_tick(); // flush anything queued
                    match crate::net::sock_accept(slot) {
                        Err(e) => (0, e),
                        Ok(crate::net::Acc::Done((peer, data_slot))) => {
                            // Fill the out-params with the peer's address.
                            if frame.x[1] != 0 && proc::user_range_ok(frame.x[1], 16) {
                                let _ = write_sockaddr_out(frame.x[1], frame.x[2], &peer.0, peer.1);
                            }
                            // smoltcp serves one connection per socket, so the
                            // accepted connection lives in `data_slot` (the
                            // same slot as the listener). Hand the caller a
                            // fresh fd for it; the listener re-enters LISTEN
                            // when that fd is closed (see `sock_close`).
                            match proc::install_fd(FdTarget::Socket(data_slot)) {
                                Ok(newfd) => {
                                    // A second fd now points at this slot; bump the refcount.
                                    crate::net::sock_ref_inc(data_slot);
                                    (newfd as i64, 0)
                                }
                                Err(e) => {
                                    crate::net::sock_ref_dec(data_slot);
                                    (0, e)
                                }
                            }
                        }
                        Ok(crate::net::Acc::Progress) => {
                            if proc::has_deliverable() {
                                (0, 4) // EINTR
                            } else {
                                proc::sleep_current(frame);
                                return;
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        206 => {
            // sendto(fd, buf, len, flags, addr*, addrlen) — also plain
            // send() with a NULL address (TCP write path).
            let len = frame.x[2] as usize;
            if len == 0 {
                (0, 0)
            } else if !proc::user_range_ok(frame.x[1], len) {
                (0, file::EFAULT)
            } else {
                match sock_slot(frame.x[0] as usize) {
                    None => (0, file::EBADF),
                    Some(slot) => {
                        let bytes =
                            unsafe { core::slice::from_raw_parts(frame.x[1] as *const u8, len) };
                        if frame.x[4] == 0 {
                            match crate::net::sock_send(slot, bytes) {
                                Ok(n) => (n as i64, 0),
                                Err(e) => (0, e),
                            }
                        } else {
                            match parse_sockaddr_in(frame.x[4], frame.x[5]) {
                                Err(e) => (0, e),
                                Ok((ip, port)) => {
                                    match crate::net::sock_send_to(slot, bytes, ip, port) {
                                        Ok(n) => (n as i64, 0),
                                        Err(e) => (0, e),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        207 => {
            // recvfrom(fd, buf, len, flags, addr* out, addrlen* out)
            let len = frame.x[2] as usize;
            if len == 0 {
                (0, 0)
            } else if !proc::user_range_ok(frame.x[1], len) {
                (0, file::EFAULT)
            } else {
                match sock_slot(frame.x[0] as usize) {
                    None => (0, file::EBADF),
                    Some(slot) => {
                        if proc::has_deliverable() {
                            (0, 4) // EINTR
                        } else {
                            let want_from = frame.x[4] != 0;
                            let mut src = ([0u8; 4], 0u16);
                            let res = {
                                let user = unsafe {
                                    core::slice::from_raw_parts_mut(frame.x[1] as *mut u8, len)
                                };
                                let from = if want_from { Some(&mut src) } else { None };
                                crate::net::sock_recv(slot, user, from)
                            };
                            match res {
                                Ok(n) => {
                                    if want_from {
                                        write_sockaddr_out(frame.x[4], frame.x[5], &src.0, src.1);
                                    }
                                    (n as i64, 0)
                                }
                                Err(crate::net::EAGAIN_L) => {
                                    #[cfg(feature = "net")]
                                    if crate::net::sock_is_nonblock(slot) {
                                        (0, 11) // EAGAIN
                                    } else {
                                        proc::sleep_current(frame);
                                        return;
                                    }
                                    #[cfg(not(feature = "net"))]
                                    {
                                        proc::sleep_current(frame);
                                        return;
                                    }
                                }
                                Err(e) => (0, e),
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        208 => {
            // setsockopt(fd, level, optname, optval, optlen)
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => {
                    // Unknown level or optname: accept and ignore (lenient policy).
                    if frame.x[1] as i32 != SOL_SOCKET_L {
                        (0, 0)
                    } else {
                        match linux_opt(frame.x[2] as i32) {
                            None => (0, 0),
                            Some(opt) => match crate::net::sock_setopt(
                                slot,
                                opt,
                                frame.x[3],
                                frame.x[4] as usize,
                            ) {
                                Ok(()) => (0, 0),
                                Err(e) => (0, e),
                            },
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        209 => {
            // getsockopt(fd, level, optname, optval, optlen*)
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => {
                    if frame.x[1] as i32 != SOL_SOCKET_L {
                        (0, 0)
                    } else {
                        match linux_opt(frame.x[2] as i32) {
                            None => {
                                // Unknown option: zero-length result, as v1 did.
                                if frame.x[4] != 0 && proc::user_range_ok(frame.x[4], 4) {
                                    unsafe { (frame.x[4] as *mut u32).write_volatile(0) };
                                }
                                (0, 0)
                            }
                            Some(opt) => {
                                match crate::net::sock_getopt(slot, opt, frame.x[3], frame.x[4]) {
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
        210 => {
            // shutdown(fd, how)
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => match crate::net::sock_shutdown(slot, frame.x[1] as i32) {
                    Ok(()) => (0, 0),
                    Err(e) => (0, e),
                },
            }
        }
        #[cfg(feature = "net")]
        211 => {
            // sendmsg(fd, msg, flags): scatter-gather into one send.
            // `frame.x[1]` is the msghdr; msg_iov is at byte 16 and
            // msg_iovlen (u32) at byte 24 on aarch64-LE.
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => {
                    let msg = frame.x[1];
                    if msg == 0 || !proc::user_range_ok(msg, 32) {
                        (0, file::EFAULT)
                    } else {
                        let iov = unsafe { (msg as *const u64).add(2).read_unaligned() };
                        let iovlen =
                            unsafe { (msg as *const u32).add(6).read_unaligned() as usize };
                        match crate::net::sock_sendmsg(slot, iov, iovlen) {
                            Ok(n) => (n as i64, 0),
                            Err(e) => (0, e),
                        }
                    }
                }
            }
        }
        #[cfg(feature = "net")]
        212 => {
            // recvmsg(fd, msg, flags): one coalesced recv into iovec[0].
            // Same msghdr offsets as arm 211.
            match sock_slot(frame.x[0] as usize) {
                None => (0, file::EBADF),
                Some(slot) => {
                    let msg = frame.x[1];
                    if msg == 0 || !proc::user_range_ok(msg, 32) {
                        (0, file::EFAULT)
                    } else {
                        let iov = unsafe { (msg as *const u64).add(2).read_unaligned() };
                        let iovlen =
                            unsafe { (msg as *const u32).add(6).read_unaligned() as usize };
                        let (iov_base, iov_len) = if iovlen == 0 || iov == 0 {
                            (0u64, 0usize)
                        } else {
                            (
                                unsafe { (iov as *const u64).read_unaligned() },
                                unsafe { (iov as *const u64).add(1).read_unaligned() as usize },
                            )
                        };
                        let mut src = ([0u8; 4], 0u16);
                        let res = if iovlen == 0 {
                            Ok(0)
                        } else if !proc::user_range_ok(iov_base, iov_len) {
                            Err(file::EFAULT)
                        } else {
                            crate::net::sock_recvmsg(slot, iov, iovlen, Some(&mut src))
                        };
                        match res {
                            Ok(n) => {
                                // Linux msghdr output fields musl inspects:
                                // msg_namelen @8, msg_controllen @40,
                                // msg_flags @48. Leaving them as the
                                // caller left them makes musl treat a
                                // perfectly good reply as truncated/unknown
                                // and report a lookup failure.
                                unsafe {
                                    let m = msg as *mut u8;
                                    if n > 0 {
                                        let nameptr = *(m as *const u64);
                                        write_sockaddr_out(nameptr, m as u64 + 8, &src.0, src.1);
                                        *(m.add(40) as *mut u64) = 0; // msg_controllen
                                        *(m.add(48) as *mut u32) = 0; // msg_flags
                                    }
                                }
                                // Inline-flush so an echo right after the
                                // recvmsg reaches the peer (N4 fix).
                                if n > 0 {
                                    crate::net::service_iface();
                                }
                                (n as i64, 0)
                            }
                            Err(crate::net::EAGAIN_L) => {
                                #[cfg(feature = "net")]
                                if crate::net::sock_is_nonblock(slot) {
                                    (0, 11) // EAGAIN
                                } else {
                                    proc::sleep_current(frame);
                                    return;
                                }
                                #[cfg(not(feature = "net"))]
                                {
                                    proc::sleep_current(frame);
                                    return;
                                }
                            }
                            Err(e) => (0, e),
                        }
                    }
                }
            }
        }
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
        #[cfg(feature = "net")]
        240 => {
            // tihkali_resolve(const char *name, u32 *out_ipv4) — in-kernel
            // DNS. 240 is unused on Linux aarch64, chosen so the musl
            // getaddrinfo path can be redirected here without colliding
            // with a real syscall. Returns 0 + the A record on success,
            // or -EHOSTUNREACH / -EFAULT.
            let out = frame.x[1];
            if out == 0 || !proc::user_range_ok(out, 4) {
                (0, file::EFAULT)
            } else {
                match proc::read_user_cstr(frame.x[0], 256) {
                    None => (0, file::EFAULT),
                    Some(name) => match crate::net::resolve(&name, crate::net::DNS_TIMEOUT) {
                        Some(ip) => {
                            // Bounds validated above; write the 4-byte A
                            // record as one volatile store.
                            unsafe { (out as *mut u32).write_volatile(u32::from_le_bytes(ip)) };
                            (0, 0)
                        }
                        None => (0, 2), // ENOENT: no such name / timed out
                    },
                }
            }
        }
        #[cfg(feature = "qemu-virt")]
        480 => {
            // tihkali: gui_fb_info(out) -> {width, height, stride, pa}
            match crate::gui::sys_fb_info(frame.x[0]) {
                Ok(()) => (0, 0),
                Err(e) => (0, linux_errno(e)),
            }
        }
        #[cfg(feature = "qemu-virt")]
        481 => {
            // tihkali: gui_fill_rect(x, y, w, h, rgb)
            match crate::gui::sys_fill_rect(
                frame.x[0] as u32,
                frame.x[1] as u32,
                frame.x[2] as u32,
                frame.x[3] as u32,
                frame.x[4] as u32,
            ) {
                Ok(()) => (0, 0),
                Err(e) => (0, linux_errno(e)),
            }
        }
        #[cfg(feature = "qemu-virt")]
        482 => {
            // tihkali: gui_blit(src, x, y, w, h, src_stride)
            match crate::gui::sys_blit(
                frame.x[0],
                frame.x[1] as u32,
                frame.x[2] as u32,
                frame.x[3] as u32,
                frame.x[4] as u32,
                frame.x[5] as u32,
            ) {
                Ok(()) => (0, 0),
                Err(e) => (0, linux_errno(e)),
            }
        }
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
    //
    // EINVAL is an expected return from several arms now (setsockopt on a
    // read-only option, for one), so only trace it where it still signals
    // a real defect.
    if err == 22 && matches!(nr, 221 | 222 | 226) {
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
        #[cfg(feature = "net")]
        FdTarget::Socket(s) => match crate::net::sock_poll(s) {
            None => POLLNVAL,
            Some((recv, send)) => {
                let mut r = 0;
                if recv {
                    r |= events & POLLIN;
                }
                if send {
                    r |= events & POLLOUT;
                }
                r
            }
        },
        #[cfg(not(feature = "net"))]
        FdTarget::Socket(_) => POLLNVAL,
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
    // Service the NIC once, before sampling any fd: a datagram that landed
    // since the last poll_tick is still in the rx queue, not yet in the
    // socket buffer, so sock_poll would report "not ready" and the caller
    // would sleep through its arrival. Done here rather than inside
    // poll_revents because poll_tick wakes sleepers — doing that per-fd
    // would wake this process while it is still walking its fd list.
    #[cfg(feature = "net")]
    crate::net::poll_tick();
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
        78 => 38,  // ENOSYS
        66 => 39,  // ENOTEMPTY
        35 => 11,  // EAGAIN
        63 => 36,  // ENAMETOOLONG
        47 => 97,  // EAFNOSUPPORT
        38 => 88,  // ENOTSOCK
        57 => 107, // ENOTCONN
        56 => 106, // EISCONN
        54 => 104, // ECONNRESET
        61 => 111, // ECONNREFUSED
        60 => 110, // ETIMEDOUT
        48 => 98,  // EADDRINUSE
        other => other,
    }
}

// ---------- socket helpers ----------

/// Current process's fd → net pool slot (None if not a socket fd).
#[cfg(feature = "net")]
pub fn sock_slot(fd: usize) -> Option<usize> {
    match proc::current_target(fd) {
        Some(FdTarget::Socket(s)) => Some(s),
        _ => None,
    }
}

/// Linux `SOL_SOCKET` (asm-generic/socket.h).
#[cfg(feature = "net")]
const SOL_SOCKET_L: i32 = 1;

/// Map a Linux `SO_*` optname onto the ABI-neutral `net::OPT_*` value.
/// `None` means the option is not one we plumb through; the caller decides
/// how to treat it (lenient accept-and-ignore for setsockopt, zero-length
/// for getsockopt).
#[cfg(feature = "net")]
fn linux_opt(name: i32) -> Option<i32> {
    use crate::net::{OPT_SO_BROADCAST, OPT_SO_ERROR, OPT_SO_KEEPALIVE, OPT_SO_RCVBUF,
                     OPT_SO_REUSEADDR, OPT_SO_SNDBUF, OPT_SO_TYPE};
    Some(match name {
        3 => OPT_SO_TYPE,          // SO_TYPE
        4 => OPT_SO_ERROR,         // SO_ERROR
        2 => OPT_SO_REUSEADDR,     // SO_REUSEADDR
        6 => OPT_SO_BROADCAST,     // SO_BROADCAST
        7 => OPT_SO_SNDBUF,        // SO_SNDBUF
        8 => OPT_SO_RCVBUF,        // SO_RCVBUF
        9 => OPT_SO_KEEPALIVE,     // SO_KEEPALIVE
        _ => return None,
    })
}

/// NetBSD `SOL_SOCKET` is 0xffff — NOT the Linux 1. (sys/socket.h)
#[cfg(feature = "net")]
pub const SOL_SOCKET_N: i32 = 0xffff;

/// Map a NetBSD `SO_*` name onto the ABI-neutral `net::OPT_*` value.
/// NetBSD numbers the boolean flags as low `so_options` bits (SO_REUSEADDR
/// 0x0004, SO_BROADCAST 0x0020, SO_KEEPALIVE 0x0008) and the extra options
/// high (SO_SNDBUF 0x1001, SO_RCVBUF 0x1002, SO_ERROR 0x1007, SO_TYPE 0x1008).
#[cfg(feature = "net")]
pub fn netbsd_opt(name: i32) -> Option<i32> {
    use crate::net::{OPT_SO_BROADCAST, OPT_SO_ERROR, OPT_SO_KEEPALIVE, OPT_SO_RCVBUF,
                     OPT_SO_REUSEADDR, OPT_SO_SNDBUF, OPT_SO_TYPE};
    Some(match name {
        0x1008 => OPT_SO_TYPE,      // SO_TYPE
        0x1007 => OPT_SO_ERROR,     // SO_ERROR
        0x0004 => OPT_SO_REUSEADDR, // SO_REUSEADDR
        0x0020 => OPT_SO_BROADCAST, // SO_BROADCAST
        0x1001 => OPT_SO_SNDBUF,    // SO_SNDBUF
        0x1002 => OPT_SO_RCVBUF,    // SO_RCVBUF
        0x0008 => OPT_SO_KEEPALIVE, // SO_KEEPALIVE
        _ => return None,
    })
}

/// Linux `struct sockaddr_in` (16 bytes): family u16 LE, port u16 BE,
/// IPv4 u32 BE, 8 bytes padding. Returns ([u8; 4], port).
#[cfg(feature = "net")]
fn parse_sockaddr_in(ptr: u64, len: u64) -> Result<([u8; 4], u16), u8> {
    if len < 16 {
        return Err(file::EINVAL);
    }
    if !proc::user_range_ok(ptr, 16) {
        return Err(file::EFAULT);
    }
    let b = unsafe { core::slice::from_raw_parts(ptr as *const u8, 16) };
    let fam = u16::from_le_bytes([b[0], b[1]]);
    if fam as i64 != 2 {
        return Err(crate::net::EAFNOSUPPORT); // AF_INET
    }
    let port = u16::from_be_bytes([b[2], b[3]]);
    Ok(([b[4], b[5], b[6], b[7]], port))
}

/// recvfrom: write the sender's sockaddr_in back to user memory
/// (best-effort; silently skipped on bad pointers — POSIX allows it? No,
/// but a wrong pointer here only loses the optional source address).
#[cfg(feature = "net")]
fn write_sockaddr_out(ptr: u64, len_ptr: u64, ip: &[u8; 4], port: u16) {
    if ptr == 0 || !proc::user_range_ok(ptr, 16) {
        return;
    }
    let b = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, 16) };
    b[0] = 2; // AF_INET LE
    b[1] = 0;
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(ip);
    for x in b[8..16].iter_mut() {
        *x = 0;
    }
    if len_ptr != 0 && proc::user_range_ok(len_ptr, 4) {
        unsafe { (len_ptr as *mut i32).write_unaligned(16) };
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

/// Fill musl-aarch64 `struct stat` at a user address. Offsets verified
/// against the toolchain's bits/stat.h: size@48, blksize@56, blocks@72,
/// atime@80, mtime@96, ctime@112 (v1: all three times = mtime).
fn write_linux_stat(addr: u64, mode: u32, size: u64, ino: u64, mtime: i64) -> Result<(), u8> {
    if !proc::user_range_ok(addr, 128) {
        return Err(14);
    }
    unsafe {
        let p = addr as *mut u8;
        core::ptr::write_bytes(p, 0, 128);
        // Offsets measured from musl aarch64 (gcc offsetof): dev@0 ino@8
        // mode@16 nlink@20 rdev@32 size@48 blksize@56 blocks@64
        // atim@72 mtim@88 ctim@104, sizeof 128. tv_sec slots get mtime,
        // tv_nsec stays 0.
        (p as *mut u64).add(0).write_unaligned(1); // st_dev
        (p as *mut u64).add(1).write_unaligned(ino);
        (p as *mut u32).add(4).write_unaligned(mode); // @16
        (p as *mut u32).add(5).write_unaligned(1); // nlink @20
        (p as *mut i64).add(6).write_unaligned(size as i64); // size @48
        (p as *mut i64).add(7).write_unaligned(4096); // blksize @56
        (p as *mut i64).add(8).write_unaligned(((size + 511) / 512) as i64); // blocks @64
        (p as *mut i64).add(9).write_unaligned(mtime); // atim.tv_sec @72
        (p as *mut i64).add(11).write_unaligned(mtime); // mtim.tv_sec @88
        (p as *mut i64).add(13).write_unaligned(mtime); // ctim.tv_sec @104
    }
    Ok(())
}

/// S_IFCHR|0666 (tty fds).
const MODE_CHR: u32 = 0x21B6;

/// stat by node index: type|perms, size, ino (= node+1), mtime.
fn stat_node(idx: usize, buf: u64) -> Result<(), u8> {
    let mode = if fs::is_symlink(idx) {
        0o120777 // S_IFLNK | 0777
    } else if fs::is_dir(idx) {
        0o40000 | fs::perms(idx) as u32
    } else {
        0o100000 | fs::perms(idx) as u32
    };
    write_linux_stat(
        buf,
        mode,
        fs::data_len(idx) as u64,
        (idx + 1) as u64,
        fs::mtime_of(idx),
    )
}

fn fstat_fd(fd: usize, buf: u64) -> Result<(), u8> {
    match proc::current_target(fd) {
        None => Err(file::EBADF),
        Some(FdTarget::File(i)) => {
            let node = file::node_of(i)?;
            stat_node(node, buf)
        }
        Some(_) => write_linux_stat(buf, MODE_CHR, 0, 1, 0),
    }
}

/// read_user_cstr as an option→EFAULT/ENOENT-friendly Result.
fn read_cstr(ptr: u64) -> String {
    proc::read_user_cstr(ptr, 128).unwrap_or_default()
}

/// renameat(2) core: (olddirfd, oldpath, newdirfd, newpath).
fn renameat_arm(od: i64, op: u64, nd: i64, np: u64) -> (i64, u8) {
    let Some(oldp) = proc::read_user_cstr(op, 128) else {
        return (0, 14);
    };
    let old = match resolve_path(od, oldp) {
        Ok(p) => p,
        Err(e) => return (0, e),
    };
    let Some(newp) = proc::read_user_cstr(np, 128) else {
        return (0, 14);
    };
    let new = match resolve_path(nd, newp) {
        Ok(p) => p,
        Err(e) => return (0, e),
    };
    match fs::rename(&old, &new) {
        Ok(()) => (0, 0),
        Err(e) => (0, e),
    }
}

/// utimensat(dirfd, path, times[2], flags): v1 tracks mtime only and
/// always follows symlinks (AT_SYMLINK_NOFOLLOW ignored); times=NULL
/// stamps "now".
fn utimensat(dirfd: i64, path_ptr: u64, times: u64) -> (i64, u8) {
    let Some(path) = proc::read_user_cstr(path_ptr, 128) else {
        return (0, 14);
    };
    let resolved = match resolve_path(dirfd, path) {
        Ok(p) => p,
        Err(e) => return (0, e),
    };
    let Some(idx) = fs::lookup(&resolved) else {
        return (0, 2);
    };
    let now = crate::arch::timer::unix_secs();
    if times == 0 {
        fs::set_mtime(idx, now);
        return (0, 0);
    }
    if !proc::user_range_ok(times, 32) {
        return (0, 14);
    }
    // mtime = times[1] = {tv_sec @+16, tv_nsec @+24}
    let (sec, nsec) = unsafe {
        (
            *((times + 16) as *const i64),
            *((times + 24) as *const i64),
        )
    };
    const UTIME_OMIT: i64 = 0x7FFF_FFFF;
    const UTIME_NOW: i64 = 0x3FFF_FFFF;
    let t = match nsec {
        UTIME_OMIT => return (0, 0), // mtime untouched
        UTIME_NOW => now,
        n if n >= 0 && n < 1_000_000_000 && sec >= 0 => sec,
        _ => return (0, 22),
    };
    fs::set_mtime(idx, t);
    (0, 0)
}

/// symlinkat(target, newdirfd, linkpath).
fn symlinkat_arm(target_ptr: u64, dirfd: i64, link_ptr: u64) -> (i64, u8) {
    let Some(target) = proc::read_user_cstr(target_ptr, 128) else {
        return (0, 14);
    };
    let Some(link) = proc::read_user_cstr(link_ptr, 128) else {
        return (0, 14);
    };
    match resolve_path(dirfd, link) {
        Err(e) => (0, e),
        Ok(path) => match fs::create_symlink(&path, &target) {
            Ok(_) => (0, 0),
            Err(e) => (0, e),
        },
    }
}

/// readlinkat(dirfd, path, buf, bufsiz): no NUL appended.
fn readlinkat_arm(dirfd: i64, path_ptr: u64, buf: u64, bufsiz: u64) -> (i64, u8) {
    let Some(path) = proc::read_user_cstr(path_ptr, 128) else {
        return (0, 14);
    };
    let resolved = match resolve_path(dirfd, path) {
        Ok(p) => p,
        Err(e) => return (0, e),
    };
    let Some(idx) = fs::lookup_nofollow(&resolved) else {
        return (0, 2);
    };
    if !fs::is_symlink(idx) {
        return (0, 22); // EINVAL on non-symlink
    }
    let bufsiz = bufsiz as usize;
    let n = fs::with_bytes(idx, |b: &[u8]| {
        let n = b.len().min(bufsiz);
        if n > 0 {
            if !proc::user_range_ok(buf, n as usize) {
                return None;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(b.as_ptr(), buf as *mut u8, n);
            }
        }
        Some(n)
    });
    match n {
        None => (0, 14),
        Some(n) => (n as i64, 0),
    }
}

/// Resolve (dirfd, path) to an absolute path. Absolute paths and
/// AT_FDCWD resolve as given (root-relative — no cwd tracking v1);
/// dirfd-relative paths are prefixed with the fd's directory.
fn resolve_path(dirfd: i64, path: String) -> Result<String, u8> {
    if path.starts_with('/') || dirfd == AT_FDCWD {
        return Ok(path);
    }
    if dirfd >= 0 {
        match proc::current_target(dirfd as usize) {
            Some(FdTarget::File(i)) => match file::path_of_fd(i) {
                Ok(dir) => {
                    let mut p = String::from(dir);
                    if p != "/" {
                        p.push('/');
                    }
                    p.push_str(&path);
                    Ok(p)
                }
                Err(e) => Err(e),
            },
            _ => Err(file::EBADF),
        }
    } else {
        Err(file::EINVAL)
    }
}

fn newfstatat(dirfd: i64, path_ptr: u64, buf: u64, flags: u64) -> (i64, u8) {
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
    let resolved = match resolve_path(dirfd, path) {
        Ok(p) => p,
        Err(e) => return (0, e),
    };
    // AT_SYMLINK_NOFOLLOW: stat the link itself, not its target.
    let idx = if flags & 0x100 != 0 {
        fs::lookup_nofollow(&resolved)
    } else {
        fs::lookup(&resolved)
    };
    match idx {
        None => (0, file::ENOENT),
        Some(i) => match stat_node(i, buf) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
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
            Some(FdTarget::Socket(s)) => {
                #[cfg(feature = "net")]
                {
                    if crate::net::sock_is_nonblock(s) {
                        (crate::net::O_NONBLOCK as i64, 0)
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
            None => (0, file::EBADF),
            _ => (0, 0), // TtyIn/TtyOut/Pipe: no flags tracked
        },
        // F_SETFL: O_NONBLOCK is load-bearing — musl's resolver polls a
        // non-blocking UDP socket and expects EAGAIN rather than a sleep.
        4 => match proc::current_target(fd) {
            Some(FdTarget::Socket(s)) => {
                #[cfg(feature = "net")]
                crate::net::sock_set_nonblock(s, arg & crate::net::O_NONBLOCK as i64 != 0);
                #[cfg(not(feature = "net"))]
                {
                    let _ = (s, arg);
                }
                (0, 0)
            }
            _ => (0, 0),
        },
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
                crate::hal::console::write_bytes(bytes);
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
