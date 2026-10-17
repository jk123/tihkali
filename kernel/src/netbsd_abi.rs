//! NetBSD syscall personality.
//!
//! Numbers are generated at build time from NetBSD's own
//! `sys/kern/syscalls.master` — the same table `makesyscalls.sh` consumes —
//! rather than transcribed by hand, so the compat_09..compat_110 numbering
//! stays authoritative. See `assets/bsd/THIRD-PARTY.txt` for its BSD
//! 4-clause attribution.

// Most of the 512 generated calls are not dispatched yet. A warning is a
// failure in this build, so the table must not trip dead_code.
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/netbsd_syscall_table.rs"));

/// tihkali's private display door, in the NetBSD ABI's number space.
///
/// These are NOT NetBSD syscalls — they collide with nothing NetBSD
/// defines on aarch64 and are unreachable from a real NetBSD libc, so
/// userland sees them as unknown.
pub mod fb {
    pub const INFO: u16 = 481;
    pub const FILL_RECT: u16 = 482;
    pub const BLIT: u16 = 483;
}

/// NetBSD aarch64 `struct stat` — 152 bytes, padded to 16-byte alignment.
///
/// Field offsets were verified by compiling the layout transcribed from
/// NetBSD's `sys/sys/stat.h` against the aarch64 ABI and reading the
/// offsets back out of the generated code. They are NOT the Linux ones:
/// Linux puts `st_size` at 48 and is 128 bytes overall, NetBSD puts it at
/// 112 and carries a fourth timestamp (`st_birthtim`) that Linux lacks.
pub const STAT_SIZE: usize = 152;

/// mode|perms for a node, matching NetBSD's S_IF* encoding.
fn node_mode(idx: usize) -> u32 {
    if crate::fs::is_symlink(idx) {
        0o120777 // S_IFLNK | 0777
    } else if crate::fs::is_dir(idx) {
        0o40000 | crate::fs::perms(idx) as u32
    } else {
        0o100000 | crate::fs::perms(idx) as u32
    }
}

/// Write `struct stat` for node `idx` to `addr` in NetBSD's layout.
pub fn write_stat_node(addr: u64, idx: usize) -> Result<(), u8> {
    if !crate::proc::user_range_ok(addr, STAT_SIZE) {
        return Err(14); // EFAULT
    }
    let mode = node_mode(idx);
    let size = crate::fs::data_len(idx) as u64;
    let ino = (idx + 1) as u64;
    let mtime = crate::fs::mtime_of(idx);
    unsafe {
        let p = addr as *mut u8;
        core::ptr::write_bytes(p, 0, STAT_SIZE);
        let u32at = |off: usize, v: u32| ((p as *mut u32).add(off / 4)).write_unaligned(v);
        let u64at = |off: usize, v: u64| ((p as *mut u64).add(off / 8)).write_unaligned(v);
        let i64at = |off: usize, v: i64| ((p as *mut i64).add(off / 8)).write_unaligned(v);
        u64at(0, 1); // st_dev
        u32at(8, mode); // st_mode
        u64at(16, ino); // st_ino
        u32at(24, 1); // st_nlink
        u32at(28, 0); // st_uid
        u32at(32, 0); // st_gid
        u64at(40, 0); // st_rdev
        // Four timestamps, 16 bytes each. Only tv_sec carries a value;
        // tv_nsec stays 0, matching what the Linux writer does.
        i64at(48, mtime); // st_atim.tv_sec
        i64at(64, mtime); // st_mtim.tv_sec
        i64at(80, mtime); // st_ctim.tv_sec
        i64at(96, mtime); // st_birthtim.tv_sec
        i64at(112, size as i64); // st_size
        i64at(120, ((size + 511) / 512) as i64); // st_blocks
        u32at(128, 4096); // st_blksize
        u32at(132, 0); // st_flags
        u32at(136, 0); // st_gen
    }
    Ok(())
}

/// Write `struct stat` for an open fd (a tty reports char-device mode).
pub fn write_stat_fd(addr: u64, fd: usize) -> Result<(), u8> {
    match crate::proc::current_target(fd) {
        None => Err(crate::file::EBADF),
        Some(crate::file::FdTarget::File(i)) => {
            let node = crate::file::node_of(i)?;
            write_stat_node(addr, node)
        }
        // S_IFCHR | 0666, as on the Linux side.
        Some(_) => {
            if !crate::proc::user_range_ok(addr, STAT_SIZE) {
                return Err(14);
            }
            unsafe {
                let p = addr as *mut u8;
                core::ptr::write_bytes(p, 0, STAT_SIZE);
                ((p as *mut u64).add(0)).write_unaligned(1);
                ((p as *mut u32).add(2)).write_unaligned(0o210666); // st_mode @8
                ((p as *mut u64).add(2)).write_unaligned(1); // st_ino @16
            }
            Ok(())
        }
    }
}
/// Cap on iovcnt, matching the Linux arm's existing bound.
const IOV_MAX: u64 = 64;

/// Read a user iovec array into `(base, len)` pairs.
///
/// NetBSD's `struct iovec` is `{ void *iov_base; size_t iov_len; }` —
/// verified against `sys/sys/uio.h`, and identical to Linux's, so the
/// 16-byte stride is shared rather than assumed.
///
/// `None` means iovcnt is out of range; `Err` is the errno for an
/// unreadable entry. Validating every entry up front matters: a partial
/// walk that faults halfway would leave the caller unable to tell which
/// vectors were consumed.
pub fn walk_iovecs(iov: u64, cnt: u64) -> Result<alloc::vec::Vec<(u64, u64)>, u8> {
    if cnt > IOV_MAX {
        return Err(22); // EINVAL
    }
    let mut out = alloc::vec::Vec::with_capacity(cnt as usize);
    for i in 0..cnt {
        let base = crate::proc::read_user_u64(iov + 16 * i).ok_or(14u8)?;
        let len = crate::proc::read_user_u64(iov + 16 * i + 8).ok_or(14u8)?;
        out.push((base, len));
    }
    Ok(out)
}

// ---------- kqueue ----------

/// NetBSD aarch64 `struct kevent` — **72 bytes**.
///
/// Layout measured by compiling the `struct kevent` from `sys/sys/event.h`
/// against the aarch64 ABI with the vendored cross gcc and reading the
/// `offsetof` immediates out of the object file:
///
///   ident@0 u64, filter@8 u32, flags@12 u32, fflags@16 u32,
///   data@24 i64, udata@32 u64, ext[4]@40 => 72 bytes
///
/// Three traps, each of which compiles and runs while reading garbage:
/// `ident` is a full 8-byte `uintptr_t`, so `filter` starts at offset 8 and
/// not 4; `filter` and `flags` are `uint32_t` despite every reference
/// spelling them as u16 — reading them as u16 yields the right *value*
/// while putting every later field at the wrong address; and the trailing
/// `ext[4]` is easy to forget when adding up the size. Linux's kevent also
/// leads with `udata`, so copying the Linux arm would hand back the wrong
/// opaque pointer.
pub const KEVENT_SIZE: usize = 72;

/// `filter` and `flags` are `uint32_t`, not `uint16_t`. Reading them as u16
/// would appear to work -- the low half holds the value and the value is
/// small -- while every later field lands at the wrong address.
struct Ke {
    ident: u64,
    filter: u32,
    flags: u32,
    fflags: u32,
    data: i64,
    udata: u64,
}

fn ke_read(addr: u64) -> Option<Ke> {
    if !crate::proc::user_range_ok(addr, KEVENT_SIZE) {
        return None;
    }
    unsafe {
        let p = addr as *const u8;
        Some(Ke {
            ident: (p as *const u64).read_unaligned(),
            filter: (p as *const u32).add(2).read_unaligned(),
            flags: (p as *const u32).add(3).read_unaligned(),
            fflags: (p as *const u32).add(4).read_unaligned(),
            data: (p as *const i64).add(3).read_unaligned(),
            udata: (p as *const u64).add(4).read_unaligned(),
        })
    }
}

fn ke_write(
    addr: u64,
    k: &crate::proc::Kevent,
    filter: u32,
    flags: u32,
    data: i64,
    fflags: u32,
) {
    unsafe {
        let p = addr as *mut u8;
        (p as *mut u64).write_unaligned(k.ident);
        (p as *mut u32).add(2).write_unaligned(filter);
        (p as *mut u32).add(3).write_unaligned(flags);
        (p as *mut u32).add(4).write_unaligned(fflags);
        (p as *mut i64).add(3).write_unaligned(data);
        (p as *mut u64).add(4).write_unaligned(k.udata);
        for i in 0..4 {
            (p as *mut u64).add(5 + i).write_unaligned(0);
        }
    }
}

/// Is this registration's fd ready for its filter right now?
fn ke_ready(k: &crate::proc::Kevent) -> Option<i64> {
    let fd = k.ident as i64;
    if fd < 0 {
        return None;
    }
    let target = crate::proc::current_target(fd as usize)?;
    let (recv, send) = match target {
        crate::file::FdTarget::TtyIn => (crate::tty::has_data(), false),
        crate::file::FdTarget::TtyOut => (false, true),
        crate::file::FdTarget::File(_) => (true, true),
        crate::file::FdTarget::Pipe { slot, write_end: false } => {
            let eof = crate::proc::pipe_end_count(slot, true) == 0;
            (crate::file::pipe_avail(slot) > 0 || eof, false)
        }
        crate::file::FdTarget::Pipe { slot, write_end: true } => (
            false,
            crate::proc::pipe_end_count(slot, false) > 0 && crate::file::pipe_free(slot) > 0,
        ),
        #[cfg(feature = "net")]
        crate::file::FdTarget::Socket(s) => match crate::net::sock_poll(s) {
            Some((r, w)) => (r, w),
            None => return None,
        },
        #[cfg(not(feature = "net"))]
        crate::file::FdTarget::Socket(_) => return None,
        crate::file::FdTarget::Kqueue => (crate::proc::kq_any_ready(), false),
    };
    match k.filter {
        crate::proc::EVFILT_READ => recv.then_some(1),
        crate::proc::EVFILT_WRITE => send.then_some(1),
        _ => None,
    }
}

/// `kevent(2)` for the NetBSD personality.
///
/// Returns the number of events written, `Err` with an errno, or `Slept`
/// when the caller parked waiting (the syscall epilogue must not run then).
pub fn kevent_arm(frame: &mut crate::arch::trap::TrapFrame) -> crate::proc::Io {
    use crate::proc::Io;
    let changelist = frame.x[1];
    let nchanges = frame.x[2] as u64;
    let eventlist = frame.x[3];
    let nevents = frame.x[4] as u64;
    let timeout_ptr = frame.x[5];

    if nchanges > crate::proc::KQUEUE_MAX as u64 || nevents > crate::proc::KQUEUE_MAX as u64 {
        return Io::Err(22); // EINVAL
    }
    if nevents != 0 && !crate::proc::user_range_ok(eventlist, (nevents * KEVENT_SIZE as u64) as usize) {
        return Io::Err(14); // EFAULT
    }

    // --- changelist ---
    for i in 0..nchanges {
        let addr = changelist + i * KEVENT_SIZE as u64;
        let Some(k) = ke_read(addr) else {
            return Io::Err(14);
        };
        if k.filter == crate::proc::EVFILT_SIGNAL {
            // EVFILT_SIGNAL watches a SIGNAL NUMBER on the calling process.
            // fflags carries no note bits: the note IS the signal, and it
            // comes back in `data`. There is nothing to narrow with, so no
            // NOTE_FFAND/NOTE_FFOR handling here.
            let sig = k.ident;
            if sig == 0 || sig >= crate::proc::NSIG as u64 {
                return Io::Err(22); // EINVAL: not a signal number
            }
            if k.flags & crate::proc::EV_DELETE != 0 {
                match crate::proc::kq_delete(sig, k.filter) {
                    Ok(()) => {}
                    Err(e) => return Io::Err(e),
                }
                continue;
            }
            if k.flags & (crate::proc::EV_ADD | crate::proc::EV_ENABLE) == 0 {
                if k.flags & crate::proc::EV_DISABLE != 0 {
                    let regs = crate::proc::kq_regs();
                    match regs
                        .iter_mut()
                        .find(|e| e.ident == sig && e.filter == k.filter)
                    {
                        Some(e) => e.flags |= crate::proc::EV_DISABLE,
                        None => return Io::Err(2),
                    }
                    continue;
                }
                return Io::Err(22);
            }
            // Only a FIRST registration baselines history, so re-enabling a
            // filter that was disabled while signals arrived does not
            // discard them.
            let prior = crate::proc::kq_regs()
                .iter()
                .find(|e| e.ident == sig && e.filter == k.filter)
                .map(|e| e.vseq);
            let seq = match prior {
                Some(v) => v,
                None => {
                    crate::proc::sig_clear(sig);
                    crate::proc::sig_seq(sig)
                }
            };
            let mut r = crate::proc::Kevent {
                ident: sig,
                vseq: seq,
                filter: k.filter,
                flags: 0,
                fflags: k.fflags,
                udata: k.udata,
            };
            if k.flags & crate::proc::EV_DISABLE != 0 {
                r.flags |= crate::proc::EV_DISABLE;
            }
            r.flags |= k.flags & (crate::proc::EV_ONESHOT | crate::proc::EV_CLEAR);
            if let Err(e) = crate::proc::kq_add(r) {
                return Io::Err(e);
            }
            continue;
        }
        if k.filter == crate::proc::EVFILT_PROC {
            // EVFILT_PROC watches a PID, not a path or a descriptor.
            let pid = k.ident as usize;
            if pid == 0 || !crate::proc::pid_exists(pid) {
                // ESRCH: the process this asks about is gone. Registering
                // anyway would watch an event that can never arrive.
                return Io::Err(3);
            }
            if k.flags & crate::proc::EV_DELETE != 0 {
                match crate::proc::kq_delete(pid as u64, k.filter) {
                    Ok(()) => {}
                    Err(e) => return Io::Err(e),
                }
                continue;
            }
            if k.flags & (crate::proc::EV_ADD | crate::proc::EV_ENABLE) == 0 {
                if k.flags & crate::proc::EV_DISABLE != 0 {
                    let regs = crate::proc::kq_regs();
                    let hit = regs
                        .iter_mut()
                        .find(|e| e.ident == pid as u64 && e.filter == k.filter);
                    match hit {
                        Some(e) => e.flags |= crate::proc::EV_DISABLE,
                        None => return Io::Err(2),
                    }
                    continue;
                }
                return Io::Err(22);
            }
            // Same rule as EVFILT_VNODE: only a first registration
            // baselines history, so re-widening a narrowed filter does not
            // discard events that arrived in between.
            let prior = crate::proc::kq_regs()
                .iter()
                .find(|e| e.ident == pid as u64 && e.filter == k.filter)
                .map(|e| e.vseq);
            // A pid whose slot is GONE can only have pending events: it has
            // no future to baseline against. Clearing there would discard
            // exactly the NOTE_EXIT/NOTE_EXEC the watcher came for.
            let seq = match prior {
                Some(v) => v,
                None => {
                    if crate::proc::pid_exists(pid) {
                        crate::proc::proc_clear(pid);
                    }
                    crate::proc::proc_seq(pid)
                }
            };
            let mut r = crate::proc::Kevent {
                ident: pid as u64,
                vseq: seq,
                filter: k.filter,
                flags: if k.flags & crate::proc::EV_DISABLE != 0 {
                    crate::proc::EV_DISABLE
                } else {
                    0
                },
                fflags: k.fflags,
                udata: k.udata,
            };
            r.flags |= k.flags & (crate::proc::EV_ONESHOT | crate::proc::EV_CLEAR);
            if let Err(e) = crate::proc::kq_add(r) {
                return Io::Err(e);
            }
            continue;
        }
        let is_vnode = k.filter == crate::proc::EVFILT_VNODE;
        // Filters needing kernel objects this kernel does not have are
        // refused here rather than registered and never delivered. The
        // remaining NetBSD filters are EVFILT_AIO (no async I/O at all),
        // EVFILT_TIMER (ident is a nanosecond timeout, a different clock
        // from the tick timer signals use), EVFILT_FS and EVFILT_USER.
        if k.filter != crate::proc::EVFILT_READ
            && k.filter != crate::proc::EVFILT_WRITE
            && !is_vnode
            && k.filter != crate::proc::EVFILT_PROC
            && k.filter != crate::proc::EVFILT_SIGNAL
        {
            if k.filter == crate::proc::EVFILT_AIO {
                return Io::Err(38); // ENOSYS: no aio subsystem to attach to
            }
            return Io::Err(22); // EINVAL
        }
        if is_vnode {
            // EVFILT_VNODE watches a PATH, not a descriptor, so `ident` is
            // a pointer to a string rather than an fd.
            let raw = match crate::proc::read_user_cstr(k.ident, 256) {
                Some(p) => p,
                None => return Io::Err(14),
            };
            match crate::fs::lookup(&crate::proc::abspath(&raw)) {
                None => return Io::Err(crate::file::ENOENT),
                Some(idx) => {
                    if k.flags & crate::proc::EV_DELETE != 0 {
                        match crate::proc::kq_delete(idx as u64, k.filter) {
                            Ok(()) => {}
                            Err(e) => return Io::Err(e),
                        }
                        continue;
                    }
                    if k.flags & (crate::proc::EV_ADD | crate::proc::EV_ENABLE) == 0 {
                        if k.flags & crate::proc::EV_DISABLE != 0 {
                            let regs = crate::proc::kq_regs();
                            let hit = regs
                                .iter_mut()
                                .find(|e| e.ident == idx as u64 && e.filter == k.filter);
                            match hit {
                                Some(e) => e.flags |= crate::proc::EV_DISABLE,
                                None => return Io::Err(2),
                            }
                            continue;
                        }
                        return Io::Err(22);
                    }
                    // Re-registering must not silently discard a note the
                    // watcher has not been told about yet, and must not
                    // re-baseline the generation either: a narrowed filter
                    // that is widened again must still deliver the events
                    // that arrived while it was narrowed.
                    //
                    // Only the FIRST registration baselines -- a brand new
                    // watcher must not be woken by history it never asked
                    // about. A re-registration keeps the existing entry's
                    // generation, so anything already pending still fires.
                    let prior = crate::proc::kq_regs()
                        .iter()
                        .find(|e| e.ident == idx as u64 && e.filter == k.filter)
                        .map(|e| e.vseq);
                    let seq = match prior {
                        Some(v) => {
                            if v == 0 {
                                crate::fs::vnode_clear_notes(idx);
                            }
                            v
                        }
                        None => {
                            crate::fs::vnode_clear_notes(idx);
                            crate::fs::vnode_seq(idx)
                        }
                    };
                    let mut r = crate::proc::Kevent {
                        ident: idx as u64,
                        vseq: seq,
                        filter: k.filter,
                        flags: if k.flags & crate::proc::EV_DISABLE != 0 {
                            crate::proc::EV_DISABLE
                        } else {
                            0
                        },
                        fflags: k.fflags,
                        udata: k.udata,
                    };
                    r.flags |= k.flags & (crate::proc::EV_ONESHOT | crate::proc::EV_CLEAR);
                    if let Err(e) = crate::proc::kq_add(r) {
                        return Io::Err(e);
                    }
                    continue;
                }
            }
        }
        if k.ident as i64 >= 0 && crate::proc::current_target(k.ident as usize).is_none() {
            // EV_ERROR would be reported in the event list; failing the
            // whole call is simpler and still tells the caller the fd is
            // bad.
            return Io::Err(9); // EBADF
        }
        if k.flags & crate::proc::EV_DELETE != 0 {
            match crate::proc::kq_delete(k.ident, k.filter) {
                Ok(()) => {}
                Err(e) => return Io::Err(e),
            }
            continue;
        }
        // EV_ADD and EV_ENABLE both mean "registered"; EV_DISABLE only
        // silences an existing one, so keep the entry but mark it off.
        if k.flags & crate::proc::EV_ADD != 0 || k.flags & crate::proc::EV_ENABLE != 0 {
            let mut r = crate::proc::Kevent {
                ident: k.ident,
                vseq: 0,
                filter: k.filter,
                flags: if k.flags & crate::proc::EV_DISABLE != 0 {
                    crate::proc::EV_DISABLE
                } else {
                    0
                },
                fflags: k.fflags,
                udata: k.udata,
            };
            r.flags |= k.flags & (crate::proc::EV_ONESHOT | crate::proc::EV_CLEAR);
            if let Err(e) = crate::proc::kq_add(r) {
                return Io::Err(e);
            }
        } else if k.flags & crate::proc::EV_DISABLE != 0 {
            // Disable an existing registration without adding a new one.
            let regs = crate::proc::kq_regs();
            if let Some(e) = regs.iter_mut().find(|e| e.ident == k.ident && e.filter == k.filter) {
                e.flags |= crate::proc::EV_DISABLE;
            } else {
                return Io::Err(2); // ENOENT
            }
        }
    }

    // --- eventlist ---
    #[cfg(feature = "net")]
    crate::net::poll_tick();

    let mut n = 0u64;
    let regs = crate::proc::kq_regs();
    let mut keep: alloc::vec::Vec<crate::proc::Kevent> = alloc::vec::Vec::new();
    for r in regs.iter() {
        if n >= nevents {
            keep.push(*r);
            continue;
        }
        if r.flags & crate::proc::EV_DISABLE != 0 {
            keep.push(*r);
            continue;
        }
        // A vnode event reports the NOTE bits that fired in fflags and
        // re-bases the registration's generation, so the same change is not
        // reported twice.
        let ready = if r.filter == crate::proc::EVFILT_VNODE {
            crate::proc::kq_vnode_ready(r).map(|notes| (notes, 0i64))
        } else if r.filter == crate::proc::EVFILT_PROC {
            crate::proc::kq_proc_ready(r).map(|(notes, child)| (notes, child as i64))
        } else if r.filter == crate::proc::EVFILT_SIGNAL {
            crate::proc::kq_sig_ready(r).map(|sig| (0u32, sig as i64))
        } else {
            ke_ready(r).map(|nbytes| (0u32, nbytes))
        };
        match ready {
            Some((notes, val)) => {
                let is_vn = r.filter == crate::proc::EVFILT_VNODE;
                let is_pp = r.filter == crate::proc::EVFILT_PROC;
                // For EVFILT_PROC, `data` carries the pid that triggered the
                // event -- the child for NOTE_FORK, the process itself for
                // NOTE_EXEC/NOTE_EXIT. It is taken from the low bits of the
                // pending note so a watcher learns WHICH pid it was.
                // For EVFILT_PROC, `data` carries the pid that triggered the
                // event -- the child for NOTE_FORK, the process itself for
                // NOTE_EXEC/NOTE_EXIT. For EVFILT_SIGNAL it carries the
                // signal number.
                ke_write(
                    eventlist + n * KEVENT_SIZE as u64,
                    r,
                    r.filter,
                    0,
                    val,
                    if is_vn || is_pp { notes } else { r.fflags },
                );
                n += 1;
                let is_sig = r.filter == crate::proc::EVFILT_SIGNAL;
                if is_vn || is_pp || is_sig {
                    // Re-base the registration's generation so the next
                    // call reports only what happens after this one, then
                    // KEEP it. Dropping it here would silently unregister
                    // the watcher after its first event.
                    let mut next = *r;
                    next.vseq = if is_pp {
                        crate::proc::proc_seq(r.ident as usize)
                    } else if is_sig {
                        crate::proc::sig_seq(r.ident)
                    } else {
                        crate::fs::vnode_seq(r.ident as usize)
                    };
                    if r.flags & crate::proc::EV_ONESHOT != 0 {
                        continue; // drop it
                    }
                    keep.push(next);
                    continue;
                }
                if r.flags & crate::proc::EV_ONESHOT != 0 {
                    continue; // drop it
                }
                keep.push(*r);
            }
            None => keep.push(*r),
        }
    }
    *regs = keep;

    if n > 0 {
        crate::proc::deadline_clear();
        return Io::Val(n as i64);
    }
    if crate::proc::has_deliverable() {
        crate::proc::deadline_clear();
        return Io::Err(4); // EINTR
    }
    if nevents == 0 {
        // A pure changelist call never blocks, whatever the timeout says.
        crate::proc::deadline_clear();
        return Io::Val(0);
    }

    // --- park ---
    // A null timeout blocks indefinitely; anything else is a timespec.
    if timeout_ptr != 0 {
        if !crate::proc::user_range_ok(timeout_ptr, 16) {
            return Io::Err(14);
        }
        let (sec, nsec) = unsafe {
            (
                (timeout_ptr as *const i64).read_unaligned(),
                (timeout_ptr as *const i64).add(1).read_unaligned(),
            )
        };
        if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return Io::Err(22);
        }
        if sec == 0 && nsec == 0 {
            return Io::Val(0); // pure poll
        }
        let ms = (sec as u64).saturating_mul(1000) + (nsec as u64) / 1_000_000;
        let at = crate::arch::timer::now().saturating_add(ms);
        crate::proc::sleep_timed(frame, at);
        return Io::Slept;
    }
    crate::proc::deadline_clear();
    crate::proc::sleep_current(frame);
    Io::Slept
}

// ---------- uname ----------

/// NetBSD `struct utsname`: five 256-byte char arrays, no padding.
/// 1280 bytes total -- not Linux's 390, and not a subset of it.
///
/// Measured with the vendored cross gcc against sys/sys/utsname.h:
///   sysname@0 nodename@256 release@512 version@768 machine@1024
pub const UTSNAME_SIZE: usize = 1280;

const NMLN: usize = 256;

pub fn write_utsname(buf: u64) {
    let fields: [(usize, &[u8]); 5] = [
        (0, b"NetBSD\0"),
        (NMLN, b"tihkali\0"),
        (2 * NMLN, b"0.1.0\0"),
        (3 * NMLN, b"tihkali aarch64\0"),
        (4 * NMLN, b"aarch64\0"),
    ];
    unsafe {
        let p = buf as *mut u8;
        // Zero the whole struct first: a caller that memcmp()s it must not
        // see stack garbage in the unused tail of each 256-byte field.
        core::ptr::write_bytes(p, 0, UTSNAME_SIZE);
        for (off, s) in fields {
            core::ptr::copy_nonoverlapping(s.as_ptr(), p.add(off), s.len());
        }
    }
}

// ---------- ioctl ----------

// NetBSD's ioctl request encoding is NOT Linux's, despite the same TIOC*
// names, the same 't' group character and the same parameter sizes.
//
// Linux:    dir<<30 | size<<16 | 't'<<8 | num      (IOC_VOID 0, O 1<<1, I 1<<2)
// NetBSD:   dir in bits 29-31, with IOC_IN 0x80000000 and IOC_OUT
//           0x40000000 -- the two are SWAPPED relative to Linux's sense.
//
// Values below are computed from sys/sys/ioccom.h and sys/sys/ttycom.h.
// Linux's TIOCGWINSZ is 0x5413; NetBSD's is 0x80087468, so a kernel that
// reused the Linux table would reject every request a NetBSD caller makes
// with ENOTTY.
pub const TIOCEXCL: u64 = 0x2000740d;
pub const TIOCNXCL: u64 = 0x2000740e;
pub const TIOCFLUSH: u64 = 0x40047410;
pub const TIOCGETA: u64 = 0x802c7413;
pub const TIOCSETA: u64 = 0x402c7414;
pub const TIOCSETAW: u64 = 0x402c7415;
pub const TIOCSETAF: u64 = 0x402c7416;
pub const TIOCGETD: u64 = 0x8004741a;
pub const TIOCSETD: u64 = 0x4004741b;
pub const TIOCGLINED: u64 = 0x80047442;
pub const TIOCSLINED: u64 = 0x40047443;
pub const TIOCSWINSZ: u64 = 0x40087467;
pub const TIOCGWINSZ: u64 = 0x80087468;
pub const TIOCREMOTE: u64 = 0x40047469;
pub const TIOCMGET: u64 = 0x8004746a;
pub const TIOCMBIC: u64 = 0x4004746b;
pub const TIOCMBIS: u64 = 0x4004746c;
pub const TIOCMSET: u64 = 0x4004746d;
pub const TIOCSTART: u64 = 0x2000746e;
pub const TIOCSTOP: u64 = 0x2000746f;
pub const TIOCPKT: u64 = 0x40047470;
pub const TIOCNOTTY: u64 = 0x20007471;
pub const TIOCSTI: u64 = 0x40017472;
pub const TIOCOUTQ: u64 = 0x80047473;
pub const TIOCSPGRP: u64 = 0x40047476;
pub const TIOCGPGRP: u64 = 0x80047477;
pub const TIOCCDTR: u64 = 0x20007478;
pub const TIOCSDTR: u64 = 0x20007479;
pub const TIOCCBRK: u64 = 0x2000747a;
pub const TIOCSBRK: u64 = 0x2000747b;

/// NetBSD `struct termios`: 4 x tcflag_t(u32) + c_cc[NCCS=20] + 2 x int
/// = **44 bytes**, against Linux's 36 (whose NCCS is 19).
///
/// NetBSD's local-flag values are POSIX, not Linux's: ICANON is 0x100
/// here and 0x2 on Linux, ECHO is 0x8 here and 0x10 on Linux. Copying the
/// Linux writer would leave the caller reading garbage flags while the
/// call returned 0.
pub const TERMIOS_SIZE: usize = 44;
pub const NB_NCCS: usize = 20;
pub const NB_ICANON: u32 = 0x100;
pub const NB_ECHO: u32 = 0x8;

/// Fill a NetBSD `struct termios` with the same state the Linux arm
/// reports: canonical input, echoing.
pub fn write_netbsd_termios(arg: u64) -> Result<(), u8> {
    if !crate::proc::user_range_ok(arg, TERMIOS_SIZE) {
        return Err(14); // EFAULT
    }
    unsafe {
        let p = arg as *mut u8;
        core::ptr::write_bytes(p, 0, TERMIOS_SIZE);
        // c_lflag @12: ICANON | ECHO
        (p as *mut u32).add(3).write_unaligned(NB_ICANON | NB_ECHO);
        // c_ispeed @36, c_ospeed @40: 4 flags (16 B) + c_cc[20] (20 B).
        // B115200 (13) is what a real tty reports and what a libc uses to
        // pick its baud divisor. Writing these at 40/44 would be 4 B past
        // the end of a 44-byte struct -- corrupting the caller's stack.
        (p as *mut u32).add(9).write_unaligned(0x0000_000d);
        (p as *mut u32).add(10).write_unaligned(0x0000_000d);
    }
    Ok(())
}

/// `ioctl(2)` for the NetBSD personality.
///
/// Shares the same fake-terminal policy as the Linux arm — the same winsize,
/// the same process-group handling — but with NetBSD's request encoding and
/// NetBSD's termios layout.
pub fn ioctl_arm(fd: usize, cmd: u64, arg: u64) -> (i64, u8) {
    use crate::file::EBADF;
    if crate::proc::current_target(fd).is_none() {
        return (-1, EBADF);
    }
    match cmd {
        TIOCGETA => match write_netbsd_termios(arg) {
            Ok(()) => (0, 0),
            Err(e) => (-1, e),
        },
        // Accept and ignore. A tty with no real line discipline here cannot
        // honour these, but refusing them would make a libc's termios setup
        // fail outright rather than degrade.
        TIOCSETA | TIOCSETAW | TIOCSETAF | TIOCSETD | TIOCSLINED | TIOCREMOTE
        | TIOCMSET | TIOCMBIS | TIOCMBIC | TIOCPKT => (0, 0),
        TIOCGLINED => {
            // The only line discipline a libc asks for is N_TTY (1).
            if !crate::proc::user_range_ok(arg, 4) {
                return (-1, 14);
            }
            unsafe { (arg as *mut u32).write_volatile(1) };
            (0, 0)
        }
        TIOCGWINSZ => {
            // struct winsize { ws_row, ws_col, ws_xpixel, ws_ypixel }: u16 x4
            if !crate::proc::user_range_ok(arg, 8) {
                return (-1, 14);
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
        TIOCSWINSZ => {
            if !crate::proc::user_range_ok(arg, 8) {
                return (-1, 14);
            }
            (0, 0)
        }
        TIOCGPGRP => {
            if !crate::proc::user_range_ok(arg, 4) {
                return (-1, 14);
            }
            let g = crate::proc::fg_pgrp().unwrap_or_else(crate::proc::current_pgrp) as i32;
            unsafe { (arg as *mut i32).write_volatile(g) };
            (0, 0)
        }
        TIOCSPGRP => {
            if !crate::proc::user_range_ok(arg, 4) {
                return (-1, 14);
            }
            let g = unsafe { (arg as *const i32).read_volatile() };
            if g < 0 {
                return (-1, 22);
            }
            crate::proc::set_fg_pgrp(g as usize);
            (0, 0)
        }
        TIOCOUTQ => {
            if !crate::proc::user_range_ok(arg, 4) {
                return (-1, 14);
            }
            unsafe { (arg as *mut i32).write_volatile(0) };
            (0, 0)
        }
        TIOCMGET => {
            // No modem: a console UART on the other end reports nothing
            // about carrier or line state.
            if !crate::proc::user_range_ok(arg, 4) {
                return (-1, 14);
            }
            unsafe { (arg as *mut i32).write_volatile(0) };
            (0, 0)
        }
        TIOCFLUSH => (0, 0),
        TIOCGETD => {
            if !crate::proc::user_range_ok(arg, 4) {
                return (-1, 14);
            }
            unsafe { (arg as *mut i32).write_volatile(1) }; // N_TTY
            (0, 0)
        }
        // Accepted no-ops: there is no modem, no packet mode and no break
        // bit to set on a fixed emulated console.
        TIOCEXCL | TIOCNXCL | TIOCSTART | TIOCSTOP | TIOCNOTTY | TIOCCDTR
        | TIOCSDTR | TIOCCBRK | TIOCSBRK => (0, 0),
        _ => {
            crate::kprintln!("[netbsd] ioctl ENOTTY cmd={cmd:#x} fd={fd}");
            (-1, 25) // ENOTTY
        }
    }
}
