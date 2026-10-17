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
