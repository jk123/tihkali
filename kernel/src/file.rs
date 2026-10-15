//! Global open-file table + per-process fd targets.
//!
//! Files are identified by node index into the writable `fs` table; offsets
//! live here and refcounts keep shared offsets alive across fork.

use core::cell::UnsafeCell;

use alloc::vec::Vec;

use crate::fs;

pub const ENOENT: u8 = 2;
pub const EINTR: u8 = 4;
pub const EIO: u8 = 5;
pub const ESRCH: u8 = 3;
pub const EBADF: u8 = 9;
pub const EACCES: u8 = 13;
pub const EFAULT: u8 = 14;
pub const EEXIST: u8 = 17;
pub const ENOTDIR: u8 = 20;
pub const EISDIR: u8 = 21;
pub const EINVAL: u8 = 22;
pub const ENOSPC: u8 = 28;
pub const EBUSY: u8 = 16;
pub const ENOTEMPTY: u8 = 66;

// NetBSD aarch64 open(2) flags (sys/fcntl.h).
pub const O_APPEND: u64 = 0x0008;
pub const O_CREAT: u64 = 0x0200;
pub const O_TRUNC: u64 = 0x0400;
pub const O_EXCL: u64 = 0x0800;

#[derive(Clone, Copy)]
pub enum FdTarget {
    TtyIn,
    TtyOut,
    File(usize),
    /// Anonymous pipe: (buffer slot, is this the write end?)
    Pipe { slot: usize, write_end: bool },
    /// Network socket: index into the kernel net.rs pool (N2).
    /// (Never constructed without the `net` feature — hence the allow.)
    #[cfg_attr(not(feature = "net"), allow(dead_code))]
    Socket(usize),
}

/// Fixed pool of anonymous pipes (v1: 8 × 512 B).
const NPIPES: usize = 8;
const PIPESZ: usize = 512;
/// Reported by fcntl(F_GETPIPE_SZ/F_SETPIPE_SZ).
pub const PIPE_SIZE: usize = PIPESZ;

struct PipeBuf {
    data: [u8; PIPESZ],
    head: u64, // monotonic
    tail: u64,
}

struct PipePool(UnsafeCell<[Option<PipeBuf>; NPIPES]>);
unsafe impl Sync for PipePool {}

static PIPES: PipePool = PipePool(UnsafeCell::new([const { None }; NPIPES]));

fn pipe(slot: usize) -> &'static mut PipeBuf {
    unsafe { (*PIPES.0.get())[slot].as_mut().expect("bad pipe slot") }
}

/// Create a pipe; returns its buffer slot.
pub fn pipe_create() -> Result<usize, u8> {
    let pool = unsafe { &mut *PIPES.0.get() };
    let slot = pool.iter().position(|p| p.is_none()).ok_or(28 /*ENOSPC*/)?;
    pool[slot] = Some(PipeBuf { data: [0; PIPESZ], head: 0, tail: 0 });
    Ok(slot)
}

pub enum PipeRead {
    Data(usize),
    WouldBlock,
}

/// Bytes queued in the pipe (poll readiness, no consumption).
pub fn pipe_avail(slot: usize) -> usize {
    let p = pipe(slot);
    (p.head - p.tail) as usize
}

/// Free space in the pipe buffer.
pub fn pipe_free(slot: usize) -> usize {
    let p = pipe(slot);
    (PIPESZ as u64 - (p.head - p.tail)) as usize
}

/// Pop up to `len` bytes into the user buffer.
pub fn pipe_read(slot: usize, addr: u64, len: usize) -> Result<PipeRead, u8> {
    if !crate::proc::user_range_ok(addr, len.max(1)) {
        return Err(14);
    }
    let p = pipe(slot);
    let avail = (p.head - p.tail) as usize;
    if avail == 0 {
        return Ok(PipeRead::WouldBlock);
    }
    let n = avail.min(len);
    unsafe {
        for i in 0..n {
            *((addr as usize + i) as *mut u8) = p.data[((p.tail + i as u64) as usize) % PIPESZ];
        }
    }
    p.tail += n as u64;
    Ok(PipeRead::Data(n))
}

/// Push bytes; returns how many were accepted (short write when full).
pub fn pipe_write(slot: usize, addr: u64, len: usize) -> Result<usize, u8> {
    if !crate::proc::user_range_ok(addr, len) {
        return Err(14);
    }
    let p = pipe(slot);
    let free = PIPESZ as u64 - (p.head - p.tail);
    let n = (len as u64).min(free) as usize;
    unsafe {
        for i in 0..n {
            p.data[((p.head + i as u64) as usize) % PIPESZ] = *((addr as usize + i) as *const u8);
        }
    }
    p.head += n as u64;
    Ok(n)
}

pub struct OpenFile {
    pub node: usize,
    pub pos: usize,
    pub refs: u8,
    /// Opened with O_WRONLY/O_RDWR (drives F_GETFL).
    pub writable: bool,
}

struct FileTable(UnsafeCell<Vec<Option<OpenFile>>>);
unsafe impl Sync for FileTable {}

static FILES: FileTable = FileTable(UnsafeCell::new(Vec::new()));

fn table() -> &'static mut Vec<Option<OpenFile>> {
    unsafe { &mut *FILES.0.get() }
}

/// open(2): read-only opens never create; write opens honor O_CREAT/O_TRUNC/
/// O_APPEND/O_EXCL. Directories open fine for getdents, but not for writing.
pub fn open(path: &str, flags: u64) -> Result<usize, u8> {
    let acc = flags & 3;
    if acc == 3 {
        return Err(EINVAL); // O_ACCMODE = 3 is invalid
    }
    let idx = if acc == 0 {
        // O_RDONLY
        fs::lookup(path).ok_or(ENOENT)?
    } else if flags & O_CREAT != 0 {
        match fs::lookup(path) {
            Some(i) => {
                if flags & O_EXCL != 0 {
                    return Err(EEXIST);
                }
                if fs::is_dir(i) {
                    return Err(EISDIR);
                }
                i
            }
            None => fs::create_file(path)?,
        }
    } else {
        let i = fs::lookup(path).ok_or(ENOENT)?;
        if fs::is_dir(i) {
            return Err(EISDIR);
        }
        i
    };

    if acc != 0 && flags & O_TRUNC != 0 {
        fs::truncate(idx);
    }
    let pos = if flags & O_APPEND != 0 { fs::data_len(idx) } else { 0 };

    let t = table();
    let slot = match t.iter().position(|f| f.is_none()) {
        Some(i) => i,
        None => {
            t.push(None);
            t.len() - 1
        }
    };
    t[slot] = Some(OpenFile { node: idx, pos, refs: 1, writable: acc != 0 });
    Ok(slot)
}

/// Share a file description with another process (fork).
pub fn dup(idx: usize) {
    if let Some(f) = &mut table()[idx] {
        f.refs = f.refs.saturating_add(1);
    }
}

/// Drop one reference; the slot is released at zero.
pub fn close(idx: usize) -> Result<(), u8> {
    let t = table();
    let Some(f) = t[idx].as_mut() else { return Err(EBADF) };
    f.refs -= 1;
    if f.refs == 0 {
        t[idx] = None;
    }
    Ok(())
}

/// Copy up to `len` bytes from the file at its current position.
/// Returns 0 at EOF.
pub fn read_to_user(idx: usize, addr: u64, len: usize) -> Result<usize, u8> {
    let (node, pos) = {
        let f = table()[idx].as_ref().ok_or(EBADF)?;
        (f.node, f.pos)
    };
    if fs::is_dir(node) {
        return Err(EISDIR);
    }
    let n = fs::read_to_user(node, pos, addr, len);
    table()[idx].as_mut().unwrap().pos += n;
    Ok(n)
}

/// Append `len` bytes from the (validated) user buffer at the current
/// position; grows the node and marks it dirty.
pub fn write_from_user(idx: usize, addr: u64, len: usize) -> Result<usize, u8> {
    let (node, pos) = {
        let f = table()[idx].as_ref().ok_or(EBADF)?;
        (f.node, f.pos)
    };
    if fs::is_dir(node) {
        return Err(EISDIR);
    }
    let n = fs::write_at(node, pos, addr, len);
    table()[idx].as_mut().unwrap().pos += n;
    Ok(n)
}

/// Fill a user buffer with `struct dirent` records (NetBSD `__getdents30`):
/// `{ino_t d_fileno; u16 d_reclen; u16 d_namlen; u8 d_type; char d_name[]}`
/// with d_name at offset 9; reclen = align4(10 + namlen). The per-open
/// cursor is `pos` = number of entries already returned.
pub fn getdents_to_user(idx: usize, addr: u64, len: usize) -> Result<usize, u8> {
    let (dir, mut pos) = {
        let f = table()[idx].as_ref().ok_or(EBADF)?;
        if !fs::is_dir(f.node) {
            return Err(ENOTDIR);
        }
        (fs::path_of(f.node), f.pos)
    };

    let list = fs::listable(dir);
    let mut written = 0usize;
    let mut matched = 0usize; // ordinal of the current matching entry (1-based)
    for node in list {
        matched += 1;
        if matched <= pos {
            continue; // already returned by previous getdents calls
        }
        let path = fs::path_of(node);
        let name = match path.rfind('/') {
            Some(i) => &path[i + 1..],
            None => path,
        };
        let namlen = name.len();
        let reclen = (9 + namlen + 1 + 3) & !3;
        if written + reclen > len {
            if written == 0 {
                return Err(EINVAL); // buffer too small even for one entry
            }
            break;
        }
        unsafe {
            let rec = (addr as *mut u8).add(written);
            rec.cast::<u32>().write_unaligned((node as u32) + 1); // d_fileno
            rec.add(4).cast::<u16>().write_unaligned(reclen as u16);
            rec.add(6).cast::<u16>().write_unaligned(namlen as u16);
            rec.add(8).write(if fs::is_dir(node) { 4 } else { 8 }); // DT_DIR/DT_REG
            core::ptr::copy_nonoverlapping(name.as_ptr(), rec.add(9), namlen);
            rec.add(9 + namlen).write(0); // NUL
            for off in (10 + namlen)..reclen {
                rec.add(off).write(0);
            }
        }
        written += reclen;
        pos = matched;
    }
    table()[idx].as_mut().unwrap().pos = pos;
    Ok(written)
}

/// Close every file fd an exiting process holds (tty/pipe targets need no
/// refcounting: pipe EOF is decided by scanning live fds in proc).
pub fn release_all(targets: &[Option<FdTarget>]) {
    for t in targets {
        match t {
            Some(FdTarget::File(i)) => {
                let _ = close(*i);
            }
            #[cfg(feature = "net")]
            // Each fd entry drops exactly one socket reference; the pool
            // slot tears down when the last distinct reference is gone.
            Some(FdTarget::Socket(s)) => crate::net::sock_ref_dec(*s),
            _ => {}
        }
    }
}

/// Fs node index behind an open file (for stat/chmod/ftruncate).
pub fn node_of(idx: usize) -> Result<usize, u8> {
    Ok(table()[idx].as_ref().ok_or(EBADF)?.node)
}

/// Fs node behind an open *fd* (resolves the process fd table first).
pub fn node_of_fd(fd: usize) -> Result<usize, u8> {
    match crate::proc::current_target(fd) {
        Some(FdTarget::File(i)) => node_of(i),
        _ => Err(EBADF),
    }
}

/// Path of an open file (for dirfd-relative lookups).
pub fn path_of_fd(idx: usize) -> Result<&'static str, u8> {
    let f = table()[idx].as_ref().ok_or(EBADF)?;
    if !fs::is_dir(f.node) {
        return Err(ENOTDIR);
    }
    Ok(fs::path_of(f.node))
}

/// Whether the description was opened for writing (F_GETFL).
pub fn is_writable(idx: usize) -> Result<bool, u8> {
    Ok(table()[idx].as_ref().ok_or(EBADF)?.writable)
}

/// lseek(2): SEEK_SET/CUR/END; returns the new absolute position.
pub fn lseek(idx: usize, offset: i64, whence: u32) -> Result<i64, u8> {
    let (node, pos) = {
        let f = table()[idx].as_ref().ok_or(EBADF)?;
        (f.node, f.pos as i64)
    };
    let new = match whence {
        0 => offset,
        1 => pos.checked_add(offset).ok_or(EINVAL)?,
        2 => fs::data_len(node) as i64 + offset,
        _ => return Err(EINVAL),
    };
    if new < 0 {
        return Err(EINVAL);
    }
    table()[idx].as_mut().unwrap().pos = new as usize;
    Ok(new)
}

/// getdents64(2) buffer fill — Linux `struct dirent64`:
/// {ino u64, off i64, reclen u16, d_type u8, name[]}, reclen = align8(20+namlen).
/// Cursor semantics identical to the NetBSD getdents path.
pub fn getdents64_to_user(idx: usize, addr: u64, len: usize) -> Result<usize, u8> {
    let (dir, mut pos) = {
        let f = table()[idx].as_ref().ok_or(EBADF)?;
        if !fs::is_dir(f.node) {
            return Err(ENOTDIR);
        }
        (fs::path_of(f.node), f.pos)
    };

    let list = fs::listable(dir);
    let mut written = 0usize;
    let mut matched = 0usize;
    for node in list {
        matched += 1;
        if matched <= pos {
            continue;
        }
        let path = fs::path_of(node);
        let name = match path.rfind('/') {
            Some(i) => &path[i + 1..],
            None => path,
        };
        let namlen = name.len();
        let reclen = (20 + namlen + 7) & !7; // header19 + name + NUL, 8-aligned
        if written + reclen > len {
            if written == 0 {
                return Err(EINVAL);
            }
            break;
        }
        unsafe {
            let rec = (addr as *mut u8).add(written);
            rec.cast::<u64>().write_unaligned((node as u64) + 1); // d_ino
            rec.add(8).cast::<i64>().write_unaligned(0); // d_off
            rec.add(16).cast::<u16>().write_unaligned(reclen as u16);
            rec.add(18).write(if fs::is_dir(node) { 4 } else { 8 }); // DT_*
            core::ptr::copy_nonoverlapping(name.as_ptr(), rec.add(19), namlen);
            rec.add(19 + namlen).write(0);
            for off in (20 + namlen)..reclen {
                rec.add(off).write(0);
            }
        }
        written += reclen;
        pos = matched;
    }
    table()[idx].as_mut().unwrap().pos = pos;
    Ok(written)
}
