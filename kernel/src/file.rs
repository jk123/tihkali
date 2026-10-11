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
}

pub struct OpenFile {
    pub node: usize,
    pub pos: usize,
    pub refs: u8,
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
    t[slot] = Some(OpenFile { node: idx, pos, refs: 1 });
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

/// Close every file fd an exiting process holds (tty targets need no action).
pub fn release_all(targets: &[Option<FdTarget>]) {
    for t in targets {
        if let Some(FdTarget::File(i)) = t {
            let _ = close(*i);
        }
    }
}
