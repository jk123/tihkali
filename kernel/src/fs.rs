//! Writable initramfs: mutable in-memory nodes plus cpio write-back.
//!
//! Mount parses the boot-time archive into owned nodes; `create`/`write`
//! mutate them in place and mark them dirty; `sync_to_disk` rebuilds the
//! whole cpio image and writes it back through the block device.

use core::cell::UnsafeCell;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::kprintln;

use crate::cpio;
use crate::file::{EIO, ENOENT, ENOSPC, ENOTDIR, EEXIST, EISDIR, EBUSY, ENOTEMPTY};
use crate::virtio_blk;

pub struct FsNode {
    path: String,
    data: Vec<u8>,
    is_dir: bool,
    /// Symlink: `data` holds the target path (Alpine-style /bin/cat links).
    symlink: bool,
    dirty: bool,
    /// Tombstone: index stays stable for open fds; hidden from lookup,
    /// listing and write-back (sync drops it from the disk image).
    removed: bool,
    /// Permission bits (0o7777). Type bits live in is_dir/symlink.
    mode: u16,
    /// Modification time (unix seconds); persisted through cpio.
    mtime: i64,
    /// EVFILT_VNODE generation counter. Bumped on every change a watcher
    /// could care about; kqueue compares it against the value recorded at
    /// registration, so no notification can be lost between syscalls.
    vseq: u32,
    /// NOTE_* bits accumulated since the last drain, for EVFILT_VNODE.
    /// Held on the node rather than in a global log so that a change made
    /// while no watcher exists is simply never observed.
    vnotes: u32,
}

struct Nodes(UnsafeCell<Option<Vec<FsNode>>>);
unsafe impl Sync for Nodes {}

static NODES: Nodes = Nodes(UnsafeCell::new(None));

fn nodes() -> &'static mut Vec<FsNode> {
    unsafe { (*NODES.0.get()).as_mut().expect("initramfs not mounted") }
}

/// Parse the boot archive into owned nodes. Returns the entry count.
pub fn mount(img: Vec<u8>) -> usize {
    let raw = cpio::parse(&img);
    let mut v: Vec<FsNode> = Vec::with_capacity(raw.len());
    for e in raw {
        let is_dir = e.mode & 0o170000 == 0o040000;
        let symlink = e.mode & 0o170000 == 0o120000;
        let perms = (e.mode & 0o7777) as u16;
        v.push(FsNode {
            path: e.path,
            data: img[e.data_off..e.data_off + e.data_len].to_vec(),
            is_dir,
            symlink,
            dirty: false,
            removed: false,
            mode: if perms == 0 { 0o644 } else { perms },
            mtime: e.mtime,
            vseq: 0,
            vnotes: 0,
        });
    }
    let n = v.len();
    unsafe { *NODES.0.get() = Some(v) };
    for i in 0..n {
        if nodes()[i].symlink {
            let t = core::str::from_utf8(&nodes()[i].data).unwrap_or("?");
            kprintln!("initramfs: {} -> {}", path_of(i), t);
        } else {
            let suffix = if is_dir(i) && path_of(i) != "/" { "/" } else { "" };
            kprintln!("initramfs: {}{}", path_of(i), suffix);
        }
    }
    n
}

/// Normalize to an absolute path without a trailing slash (except `/`).
fn normalize(path: &str) -> String {
    let mut p = String::new();
    if !path.starts_with('/') {
        p.push('/');
    }
    p.push_str(path);
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

pub fn lookup(path: &str) -> Option<usize> {
    let mut p = normalize(path);
    // Follow symlink chains (bounded; relative targets resolve against
    // the link's parent directory).
    for _ in 0..8 {
        let idx = nodes().iter().position(|n| !n.removed && n.path == p.as_str())?;
        if !nodes()[idx].symlink {
            return Some(idx);
        }
        let target = core::str::from_utf8(&nodes()[idx].data).ok()?.to_string();
        p = if target.starts_with('/') {
            normalize(&target)
        } else {
            let dir = parent_of(&p);
            if dir == "/" {
                normalize(&format!("/{target}"))
            } else {
                normalize(&format!("{dir}/{target}"))
            }
        };
    }
    None
}


pub fn is_dir(idx: usize) -> bool {
    nodes()[idx].is_dir
}

pub fn data_len(idx: usize) -> usize {
    nodes()[idx].data.len()
}

/// Node paths are immutable and nodes are never removed, so the borrow is
/// valid for the lifetime of the mounted filesystem.
pub fn path_of(idx: usize) -> &'static str {
    let s = nodes()[idx].path.as_str();
    unsafe { core::mem::transmute::<&str, &'static str>(s) }
}

/// Borrow a node's bytes for the duration of `f` (execve's ELF load).
pub fn with_bytes<T>(idx: usize, f: impl FnOnce(&[u8]) -> T) -> T {
    f(&nodes()[idx].data)
}

pub fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

/// Indices of entries whose parent is `dir` (never including `dir` itself).
/// Node order is append-stable, so ordinals stay consistent across calls.
pub fn listable(dir: &str) -> Vec<usize> {
    let d = normalize(dir);
    nodes()
        .iter()
        .enumerate()
        .filter(|(_, n)| !n.removed && n.path != d.as_str() && parent_of(&n.path) == d.as_str())
        .map(|(i, _)| i)
        .collect()
}

/// Copy up to `len` bytes from node `idx` at `pos` into the user buffer.
pub fn read_to_user(idx: usize, pos: usize, addr: u64, len: usize) -> usize {
    let n = &nodes()[idx];
    let avail = n.data.len().saturating_sub(pos);
    let cnt = avail.min(len);
    unsafe {
        core::ptr::copy_nonoverlapping(n.data.as_ptr().add(pos), addr as *mut u8, cnt);
    }
    cnt
}

/// Write `len` bytes from the (validated) user buffer into the node at
/// `pos`, zero-filling any gap and growing the file. Marks the node dirty.
pub fn write_at(idx: usize, pos: usize, src: u64, len: usize) -> usize {
    let n = &mut nodes()[idx];
    if pos > n.data.len() {
        n.data.resize(pos, 0);
    }
    n.data.resize(pos + len, 0);
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, n.data.as_mut_ptr().add(pos), len);
    }
    n.dirty = true;
    n.mtime = crate::arch::timer::unix_secs();
    notify(idx, NOTE_WRITE | NOTE_ATTRIB);
    len
}

pub fn truncate(idx: usize) {
    let n = &mut nodes()[idx];
    if !n.data.is_empty() {
        n.data.clear();
        n.dirty = true;
        notify(idx, NOTE_WRITE | NOTE_ATTRIB);
    }
}

/// Create a regular file; parent must exist and be a directory.
pub fn create_file(path: &str) -> Result<usize, u8> {
    create_node(path, false)
}

/// Create a directory node.
pub fn create_dir(path: &str) -> Result<usize, u8> {
    create_node(path, true)
}

fn create_node(path: &str, as_dir: bool) -> Result<usize, u8> {
    let p = normalize(path);
    if p == "/" {
        return Err(EEXIST);
    }
    // Name occupancy, not target: a dangling symlink at `p` must block the
    // create, or the node table ends up with two live nodes on one path.
    if lookup_nofollow(&p).is_some() {
        return Err(EEXIST);
    }
    let parent = parent_of(&p).to_string();
    match lookup(&parent) {
        None => Err(ENOENT),
        Some(pi) if !is_dir(pi) => Err(ENOTDIR),
        Some(_) => {
            let n = nodes();
            n.push(FsNode {
                path: p,
                data: Vec::new(),
                is_dir: as_dir,
                symlink: false,
                dirty: true,
                removed: false,
                mode: if as_dir { 0o755 } else { 0o644 },
                mtime: crate::arch::timer::unix_secs(),
                vseq: 1,
                vnotes: 0,
            });
            Ok(n.len() - 1)
        }
    }
}

fn any_dirty() -> bool {
    nodes().iter().any(|n| n.dirty)
}

/// Permission bits of a node (for stat/chmod).
pub fn perms(idx: usize) -> u16 {
    nodes()[idx].mode
}

/// Modification time (unix seconds).
pub fn mtime_of(idx: usize) -> i64 {
    nodes()[idx].mtime
}

/// True when the node is a symlink (lstat/readlink).
pub fn is_symlink(idx: usize) -> bool {
    nodes()[idx].symlink
}

/// chmod(2): replace permission bits (type unchanged).
pub fn set_mode(idx: usize, mode: u16) -> Result<(), u8> {
    let n = &mut nodes()[idx];
    if n.removed {
        return Err(ENOENT);
    }
    n.mode = mode & 0o7777;
    n.dirty = true;
    notify(idx, NOTE_ATTRIB);
    Ok(())
}

/// ftruncate/truncate: shrink or zero-extend a file.
pub fn set_len(idx: usize, len: usize) -> Result<(), u8> {
    let n = &mut nodes()[idx];
    if n.is_dir {
        return Err(EISDIR);
    }
    let grew = len > n.data.len();
    if len < n.data.len() {
        n.data.truncate(len);
    } else {
        n.data.resize(len, 0);
    }
    n.dirty = true;
    n.mtime = crate::arch::timer::unix_secs();
    // A file that grew is a distinct event from one that merely changed:
    // a watcher on tail-like behaviour filters on EXTEND alone.
    notify(idx, NOTE_WRITE | NOTE_ATTRIB | if grew { NOTE_EXTEND } else { 0 });
    Ok(())
}

/// Set the modification time (utimensat/touch).
pub fn set_mtime(idx: usize, t: i64) {
    let n = &mut nodes()[idx];
    n.mtime = t;
    n.dirty = true;
    notify(idx, NOTE_ATTRIB);
}

/// lookup without following the final symlink (lstat/readlink).
pub fn lookup_nofollow(path: &str) -> Option<usize> {
    let p = normalize(path);
    nodes().iter().position(|n| !n.removed && n.path == p)
}

/// symlink(2): create a symbolic link node whose data is the target.
pub fn create_symlink(path: &str, target: &str) -> Result<usize, u8> {
    let p = normalize(path);
    if lookup_nofollow(&p).is_some() {
        return Err(EEXIST);
    }
    let parent = parent_of(&p).to_string();
    match lookup(&parent) {
        None => Err(ENOENT),
        Some(pi) if !is_dir(pi) => Err(ENOTDIR),
        Some(_) => {
            let n = nodes();
            n.push(FsNode {
                path: p,
                data: target.as_bytes().to_vec(),
                is_dir: false,
                symlink: true,
                dirty: true,
                removed: false,
                mode: 0o777,
                mtime: crate::arch::timer::unix_secs(),
                vseq: 1,
                vnotes: 0,
            });
            Ok(n.len() - 1)
        }
    }
}

/// rename(2): move `old` onto `new` (single filesystem). Directories take
/// their children along; an existing non-empty target is rejected, an
/// existing file target is replaced (tombstoned — open fds keep working).
pub fn rename(old: &str, new: &str) -> Result<(), u8> {
    let o = normalize(old);
    let n = normalize(new);
    if o == n {
        return Ok(());
    }
    if o != "/" && n.starts_with(&format!("{o}/")) {
        return Err(22); // EINVAL: directory moved into itself
    }
    let oi = lookup_nofollow(&o).ok_or(ENOENT)?;
    let np = parent_of(&n).to_string();
    match lookup(&np) {
        None => return Err(ENOENT),
        Some(pi) if !is_dir(pi) => return Err(ENOTDIR),
        Some(_) => {}
    }
    let o_dir = is_dir(oi);
    if let Some(ni) = lookup_nofollow(&n) {
        if ni == oi {
            return Ok(());
        }
        let n_dir = is_dir(ni);
        if n_dir && !o_dir {
            return Err(EISDIR);
        }
        if o_dir && !n_dir {
            return Err(ENOTDIR);
        }
        if n_dir {
            let empty = nodes().iter().all(|m| {
                m.removed || m.path == n || parent_of(&m.path) != n.as_str()
            });
            if !empty {
                return Err(ENOTEMPTY);
            }
        }
        let tn = &mut nodes()[ni];
        tn.removed = true;
        tn.dirty = true;
        // The clobbered name is gone from the namespace, which is the only
        // note that matters for it.
        notify(ni, NOTE_DELETE);
    }
    let mut moved: Vec<usize> = Vec::new();
    if o_dir {
        let prefix = format!("{o}/");
        let kids: Vec<usize> = nodes()
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.removed && m.path.starts_with(&prefix))
            .map(|(i, _)| i)
            .collect();
        for i in kids {
            let m = &mut nodes()[i];
            m.path = format!("{}/{}", n, &m.path[prefix.len()..]);
            m.dirty = true;
            moved.push(i);
        }
    }
    {
        let nn = &mut nodes()[oi];
        nn.path = n;
        nn.dirty = true;
    }
    // Notified after the mutable borrows are dropped.
    notify(oi, NOTE_RENAME | NOTE_LINK);
    for i in moved {
        notify(i, NOTE_RENAME);
    }
    Ok(())
}

/// unlink(2): remove a regular file (tombstoned; open fds keep reading).
pub fn remove_file(path: &str) -> Result<(), u8> {
    let p = normalize(path);
    if p == "/" {
        return Err(EISDIR);
    }
    // unlink(2) removes the final symlink itself, never its target.
    let i = lookup_nofollow(&p).ok_or(ENOENT)?;
    if is_dir(i) {
        return Err(EISDIR);
    }
    {
        let n = &mut nodes()[i];
        n.removed = true;
        n.dirty = true;
    }
    // Outside the borrow: notify() takes &mut nodes() itself.
    notify(i, NOTE_DELETE);
    Ok(())
}

/// rmdir(2): remove an empty directory.
pub fn remove_dir(path: &str) -> Result<(), u8> {
    let p = normalize(path);
    if p == "/" {
        return Err(EBUSY);
    }
    let i = lookup_nofollow(&p).ok_or(ENOENT)?;
    if !is_dir(i) {
        return Err(ENOTDIR);
    }
    let empty = nodes()
        .iter()
        .all(|n| n.removed || n.path == p || parent_of(&n.path) != p.as_str());
    if !empty {
        return Err(ENOTEMPTY);
    }
    {
        let n = &mut nodes()[i];
        n.removed = true;
        n.dirty = true;
    }
    // Outside the borrow: notify() takes &mut nodes() itself.
    notify(i, NOTE_DELETE);
    Ok(())
}

/// Rebuild the cpio image from the current nodes (512-byte padded).
fn build_cpio() -> Vec<u8> {
    let mut out = Vec::new();
    let mut ino = 1u32;
    for n in nodes().iter() {
        if n.removed {
            continue;
        }
        let rel: &str = if n.path == "/" { "." } else { &n.path[1..] };
        let mode = if n.is_dir {
            0o40000 | n.mode as u32
        } else if n.symlink {
            0o120000 | 0o777
        } else {
            0o100000 | n.mode as u32
        };
        write_newc(&mut out, ino, mode, rel, &n.data, n.mtime);
        ino += 1;
    }
    write_newc(&mut out, 0, 0, "TRAILER!!!", &[], 0);
    while out.len() % 512 != 0 {
        out.push(0);
    }
    out
}

fn push_hex8(out: &mut Vec<u8>, v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in (0..8).rev() {
        out.push(HEX[((v >> (i * 4)) & 0xf) as usize]);
    }
}

fn write_newc(out: &mut Vec<u8>, ino: u32, mode: u32, name: &str, data: &[u8], mtime: i64) {
    out.extend_from_slice(b"070701");
    for field in [
        ino,
        mode,
        0, // uid
        0, // gid
        1, // nlink
        mtime as u32,
        data.len() as u32,
        0, // devmajor
        0, // devminor
        0, // rdevmajor
        0, // rdevminor
        (name.len() + 1) as u32, // namesize incl. NUL
        0, // check
    ] {
        push_hex8(out, field);
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Write every dirty node back to disk. Returns sectors written (0 = clean).
pub fn sync_to_disk() -> Result<usize, u8> {
    if !any_dirty() {
        return Ok(0);
    }
    if !virtio_blk::ready() {
        return Err(EIO);
    }
    let cap = virtio_blk::capacity_sectors() as usize * 512;
    let img = build_cpio();
    if img.len() > cap {
        return Err(ENOSPC);
    }
    virtio_blk::write_sectors(0, &img).map_err(|_| EIO)?;
    for n in nodes() {
        n.dirty = false;
    }
    Ok(img.len().div_ceil(512))
}

// ---------- EVFILT_VNODE notifications ----------

// NOTE_* bits from sys/sys/event.h. Only the ones this fs can actually
// produce are listed; NOTE_DELETE/EXTEND/LINK/RENAME all follow from a
// change here, so they are reported deliberately rather than incidentally.
pub const NOTE_DELETE: u32 = 0x0001;
pub const NOTE_WRITE: u32 = 0x0002;
pub const NOTE_EXTEND: u32 = 0x0004;
pub const NOTE_ATTRIB: u32 = 0x0008;
pub const NOTE_LINK: u32 = 0x0010;
pub const NOTE_RENAME: u32 = 0x0020;

/// Record a change to `idx` and wake any EVFILT_VNODE watcher.
///
/// Bumping the generation AND accumulating the note bits means a watcher
/// cannot miss a change by not being in the syscall at the moment it
/// happened: it compares generations, and it reports whichever notes
/// accumulated since it last drained. Notes left on a node nobody watches
/// are simply never read, so there is no global log to overflow.
pub fn notify(idx: usize, notes: u32) {
    let n = &mut nodes()[idx];
    // A removed node is a tombstone: it keeps its index for open fds but
    // is gone from the namespace, and only NOTE_DELETE is meaningful.
    if n.removed && notes & NOTE_DELETE == 0 {
        return;
    }
    n.vseq = n.vseq.wrapping_add(1);
    n.vnotes |= notes;

}

/// Current generation, for a watcher recording its starting point.
pub fn vnode_seq(idx: usize) -> u32 {
    nodes()[idx].vseq
}

/// Take the accumulated notes and clear them. Returns `(new_seq, notes)`.
pub fn vnode_take_notes(idx: usize) -> (u32, u32) {
    let n = &mut nodes()[idx];
    let out = n.vnotes;

    n.vnotes = 0;
    (n.vseq, out)
}

/// Put notes back. A watcher took them to test them and found no match, so
/// they must remain pending for the next call.
pub fn vnode_restore_notes(idx: usize, notes: u32) {
    nodes()[idx].vnotes |= notes;
}

/// Number of nodes, for bounds-checking a watcher's stored index.
pub fn node_count() -> usize {
    nodes().len()
}

/// Drop accumulated notes without reporting them — used when a watcher's
/// registration is first established, so it does not immediately fire on
/// history it never asked about.
pub fn vnode_clear_notes(idx: usize) {
    nodes()[idx].vnotes = 0;
}
