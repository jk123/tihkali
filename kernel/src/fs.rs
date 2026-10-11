//! Writable initramfs: mutable in-memory nodes plus cpio write-back.
//!
//! Mount parses the boot-time archive into owned nodes; `create`/`write`
//! mutate them in place and mark them dirty; `sync_to_disk` rebuilds the
//! whole cpio image and writes it back through the block device.

use core::cell::UnsafeCell;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use tihkali_hal::kprintln;

use crate::cpio;
use crate::file::{EIO, ENOENT, ENOSPC, ENOTDIR, EEXIST, EISDIR, EBUSY, ENOTEMPTY};
use crate::virtio_blk;

pub struct FsNode {
    path: String,
    data: Vec<u8>,
    is_dir: bool,
    dirty: bool,
    /// Tombstone: index stays stable for open fds; hidden from lookup,
    /// listing and write-back (sync drops it from the disk image).
    removed: bool,
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
        v.push(FsNode {
            path: e.path,
            data: img[e.data_off..e.data_off + e.data_len].to_vec(),
            is_dir,
            dirty: false,
            removed: false,
        });
    }
    let n = v.len();
    unsafe { *NODES.0.get() = Some(v) };
    for i in 0..n {
        let suffix = if is_dir(i) && path_of(i) != "/" { "/" } else { "" };
        kprintln!("initramfs: {}{}", path_of(i), suffix);
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
    let p = normalize(path);
    nodes().iter().position(|n| !n.removed && n.path == p)
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
    len
}

pub fn truncate(idx: usize) {
    let n = &mut nodes()[idx];
    if !n.data.is_empty() {
        n.data.clear();
        n.dirty = true;
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
    if lookup(&p).is_some() {
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
                dirty: true,
                removed: false,
            });
            Ok(n.len() - 1)
        }
    }
}

fn any_dirty() -> bool {
    nodes().iter().any(|n| n.dirty)
}

/// unlink(2): remove a regular file (tombstoned; open fds keep reading).
pub fn remove_file(path: &str) -> Result<(), u8> {
    let p = normalize(path);
    if p == "/" {
        return Err(EISDIR);
    }
    let i = lookup(&p).ok_or(ENOENT)?;
    if is_dir(i) {
        return Err(EISDIR);
    }
    let n = &mut nodes()[i];
    n.removed = true;
    n.dirty = true;
    Ok(())
}

/// rmdir(2): remove an empty directory.
pub fn remove_dir(path: &str) -> Result<(), u8> {
    let p = normalize(path);
    if p == "/" {
        return Err(EBUSY);
    }
    let i = lookup(&p).ok_or(ENOENT)?;
    if !is_dir(i) {
        return Err(ENOTDIR);
    }
    let empty = nodes()
        .iter()
        .all(|n| n.removed || n.path == p || parent_of(&n.path) != p.as_str());
    if !empty {
        return Err(ENOTEMPTY);
    }
    let n = &mut nodes()[i];
    n.removed = true;
    n.dirty = true;
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
        let mode = if n.is_dir { 0o40755 } else { 0o100644 };
        write_newc(&mut out, ino, mode, rel, &n.data);
        ino += 1;
    }
    write_newc(&mut out, 0, 0, "TRAILER!!!", &[]);
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

fn write_newc(out: &mut Vec<u8>, ino: u32, mode: u32, name: &str, data: &[u8]) {
    out.extend_from_slice(b"070701");
    for field in [
        ino,
        mode,
        0, // uid
        0, // gid
        1, // nlink
        0, // mtime
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
