//! cpio "newc" archive parser (read-only).

use alloc::string::String;
use alloc::vec::Vec;

pub struct RawEntry {
    pub path: String,
    pub mode: u32,
    pub data_off: usize,
    pub data_len: usize,
    /// newc header mtime (unix seconds).
    pub mtime: i64,
}

fn hex8(img: &[u8], off: usize) -> Option<u32> {
    let s = core::str::from_utf8(img.get(off..off + 8)?).ok()?;
    u32::from_str_radix(s, 16).ok()
}

fn align4(v: usize) -> usize {
    (v + 3) & !3
}

/// Parse a newc archive into entries with paths made absolute
/// (`bin/sh` → `/bin/sh`, `.` → `/`). Panics on malformed input — the
/// image is built by our own packer, corruption means a build bug.
pub fn parse(img: &[u8]) -> Vec<RawEntry> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos + 110 > img.len() {
            panic!("cpio: truncated header at {pos:#x}");
        }
        if &img[pos..pos + 6] != b"070701" {
            panic!("cpio: bad magic at {pos:#x}");
        }
        let mode = hex8(img, pos + 14).expect("cpio: mode");
        let mtime = hex8(img, pos + 46).expect("cpio: mtime") as i64;
        let filesize = hex8(img, pos + 54).expect("cpio: filesize") as usize;
        let namesize = hex8(img, pos + 94).expect("cpio: namesize") as usize;
        if namesize == 0 || pos + 110 + namesize > img.len() {
            panic!("cpio: bad namesize at {pos:#x}");
        }
        let name_bytes = &img[pos + 110..pos + 110 + namesize];
        let name = core::str::from_utf8(&name_bytes[..namesize - 1])
            .expect("cpio: name not utf8");
        let data_off = align4(pos + 110 + namesize);
        if data_off + filesize > img.len() {
            panic!("cpio: data out of range for {name}");
        }

        if name == "TRAILER!!!" {
            break;
        }
        let path = if name == "." {
            String::from("/")
        } else if name.starts_with('/') {
            String::from(name)
        } else {
            let mut p = String::from("/");
            p.push_str(name);
            p
        };
        out.push(RawEntry {
            path,
            mode,
            data_off,
            data_len: filesize,
            mtime,
        });
        pos = align4(data_off + filesize);
    }
    out
}
