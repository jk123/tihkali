//! Framebuffer via QEMU `ramfb`, handed to the host over fw_cfg DMA.
//!
//! `ramfb` is a *passive* device: there is no MMIO window and no virtqueue
//! to drive. The guest simply describes a rectangle of its own physical RAM
//! and QEMU maps it as the display surface (QEMU hw/display/ramfb.c). The
//! description is written through the fw_cfg DMA interface, so the whole
//! driver is this file.
//!
//! Why not virtio-gpu: this QEMU build ships no virtio-gpu device at all
//! (`qemu-system-aarch64 -device help` lists none), and `-machine virt` has
//! no PL110 LCD. `ramfb` needs neither PCI nor an IRQ: the refresh is driven
//! by QEMU's own display timer.
//!
//! Framebuffer memory comes from `pmm::alloc_contiguous` and stays
//! identity-mapped normal (cacheable) memory, which is coherent with QEMU
//! reading it as RAM — no cache maintenance and no non-cacheable mapping.

use core::ptr::{read_volatile, write_volatile};

use crate::kprintln;
use crate::hal::platform::FW_CFG_BASE;
use crate::mm::pmm;
/// QEMU maps the three fw_cfg windows from `fw_cfg_init_mem_wide` as
/// (ctl_addr, data_addr, width, dma_addr) = (base+8, base, 8, base+16):
/// the *selector* is at base+8 and the 1-byte data window at base+0
/// (confirmed with `info mtree -f`: fwcfg.data 0x9020000, fwcfg.ctl
/// 0x9020008, fwcfg.dma 0x9020010).
const FW_CFG_DATA: usize = FW_CFG_BASE;
const FW_CFG_CTL: usize = FW_CFG_BASE + 8;
const FW_CFG_DMA: usize = FW_CFG_BASE + 16;

// Selectors (include/standard-headers/linux/qemu_fw_cfg.h).
const FW_CFG_FILE_DIR: u16 = 0x19;
const FW_CFG_FILE_FIRST: u16 = 0x20;

const FW_CFG_DMA_SIGNATURE: u64 = 0x5145_4d55_2043_4647; // "QEMU CFG"
const FW_CFG_DMA_CTL_READ: u32 = 0x02;
const FW_CFG_DMA_CTL_WRITE: u32 = 0x10;
const FW_CFG_DMA_CTL_SELECT: u32 = 0x08;
const FW_CFG_DMA_CTL_ERROR: u32 = 0x01;

/// DRM fourcc for XRGB8888 — QEMU maps it to pixman and reads it as RAM.
const FOURCC_XRGB8888: u32 = 0x3432_5258;

pub const FB_WIDTH: u32 = 640;
pub const FB_HEIGHT: u32 = 480;
/// XRGB8888 is 4 bytes per pixel.
pub const FB_BPP: u32 = 4;
pub const FB_STRIDE: u32 = FB_WIDTH * FB_BPP;
const FB_BYTES: usize = FB_STRIDE as usize * FB_HEIGHT as usize;

/// `struct FWCfgFileEntry`: `size`, `name[56]`, `reserved`. Each is
/// prefixed in the directory blob by its own big-endian size (always 64).
const FILE_ENTRY_SIZE: usize = 64;

/// `struct fw_cfg_dma_access` (include/standard-headers/linux/qemu_fw_cfg.h).
/// Field order matters — QEMU reads it by offset. Every field is big-endian.
#[repr(C)]
struct DmaAccess {
    control: u32,
    length: u32,
    address: u64,
}

/// Wire size of `struct RAMFBCfg` — must equal `sizeof(RAMFBCfg)` in QEMU.
const RAMFB_CFG_LEN: u32 = 28;

/// `struct RAMFBCfg` (hw/display/ramfb.c) — also big-endian.
///
/// The C struct is QEMU_PACKED and totals **28** bytes (8+4*5). The entry
/// length is that exact size, and `fw_cfg_dma_transfer` rejects a write whose
/// length does not match it, so this must be packed to match — a plain
/// `#[repr(C)]` layout would be 32 and the write would fail.
#[repr(C, packed)]
struct RamfbCfg {
    addr: u64,
    fourcc: u32,
    flags: u32,
    width: u32,
    height: u32,
    stride: u32,
}

static mut FB_PA: usize = 0;

/// Select a fw_cfg entry.
///
/// The control window is DEVICE_BIG_ENDIAN and accepts only a 2-byte write
/// (`fw_cfg_ctl_mem_valid`: `is_write && size == 2`), so QEMU composes the
/// value most-significant byte first. A little-endian `u16` store would
/// deliver the selector's two bytes reversed and the entry would never be
/// selected, so swap it. (Verified: removing this swap makes
/// `find_ramfb_selector` find nothing.)
fn ctl_write(sel: u16) {
    unsafe { write_volatile(FW_CFG_CTL as *const u16 as *mut u16, sel.swap_bytes()) }
}

/// Read `n` bytes of the selected entry as one big-endian word.
///
/// The data window accepts access **only at offset 0** and serves `size`
/// bytes from the current `cur_offset`, advancing it. Reading byte-by-byte
/// with an added address is invalid (`fw_cfg_data_mem_valid` takes
/// `addr == 0`) and faults on the second access — so every multi-byte read
/// must be a single access at +0.
fn data_read(n: usize) -> u64 {
    match n {
        1 => unsafe { read_volatile(FW_CFG_DATA as *const u8) as u64 },
        2 => unsafe { read_volatile(FW_CFG_DATA as *const u16) as u64 },
        4 => unsafe { read_volatile(FW_CFG_DATA as *const u32) as u64 },
        8 => unsafe { read_volatile(FW_CFG_DATA as *const u64) },
        _ => 0,
    }
}

/// Read a 4-byte entry as its numeric value.
///
/// fw_cfg composes entries most-significant-byte first and the data region
/// is DEVICE_BIG_ENDIAN, but a little-endian guest's integer load sees the
/// stream reversed: "QEMU" arrives as 0x554d4551. Swap to recover the
/// numeric value (verified against FW_CFG_SIGNATURE).
fn data_read_u32() -> u32 {
    (data_read(4) as u32).swap_bytes()
}

/// Read `buf.len()` bytes of the selected entry, in multi-byte accesses at
/// offset 0 (see `data_read`). The region is DEVICE_BIG_ENDIAN, so an
/// `n`-byte read yields the wire bytes most-significant first.
fn data_read_into(buf: &mut [u8]) {
    let mut i = 0usize;
    while i < buf.len() {
        let left = buf.len() - i;
        let n = if left >= 4 { 4 } else { left };
        // Little-endian in the guest = stream order.
        let v = (data_read(n) as u32).swap_bytes().to_be_bytes();
        buf[i..i + n].copy_from_slice(&v[..n]);
        i += n;
    }
}

/// Staging descriptor. It must live in guest RAM because QEMU DMAs *from*
/// this address; a kernel static is identity-mapped, so it qualifies.
/// DMA descriptor staging.
///
/// `fw_cfg_dma_transfer` reads this with `dma_memory_read` against the
/// *system* address space, so it must live in ordinary RAM. `.bss` is RAM
/// here too, but the transfer is triggered by the store that publishes the
/// descriptor's address, so keep it in a plainly allocated frame to stay
/// clear of any cacheability question on kernel statics.
static mut DESC: DmaAccess = DmaAccess {
    control: 0,
    length: 0,
    address: 0,
};

/// DMA-transfer `len` bytes of selector `sel` between guest memory and
/// the fw_cfg entry. `write` selects the direction.
///
/// The single 64-bit store to the DMA port carries the *descriptor's*
/// address; QEMU then reads control/length/address from there, moves the
/// payload, and stores the finished control word back over
/// `DESC.control`. `fw_cfg_dma_transfer` reports failure by setting its
/// ERROR bit, so that write-back is how we learn we failed.
fn dma_xfer(sel: u16, ptr: *mut u8, len: u32, write: bool) -> bool {
    let dir = if write { FW_CFG_DMA_CTL_WRITE } else { FW_CFG_DMA_CTL_READ };
    unsafe {
        let d = &mut *core::ptr::addr_of_mut!(DESC);
        // All three fields are big-endian on the wire (QEMU applies
        // be32/be64_to_cpu after copying the raw descriptor bytes out of
        // guest RAM), so store them pre-swapped.
        d.control = (((sel as u32) << 16) | FW_CFG_DMA_CTL_SELECT | dir).to_be();
        d.length = len.to_be();
        d.address = (ptr as u64).to_be();
        // The DMA window is DEVICE_BIG_ENDIAN, so the 8-byte store must carry the
        // value most-significant byte first; a plain LE store hands QEMU a
        // byte-reversed descriptor address and the transfer silently fails.
        write_volatile(
            FW_CFG_DMA as *const u64 as *mut u64,
            (core::ptr::addr_of!(DESC) as u64).swap_bytes(),
        );
        // QEMU overwrites DESC.control with the finished status: 0 on
        // success, or the ERROR bit when the transfer was refused.
        let raw = read_volatile(core::ptr::addr_of!(DESC) as *const u32);
        raw.swap_bytes() & FW_CFG_DMA_CTL_ERROR == 0
    }
}

/// Name of a file-directory entry.
///
/// QEMU's on-wire `struct FWCfgFile` is `[size u32 BE][name char[56]]
/// [reserved u32]` — 64 bytes total. (The published struct also carries a
/// `select` field, but QEMU only serialises size/name/reserved into the
/// directory, so the selector has to be derived from the entry's position.)
fn entry_name(raw: &[u8]) -> &[u8] {
    let n = raw[4..60].iter().position(|&c| c == 0).unwrap_or(56);
    &raw[4..4 + n]
}

/// Selector key for the Nth directory entry (`FW_CFG_FILE_FIRST + N`).
fn entry_select(idx: usize) -> u16 {
    (FW_CFG_FILE_FIRST as usize + idx) as u16
}

/// Locate the `etc/ramfb` file entry, returning its selector key.
///
/// `FW_CFG_FILE_DIR` is a big-endian u32 count followed by that many
/// 64-byte entries; file N lives at selector `FW_CFG_FILE_FIRST + N`.
fn find_ramfb_selector() -> Option<u16> {
    ctl_write(FW_CFG_FILE_DIR);
    let count = data_read_u32() as usize;
    let total = 4 + count * FILE_ENTRY_SIZE;
    let mut buf = [0u8; 4096];
    let chunk = core::cmp::min(total, buf.len());
    data_read_into(&mut buf[..chunk]);
    let mut idx = 0usize;
    while 4 + (idx + 1) * FILE_ENTRY_SIZE <= chunk {
        let raw = &buf[4 + idx * FILE_ENTRY_SIZE..4 + (idx + 1) * FILE_ENTRY_SIZE];
        if entry_name(raw) == b"etc/ramfb" {
            return Some(entry_select(idx));
        }
        idx += 1;
    }
    None
}

/// Bring up the framebuffer. Returns Err when `ramfb` is not wired into
/// the QEMU command line or fw_cfg lacks the DMA interface.
///
/// fw_cfg's data region is DEVICE_BIG_ENDIAN: QEMU composes each multi-byte
/// read most-significant-byte first, so a little-endian guest must
/// `swap_bytes` to recover the numeric value (see `data_read_u32`). The DMA
/// descriptor below is read by QEMU with explicit big-endian loads, so its
/// fields are stored pre-swapped.
pub fn init() -> Result<(), &'static str> {
    // The 64-bit DMA port must present the DMA signature. QEMU serves it via
    // extract64(FW_CFG_DMA_SIGNATURE, (8 - addr - size) * 8, size * 8), so an
    // 8-byte read yields the eight characters least-significant-byte first:
    // a little-endian guest sees "QEMU CFG" reversed, hence swap_bytes.
    let sig = unsafe { read_volatile(FW_CFG_DMA as *const u64) }.swap_bytes();
    if sig != FW_CFG_DMA_SIGNATURE {
        return Err("fw_cfg DMA signature missing (no -device ramfb?)");
    }

    let sel = find_ramfb_selector().ok_or("fw_cfg has no etc/ramfb entry")?;
    kprintln!("fb: fw_cfg etc/ramfb at selector {sel:#x}");

    let pa = pmm::alloc_contiguous(FB_BYTES / 4096).ok_or("out of frames for framebuffer")?;
    unsafe {
        core::ptr::write_bytes(pa as *mut u8, 0, FB_BYTES);
        FB_PA = pa;
    }
    kprintln!("fb: {FB_BYTES} bytes at {pa:#x} for {FB_WIDTH}x{FB_HEIGHT}x{FB_BPP}");

    // Describe the buffer to QEMU. `addr` is a *physical* address; the
    // mapping is coherent, so no flush is required before handing it over.
    let cfg = RamfbCfg {
        addr: (pa as u64).to_be(),
        fourcc: FOURCC_XRGB8888.to_be(),
        flags: 0,
        width: FB_WIDTH.to_be(),
        height: FB_HEIGHT.to_be(),
        stride: FB_STRIDE.to_be(),
    };
    if !dma_xfer(sel, &cfg as *const RamfbCfg as *mut u8, RAMFB_CFG_LEN, true) {
        return Err("fw_cfg rejected the ramfb configuration");
    }
    kprintln!("fb: framebuffer {FB_WIDTH}x{FB_HEIGHT} xrgb8888 at {pa:#x}");
    test();
    Ok(())
}

/// Paint a gradient and read one pixel back.
///
/// The boot log proves the *configuration* reached QEMU; this proves the
/// buffer is really writable, which is what `check.sh` gates on.
pub fn test() {
    let bg = 0x00101820;
    fill_rect(0, 0, FB_WIDTH, FB_HEIGHT, bg);
    // A band across the top in a distinct colour, plus a bright marker at a
    // known coordinate we read back below.
    fill_rect(0, 0, FB_WIDTH, 16, 0x00c0ff00);
    put_pixel(7, 7, 0x00ff00ff);

    let got = unsafe { read_volatile(px_at(7 * FB_STRIDE as usize + 7 * 4)) };
    let corner = unsafe { read_volatile(px_at(0)) };
    assert_eq!(got, 0x00ff00ff, "fb: framebuffer pixel readback mismatch");
    assert_eq!(corner, 0x00c0ff00, "fb: framebuffer corner mismatch");
    kprintln!("fb: paint + readback ok ({FB_WIDTH}x{FB_HEIGHT} xrgb8888)");
}

/// Physical address of the framebuffer, 0 when `init` has not run.
pub fn fb_pa() -> usize {
    unsafe { FB_PA }
}

/// Byte offset of `(x, y)` into the framebuffer.
#[inline]
fn px_at(off: usize) -> *mut u32 {
    (unsafe { FB_PA } + off) as *mut u32
}

/// Bounds-checked pixel store; `(0,0)` is top-left.
pub fn put_pixel(x: u32, y: u32, rgb: u32) {
    if x >= FB_WIDTH || y >= FB_HEIGHT {
        return;
    }
    unsafe { write_volatile(px_at(y as usize * FB_STRIDE as usize + x as usize * 4), rgb) }
}

pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, rgb: u32) {
    for row in y..(y + h).min(FB_HEIGHT) {
        for col in x..(x + w).min(FB_WIDTH) {
            put_pixel(col, row, rgb);
        }
    }
}

// ---------- syscall door ----------
//
// The user window is only 4 MiB (user::USER_LIMIT), and the framebuffer
// is contiguous *physical* memory that the MMU already identity-maps, so
// there is nothing to map into user space. Instead user space blits
// through the kernel: one copy per call, no window pressure, and no new
// vm.rs sharing/COW code.

/// Fill a rectangle with a solid colour (EFAULT on error).
pub fn sys_fill_rect(x: u32, y: u32, w: u32, h: u32, rgb: u32) -> Result<(), u8> {
    if fb_pa() == 0 || w > FB_WIDTH || h > FB_HEIGHT {
        return Err(crate::file::EFAULT);
    }
    fill_rect(x, y, w, h, rgb);
    Ok(())
}

/// Blit a caller-supplied XRGB8888 rect into the framebuffer.
///
/// `src` must hold `w * h * 4` bytes of user memory; it is copied in
/// row by row so a partial last row cannot spill past `FB_STRIDE`.
pub fn sys_blit(
    src: u64,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    src_stride: u32,
) -> Result<(), u8> {
    const EFAULT: u8 = crate::file::EFAULT;
    if fb_pa() == 0 || w == 0 || h == 0 || w > FB_WIDTH || h > FB_HEIGHT {
        return Err(EFAULT);
    }
    if src_stride < w * FB_BPP {
        return Err(EFAULT);
    }
    let mut row = 0u32;
    while row < h {
        let dy = y + row;
        if dy >= FB_HEIGHT {
            break;
        }
        let addr = src + (row as u64) * (src_stride as u64);
        if !crate::proc::user_range_ok(addr, (w * FB_BPP) as usize) {
            return Err(EFAULT);
        }
        let mut col = 0u32;
        while col < w {
            let dx = x + col;
            if dx >= FB_WIDTH {
                break;
            }
            let v = unsafe { core::ptr::read_volatile((addr + (col * FB_BPP) as u64) as *const u32) };
            put_pixel(dx, dy, v);
            col += 1;
        }
        row += 1;
    }
    Ok(())
}

/// Fill `{width, height, stride}` for user space; `out` is a 16-byte
/// user buffer.
pub fn sys_fb_info(out: u64) -> Result<(), u8> {
    if !crate::proc::user_range_ok(out, 16) {
        return Err(crate::file::EFAULT);
    }
    unsafe {
        (out as *mut u32).write_volatile(FB_WIDTH);
        (out as *mut u32).add(1).write_volatile(FB_HEIGHT);
        (out as *mut u32).add(2).write_volatile(FB_STRIDE);
        (out as *mut u32).add(3).write_volatile(fb_pa() as u32);
    }
    Ok(())
}
