//! Virtio-blk over virtio-mmio (modern v2), polled synchronous I/O.
//!
//! Discovery: QEMU virt exposes 32 transports at 0x0a00_0000 + i*0x200 and
//! assigns the FIRST `-device` to the HIGHEST slot, so every slot is probed.
//! All DMA targets (virtqueue frame, request buffers) live in identity-mapped
//! kernel RAM (VA == PA in every address space), which QEMU's coherent DMA
//! can access directly.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use alloc::vec::Vec;
use tihkali_hal::kprintln;

use crate::mm::pmm;

const SLOT_BASE: usize = 0x0a00_0000;
const SLOT_SIZE: usize = 0x200;
const NUM_SLOTS: usize = 32;

// virtio-mmio v2 registers (byte offsets; OASIS VIRTIO 1.2 §4.2.2)
const MAGIC_VALUE: usize = 0x000;
const VERSION: usize = 0x004;
const DEVICE_ID: usize = 0x008;
const DEVICE_FEATURES: usize = 0x010;
const DEVICE_FEATURES_SEL: usize = 0x014;
const DRIVER_FEATURES: usize = 0x020;
const DRIVER_FEATURES_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030; // linux/virtio_mmio.h (was 0x028 = legacy GuestPageSize)
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const INTERRUPT_STATUS: usize = 0x060;
const INTERRUPT_ACK: usize = 0x064;
const STATUS: usize = 0x070;
const QUEUE_DESC_LOW: usize = 0x080;
const QUEUE_DRIVER_LOW: usize = 0x090;
const QUEUE_DEVICE_LOW: usize = 0x0a0;
const CONFIG_GENERATION: usize = 0x0fc;
const CONFIG: usize = 0x100;

const VIRTIO_MAGIC: u32 = 0x74726976; // 'virt'
const VIRTIO_VERSION_MODERN: u32 = 2;
const VIRTIO_ID_BLOCK: u32 = 2;
const VIRTIO_F_VERSION_1_HI: u32 = 1; // feature bit 32 → hi word bit 0

const ST_ACKNOWLEDGE: u32 = 1;
const ST_DRIVER: u32 = 2;
const ST_FEATURES_OK: u32 = 8;
const ST_DRIVER_OK: u32 = 4;

const QSIZE: usize = 8; // descriptors; power of two
const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

const VIRTIO_BLK_T_IN: u32 = 0; // device writes to guest (disk → RAM)
const VIRTIO_BLK_T_OUT: u32 = 1; // device reads from guest (RAM → disk)

const TIMEOUT: u32 = 100_000_000;

/// Ring-frame layout: desc[8] @0, avail @128, used @256, hdr @512, status @528.
const OFF_AVAIL: usize = 128;
const OFF_USED: usize = 256;
const OFF_HDR: usize = 512;
const OFF_STATUS: usize = 528;

#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct BlkReqHeader {
    kind: u32,
    reserved: u32,
    sector: u64,
}

static mut BASE: usize = 0; // MMIO base of the matched slot (0 = none)
static mut RING: usize = 0; // identity-mapped frame with rings/hdr/status
static mut CAPACITY: u64 = 0; // sectors of 512 B
static mut LAST_USED: u16 = 0;

fn r(off: usize) -> u32 {
    unsafe { read_volatile((BASE + off) as *const u32) }
}

fn w(off: usize, v: u32) {
    unsafe { write_volatile((BASE + off) as *mut u32, v) }
}

/// Probe all 32 transports, negotiate features, set up virtqueue 0.
pub fn init() -> Result<(), &'static str> {
    let mut base = 0usize;
    for i in 0..NUM_SLOTS {
        let b = SLOT_BASE + i * SLOT_SIZE;
        unsafe {
            if read_volatile((b + MAGIC_VALUE) as *const u32) != VIRTIO_MAGIC {
                continue;
            }
            if read_volatile((b + VERSION) as *const u32) != VIRTIO_VERSION_MODERN {
                continue;
            }
            if read_volatile((b + DEVICE_ID) as *const u32) == VIRTIO_ID_BLOCK {
                base = b;
                kprintln!("virtio-blk: found at slot {i} ({b:#x})");
                break;
            }
        }
    }
    if base == 0 {
        return Err("no device in 32 MMIO slots");
    }
    unsafe { BASE = base };

    // Reset + ACKNOWLEDGE + DRIVER.
    w(STATUS, 0);
    w(STATUS, ST_ACKNOWLEDGE | ST_DRIVER);

    // Features: accept only VIRTIO_F_VERSION_1, reject everything else.
    w(DEVICE_FEATURES_SEL, 0);
    let _lo = r(DEVICE_FEATURES);
    w(DEVICE_FEATURES_SEL, 1);
    let hi = r(DEVICE_FEATURES);
    if hi & VIRTIO_F_VERSION_1_HI == 0 {
        return Err("device lacks VIRTIO_F_VERSION_1");
    }
    w(DRIVER_FEATURES_SEL, 0);
    w(DRIVER_FEATURES, 0);
    w(DRIVER_FEATURES_SEL, 1);
    w(DRIVER_FEATURES, VIRTIO_F_VERSION_1_HI);
    w(STATUS, ST_ACKNOWLEDGE | ST_DRIVER | ST_FEATURES_OK);
    if r(STATUS) & ST_FEATURES_OK == 0 {
        return Err("FEATURES_OK rejected");
    }

    // Virtqueue 0: one 4 KiB frame holds desc + avail + used + hdr + status.
    w(QUEUE_SEL, 0);
    let max = r(QUEUE_NUM_MAX);
    if max < QSIZE as u32 {
        return Err("QUEUE_NUM_MAX too small");
    }
    w(QUEUE_NUM, QSIZE as u32);
    let frame = pmm::alloc().ok_or("out of frames for virtqueue")?;
    unsafe {
        core::ptr::write_bytes(frame as *mut u8, 0, 4096);
        RING = frame;
        LAST_USED = 0;
    }
    w(QUEUE_DESC_LOW, frame as u32);
    w(QUEUE_DRIVER_LOW, (frame + OFF_AVAIL) as u32);
    w(QUEUE_DEVICE_LOW, (frame + OFF_USED) as u32);
    w(QUEUE_READY, 1);
    w(STATUS, ST_ACKNOWLEDGE | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK);

    // Capacity, bracketed by CONFIG_GENERATION.
    let cap = loop {
        let g1 = r(CONFIG_GENERATION);
        let lo = unsafe { read_volatile((base + CONFIG) as *const u32) };
        let hi = unsafe { read_volatile((base + CONFIG + 4) as *const u32) };
        let g2 = r(CONFIG_GENERATION);
        if g1 == g2 {
            break u64::from(lo) | (u64::from(hi) << 32);
        }
    };
    unsafe { CAPACITY = cap };
    kprintln!("virtio-blk: {cap} sectors ({} KiB)", cap * 512 / 1024);
    Ok(())
}


/// Volatile accessors for the ring index fields (device-owned memory).
fn avail_idx(ring: usize) -> u16 {
    unsafe { read_volatile((ring + OFF_AVAIL + 2) as *const u16) }
}

fn used_idx(ring: usize) -> u16 {
    unsafe { read_volatile((ring + OFF_USED + 2) as *const u16) }
}

pub fn ready() -> bool {
    unsafe { BASE != 0 }
}

pub fn capacity_sectors() -> u64 {
    unsafe { CAPACITY }
}

/// Read `buf.len()` bytes starting at `lba`. `buf` must be in identity-mapped
/// kernel memory (heap or kernel stack); length must be a multiple of 512.
pub fn read_sectors(lba: u64, buf: &mut [u8]) -> Result<(), &'static str> {
    submit(VIRTIO_BLK_T_IN, lba, buf.as_mut_ptr() as u64, buf.len(), true)
}

/// Write `buf.len()` bytes starting at `lba` (buffer must stay alive for
/// the whole polled request — callers pass slices of live allocations).
pub fn write_sectors(lba: u64, buf: &[u8]) -> Result<(), &'static str> {
    submit(VIRTIO_BLK_T_OUT, lba, buf.as_ptr() as u64, buf.len(), false)
}

fn submit(
    kind: u32,
    lba: u64,
    ptr: u64,
    len: usize,
    data_to_guest: bool,
) -> Result<(), &'static str> {
    if !ready() {
        return Err("no virtio-blk device");
    }
    if len == 0 || len % 512 != 0 {
        return Err("buffer must be a non-empty multiple of 512");
    }
    let sectors = (len / 512) as u64;
    if lba + sectors > unsafe { CAPACITY } {
        return Err("beyond capacity");
    }
    let buf_len = len;
    let data_flags = if data_to_guest { DESC_WRITE } else { 0 };
    let _ = &buf_len;

    let ring = unsafe { RING };
    unsafe {
        let descs = ring as *mut Desc;
        let hdr = (ring + OFF_HDR) as *mut BlkReqHeader;
        let status = (ring + OFF_STATUS) as *mut u8;

        // Request header: device reads it.
        *hdr = BlkReqHeader { kind, reserved: 0, sector: lba };
        *status = 0xff;

        // Chain: header -> data -> status (device always writes status).
        descs.add(0).write(Desc {
            addr: hdr as u64,
            len: core::mem::size_of::<BlkReqHeader>() as u32,
            flags: DESC_NEXT,
            next: 1,
        });
        descs.add(1).write(Desc {
            addr: ptr,
            len: len as u32,
            flags: DESC_NEXT | data_flags,
            next: 2,
        });
        descs.add(2).write(Desc {
            addr: status as u64,
            len: 1,
            flags: DESC_WRITE,
            next: 0,
        });

        // Publish head (desc 0) on the avail ring (volatile idx accesses:
        // the device updates used.idx behind our back).
        let idx = avail_idx(ring);
        write_volatile(
            (ring + OFF_AVAIL + 4 + 2 * ((idx as usize) % QSIZE)) as *mut u16,
            0u16,
        );
        fence(Ordering::SeqCst);
        write_volatile((ring + OFF_AVAIL + 2) as *mut u16, idx.wrapping_add(1));
        fence(Ordering::SeqCst);

        w(QUEUE_NOTIFY, 0);
    }

    // Polled completion (synchronous v1; all disk IO happens at boot).
    let mut spins = 0u32;
    loop {
        fence(Ordering::Acquire);
        if used_idx(ring) != unsafe { LAST_USED } {
            unsafe { LAST_USED = used_idx(ring) };
            break;
        }
        spins += 1;
        if spins > TIMEOUT {
            return Err("virtqueue timeout");
        }
        core::hint::spin_loop();
    }

    // The device may update the used ring before the status byte: wait for
    // our 0xff sentinel to be replaced (bounded).
    let mut status = unsafe { read_volatile((ring + OFF_STATUS) as *const u8) };
    let mut spins = 0u32;
    while status == 0xff {
        spins += 1;
        if spins > TIMEOUT {
            kprintln!(
                "virtio-blk: status timeout; used.idx={} avail.idx={}",
                used_idx(ring),
                avail_idx(ring)
            );
            return Err("status byte never written");
        }
        core::hint::spin_loop();
        status = unsafe { read_volatile((ring + OFF_STATUS) as *const u8) };
    }

    // Ack any interrupt we did not consume via the GIC (we never enable it).
    let isr = r(INTERRUPT_STATUS);
    if isr != 0 {
        w(INTERRUPT_ACK, isr);
    }

    if status != 0 {
        kprintln!(
            "virtio-blk: request failure (status={status}, used.idx={}, avail.idx={})",
            used_idx(ring),
            avail_idx(ring)
        );
        return Err("device reported request failure");
    }
    Ok(())
}

/// Read the whole disk image into a heap Vec (identity-mapped → DMA-safe).
pub fn read_disk() -> Result<Vec<u8>, &'static str> {
    let bytes = unsafe { CAPACITY } as usize * 512;
    if bytes == 0 {
        return Err("zero-capacity disk");
    }
    if bytes > 1024 * 1024 {
        return Err("disk image larger than 1 MiB");
    }
    let mut buf = alloc::vec![0u8; bytes];
    read_sectors(0, &mut buf)?;
    Ok(buf)
}
