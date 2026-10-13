//! Virtio-net over virtio-mmio (modern v2), polled synchronous TX/RX.
//!
//! Queue layout comes from QEMU's `virtio_net_add_queue`: the receive queue
//! is added first (index 0), the transmit queue second (index 1), the
//! optional control queue last (never touched — VIRTIO_NET_F_CTRL_VQ is not
//! negotiated). Under VIRTIO_F_VERSION_1 the packet header is the 12-byte
//! `virtio_net_hdr_v1` (`virtio_net_hdr` + `num_buffers`) on both
//! directions, regardless of MRG_RXBUF (QEMU `guest_hdr_len` logic).
//! All DMA targets are identity-mapped kernel RAM (VA == PA).

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

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
const QUEUE_SEL: usize = 0x030; // linux/virtio_mmio.h (NOT 0x028 = legacy GuestPageSize)
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
const CONFIG: usize = 0x100;

const VIRTIO_MAGIC: u32 = 0x74726976; // 'virt'
const VIRTIO_VERSION_MODERN: u32 = 2;
const VIRTIO_ID_NET: u32 = 1;
const VIRTIO_F_VERSION_1_HI: u32 = 1; // feature bit 32 → hi word bit 0
const VIRTIO_NET_F_MAC: u32 = 1 << 5; // lo word bit 5

const ST_ACKNOWLEDGE: u32 = 1;
const ST_DRIVER: u32 = 2;
const ST_FEATURES_OK: u32 = 8;
const ST_DRIVER_OK: u32 = 4;

const QSIZE: usize = 8; // descriptors; power of two
const NBUF: usize = 8; // RX buffers
const HDR: usize = 12; // virtio_net_hdr_v1 under VERSION_1
const DESC_WRITE: u16 = 2;

const TIMEOUT: u32 = 100_000_000;

// Ring-frame layout (shared with virtio_blk): desc[8] @0, avail @128, used @256.
// TX packet staging starts at @512 (ring metadata ends well before that).
const OFF_AVAIL: usize = 128;
const OFF_USED: usize = 256;
const OFF_TXBUF: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem {
    id: u32,
    len: u32,
}

static mut BASE: usize = 0; // MMIO base of the matched slot (0 = none)
static mut RX_RING: usize = 0;
static mut TX_RING: usize = 0;
static mut RX_BUFS: [usize; NBUF] = [0; NBUF];
static mut LAST_RX: u16 = 0;
static mut LAST_TX: u16 = 0;
static mut MAC: [u8; 6] = [0; 6];

fn r(off: usize) -> u32 {
    unsafe { read_volatile((BASE + off) as *const u32) }
}

fn w(off: usize, v: u32) {
    unsafe { write_volatile((BASE + off) as *mut u32, v) }
}

fn avail_idx(ring: usize) -> u16 {
    unsafe { read_volatile((ring + OFF_AVAIL + 2) as *const u16) }
}

fn used_idx(ring: usize) -> u16 {
    unsafe { read_volatile((ring + OFF_USED + 2) as *const u16) }
}

pub fn ready() -> bool {
    unsafe { BASE != 0 }
}

pub fn mac() -> [u8; 6] {
    unsafe { MAC }
}

/// Configure one virtqueue (RX = 0 or TX = 1): one 4 KiB frame holds
/// desc + avail + used. TX staging shares that frame at OFF_TXBUF.
fn setup_queue(sel: u32) -> Result<usize, &'static str> {
    w(QUEUE_SEL, sel);
    let max = r(QUEUE_NUM_MAX);
    if max < QSIZE as u32 {
        return Err("QUEUE_NUM_MAX too small");
    }
    w(QUEUE_NUM, QSIZE as u32);
    let frame = pmm::alloc().ok_or("out of frames for virtqueue")?;
    unsafe {
        core::ptr::write_bytes(frame as *mut u8, 0, 4096);
    }
    w(QUEUE_DESC_LOW, frame as u32);
    w(QUEUE_DRIVER_LOW, (frame + OFF_AVAIL) as u32);
    w(QUEUE_DEVICE_LOW, (frame + OFF_USED) as u32);
    w(QUEUE_READY, 1);
    Ok(frame)
}

/// Probe all 32 transports for the net device (DEVICE_ID 1), negotiate
/// features, set up RX queue 0 and TX queue 1, pre-post all RX buffers.
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
            if read_volatile((b + DEVICE_ID) as *const u32) == VIRTIO_ID_NET {
                base = b;
                kprintln!("virtio-net: found at slot {i} ({b:#x})");
                break;
            }
        }
    }
    if base == 0 {
        return Err("no virtio-net in 32 MMIO slots");
    }
    unsafe { BASE = base };

    // Reset + ACKNOWLEDGE + DRIVER.
    w(STATUS, 0);
    w(STATUS, ST_ACKNOWLEDGE | ST_DRIVER);

    // Features: accept VIRTIO_NET_F_MAC + VIRTIO_F_VERSION_1 only.
    // Rejecting MRG_RXBUF/CTRL_VQ keeps single-buffer RX and no ctrl queue.
    w(DEVICE_FEATURES_SEL, 0);
    let _lo = r(DEVICE_FEATURES);
    w(DEVICE_FEATURES_SEL, 1);
    let hi = r(DEVICE_FEATURES);
    if hi & VIRTIO_F_VERSION_1_HI == 0 {
        return Err("device lacks VIRTIO_F_VERSION_1");
    }
    w(DRIVER_FEATURES_SEL, 0);
    w(DRIVER_FEATURES, VIRTIO_NET_F_MAC);
    w(DRIVER_FEATURES_SEL, 1);
    w(DRIVER_FEATURES, VIRTIO_F_VERSION_1_HI);
    w(STATUS, ST_ACKNOWLEDGE | ST_DRIVER | ST_FEATURES_OK);
    if r(STATUS) & ST_FEATURES_OK == 0 {
        return Err("FEATURES_OK rejected");
    }

    // Queues: 0 = receive, 1 = transmit (QEMU adds rx first).
    let rx_ring = setup_queue(0)?;
    let tx_ring = setup_queue(1)?;
    unsafe {
        RX_RING = rx_ring;
        TX_RING = tx_ring;
        LAST_RX = 0;
        LAST_TX = 0;
    }

    // MAC from config space (struct virtio_net_config starts with mac[6]).
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = unsafe { read_volatile((base + CONFIG + i) as *const u8) };
    }
    unsafe { MAC = mac };

    // RX pool: one PMM frame per buffer, each a single device-writable
    // descriptor; post all 8 onto the avail ring up front.
    let descs = rx_ring as *mut Desc;
    for i in 0..NBUF {
        let f = pmm::alloc().ok_or("out of frames for rx buffers")?;
        unsafe {
            core::ptr::write_bytes(f as *mut u8, 0, 4096);
            RX_BUFS[i] = f;
            descs.add(i).write(Desc {
                addr: f as u64,
                len: 4096,
                flags: DESC_WRITE,
                next: 0,
            });
            write_volatile((rx_ring + OFF_AVAIL + 4 + 2 * i) as *mut u16, i as u16);
        }
    }
    fence(Ordering::SeqCst);
    unsafe { write_volatile((rx_ring + OFF_AVAIL + 2) as *mut u16, NBUF as u16) };
    fence(Ordering::SeqCst);
    w(QUEUE_NOTIFY, 0);

    w(STATUS, ST_ACKNOWLEDGE | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK);
    kprintln!(
        "virtio-net: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    Ok(())
}

/// Take one received frame from the RX used ring: (buffer index, total
/// bytes written by the device including the 12-byte header). Non-blocking.
pub fn poll_rx() -> Option<(usize, usize)> {
    if !ready() {
        return None;
    }
    fence(Ordering::Acquire);
    let ring = unsafe { RX_RING };
    if used_idx(ring) == unsafe { LAST_RX } {
        return None;
    }
    let slot = (unsafe { LAST_RX } % QSIZE as u16) as usize;
    let elem = unsafe {
        read_volatile((ring + OFF_USED + 4 + 8 * slot) as *const UsedElem)
    };
    unsafe { LAST_RX = LAST_RX.wrapping_add(1) };
    Some((elem.id as usize, elem.len as usize))
}

/// Payload bytes of a frame taken by `poll_rx` (header stripped).
/// Returns an empty slice if the device reported a short frame.
pub fn rx_bytes(id: usize, total: usize) -> &'static [u8] {
    if id >= NBUF || total < HDR || total > 4096 {
        return &[];
    }
    unsafe {
        core::slice::from_raw_parts((RX_BUFS[id] + HDR) as *const u8, total - HDR)
    }
}

/// Return an RX buffer to the device so it can be refilled.
pub fn repost_rx(id: usize) {
    if !ready() || id >= NBUF {
        return;
    }
    let ring = unsafe { RX_RING };
    let idx = avail_idx(ring);
    unsafe {
        write_volatile(
            (ring + OFF_AVAIL + 4 + 2 * ((idx as usize) % QSIZE)) as *mut u16,
            id as u16,
        );
        fence(Ordering::SeqCst);
        write_volatile((ring + OFF_AVAIL + 2) as *mut u16, idx.wrapping_add(1));
        fence(Ordering::SeqCst);
    }
    w(QUEUE_NOTIFY, 0);
}

/// Transmit one ethernet frame: build the 12-byte header + payload in the
/// TX staging area, publish a single descriptor, notify, and poll for the
/// device to consume it (synchronous, matching the virtio-blk pattern).
pub fn transmit_with<R>(len: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
    let ring = unsafe { TX_RING };
    let stage = ring + OFF_TXBUF;
    debug_assert!(len + HDR <= 4096 - OFF_TXBUF);

    // Header first: zeroed = no offloads (flags/gso/csum all 0).
    unsafe { core::ptr::write_bytes(stage as *mut u8, 0, HDR) };
    let out = unsafe {
        core::slice::from_raw_parts_mut((stage + HDR) as *mut u8, len)
    };
    let result = f(out);

    if ready() {
        unsafe {
            (ring as *mut Desc).add(0).write(Desc {
                addr: stage as u64,
                len: (HDR + len) as u32,
                flags: 0, // device reads the whole buffer
                next: 0,
            });
            let idx = avail_idx(ring);
            write_volatile(
                (ring + OFF_AVAIL + 4 + 2 * ((idx as usize) % QSIZE)) as *mut u16,
                0u16,
            );
            fence(Ordering::SeqCst);
            write_volatile((ring + OFF_AVAIL + 2) as *mut u16, idx.wrapping_add(1));
            fence(Ordering::SeqCst);
        }
        w(QUEUE_NOTIFY, 1);

        // Polled completion (device read the descriptor).
        let mut spins = 0u32;
        loop {
            fence(Ordering::Acquire);
            if used_idx(ring) != unsafe { LAST_TX } {
                unsafe { LAST_TX = used_idx(ring) };
                break;
            }
            spins += 1;
            if spins > TIMEOUT {
                kprintln!(
                    "virtio-net: tx timeout (avail={} used={})",
                    avail_idx(ring),
                    used_idx(ring)
                );
                break;
            }
            core::hint::spin_loop();
        }

        // Ack any interrupt we did not consume via the GIC (never enabled).
        let isr = r(INTERRUPT_STATUS);
        if isr != 0 {
            w(INTERRUPT_ACK, isr);
        }
    }
    result
}
