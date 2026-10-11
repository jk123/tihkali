//! Kernel MMU setup: identity maps for RAM and device ranges, then enable.
//!
//! Boot tables (used until the first process space is activated):
//!   L0[0]    -> L1
//!   L1[0]    -> L2_DEV : 0x0000_0000-0x3fff_ffff (GIC + UART 2 MiB blocks)
//!   L1[1]    -> L2_RAM : 0x4000_0000-0x4fff_ffff identity (256 MiB)
//!
//! Per-process spaces (`create_space`) copy these kernel tables and add
//! L1[4] -> L2_USER covering the user VA window at 4 GiB (see user.rs),
//! with empty L3 page tables filled in on demand.

use alloc::vec::Vec;

use tihkali_hal::kprintln;
use tihkali_hal::platform::{GICD_BASE, RAM_BASE, RAM_SIZE, UART0_BASE, VIRTIO_MMIO_BASE};

use crate::mm::pmm;

const BLOCK_2M: u64 = 2 * 1024 * 1024;

const VALID: u64 = 1;
const TABLE: u64 = 2;
const ATTR_NORMAL: u64 = 0 << 2; // MAIR index 0
const ATTR_DEVICE: u64 = 1 << 2; // MAIR index 1
const SH_INNER: u64 = 3 << 8;
const AF: u64 = 1 << 10;

const MAIR_VAL: u64 = 0xFF | (0x04 << 8); // normal WB | device-nGnRE
const TCR_VAL: u64 = 16 | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 32);
// T0SZ=16 (48-bit), IRGN=WBWA, ORGN=WBWA, SH=inner, TG0=4K, IPS=40-bit

/// L1 slot covering VA 4..5 GiB (the user window).
pub(crate) const L1_USER_SLOT: usize = 4;

#[repr(C, align(4096))]
pub(crate) struct Table(pub(crate) [u64; 512]);

static mut L0: Table = Table([0; 512]);
static mut L1: Table = Table([0; 512]);
static mut L2_DEV: Table = Table([0; 512]);
static mut L2_RAM: Table = Table([0; 512]);

pub(crate) fn block_desc(addr: u64, attr: u64) -> u64 {
    addr | attr | SH_INNER | AF | VALID
}

/// Descriptor bits shared by table and page entries.
pub(crate) const TBL: u64 = TABLE | VALID;
pub(crate) const DESC_MASK: u64 = 0x0000_FFFF_FFFF_F000; // address bits [47:12]

pub fn init() {
    unsafe {
        let l0 = core::ptr::addr_of_mut!(L0);
        let l1 = core::ptr::addr_of_mut!(L1);
        let l2d = core::ptr::addr_of_mut!(L2_DEV);
        let l2r = core::ptr::addr_of_mut!(L2_RAM);

        // Devices: GIC distributor/redistributor and PL011.
        (*l2d).0[(GICD_BASE as u64 / BLOCK_2M) as usize] =
            block_desc(GICD_BASE as u64, ATTR_DEVICE);
        (*l2d).0[(UART0_BASE as u64 / BLOCK_2M) as usize] =
            block_desc(UART0_BASE as u64, ATTR_DEVICE);
        (*l2d).0[(VIRTIO_MMIO_BASE as u64 / BLOCK_2M) as usize] =
            block_desc(VIRTIO_MMIO_BASE as u64, ATTR_DEVICE);

        // RAM: exactly the 256 MiB QEMU gives us.
        let n = (RAM_SIZE as u64 / BLOCK_2M) as usize;
        for i in 0..n {
            let addr = RAM_BASE as u64 + i as u64 * BLOCK_2M;
            (*l2r).0[i] = block_desc(addr, ATTR_NORMAL);
        }

        (*l1).0[0] = l2d as u64 | TBL;
        (*l1).0[1] = l2r as u64 | TBL;
        (*l0).0[0] = l1 as u64 | TBL;

        core::arch::asm!("msr mair_el1, {}", in(reg) MAIR_VAL);
        core::arch::asm!("msr tcr_el1, {}", in(reg) TCR_VAL);
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) l0 as u64);

        flush_tlb();

        kprintln!("mmu: tables built (L0->L1->L2), enabling");

        let mut sctlr: u64;
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12); // M | C | I
        core::arch::asm!("msr sctlr_el1, {}", "isb", in(reg) sctlr);

        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        kprintln!("mmu: enabled, SCTLR_EL1 = {sctlr:#018x}, TTBR0 = {:#x}", l0 as u64);
    }
}

pub(crate) fn flush_tlb() {
    unsafe {
        core::arch::asm!("dsb sy");
        core::arch::asm!("tlbi vmalle1");
        core::arch::asm!("dsb sy", "isb");
    }
}

/// Point TTBR0 at `ttbr` (6 frame addresses: see `create_space`).
pub fn activate(ttbr: usize) {
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr as u64);
        flush_tlb();
    }
}

/// Build a fresh address space: [l0, l1, l2_ram, l2_user, l3_text, l3_stack].
/// Kernel identity/device tables are shared with the boot tables; user L3s
/// start empty (pages are populated by exec's loader or demand-faults).
pub fn create_space() -> Option<Vec<usize>> {
    let mut frames: Vec<usize> = Vec::with_capacity(6);
    for _ in 0..6 {
        frames.push(pmm::alloc()?);
    }
    // Zero every new table.
    for &f in frames.iter() {
        unsafe { core::ptr::write_bytes(f as *mut u8, 0, 4096) };
    }
    let [l0, l1, l2ram, l2user, l3t, l3s] = [frames[0], frames[1], frames[2], frames[3], frames[4], frames[5]];

    unsafe {
        // Kernel RAM identity map: copy the boot template.
        (l2ram as *mut Table)
            .copy_from_nonoverlapping(core::ptr::addr_of!(L2_RAM) as *const Table, 1);

        // L1: shared devices, private RAM/user L2s.
        let l1p = l1 as *mut Table;
        (*l1p).0[0] = core::ptr::addr_of!(L2_DEV) as u64 | TBL;
        (*l1p).0[1] = l2ram as u64 | TBL;
        (*l1p).0[L1_USER_SLOT] = l2user as u64 | TBL;

        // L0 -> L1.
        (*(l0 as *mut Table)).0[0] = l1 as u64 | TBL;

        // User L2: text/stack slots point at the (empty) L3s.
        let l2u = l2user as *mut Table;
        (*l2u).0[0] = l3t as u64 | TBL;
        (*l2u).0[1] = l3s as u64 | TBL;
    }
    Some(frames)
}
