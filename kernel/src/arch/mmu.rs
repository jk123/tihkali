//! Kernel MMU: identity+device tables per 1 GiB slot plus the user window.
//!
//! Board-neutral builder: RAM becomes normal-memory identity blocks, the
//! board's device list is overlaid as device blocks (overriding RAM where
//! the peripheral window shadows it, as on the Pi). All slots are SHARED
//! between address spaces; only the user window (L1 slot 4) is private.

use alloc::vec::Vec;

use tihkali_hal::kprintln;
use tihkali_hal::platform::{self, RAM_BASE, RAM_SIZE};

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

impl Clone for Table {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for Table {}

static mut L0: Table = Table([0; 512]);
static mut L1: Table = Table([0; 512]);
/// One L2 per 1 GiB slot of the low 4 GiB.
static mut SLOT_L2: [Table; 4] = [Table([0; 512]); 4];

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
        let slot_l2 = core::ptr::addr_of_mut!(SLOT_L2);

        let ram_lo = RAM_BASE as u64;
        let ram_hi = RAM_BASE as u64 + RAM_SIZE as u64;

        for slot in 0..4usize {
            let base = (slot as u64) << 30;
            let mut used = false;

            // RAM identity (normal memory) within this slot.
            let lo = ram_lo.max(base);
            let hi = ram_hi.min(base + (1u64 << 30));
            if lo < hi {
                used = true;
                let mut a = lo;
                while a < hi {
                    let idx = ((a - base) >> 21) as usize;
                    (*slot_l2)[slot].0[idx] = block_desc(a, ATTR_NORMAL);
                    a += BLOCK_2M;
                }
            }

            // Board devices, applied after RAM so they shadow it (the Pi's
            // peripheral window sits inside its RAM range).
            for &d in platform::LOW_DEVICES.iter().chain(platform::MID_DEVICES.iter()) {
                if (d as u64) >> 30 == slot as u64 {
                    used = true;
                    let idx = (((d as u64) - base) >> 21) as usize;
                    (*slot_l2)[slot].0[idx] = block_desc(d as u64, ATTR_DEVICE);
                }
            }

            if used {
                let tbl = core::ptr::addr_of!(SLOT_L2) as u64
                    + (slot * core::mem::size_of::<Table>()) as u64;
                (*l1).0[slot] = tbl | TBL;
            }
        }
        // Slot 4 (user window) is installed per address space by create_space.

        (*l0).0[0] = l1 as u64 | TBL;

        core::arch::asm!("msr mair_el1, {}", in(reg) MAIR_VAL);
        core::arch::asm!("msr tcr_el1, {}", in(reg) TCR_VAL);
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) l0 as u64);

        flush_tlb();

        kprintln!("mmu: tables built (L0->L1->slot L2s), enabling");

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

/// Point TTBR0 at `ttbr`.
pub fn activate(ttbr: usize) {
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr as u64);
        flush_tlb();
    }
}

/// Boot L1 words (kernel slots) — copied into every new address space.
fn boot_l1() -> [u64; 512] {
    unsafe { (*core::ptr::addr_of!(L1)).0 }
}

/// Build a fresh address space: [l0, l1, l2_user, l3_text, l3_stack].
/// Kernel/device slots are SHARED with the boot tables; only the user
/// window (L1 slot 4) and its empty L3s are private.
pub fn create_space() -> Option<Vec<usize>> {
    let mut frames: Vec<usize> = Vec::with_capacity(5);
    for _ in 0..5 {
        match pmm::alloc() {
            Some(f) => frames.push(f),
            None => {
                for f in frames.iter() {
                    pmm::free(*f);
                }
                return None;
            }
        }
    }
    let [l0, l1, l2u, l3t, l3s] = [frames[0], frames[1], frames[2], frames[3], frames[4]];
    unsafe {
        for &f in frames.iter() {
            core::ptr::write_bytes(f as *mut u8, 0, 4096);
        }
        // Private L1: inherit kernel slots, own the user slot.
        let words = boot_l1();
        (l1 as *mut u64).copy_from_nonoverlapping(words.as_ptr(), 512);
        (l1 as *mut u64).add(L1_USER_SLOT).write(l2u as u64 | TBL);
        // L0 -> L1.
        (l0 as *mut u64).write(l1 as u64 | TBL);
        // User L2: text/stack slots point at the (empty) L3s.
        (l2u as *mut u64).write(l3t as u64 | TBL);
        (l2u as *mut u64).add(1).write(l3s as u64 | TBL);
    }
    Some(frames)
}
