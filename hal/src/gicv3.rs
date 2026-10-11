//! GICv3 driver (GICD + one GICR + CPU interface via system registers).
//! Assumes a single core — tihkali's current target configuration.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

use crate::platform::{GICD_BASE, GICR_BASE};

const GICD_CTLR: usize = 0x000;
const GICD_ICENABLER0: usize = 0x180;
const GICD_RWP: u32 = 1 << 31;

const GICR_WAKER: usize = 0x0014;
const GICR_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_CHILDREN_ASLEEP: u32 = 1 << 2;
/// SGI/PPI frame sits 64 KiB above the redistributor base.
const GICR_SGI_FRAME: usize = 0x1_0000;
const GICR_IGROUPR0: usize = 0x080;
const GICR_ISENABLER0: usize = 0x100;
const GICR_ICENABLER0: usize = 0x180;
const GICR_IPRIORITYR0: usize = 0x400;

/// Non-secure physical timer PPI.
pub const PPI_PHYS_TIMER: u32 = 30;

fn w32(base: usize, off: usize, val: u32) {
    unsafe { write_volatile((base + off) as *mut u32, val) }
}

fn r32(base: usize, off: usize) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}

fn wait_rwp(base: usize) {
    while r32(base, GICD_CTLR) & GICD_RWP != 0 {
        core::hint::spin_loop();
    }
}

/// Initialize distributor, redistributor, and CPU interface for
/// group-1 non-secure interrupts, then enable INTID 30 (PPI).
pub fn init() {
    // Distributor off while configuring; clear all SPI enables.
    w32(GICD_BASE, GICD_CTLR, 0);
    wait_rwp(GICD_BASE);
    for n in 1..32u32 {
        w32(GICD_BASE, GICD_ICENABLER0 as usize + n as usize * 4, 0xffff_ffff);
    }

    // Wake the redistributor.
    let waker = r32(GICR_BASE, GICR_WAKER) & !GICR_PROCESSOR_SLEEP;
    w32(GICR_BASE, GICR_WAKER, waker);
    while r32(GICR_BASE, GICR_WAKER) & GICR_CHILDREN_ASLEEP != 0 {
        core::hint::spin_loop();
    }

    // SGI/PPI frame: all group 1, all off, then enable the timer PPI.
    let sgi = GICR_BASE + GICR_SGI_FRAME;
    w32(sgi, GICR_IGROUPR0, 0xffff_ffff);
    w32(sgi, GICR_ICENABLER0, 0xffff_ffff);
    unsafe { write_volatile((sgi + GICR_IPRIORITYR0 + PPI_PHYS_TIMER as usize) as *mut u8, 0x80) };
    w32(sgi, GICR_ISENABLER0, 1 << PPI_PHYS_TIMER);

    // CPU interface: system registers, allow priorities > 0x80, group1.
    unsafe {
        asm!("msr icc_sre_el1, {}", "isb", in(reg) 1u64);
        asm!("msr icc_pmr_el1, {}", in(reg) 0xf0u64);
        asm!("msr icc_bpr1_el1, {}", in(reg) 0u64);
        asm!("msr icc_ctlr_el1, {}", in(reg) 0u64);
        asm!("msr icc_igrpen1_el1, {}", "isb", in(reg) 1u64);
    }

    // Distributor on: EnableGrp1NS is bit 1 (GICv3 5.3.20; bit 2 = Grp1S).
    w32(GICD_BASE, GICD_CTLR, 1 << 1);
    wait_rwp(GICD_BASE);
}

/// Acknowledge: returns the INTID (and priority/cluster bits to hand to EOI).
pub fn iar() -> u32 {
    let v: u64;
    unsafe { asm!("mrs {}, icc_iar1_el1", out(reg) v, options(nomem, nostack)) }
    v as u32
}

/// End of interrupt. Pass the value read from [`iar`].
pub fn eoir(val: u32) {
    unsafe { asm!("msr icc_eoir1_el1, {}", in(reg) val as u64, options(nomem, nostack)) }
}

/// Spurious interrupt ID returned when there is nothing to claim.
pub const SPURIOUS: u32 = 1023;

/// Enable an SPI: group 1, priority 0x80, unmasked in the distributor.
pub fn enable_spi(intid: u32) {
    let n = (intid / 32) as usize;
    let bit = 1u32 << (intid % 32);
    w32(GICD_BASE, 0x80 + n * 4, 0xffff_ffff); // IGROUPR: group 1
    w32(GICD_BASE, 0x100 + n * 4, bit); // ISENABLER
    unsafe {
        write_volatile((GICD_BASE + 0x400 + intid as usize) as *mut u8, 0x80);
    }
}
