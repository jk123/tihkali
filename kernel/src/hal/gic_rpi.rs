//! Interrupt handling on BCM283x: QEMU wires controller outputs straight
//! into the CPU IRQ line — there is no GIC to claim from. `iar()` polls the
//! two sources we use; acks are source-side (re-arming the generic timer
//! drops CNTPNSIRQ, draining the PL011 drops the GPU IRQ).

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

use super::console;
use super::platform::{CTRL_BASE, UART0_SPI, VCIC_BASE};

pub const SPURIOUS: u32 = 1023;
pub const PPI_PHYS_TIMER: u32 = 30;

/// Route the non-secure physical timer (control source 1 = CNTPNSIRQ) to
/// this core's IRQ. GPU IRQs already target core0 (route regs reset to 0).
pub fn init() {
    unsafe {
        let p = (CTRL_BASE + 0x40) as *mut u32; // timercontrol[0]
        write_volatile(p, read_volatile(p) | 0x2);
    }
    crate::kprintln!("irq: BCM283x poll dispatcher (board has no GIC)");
}

/// Enable a source. On this board the numbers are VC/GPU interrupt IDs
/// (plat::UART0_SPI = 57): ENABLE_1 covers 0..31, ENABLE_2 covers 32..63.
pub fn enable_spi(intid: u32) {
    unsafe {
        let (off, bit) = if intid < 32 {
            (0x10usize, intid)
        } else if intid < 64 {
            (0x14, intid - 32)
        } else {
            return; // GPU bank beyond 64: unused on this board
        };
        let p = (VCIC_BASE + off) as *mut u32;
        write_volatile(p, read_volatile(p) | (1 << bit));
    }
}

/// Highest-priority pending source, or SPURIOUS.
pub fn iar() -> u32 {
    let (ctl, tval): (u64, i64);
    unsafe {
        asm!("mrs {}, cntp_ctl_el0", out(reg) ctl, options(nomem, nostack));
        asm!("mrs {}, cntp_tval_el0", out(reg) tval, options(nomem, nostack));
    }
    // CNTP_TVAL is a 32-bit register that mrs zero-extends: interpret as i32.
    if ctl & 1 != 0 && (tval as i32) < 0 {
        return PPI_PHYS_TIMER;
    }
    if console::rx_pending() {
        return UART0_SPI;
    }
    SPURIOUS
}

/// No GIC register to write: handlers re-arm the timer / drain the UART.
pub fn eoir(_id: u32) {}
