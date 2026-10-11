#![no_std]

//! Platform abstraction layer for tihkali.
//!
//! One feature selects the board: `qemu-virt` (default), later `rpi3`/`rpi4`.

#[cfg(feature = "qemu-virt")]
pub mod platform;

pub mod console;
pub mod gicv3;
pub mod uart;

pub use platform::{GICD_BASE, GICR_BASE, RAM_BASE, RAM_SIZE, UART0_BASE};
