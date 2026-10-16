//! Platform abstraction layer for tihkali.
//!
//! Exactly one board feature must be selected (the kernel crate's own
//! features): `qemu-virt` (default) or `rpi3`. The mutual-exclusion
//! guards live in `main.rs`.

#[cfg(feature = "qemu-virt")]
#[path = "platform_virt.rs"]
pub mod platform;
#[cfg(feature = "rpi3")]
#[path = "platform_raspi.rs"]
pub mod platform;

pub mod console;
pub mod gic;
#[cfg(feature = "qemu-virt")]
pub mod gicv3;
#[cfg(feature = "rpi3")]
pub mod gic_rpi;
pub mod uart;