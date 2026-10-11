#![no_std]

//! Platform abstraction layer for tihkali.
//!
//! Exactly one board feature must be selected (normally via the kernel's
//! own features): `qemu-virt` (default) or `raspi3`.

#[cfg(all(feature = "qemu-virt", feature = "raspi3"))]
compile_error!("board features are mutually exclusive: qemu-virt xor raspi3");
#[cfg(not(any(feature = "qemu-virt", feature = "raspi3")))]
compile_error!("enable exactly one board feature: qemu-virt or raspi3");

#[cfg(feature = "qemu-virt")]
#[path = "platform_virt.rs"]
pub mod platform;
#[cfg(feature = "raspi3")]
#[path = "platform_raspi.rs"]
pub mod platform;

pub mod console;
pub mod gic;
#[cfg(feature = "qemu-virt")]
pub mod gicv3;
#[cfg(feature = "raspi3")]
pub mod gic_rpi;
pub mod uart;
