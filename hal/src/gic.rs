//! Board-selected interrupt facade: same names on every board so the
//! kernel's trap dispatch stays board-agnostic.

#[cfg(feature = "qemu-virt")]
pub use crate::gicv3::{eoir, enable_spi, init, iar, PPI_PHYS_TIMER, SPURIOUS};

#[cfg(feature = "raspi3")]
pub use crate::gic_rpi::{eoir, enable_spi, init, iar, PPI_PHYS_TIMER, SPURIOUS};
