//! QEMU `-machine virt` (aarch64) memory map.

/// PL011 UART0.
pub const UART0_BASE: usize = 0x0900_0000;

/// GICv3 distributor.
pub const GICD_BASE: usize = 0x0800_0000;

/// GICv3 redistributor (single core).
pub const GICR_BASE: usize = 0x080A_0000;

/// virtio-mmio transports (32 slots × 0x200).
pub const VIRTIO_MMIO_BASE: usize = 0x0A00_0000;

/// Start of RAM.
pub const RAM_BASE: usize = 0x4000_0000;

/// RAM size handed to QEMU (-m 256M).
pub const RAM_SIZE: usize = 256 * 1024 * 1024;
