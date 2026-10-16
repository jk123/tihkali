//! Raspberry Pi 3 (QEMU `-M raspi3b` / real BCM2837).
//!
//! No GIC on this board's QEMU wiring: IRQ lines come from the BCM2835/6
//! controllers straight into the CPU (see `gic_rpi`). RAM occupies the low
//! 1 GiB with the peripheral window shadowing its top (0x3f000000+).

/// PL011 UART0 (GPIO14/15 ALT0 must be set on real hardware).
pub const UART0_BASE: usize = 0x3F20_1000;

/// BCM2835 interrupt controller (mapped only at ARMCTRL_IC = peri+0xB200;
/// the INTE 0x2000 window is NOT this device). Enables at +0x10/+0x14.
pub const VCIC_BASE: usize = 0x3F00_B200;

/// ARM-local control block (timer routing: timercontrol[0] at +0x40).
pub const CTRL_BASE: usize = 0x4000_0000;

pub const RAM_BASE: usize = 0x0000_0000;

/// 1 GiB (the peripheral window shadows the top16 MiB of it).
pub const RAM_SIZE: usize = 1024 * 1024 * 1024;

/// UART0's VC/GPU interrupt number (INTERRUPT_UART0, enable in ENABLE_2).
pub const UART0_SPI: u32 = 57;

pub const LOW_DEVICES: &[usize] = &[VCIC_BASE, UART0_BASE];
pub const MID_DEVICES: &[usize] = &[CTRL_BASE];
