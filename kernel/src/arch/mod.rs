//! aarch64 architecture support.

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("trap.S"));

pub mod mmu;
pub mod timer;
pub mod trap;
