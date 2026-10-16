//! NetBSD syscall personality.
//!
//! Numbers are generated at build time from NetBSD's own
//! `sys/kern/syscalls.master` — the same table `makesyscalls.sh` consumes —
//! rather than transcribed by hand, so the compat_09..compat_110 numbering
//! stays authoritative. See `assets/bsd/THIRD-PARTY.txt` for its BSD
//! 4-clause attribution.

// Most of the 512 generated calls are not dispatched yet. A warning is a
// failure in this build, so the table must not trip dead_code.
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/netbsd_syscall_table.rs"));

/// tihkali's private display door, in the NetBSD ABI's number space.
///
/// These are NOT NetBSD syscalls — they collide with nothing NetBSD
/// defines on aarch64 and are unreachable from a real NetBSD libc, so
/// userland sees them as unknown.
pub mod fb {
    pub const INFO: u16 = 481;
    pub const FILL_RECT: u16 = 482;
    pub const BLIT: u16 = 483;
}