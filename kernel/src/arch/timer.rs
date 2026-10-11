//! ARM generic timer (non-secure physical timer, PPI 30).

use core::sync::atomic::{AtomicU64, Ordering};

use tihkali_hal::kprintln;

static TICKS: AtomicU64 = AtomicU64::new(0);
static mut INTERVAL_TICKS: u64 = 0;
static mut FREQ_HZ: u64 = 0;

fn read_cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

fn write_cntfrq(v: u64) {
    unsafe { core::arch::asm!("msr cntfrq_el0, {}", "isb", in(reg) v) }
}

fn set_tval(ticks: u64) {
    unsafe { core::arch::asm!("msr cntp_tval_el0, {}", "isb", in(reg) ticks) }
}

/// Arm the physical timer for `hz` periodic interrupts.
pub fn init(hz: u64) {
    let mut freq = read_cntfrq();
    if freq == 0 {
        // QEMU normally programs CNTFRQ; fall back so ticks still work.
        freq = 62_500_000;
        write_cntfrq(freq);
    }
    let interval = (freq / hz).max(1);
    unsafe {
        FREQ_HZ = freq;
        INTERVAL_TICKS = interval;
    }
    set_tval(interval);
    unsafe { core::arch::asm!("msr cntp_ctl_el0, {}", "isb", in(reg) 1u64) }
    kprintln!("timer: {hz} Hz, CNTFRQ = {freq} Hz, interval = {interval} ticks");
}

/// Called from the IRQ handler in interrupt context.
pub fn on_tick() {
    let n = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    // Re-arm first so the level-triggered PPI deasserts before EOI.
    let interval = unsafe { INTERVAL_TICKS };
    set_tval(interval);

    let freq = unsafe { FREQ_HZ };
    let hz = freq / interval; // effective tick rate (rounds down)
    if n <= 5 || n % (hz * 5) == 0 {
        let sec = n / hz;
        let frac = (n % hz) * 100 / hz;
        kprintln!("[irq] tick {n:>4}  uptime {sec:>2}.{frac:02}s");
    }
}
