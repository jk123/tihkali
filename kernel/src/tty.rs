//! Kernel tty: PL011 RX interrupt → ring buffer → blocking read(2).

use crate::proc;

const CAP: usize = 256;

static mut BUF: [u8; CAP] = [0; CAP];
static mut IN: usize = 0; // monotonic write cursor
static mut OUT: usize = 0; // monotonic read cursor

/// Board UART interrupt number (GIC SPI on virt, VC IRQ on the Pi).
pub const UART0_SPI: u32 = tihkali_hal::platform::UART0_SPI;

/// Wire up RX: unmask PL011 + enable the GIC SPI.
pub fn init() {
    tihkali_hal::console::enable_rx_irq();
    tihkali_hal::gic::enable_spi(UART0_SPI);
}

/// RX interrupt: drain the UART FIFO into the ring, wake readers.
pub fn on_rx() {
    while tihkali_hal::console::rx_pending() {
        let c = tihkali_hal::console::getc();
        if c == 0x03 {
            // Ctrl-C: line-discipline ISIG — SIGINT the foreground group
            // instead of queueing the byte (v1: ISIG always on).
            proc::sigint_foreground();
            continue;
        }
        unsafe {
            let (buf, inp) = (&raw mut BUF, &raw mut IN);
            if (*inp - OUT) < CAP {
                (*buf)[(*inp) % CAP] = c;
                *inp += 1;
            } // else: drop (flow control would go here)
        }
    }
    proc::wake_sleeping();
}

/// True when unread input is queued (poll readiness; no consumption).
pub fn has_data() -> bool {
    unsafe { (*&raw const IN) != (*&raw const OUT) }
}

/// Pop up to `len` bytes into the (already validated) user buffer.
/// Returns None when the buffer is empty → caller sleeps.
pub fn read_user(addr: u64, len: usize) -> Option<usize> {
    unsafe {
        let (inp, outp) = (&raw mut IN, &raw mut OUT);
        let avail = *inp - *outp;
        if avail == 0 {
            return None;
        }
        let n = avail.min(len);
        let dst = addr as *mut u8;
        let buf = &raw const BUF;
        for i in 0..n {
            dst.add(i).write_volatile((*buf)[(*outp + i) % CAP]);
        }
        *outp += n;
        Some(n)
    }
}
