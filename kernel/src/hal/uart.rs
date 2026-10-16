//! Minimal PL011 UART driver (polling TX).

const FR_TXFF: u32 = 1 << 5; // transmit FIFO full
const FR_RXFE: u32 = 1 << 4; // receive FIFO empty
const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;
const LCRH_WLEN_8: u32 = 0b11 << 5;
const LCRH_FEN: u32 = 1 << 4;
const IMSC_RXIM: u32 = 1 << 4; // RX receive interrupt mask

pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    const DR: usize = 0x000;
    const FR: usize = 0x018;
    const IBRD: usize = 0x024;
    const FBRD: usize = 0x028;
    const LCRH: usize = 0x02c;
    const CR: usize = 0x030;
    const IMSC: usize = 0x038;
    const ICR: usize = 0x044;

    fn write_reg(&self, off: usize, val: u32) {
        unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val) }
    }

    fn read_reg(&self, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + off) as *const u32) }
    }

    /// 8N1, FIFO on, polling mode. Baud divider assumes the 24 MHz
    /// UARTCLK of QEMU virt (QEMU does not enforce timing anyway).
    pub fn init(&self) {
        self.write_reg(Self::CR, 0);
        self.write_reg(Self::ICR, 0x7ff);
        self.write_reg(Self::IBRD, 13);
        self.write_reg(Self::FBRD, 1);
        self.write_reg(Self::LCRH, LCRH_WLEN_8 | LCRH_FEN);
        self.write_reg(Self::IMSC, 0);
        self.write_reg(Self::CR, CR_UARTEN | CR_TXE | CR_RXE);
    }

    pub fn putc(&self, c: u8) {
        while self.read_reg(Self::FR) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        self.write_reg(Self::DR, c as u32);
    }

    /// Unmask the RX interrupt (call after `init`).
    pub fn enable_rx_irq(&self) {
        let v = self.read_reg(Self::IMSC);
        self.write_reg(Self::IMSC, v | IMSC_RXIM);
    }

    pub fn rx_pending(&self) -> bool {
        self.read_reg(Self::FR) & FR_RXFE == 0
    }

    /// Pop one received byte (call only when [`Self::rx_pending`]).
    pub fn getc(&self) -> u8 {
        (self.read_reg(Self::DR) & 0xff) as u8
    }
}
