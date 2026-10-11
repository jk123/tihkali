//! Kernel console: routes `fmt::Arguments` to the platform UART.

use core::fmt::{self, Write};

use crate::platform::UART0_BASE;
use crate::uart::Pl011;

static UART: Pl011 = Pl011::new(UART0_BASE);

pub fn init() {
    UART.init();
}

impl Write for &Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            match b {
                b'\n' => {
                    self.putc(b'\r');
                    self.putc(b'\n');
                }
                _ => self.putc(b),
            }
        }
        Ok(())
    }
}

pub fn _print(args: fmt::Arguments) {
    let mut w = &UART;
    let _ = w.write_fmt(args);
}

/// Raw byte sink for `write(2)`; translates `\n` → `\r\n` like a tty.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            UART.putc(b'\r');
        }
        UART.putc(b);
    }
}

/// Unmask PL011 RX interrupts (after `init`).
pub fn enable_rx_irq() {
    UART.enable_rx_irq();
}

pub fn rx_pending() -> bool {
    UART.rx_pending()
}

pub fn getc() -> u8 {
    UART.getc()
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::console::_print(core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {
        $crate::kprint!("{}\n", core::format_args!($($arg)*))
    };
}
