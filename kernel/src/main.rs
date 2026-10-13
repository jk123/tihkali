#![no_std]
#![no_main]

//! tihkali kernel — QEMU virt (aarch64) first target.

extern crate alloc;

mod arch;
mod cpio;
mod file;
mod fs;
mod kmem;
mod linux_abi;
#[cfg(feature = "net")]
mod net;
mod mm;
mod proc;
mod tty;
mod user;
mod virtio_blk;
#[cfg(feature = "net")]
mod virtio_net;
mod vm;

use core::panic::PanicInfo;

use tihkali_hal::{console, gic, kprintln};

/// Embedded initramfs: used when no virtio-blk disk is attached.
static INITRAMFS: &[u8] = include_bytes!(env!("TIHKALI_INITRAMFS"));

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(entry_el: u64) -> ! {
    console::init();
    kprintln!("tihkali {} booting", env!("CARGO_PKG_VERSION"));
    kprintln!("boot: entered at EL{entry_el}, now at EL{}", current_el());

    gic::init();
    kprintln!("gic: distributor/redistributor/CPU interface up, PPI30 enabled");
    tty::init();
    kprintln!("tty: PL011 RX on SPI 33");

    arch::timer::init(100);
    arch::trap::init();
    kprintln!("irq: EL1 vectors installed");

    arch::mmu::init();
    mm::pmm::init();
    mm::pmm::test();
    heap_test();

    match virtio_blk::init() {
        Ok(()) => {
            // Read sector 0 and show the cpio magic as a smoke test.
            let mut magic = [0u8; 512];
            match virtio_blk::read_sectors(0, &mut magic) {
                Ok(()) => kprintln!(
                    "virtio-blk: LBA0 magic = {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    magic[0], magic[1], magic[2], magic[3], magic[4], magic[5]
                ),
                Err(e) => kprintln!("virtio-blk: read failed: {e}"),
            }
        }
        Err(e) => kprintln!("virtio-blk: {e} (kernel will use embedded initramfs)"),
    }

    // Mount the initramfs: prefer the disk image, fall back to the embed.
    let img: alloc::vec::Vec<u8> = if virtio_blk::ready() {
        match virtio_blk::read_disk() {
            Ok(v) => {
                kprintln!("initramfs: read {} bytes from disk", v.len());
                v
            }
            Err(e) => {
                kprintln!("initramfs: disk read failed ({e}), using embedded copy");
                INITRAMFS.to_vec()
            }
        }
    } else {
        INITRAMFS.to_vec()
    };
    let n = fs::mount(img);
    kprintln!("initramfs: mounted, {n} entries");

    #[cfg(feature = "net")]
    net::smoke(); // boot-time ARP/ICMP smoke; prints `net:` lines, never panics

    let Some(sh) = fs::lookup("/bin/sh") else {
        panic!("initramfs: no /bin/sh");
    };
    if fs::is_dir(sh) {
        panic!("initramfs: /bin/sh is a directory");
    }
    let Some(space) = arch::mmu::create_space() else {
        panic!("pid0: out of memory creating address space");
    };
    arch::mmu::activate(space[0]);
    let (entry, image_end) = match fs::with_bytes(sh, |elf| user::load(elf, space[0])) {
        Ok(v) => v,
        Err(msg) => panic!("pid0 load failed: {msg}"),
    };
    if user::install_trampoline(space[0]).is_err() {
        panic!("pid0: trampoline install failed");
    }
    kprintln!("user: /bin/sh ({} bytes) loaded, entry {:#x}", fs::data_len(sh), entry);
    proc::init(entry, image_end, space);
    kprintln!("boot: entering EL0 (pid 0)");
    user::enter(entry)
}


/// Where `sys_exit` returns control: no scheduler yet, so we idle at EL1
/// (interrupts enabled via the synthetic SPSR the syscall handler installs).
#[unsafe(no_mangle)]
pub extern "C" fn kernel_idle() -> ! {
    use core::sync::atomic::{AtomicBool, Ordering};
    static ANNOUNCED: AtomicBool = AtomicBool::new(false);
    if !ANNOUNCED.swap(true, Ordering::Relaxed) {
        kprintln!("kernel: back at EL1, idling");
    }
    proc::set_idle(true);
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}

fn current_el() -> u64 {
    let el: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack));
    }
    el >> 2 & 0b11
}

fn heap_test() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    let mut v: Vec<u64> = Vec::new();
    for i in 0..1000u64 {
        v.push(i * 7);
    }
    let head = v[0];
    let tail = v[999];
    drop(v);

    let b = Box::new([0xA5u8; 128]);
    let probe = b[127];
    drop(b);

    // alloc → free → alloc: exercises reuse/coalescing
    let v2: Vec<u32> = (0..64).collect();
    let sum: u32 = v2.iter().sum();
    drop(v2);

    kprintln!(
        "heap: Vec({head},{tail}) Box({probe:#x}) reuse(sum={sum}) ok"
    );
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("kernel panic: {info}");
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}
