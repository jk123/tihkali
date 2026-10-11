//! Trap frame, exception dispatch, syscall handling, and register dumps.

use tihkali_hal::gicv3;
use tihkali_hal::{kprint, kprintln};

use crate::arch::timer;

/// Saved exception context. Layout is coupled to `SAVE_FRAME`/`RESTORE_FRAME`
/// in trap.S — keep the two in sync.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
}

unsafe extern "C" {
    static vectors: u8; // opaque: address is what matters, not contents
}

pub fn init() {
    let v = core::ptr::addr_of!(vectors) as usize;
    unsafe { core::arch::asm!("msr vbar_el1, {0}", "isb", in(reg) v) }
}

fn read_far() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) v, options(nomem, nostack)) };
    v
}

/// Synchronous exception entry point (from EL0 or EL1).
/// Returns only for syscalls/resolved faults; fatal paths halt.
/// Pending-signal delivery runs before handing control back to asm.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sync_handler(frame: &mut TrapFrame) {
    let esr = frame.esr;
    match esr >> 26 {
        0x15 => svc_dispatch(frame), // SVC from AArch64
        0x20 | 0x21 => {
            // Instruction abort: nothing is mapped executable on demand.
            kprintln!("exec fault at {:#x}", frame.elr);
            fatal(frame)
        }
        0x24 | 0x25 => {
            // Data abort (lower or same EL): demand-zero / copy-on-write.
            let far = read_far() as usize;
            let is_write = (esr >> 6) & 1 == 1; // ISS.WnR (bit 6; bit 24 is ISV)
            let ttbr: u64;
            unsafe {
                core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nomem, nostack));
            }
            match crate::vm::handle_fault(ttbr as usize, far, is_write) {
                Ok(()) => {} // instruction retries (frame untouched)
                Err(msg) => {
                    kprintln!("unhandled data fault: {msg} (FAR={far:#x} WnR={is_write})");
                    fatal(frame)
                }
            }
        }
        _ => fatal(frame),
    }
    // Boundary: svc returns, resolved faults, and any frame a syscall
    // switched to are all eligible for signal delivery.
    crate::proc::deliver_signals(frame);
}

/// Split the two syscall ABIs sharing `svc`:
///   Linux   = svc #0 with the number in x8   → linux_abi::svc
///   NetBSD  = svc #NR (NR never 0)           → immediate dispatch below
fn svc_dispatch(frame: &mut TrapFrame) {
    let imm = frame.esr & 0xffff;
    if imm == 0 {
        crate::linux_abi::svc(frame);
        return;
    }
    let nr = imm;
    let (result, err): (i64, u8) = match nr {
        1 => {
            // SYS_exit(code)
            crate::proc::sys_exit(frame, frame.x[0]);
            return;
        }
        2 => match crate::proc::sys_fork(frame) {
            // SYS_fork: parent gets the child pid, child (later) gets 0
            Ok(pid) => (pid as i64, 0),
            Err(crate::proc::ForkError::NoMem) => (-1, crate::proc::ENOMEM),
        },
        3 => {
            // SYS_read(fd, buf, len): tty-in sleeps, files read through.
            match crate::proc::sys_read(frame, frame.x[0] as usize, frame.x[1], frame.x[2] as usize)
            {
                crate::proc::Io::Val(n) => (n, 0),
                crate::proc::Io::Err(e) => (-1, e),
                crate::proc::Io::Slept => return,
            }
        }
        4 => match crate::proc::sys_write(frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Ok(n) => (n, 0),
            Err(e) => (-1, e),
        },
        5 => {
            // SYS_open(path, flags): O_RDONLY only (read-only initramfs).
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_open(&path, frame.x[1]) {
                    Ok(fd) => (fd as i64, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        6 => match crate::proc::sys_close(frame.x[0] as usize) {
            Ok(()) => (0, 0),
            Err(e) => (-1, e),
        },
        20 => (crate::proc::current_pid() as i64, 0), // SYS_getpid
        59 => {
            // SYS_execve(path, argv)
            match crate::proc::sys_execve(frame, frame.x[0], frame.x[1]) {
                Ok(()) => return, // frame rebuilt: enter the new image
                Err(e) => (-1, e),
            }
        }
        10 => {
            // SYS_unlink(path)
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_unlink(&path) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        36 => match crate::proc::sys_sync() {
            // SYS_sync: write-back dirty nodes
            Ok(()) => (0, 0),
            Err(e) => (-1, e),
        },
        136 => {
            // SYS_mkdir(path, mode)
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_mkdir(&path) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        137 => {
            // SYS_rmdir(path)
            match crate::proc::read_user_cstr(frame.x[0], 128) {
                None => (-1, 14), // EFAULT
                Some(path) => match crate::proc::sys_rmdir(&path) {
                    Ok(()) => (0, 0),
                    Err(e) => (-1, e),
                },
            }
        }
        37 => {
            // SYS_kill(pid, sig)
            match crate::proc::sys_kill(frame.x[0] as i64, frame.x[1]) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        103 | 295 => {
            // SYS_sigreturn / __sigreturn14: frame fully rebuilt.
            crate::proc::sys_sigreturn(frame);
            return;
        }
        340 => {
            // SYS___sigaction_sigtramp(sig, act, oact, sigtramp, sz)
            match crate::proc::sys_sigaction(frame.x[0], frame.x[1], frame.x[2]) {
                Ok(old) => (old as i64, 0),
                Err(e) => (-1, e),
            }
        }
        390 => {
            // SYS___getdents30(fd, buf, len)
            match crate::proc::sys_getdents(frame.x[0] as usize, frame.x[1], frame.x[2] as usize)
            {
                Ok(n) => (n as i64, 0),
                Err(e) => (-1, e),
            }
        }
        293 => {
            // SYS___sigprocmask14(how, set, oset)
            match crate::proc::sys_sigprocmask(frame.x[0] as i64, frame.x[1], frame.x[2]) {
                Ok(()) => (0, 0),
                Err(e) => (-1, e),
            }
        }
        449 => {
            // SYS___wait450(pid, status, options, rusage)
            match crate::proc::sys_wait4(frame, frame.x[0] as i64, frame.x[1], frame.x[2]) {
                crate::proc::Wait4::Done(pid) => (pid, 0),
                crate::proc::Wait4::Slept => return,
                crate::proc::Wait4::Err(e) => (-1, e),
            }
        }
        _ => {
            kprintln!("[user] unknown syscall {nr} at ELR {:#x}", frame.elr);
            (-1, 78) // ENOSYS
        }
    };

    frame.x[0] = result as u64;
    // Error convention: PSTATE.C=1 + positive errno in x0 (NetBSD cerror).
    if err != 0 {
        frame.spsr |= 1 << 29;
        frame.x[0] = err as u64;
    } else {
        frame.spsr &= !(1 << 29);
    }
    // No ELR adjustment: AArch64 SVC's preferred return address already
    // points at the instruction following the svc (same as Linux/NetBSD).
}

/// Unexpected synchronous exception: dump everything we know, then halt.
fn fatal(frame: &mut TrapFrame) -> ! {
    let esr = frame.esr;
    let ec = esr >> 26;
    kprintln!();
    kprintln!("=== sync exception ===");
    kprintln!("ESR_EL1 = {esr:#018x}  (EC {ec:#x}, IL {})", (esr >> 25) & 1);
    kprintln!("ELR_EL1 = {:#018x}  SPSR_EL1 = {:#018x}", frame.elr, frame.spsr);
    kprintln!("FAR_EL1 = {:#018x}", read_far());
    for (i, &v) in frame.x.iter().enumerate() {
        if i % 4 == 0 {
            kprintln!();
        }
        kprint!("x{i:<2}={v:#018x} ");
    }
    kprintln!();
    kprintln!("halting.");
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}

/// IRQ entry: claim from the GIC, dispatch, EOI; preempt EL0 on timer ticks.
#[unsafe(no_mangle)]
pub extern "C" fn rust_irq_handler(frame: &mut TrapFrame) {
    let iar = gicv3::iar();
    let id = iar & 0x00ff_ffff;
    match id {
        gicv3::SPURIOUS => return,
        gicv3::PPI_PHYS_TIMER => timer::on_tick(),
        crate::tty::UART0_SPI => crate::tty::on_rx(),
        other => kprintln!("[irq] unhandled INTID {other}"),
    }
    gicv3::eoir(iar);
    // Round-robin when the tick interrupted user mode (SPSR M=EL0t);
    // additionally, any IRQ that lands while the kernel idles gets a
    // schedule chance (that's how a woken reader resumes from idle).
    if id == gicv3::PPI_PHYS_TIMER && frame.spsr & 0xf == 0 {
        let _ = crate::proc::schedule(frame);
    } else if crate::proc::is_idle() {
        let _ = crate::proc::schedule_ex(frame, false);
    }
    // A tick is also the delivery boundary for running processes.
    crate::proc::deliver_signals(frame);
}
