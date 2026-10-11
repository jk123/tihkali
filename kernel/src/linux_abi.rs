//! Linux (asm-generic aarch64) syscall personality.
//!
//! Dispatch discriminator: Linux uses `svc #0` with the number in x8;
//! NetBSD encodes the number in the SVC immediate (never 0). Error ABI
//! differs too: Linux returns `-errno` in x0, NetBSD sets PSTATE.C.

use tihkali_hal::kprintln;

use crate::arch::trap::TrapFrame;
use crate::proc::{self, Io};

/// Handle a `svc #0` (Linux) call. Applies the Linux epilogue itself;
/// early-returns for sleeps/exit where the frame is already handled.
pub fn svc(frame: &mut TrapFrame) {
    let nr = (frame.x[8] as u32) & 0xffff;
    let (result, err): (i64, u8) = match nr {
        // --- process ---
        93 | 94 => {
            // exit / exit_group
            proc::sys_exit(frame, frame.x[0]);
            return;
        }
        96 => (proc::current_pid() as i64, 0), // set_tid_address
        172 => (proc::current_pid() as i64, 0), // getpid
        // --- stdio ---
        64 => match proc::sys_write(frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Ok(n) => (n, 0),
            Err(e) => (0, e),
        },
        63 => match proc::sys_read(frame, frame.x[0] as usize, frame.x[1], frame.x[2] as usize) {
            Io::Val(n) => (n, 0),
            Io::Err(e) => (0, e),
            Io::Slept => return, // blocked; frame already switched/saved
        },
        57 => match proc::sys_close(frame.x[0] as usize) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        66 => writev(frame.x[0] as usize, frame.x[1], frame.x[2] as usize),
        // --- signals (Linux how = 0/1/2, NetBSD how = 1/2/3) ---
        135 => match proc::sys_sigprocmask(frame.x[0] as i64 + 1, frame.x[1], frame.x[2]) {
            Ok(()) => (0, 0),
            Err(e) => (0, e),
        },
        _ => {
            kprintln!(
                "[linux] ENOSYS nr={nr} x0={:#x} x1={:#x} x2={:#x} elr={:#x}",
                frame.x[0], frame.x[1], frame.x[2], frame.elr
            );
            (0, 78) // ENOSYS
        }
    };

    // Linux epilogue: x0 = value or -errno; carry flags untouched (musl
    // tests with `cmp x0, #-4095` in user space).
    if err != 0 {
        frame.x[0] = (-(err as i64)) as u64;
    } else {
        frame.x[0] = result as u64;
    }
}

/// writev(66): iovec array of {base: u64, len: u64}.
fn writev(fd: usize, iov: u64, cnt: usize) -> (i64, u8) {
    if cnt > 64 {
        return (0, 22); // EINVAL
    }
    let mut total: i64 = 0;
    for i in 0..cnt {
        let Some(base) = crate::proc::read_user_u64(iov + 16 * i as u64) else {
            return (0, 14); // EFAULT
        };
        let Some(len) = crate::proc::read_user_u64(iov + 16 * i as u64 + 8) else {
            return (0, 14);
        };
        if len == 0 {
            continue;
        }
        match proc::sys_write(fd, base, len as usize) {
            Ok(n) => total += n,
            Err(e) => return (total, e),
        }
    }
    (total, 0)
}
