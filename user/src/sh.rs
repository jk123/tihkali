#![no_std]
#![no_main]

//! tihkali `/bin/sh`: interactive shell over the blocking tty.
//!
//! Commands: `greet`, `hello` (fork+exec), `exit`, anything else → not found.

use core::arch::asm;
use core::panic::PanicInfo;

unsafe fn write_bytes(fd: usize, buf: &[u8]) {
    let ret: isize;
    let err: u64;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd as isize => ret,
            in("x1") buf.as_ptr() as i64,
            in("x2") buf.len() as i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 || ret < 0 {
        unsafe { exit(9) }
    }
}

unsafe fn write(fd: usize, msg: &str) {
    let ret: isize;
    let err: u64;
    unsafe {
        asm!(
            "svc #4",
            "cset {err}, hs",
            inlateout("x0") fd as isize => ret,
            in("x1") msg.as_ptr(),
            in("x2") msg.len(),
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 || ret < 0 {
        unsafe { exit(9) }
    }
}

/// Blocking read of exactly one byte; -1 on error.
unsafe fn read1() -> i32 {
    let mut c = [0u8; 1];
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #3", // SYS_read
            "cset {err}, hs",
            inlateout("x0") 0i64 => ret,
            in("x1") c.as_mut_ptr() as i64,
            in("x2") 1i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 || ret < 0 {
        -1
    } else {
        c[0] as i32
    }
}

unsafe fn fork() -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #2",
            "cset {err}, hs",
            inlateout("x0") 0i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

unsafe fn wait4o(pid: i64, status: *mut i32, options: i64) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #449",
            "cset {err}, hs",
            inlateout("x0") pid => ret,
            in("x1") status as i64,
            in("x2") options,
            in("x3") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

unsafe fn wait4(pid: i64, status: *mut i32) -> i64 {
    unsafe { wait4o(pid, status, 0) }
}

/// sigprocmask(how, mask): returns 0 or negative errno.
unsafe fn sigprocmask(how: i64, mask: u64) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #293", // SYS___sigprocmask14
            "cset {err}, hs",
            inlateout("x0") how => ret,
            in("x1") &mask as *const u64 as i64,
            in("x2") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

unsafe fn execve(path: &str, argv: &[&str]) -> i64 {
    let mut pbuf = [0u8; 64];
    let n = path.len().min(62);
    pbuf[..n].copy_from_slice(&path.as_bytes()[..n]);
    pbuf[n] = 0;

    let mut sbuf = [[0u8; 64]; 8];
    let mut ptrs = [0u64; 9];
    for (i, a) in argv.iter().enumerate().take(8) {
        let len = a.len().min(62);
        sbuf[i][..len].copy_from_slice(&a.as_bytes()[..len]);
        sbuf[i][len] = 0;
        ptrs[i] = sbuf[i].as_ptr() as u64;
    }
    ptrs[argv.len().min(8)] = 0;

    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #59",
            "cset {err}, hs",
            inlateout("x0") pbuf.as_ptr() as i64 => ret,
            in("x1") ptrs.as_ptr() as i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

unsafe fn open(path: &str, flags: i64) -> i64 {
    let mut pbuf = [0u8; 64];
    let n = path.len().min(62);
    pbuf[..n].copy_from_slice(&path.as_bytes()[..n]);
    pbuf[n] = 0;
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #5", // SYS_open
            "cset {err}, hs",
            inlateout("x0") pbuf.as_ptr() as i64 => ret,
            in("x1") flags,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn close(fd: i64) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #6", // SYS_close
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn read(fd: i64, buf: &mut [u8]) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #3", // SYS_read
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf.as_mut_ptr() as i64,
            in("x2") buf.len() as i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn getdents(fd: i64, buf: &mut [u8]) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #390", // SYS___getdents30
            "cset {err}, hs",
            inlateout("x0") fd => ret,
            in("x1") buf.as_mut_ptr() as i64,
            in("x2") buf.len() as i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn unlink(path: &str) -> i64 {
    let mut pbuf = [0u8; 64];
    let n = path.len().min(62);
    pbuf[..n].copy_from_slice(&path.as_bytes()[..n]);
    pbuf[n] = 0;
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #10", // SYS_unlink
            "cset {err}, hs",
            inlateout("x0") pbuf.as_ptr() as i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn rmdir(path: &str) -> i64 {
    let mut pbuf = [0u8; 64];
    let n = path.len().min(62);
    pbuf[..n].copy_from_slice(&path.as_bytes()[..n]);
    pbuf[n] = 0;
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #137", // SYS_rmdir
            "cset {err}, hs",
            inlateout("x0") pbuf.as_ptr() as i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn getpid() -> i64 {
    let ret: i64;
    unsafe { asm!("svc #20", inlateout("x0") 0i64 => ret, options(nostack)) };
    ret
}

unsafe fn kill(pid: i64, sig: i64) -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #37", // SYS_kill
            "cset {err}, hs",
            inlateout("x0") pid => ret,
            in("x1") sig,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn signal(sig: i64, handler: usize) -> i64 {
    // struct sigaction: sa_handler at offset 0; mask/flags zeroed (v1).
    let act: [u64; 4] = [handler as u64, 0, 0, 0];
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #340", // SYS___sigaction_sigtramp
            "cset {err}, hs",
            inlateout("x0") sig => ret,
            in("x1") act.as_ptr() as i64,
            in("x2") 0i64,
            in("x3") 0i64,
            in("x4") 0i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn mkdir(path: &str) -> i64 {
    let mut pbuf = [0u8; 64];
    let n = path.len().min(62);
    pbuf[..n].copy_from_slice(&path.as_bytes()[..n]);
    pbuf[n] = 0;
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #136", // SYS_mkdir
            "cset {err}, hs",
            inlateout("x0") pbuf.as_ptr() as i64 => ret,
            in("x1") 0o755i64,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn sync() -> i64 {
    let ret: i64;
    let err: u64;
    unsafe {
        asm!(
            "svc #36", // SYS_sync
            "cset {err}, hs",
            inlateout("x0") 0i64 => ret,
            err = out(reg) err,
            options(nostack),
        );
    }
    if err != 0 { -ret } else { ret }
}

unsafe fn exit(code: usize) -> ! {
    unsafe { asm!("svc #1", in("x0") code, options(noreturn)) }
}

fn utoa(n: u64, buf: &mut [u8; 20]) -> &str {
    if n == 0 {
        buf[19] = b'0';
        return core::str::from_utf8(&buf[19..]).unwrap_or("?");
    }
    let mut m = n;
    let mut i = 20;
    while m > 0 {
        i -= 1;
        buf[i] = b'0' + (m % 10) as u8;
        m /= 10;
    }
    core::str::from_utf8(&buf[i..]).unwrap_or("?")
}

/// Read a line with local echo. Returns length (stops at \n/\r).
fn read_line(line: &mut [u8]) -> usize {
    let mut pos = 0usize;
    loop {
        let c = unsafe { read1() };
        if c < 0 {
            return pos;
        }
        let c = c as u8;
        match c {
            b'\n' | b'\r' => {
                unsafe { write(1, "\n") };
                return pos;
            }
            0x7f | 0x08 => {
                if pos > 0 {
                    pos -= 1;
                    unsafe { write(1, "\x08 \x08") };
                }
            }
            0x00..=0x1f => {} // ignore other control chars
            _ => {
                if pos < line.len() {
                    line[pos] = c;
                    pos += 1;
                    let s = core::str::from_utf8(&line[pos - 1..pos]).unwrap_or("?");
                    unsafe { write(1, s) };
                }
            }
        }
    }
}

/// Parse leading ASCII digits; -1 if none.
fn atoi(s: &str) -> i64 {
    let mut n: i64 = 0;
    let mut any = false;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            break;
        }
        any = true;
        n = n.saturating_mul(10).saturating_add((c - b'0') as i64);
    }
    if any { n } else { -1 }
}

/// Signal handler target: prints which signal arrived.
extern "C" fn on_signal(sig: u64) {
    unsafe { write(1, "caught signal ") };
    let mut b = [0u8; 20];
    unsafe { write(1, utoa(sig, &mut b)) };
    unsafe { write(1, "\n") };
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut line = [0u8; 64];
    let mut buf = [0u8; 20];
    let mut bg: [i64; 4] = [0; 4]; // background job slots
    unsafe { write(1, "tihkali sh — try: ls, sync, trap, kill, greet &, linux-hello, exit\n") };

    loop {
        // Reap finished background jobs (WNOHANG) before the prompt.
        for slot in 0..bg.len() {
            let pid = bg[slot];
            if pid == 0 {
                continue;
            }
            let mut st: i32 = 0;
            let r = unsafe { wait4o(pid, &mut st, 1) }; // WNOHANG
            if r == 0 {
                continue;
            }
            bg[slot] = 0;
            unsafe { write(1, "[") };
            unsafe { write(1, utoa((slot + 1) as u64, &mut buf)) };
            unsafe { write(1, "] pid ") };
            unsafe { write(1, utoa(pid as u64, &mut buf)) };
            if r > 0 {
                let u = st as u32;
                if u & 0x7f != 0 {
                    unsafe { write(1, " terminated by signal ") };
                    unsafe { write(1, utoa((u & 0x7f) as u64, &mut buf)) };
                } else {
                    unsafe { write(1, " exited ") };
                    unsafe { write(1, utoa((u >> 8) as u64, &mut buf)) };
                }
            } else {
                unsafe { write(1, " gone") };
            }
            unsafe { write(1, "\n") };
        }

        unsafe { write(1, "$ ") };
        let n = read_line(&mut line);
        let text = core::str::from_utf8(&line[..n]).unwrap_or("");
        let full = text.trim();
        let background = full.ends_with('&');
        let trimmed = if background {
            full[..full.len() - 1].trim_end()
        } else {
            full
        };
        let cmd = trimmed.split(' ').next().unwrap_or("");
        let arg = trimmed.split(' ').nth(1);

        match cmd {
            "" => {}
            "exit" => unsafe { exit(0) },
            "ls" => {
                let path = arg.unwrap_or("/");
                let fd = unsafe { open(path, 0) };
                if fd < 0 {
                    unsafe { write(1, "ls: ") };
                    unsafe { write(1, path) };
                    unsafe { write(1, ": not found\n") };
                    continue;
                }
                let mut buf = [0u8; 512];
                loop {
                    let n = unsafe { getdents(fd, &mut buf) };
                    if n <= 0 {
                        break;
                    }
                    let mut off = 0usize;
                    while off < n as usize {
                        let reclen = u16::from_le_bytes([buf[off + 4], buf[off + 5]]) as usize;
                        let namlen = u16::from_le_bytes([buf[off + 6], buf[off + 7]]) as usize;
                        let typ = buf[off + 8];
                        let name = &buf[off + 9..off + 9 + namlen];
                        unsafe { write_bytes(1, name) };
                        if typ == 4 {
                            unsafe { write(1, "/") };
                        }
                        unsafe { write(1, "\n") };
                        off += reclen;
                    }
                }
                unsafe { close(fd) };
            }
            "sigblock" | "sigunblock" => {
                let Some(tok) = arg else {
                    unsafe { write(1, "usage: sigblock|sigunblock <sig>\n") };
                    continue;
                };
                let sig = atoi(tok);
                if sig <= 0 || sig > 31 {
                    unsafe { write(1, "bad signal\n") };
                    continue;
                }
                let how = if cmd == "sigblock" { 1 } else { 2 }; // BLOCK/UNBLOCK
                if unsafe { sigprocmask(how, 1u64 << sig) } < 0 {
                    unsafe { write(1, "sigprocmask: failed\n") };
                    continue;
                }
                unsafe { write(1, cmd) };
                unsafe { write(1, " ") };
                unsafe { write(1, tok) };
                unsafe { write(1, "\n") };
            }
            "jobs" => {
                let mut any = false;
                for (i, pid) in bg.iter().enumerate() {
                    if *pid != 0 {
                        any = true;
                        unsafe { write(1, "[") };
                        unsafe { write(1, utoa((i + 1) as u64, &mut buf)) };
                        unsafe { write(1, "] pid ") };
                        unsafe { write(1, utoa(*pid as u64, &mut buf)) };
                        unsafe { write(1, " running\n") };
                    }
                }
                if !any {
                    unsafe { write(1, "no jobs\n") };
                }
            }
            "trap" => {
                let Some(tok) = arg else {
                    unsafe { write(1, "usage: trap <sig>\n") };
                    continue;
                };
                let sig = atoi(tok);
                if sig <= 0 {
                    unsafe { write(1, "trap: bad signal\n") };
                    continue;
                }
                let handler = on_signal as extern "C" fn(u64) as usize;
                if unsafe { signal(sig, handler) } < 0 {
                    unsafe { write(1, "trap: failed\n") };
                } else {
                    unsafe { write(1, "handler installed for ") };
                    unsafe { write(1, tok) };
                    unsafe { write(1, "\n") };
                }
            }
            "kill" => {
                // `kill <sig>` (self) or `kill <pid> <sig>`
                let mut it = trimmed.split(' ');
                it.next();
                let a = it.next();
                let b = it.next();
                let (pid, sig) = match (a, b) {
                    (Some(x), None) => (unsafe { getpid() }, atoi(x)),
                    (Some(x), Some(y)) => (atoi(x), atoi(y)),
                    _ => (-1, -1),
                };
                if sig <= 0 || pid < 0 {
                    unsafe { write(1, "usage: kill [<pid>] <sig>\n") };
                    continue;
                }
                if unsafe { kill(pid, sig) } < 0 {
                    unsafe { write(1, "kill: failed\n") };
                }
            }
            "killchild" => {
                // killchild <sig>: fork a child that blocks in read(), then
                // terminate it — exercises sleep-kill + signaled wait4 status.
                let Some(tok) = arg else {
                    unsafe { write(1, "usage: killchild <sig>\n") };
                    continue;
                };
                let sig = atoi(tok);
                if sig <= 0 {
                    unsafe { write(1, "killchild: bad signal\n") };
                    continue;
                }
                let pid = unsafe { fork() };
                if pid == 0 {
                    let mut b = [0u8; 1];
                    let _ = unsafe { read(0, &mut b) }; // block on stdin
                    unsafe { exit(1) }
                }
                if pid < 0 {
                    unsafe { write(1, "killchild: fork failed\n") };
                    continue;
                }
                if unsafe { kill(pid, sig) } < 0 {
                    unsafe { write(1, "killchild: kill failed\n") };
                    continue;
                }
                let mut st: i32 = 0;
                let r = unsafe { wait4(-1, &mut st) };
                if r > 0 {
                    let u = st as u32;
                    unsafe { write(1, "killchild: ") };
                    if u & 0x7f != 0 {
                        unsafe { write(1, "terminated by signal ") };
                        unsafe { write(1, utoa((u & 0x7f) as u64, &mut buf)) };
                    } else {
                        unsafe { write(1, "exited ") };
                        unsafe { write(1, utoa((u >> 8) as u64, &mut buf)) };
                    }
                    unsafe { write(1, "\n") };
                }
            }
            "rm" => {
                let Some(path) = arg else {
                    unsafe { write(1, "usage: rm <path>\n") };
                    continue;
                };
                if unsafe { unlink(path) } < 0 {
                    unsafe { write(1, "rm: failed\n") };
                }
            }
            "rmdir" => {
                let Some(path) = arg else {
                    unsafe { write(1, "usage: rmdir <path>\n") };
                    continue;
                };
                if unsafe { rmdir(path) } < 0 {
                    unsafe { write(1, "rmdir: failed\n") };
                }
            }
            "mkdir" => {
                let Some(path) = arg else {
                    unsafe { write(1, "usage: mkdir <path>\n") };
                    continue;
                };
                if unsafe { mkdir(path) } < 0 {
                    unsafe { write(1, "mkdir: failed\n") };
                }
            }
            "save" => {
                // save <path> <text...> — create/truncate + write + close
                let mut it = trimmed.split(' ');
                it.next(); // cmd
                let Some(path) = it.next() else {
                    unsafe { write(1, "usage: save <path> <text...>\n") };
                    continue;
                };
                // Join the remaining words into buf with single spaces.
                let mut buf = [0u8; 128];
                let mut len = 0usize;
                for w in it {
                    if len > 0 && len < buf.len() {
                        buf[len] = b' ';
                        len += 1;
                    }
                    for &b in w.as_bytes() {
                        if len < buf.len() {
                            buf[len] = b;
                            len += 1;
                        }
                    }
                }
                if len < buf.len() {
                    buf[len] = b'\n';
                    len += 1;
                }
                // O_CREAT|O_WRONLY|O_TRUNC = 0x0200|0x0001|0x0400
                let fd = unsafe { open(path, 0x601) };
                if fd < 0 {
                    unsafe { write(1, "save: failed\n") };
                    continue;
                }
                unsafe { write_bytes(fd as usize, &buf[..len]) };
                unsafe { close(fd) };
                unsafe { write(1, "saved ") };
                unsafe { write(1, path) };
                unsafe { write(1, "\n") };
            }
            "sync" => {
                if unsafe { sync() } < 0 {
                    unsafe { write(1, "sync: failed\n") };
                }
            }
            "cat" => {
                let Some(path) = arg else {
                    unsafe { write(1, "usage: cat <path>\n") };
                    continue;
                };
                let fd = unsafe { open(path, 0) };
                if fd < 0 {
                    unsafe { write(1, "cat: ") };
                    unsafe { write(1, path) };
                    unsafe { write(1, ": not found\n") };
                    continue;
                }
                let mut buf = [0u8; 128];
                loop {
                    let r = unsafe { read(fd, &mut buf) };
                    if r <= 0 {
                        break;
                    }
                    unsafe { write_bytes(1, &buf[..r as usize]) };
                }
                unsafe { close(fd) };
            }
            other => {
                // Generic: fork + exec. A bare name resolves to /bin/<cmd>;
                // an absolute path is used verbatim (prefixing it again
                // would look up /bin//bin/<cmd> and miss).
                let cl = other.len();
                let mut path = [0u8; 64];
                let abs = other.as_bytes().first() == Some(&b'/');
                let plen = if abs {
                    cl
                } else {
                    cl + 5
                };
                if plen == 0 || plen > 63 {
                    unsafe { write(1, "sh: bad command\n") };
                    continue;
                }
                if !abs {
                    path[..5].copy_from_slice(b"/bin/");
                }
                path[plen - cl..plen].copy_from_slice(other.as_bytes());
                let path_s = core::str::from_utf8(&path[..plen]).unwrap_or("?");

                // Full argv: cmd + remaining words (busybox needs `busybox
                // echo hi` to see "echo hi", not just argv[0]).
                let mut args: [&str; 8] = [""; 8];
                let mut nargs = 0usize;
                for w in trimmed.split_whitespace() {
                    if nargs < args.len() {
                        args[nargs] = w;
                        nargs += 1;
                    }
                }

                let pid = unsafe { fork() };
                if pid == 0 {
                    let r = unsafe { execve(path_s, &args[..nargs]) };
                    // -2 = ENOENT (conventional shell exit codes)
                    unsafe { exit(if r == -2 { 127 } else { 126 }) }
                }
                if pid < 0 {
                    unsafe { write(1, "sh: fork failed\n") };
                    continue;
                }
                if background {
                    match bg.iter().position(|&p| p == 0) {
                        Some(slot) => {
                            bg[slot] = pid;
                            unsafe { write(1, "[") };
                            unsafe { write(1, utoa((slot + 1) as u64, &mut buf)) };
                            unsafe { write(1, "] pid ") };
                            unsafe { write(1, utoa(pid as u64, &mut buf)) };
                            unsafe { write(1, "\n") };
                        }
                        None => unsafe { write(1, "jobs: table full\n") },
                    }
                    continue;
                }
                let mut status: i32 = 0;
                let r = unsafe { wait4(-1, &mut status) };
                if r > 0 {
                    let st = status as u32;
                    unsafe { write(1, "sh: ") };
                    unsafe { write(1, other) };
                    if st & 0x7f != 0 {
                        unsafe { write(1, " terminated by signal ") };
                        unsafe { write(1, utoa((st & 0x7f) as u64, &mut buf)) };
                    } else {
                        let code = st >> 8;
                        if code == 127 {
                            unsafe { write(1, ": not found") };
                        } else if code == 126 {
                            unsafe { write(1, ": cannot execute") };
                        } else {
                            unsafe { write(1, " exited ") };
                            unsafe { write(1, utoa(code as u64, &mut buf)) };
                        }
                    }
                    unsafe { write(1, "\n") };
                }
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { exit(99) }
}
