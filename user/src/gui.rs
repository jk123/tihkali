#![no_std]
#![no_main]

//! tihkali `/bin/gui`: the user-space display server and demo client.
//!
//! Everything graphical lives here, not in the kernel. The kernel owns only
//! the framebuffer (kernel/src/gui.rs) and three thin syscall arms:
//!
//!   NetBSD svc #481  gui_fb_info(out)      -> {width, height, stride, pa}
//!   NetBSD svc #482  gui_fill_rect(x,y,w,h,rgb)
//!   NetBSD svc #483  gui_blit(src,x,y,w,h,src_stride)
//!
//! The Linux-ABI equivalents are 480/481/482. NetBSD numbers are used here
//! because the project is NetBSD-ABI-first.
//!
//! The server paints a title bar, an animated playfield with three bouncing
//! sprites, a frame counter and a cursor mark blitted from a user-space
//! buffer, then exits 0 — that is the whole of milestone 1. No window
//! manager, no damage tracking, no input handling yet.
//!
//! Like every other user binary this is freestanding: no libc, no heap, and
//! each syscall is a bare `svc`. The immediates must be asm literals, so
//! the syscalls come from a macro.

use core::arch::asm;
use core::panic::PanicInfo;


// NetBSD svc #4 (write) so we can still report to the console.

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

unsafe fn exit(code: usize) -> ! {
    unsafe { asm!("svc #1", in("x0") code, options(noreturn)) }
}

/// A syscall that reports success via PSTATE.C and a value in x0.
/// `svc` with a literal immediate. The `#NR` encoding bakes the number into
/// the instruction, so a macro is the only way to keep the syscall numbers
/// named. Returns (retval, success) where success is PSTATE.C after return.
macro_rules! sys {
    ($name:ident = $nr:literal) => {
        /// Returns (retval, success). Arguments go in x0..x5; pass 0 for
        /// the ones this call does not use.
        unsafe fn $name(a: [u64; 6]) -> (i64, bool) {
            let ret: i64;
            let err: u64;
            unsafe {
                asm!(
                    concat!("svc #", $nr),
                    "cset {err}, hs",
                    inlateout("x0") a[0] as i64 => ret,
                    in("x1") a[1],
                    in("x2") a[2],
                    in("x3") a[3],
                    in("x4") a[4],
                    in("x5") a[5],
                    err = out(reg) err,
                    options(nostack),
                );
            }
            (ret, err == 0)
        }
    };
}

sys!(fb_info_svc = 481);
sys!(fill_rect_svc = 482);
sys!(blit_svc = 483);

fn fill_rect(x: u32, y: u32, w: u32, h: u32, rgb: u32) {
    let (_, ok) =
        unsafe { fill_rect_svc([x as u64, y as u64, w as u64, h as u64, rgb as u64, 0]) };
    if !ok {
        unsafe { exit(12) }
    }
}

fn fb_info(out: &mut [u32; 4]) {
    let (_, ok) = unsafe { fb_info_svc([out.as_mut_ptr() as u64, 0, 0, 0, 0, 0]) };
    if !ok {
        unsafe { exit(11) }
    }
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

/// 8x8 glyphs for the handful of characters the HUD needs. Each row is a
/// bitmask with the leftmost pixel in bit 7.
fn glyph(c: u8) -> [u8; 8] {
    match c {
        b'0' => [0x3E, 0x63, 0x73, 0x7B, 0x6F, 0x67, 0x3E, 0x00],
        b'1' => [0x00, 0x0C, 0x0E, 0x04, 0x04, 0x04, 0x0E, 0x00],
        b'2' => [0x3E, 0x63, 0x03, 0x0E, 0x18, 0x30, 0x7F, 0x00],
        b'3' => [0x3E, 0x63, 0x03, 0x1E, 0x03, 0x63, 0x3E, 0x00],
        b'4' => [0x06, 0x0E, 0x1E, 0x36, 0x7F, 0x06, 0x06, 0x00],
        b'5' => [0x7F, 0x60, 0x7C, 0x03, 0x03, 0x63, 0x3E, 0x00],
        b'6' => [0x1E, 0x30, 0x60, 0x7C, 0x63, 0x63, 0x3E, 0x00],
        b'7' => [0x7F, 0x03, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x00],
        b'8' => [0x3E, 0x63, 0x63, 0x3E, 0x63, 0x63, 0x3E, 0x00],
        b'9' => [0x3E, 0x63, 0x63, 0x3F, 0x03, 0x06, 0x1C, 0x00],
        b' ' => [0x00; 8],
        b':' => [0x00, 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
        b'-' => [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
        b'/' => [0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00],
        b'=' => [0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00],
        b'x' => [0x00, 0x00, 0x63, 0x36, 0x1C, 0x36, 0x63, 0x00],
        b'a' => [0x00, 0x00, 0x3E, 0x03, 0x3F, 0x63, 0x3F, 0x00],
        b'p' => [0x00, 0x00, 0x3E, 0x63, 0x7C, 0x60, 0x3C, 0x00],
        b'i' => [0x00, 0x00, 0x0E, 0x00, 0x0E, 0x0E, 0x0E, 0x00],
        b'k' => [0x00, 0x00, 0x63, 0x36, 0x1C, 0x36, 0x63, 0x00],
        b'l' => [0x00, 0x00, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x00],
        _ => [0x3E, 0x63, 0x7B, 0x7F, 0x6F, 0x63, 0x3E, 0x00],
    }
}

/// Draw a string by blitting one 8x8 cell per character. Characters are
/// composed of solid `fg`/`bg` rectangles via the fill syscall, which keeps
/// the blit path exercised too.
fn draw_text(x0: u32, y0: u32, s: &str, fg: u32, bg: u32) {
    let mut cx = x0;
    for &b in s.as_bytes() {
        let g = glyph(b);
        fill_rect(cx, y0, 8, 8, bg);
        for (row, bits) in g.iter().enumerate() {
            for col in 0..8u32 {
                if bits & (0x80 >> col) != 0 {
                    fill_rect(cx + col, y0 + row as u32, 1, 1, fg);
                }
            }
        }
        cx += 8;
    }
}

/// A moving box, used to prove the redraw loop animates.
struct Sprite {
    x: i32,
    y: i32,
    vx: i32,
    vy: i32,
    w: u32,
    h: u32,
    rgb: u32,
}

fn utoa_u32(n: u32, buf: &mut [u8; 20]) -> &str {
    utoa(n as u64, buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_argc: u64, _argv: u64) -> ! {
    let mut info = [0u32; 4];
    fb_info(&mut info);
    let (w, h, _stride, _pa) = (info[0], info[1], info[2], info[3]);

    let mut buf = [0u8; 20];
    unsafe {
        write(1, "gui: wm up fb=");
        write(1, utoa_u32(w, &mut buf));
        write(1, "x");
        write(1, utoa_u32(h, &mut buf));
        write(1, "\n");
    }

    // Background: dark blue, then a title bar and a status strip.
    fill_rect(0, 0, w, h, 0x00201830);
    fill_rect(0, 0, w, 28, 0x00c86400);
    draw_text(8, 8, "tihkali", 0x00ffffff, 0x00c86400);
    draw_text(8, h - 20, "frame=0", 0x00d0d0d0, 0x00201830);

    let mut sprites = [
        Sprite { x: 40, y: 80, vx: 3, vy: 2, w: 48, h: 48, rgb: 0x0000e5ff },
        Sprite { x: 120, y: 140, vx: -2, vy: 3, w: 32, h: 32, rgb: 0x00e548ff },
        Sprite { x: 220, y: 100, vx: 4, vy: -2, w: 64, h: 24, rgb: 0x0058ff4a },
    ];

    // Animate: redraw the playfield each frame and update the counter.
    for frame in 0..120u32 {
        // clear the playfield band only
        fill_rect(0, 32, w, h - 32 - 28, 0x00201830);
        for s in sprites.iter_mut() {
            let nx = s.x + s.vx;
            let ny = s.y + s.vy;
            if nx < 0 || nx + s.w as i32 > w as i32 {
                s.vx = -s.vx;
            }
            if ny < 0 || ny + s.h as i32 > (h - 60) as i32 {
                s.vy = -s.vy;
            }
            s.x += s.vx;
            s.y += s.vy;
            let x = s.x.max(0) as u32;
            let y = (s.y + 32).max(32) as u32;
            fill_rect(x, y, s.w, s.h, s.rgb);
        }
        // Status line: "frame=N". Six fixed chars plus up to three digits
        // for a 120-frame loop, so 10 bytes is exact.
        let mut line = [0u8; 10];
        let mut pos = 0usize;
        for &b in b"frame=" {
            line[pos] = b;
            pos += 1;
        }
        for &b in utoa_u32(frame, &mut buf).as_bytes() {
            line[pos] = b;
            pos += 1;
        }
        let text = core::str::from_utf8(&line[..pos]).unwrap_or("");
        draw_text(8, h - 20, text, 0x00d0d0d0, 0x00201830);

        // Blit path: copy one 8x8 glyph cell through gui_blit, exercising
        // the kernel copy door with a user-space buffer.
        let cell = [0xffu8; 8 * 8 * 4];
        let (_, ok) = unsafe {
            blit_svc([
                cell.as_ptr() as u64,
                (w - 24) as u64,
                (h - 24) as u64,
                8,
                8,
                8 * 4,
            ])
        };
        if !ok {
            unsafe { write(1, "gui: blit failed\n") };
            unsafe { exit(13) }
        }
    }

    unsafe { write(1, "gui: demo ok frames=120\n") };
    unsafe { exit(0) }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe { write(1, "gui: panic: ") };
    match info.message().as_str() {
        Some(m) => unsafe { write(1, m) },
        None => unsafe { write(1, "<no message>") },
    }
    unsafe { write(1, "\n") };
    unsafe { exit(99) }
}