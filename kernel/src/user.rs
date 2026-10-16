//! Load the embedded test ELF into user mappings and enter EL0.

use crate::kprintln;

/// User VA window (see user.ld): text in the first 2 MiB, stack in the
/// second; physical frames come from the PMM on demand (COW/lazy).
pub const USER_BASE: usize = 0x1_0000_0000;
pub const USER_TEXT_LIMIT: usize = USER_BASE + 0x20_0000;
pub const USER_LIMIT: usize = USER_BASE + 0x40_0000;

/// Images must end below this (busybox is ~1.14 MiB); the rest splits into
/// the brk arena (image_end..floor) and the mmap arena (floor..2 MiB).
pub const MMAP_FLOOR: usize = USER_BASE + 0x0014_0000;

/// Top page of the text region: holds the sigreturn trampoline
/// (`svc #295; b .`), mapped executable at every image load.
pub const TRAMPOLINE: usize = USER_BASE + 0x001F_F000;

/// Kernel-provided user TLS page (musl reads/writes errno relative to
/// TPIDR_EL0; Linux sets it on exec — we must too). One zeroed,
/// user-writable page below the trampoline with TP pointing at its
/// middle, giving ±2 KiB of coverage (variant-II TLS lives below TP).
pub const TLS_BASE: usize = USER_BASE + 0x001F_E000; // 0x1001FE000
pub const TPIDR_VAL: u64 = (TLS_BASE + 0x800) as u64;

/// Map + write the sigreturn trampoline into the (fresh) address space.
pub fn install_trampoline(ttbr: usize) -> Result<(), &'static str> {
    crate::vm::map_page(ttbr, TRAMPOLINE).map_err(|_| "trampoline page alloc failed")?;
    //   d40024e1  svc #295   (opcode low bits must be ...0001, not ...0000)
    //   14000000  b .
    let code: [u8; 8] = [0xe1, 0x24, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x14];
    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), TRAMPOLINE as *mut u8, 8) };
    Ok(())
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn le64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// Copy PT_LOAD segments into the address space `ttbr`, populating pages
/// on demand (4 KiB frames); returns (entry, image_end).
pub fn load(elf: &[u8], ttbr: usize) -> Result<(usize, usize), &'static str> {
    if elf.len() < 64 {
        return Err("ELF too small");
    }
    if &elf[0..4] != b"\x7fELF" {
        return Err("bad ELF magic");
    }
    if elf[4] != 2 || elf[5] != 1 {
        return Err("need ELF64 little-endian");
    }
    if le16(elf, 18) != 183 {
        return Err("need EM_AARCH64");
    }
    if elf[16] != 2 {
        return Err("need ET_EXEC");
    }

    let entry = le64(elf, 24) as usize;
    let phoff = le64(elf, 32) as usize;
    let phentsize = le16(elf, 54) as usize;
    let phnum = le16(elf, 56) as usize;
    if !(USER_BASE..USER_LIMIT).contains(&entry) {
        return Err("entry outside user space");
    }

    let mut loaded = 0usize;
    let mut image_end = entry;
    for i in 0..phnum as usize {
        let p = phoff + i * phentsize as usize;
        if p + 56 > elf.len() {
            return Err("program header out of range");
        }
        if le32(elf, p) != 1 {
            continue; // not PT_LOAD
        }
        let offset = le64(elf, p + 8) as usize;
        let vaddr = le64(elf, p + 16) as usize;
        let filesz = le64(elf, p + 32) as usize;
        let memsz = le64(elf, p + 40) as usize;
        if !(vaddr >= USER_BASE
            && vaddr.checked_add(memsz).is_some_and(|e| e <= USER_LIMIT))
        {
            return Err("segment outside user space");
        }
        if vaddr + memsz > MMAP_FLOOR {
            return Err("image larger than 1 MiB (no room for brk arena)");
        }
        if offset + filesz > elf.len() {
            return Err("segment data out of file");
        }
        // Populate every page the segment touches, then copy/zero.
        let first = vaddr & !0xfff;
        let end = (vaddr + memsz + 0xfff) & !0xfff;
        let mut page = first;
        while page < end {
            if crate::vm::map_page(ttbr, page).is_err() {
                return Err("out of frames while loading");
            }
            page += 0x1000;
        }
        unsafe {
            let dst = vaddr as *mut u8;
            for j in 0..filesz {
                dst.add(j).write_volatile(elf[offset + j]);
            }
            for j in filesz..memsz {
                dst.add(j).write_volatile(0);
            }
        }
        loaded += memsz;
        image_end = image_end.max(vaddr + memsz);
        kprintln!("user: PT_LOAD {vaddr:#x} +{memsz:#x} (filesz {filesz:#x})");
    }
    if loaded == 0 {
        return Err("no PT_LOAD segments");
    }
    // Anchor TPIDR_EL0 for this image (fresh page, zeroed by map_page).
    // Runs for pid0 boot and every execve — same constant value, so a
    // forked child needs nothing (TPIDR_EL0 is a shared system register).
    crate::vm::map_page(ttbr, TLS_BASE).map_err(|_| "out of frames while loading")?;
    unsafe {
        core::arch::asm!("msr tpidr_el0, {}", "isb", in(reg) TPIDR_VAL, options(nomem, nostack));
    }
    Ok((entry, image_end))
}

/// Drop to EL0 at `entry` with interrupts enabled (via SPSR).
pub fn enter(entry: usize) -> ! {
    const STACK_TOP: u64 = USER_LIMIT as u64; // 16-byte aligned
    unsafe {
        core::arch::asm!("msr sp_el0, {}", in(reg) STACK_TOP);
        core::arch::asm!("msr elr_el1, {}", in(reg) entry as u64);
        // SPSR = 0: EL0t, DAIF clear — ticks fire while user code runs.
        core::arch::asm!("msr spsr_el1, {}", "isb", in(reg) 0u64);
        core::arch::asm!("eret");
    }
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}
