//! User virtual memory: page-table walks, demand paging, COW.

use crate::arch::mmu::{self, DESC_MASK, TBL};
use crate::mm::pmm;
use crate::user::{USER_BASE, USER_LIMIT, USER_TEXT_LIMIT};

const PTE_VALID: u64 = 1;
const PTE_TABLE_BIT: u64 = 2;
const ATTR_NORMAL: u64 = 0 << 2;
const SH_INNER: u64 = 3 << 8;
const AF: u64 = 1 << 10;
const AP_RW: u64 = 1 << 6; // EL0/EL1 read-write  (AP = 0b01)
const AP_RO: u64 = 3 << 6; // read-only           (AP = 0b11)
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

/// Descriptor for a 4 KiB user page. `rw` selects AP, `exec_el0` clears UXN.
fn page_desc(pa: usize, rw: bool, exec_el0: bool) -> u64 {
    let ap = if rw { AP_RW } else { AP_RO };
    let xnu = if exec_el0 { PXN } else { PXN | UXN };
    (pa as u64 & DESC_MASK) | ATTR_NORMAL | SH_INNER | AF | ap | xnu | PTE_VALID | PTE_TABLE_BIT
}

fn pte_present(pte: u64) -> bool {
    pte & (PTE_VALID | PTE_TABLE_BIT) == (PTE_VALID | PTE_TABLE_BIT)
}

fn pte_frame(pte: u64) -> usize {
    (pte & DESC_MASK) as usize
}

/// Walk the user page tables for `va`; returns the L3 PTE slot.
pub fn walk(ttbr: usize, va: usize) -> Option<*mut u64> {
    unsafe {
        let l0 = ttbr as *const u64;
        let e0 = *l0.add((va >> 39) & 511);
        if e0 & TBL != TBL {
            return None;
        }
        let l1 = (e0 & DESC_MASK) as *const u64;
        let e1 = *l1.add((va >> 30) & 511);
        if e1 & TBL != TBL {
            return None;
        }
        let l2 = (e1 & DESC_MASK) as *const u64;
        let e2 = *l2.add((va >> 21) & 511);
        if e2 & TBL != TBL {
            return None;
        }
        let l3 = (e2 & DESC_MASK) as *mut u64;
        Some(l3.add((va >> 12) & 511))
    }
}

fn in_text(va: usize) -> bool {
    (USER_BASE..USER_TEXT_LIMIT).contains(&va)
}

fn in_stack(va: usize) -> bool {
    (USER_TEXT_LIMIT..USER_LIMIT).contains(&va)
}

/// Map a fresh zeroed page at `va` (loader + demand-zero entry point).
pub fn map_page(ttbr: usize, va: usize) -> Result<(), ()> {
    let Some(pte) = walk(ttbr, va & !0xfff) else {
        return Err(());
    };
    unsafe {
        if pte_present(*pte) {
            return Ok(()); // overlapping segments
        }
    }
    let frame = pmm::alloc().ok_or(())?;
    unsafe { core::ptr::write_bytes(frame as *mut u8, 0, 4096) };
    let exec_el0 = in_text(va);
    unsafe { *pte = page_desc(frame, true, exec_el0) };
    mmu::flush_tlb();
    Ok(())
}

/// Copy-on-write / demand-zero handling for a fault at `far`.
/// Returns Ok when the fault is resolved (instruction retries).
pub fn handle_fault(ttbr: usize, far: usize, is_write: bool) -> Result<(), &'static str> {
    let va = far & !0xfff;
    if !(USER_BASE..USER_LIMIT).contains(&far) {
        return Err("fault outside user space");
    }
    let Some(pte) = walk(ttbr, va) else {
        return Err("bad user page-table walk");
    };

    let pte_val = unsafe { *pte };
    if !pte_present(pte_val) {
        if in_text(va) {
            // brk/mmap arenas inside the text window grow on first touch.
            let (brk, mmap_next) = crate::proc::current_arenas();
            if (va as u64) < brk
                || ((va as u64) >= crate::user::MMAP_FLOOR as u64 && (va as u64) < mmap_next)
            {
                return map_page(ttbr, va).map_err(|_| "arena page alloc failed");
            }
            return Err("text-region access outside brk/mmap arenas");
        }
        if in_stack(va) {
            // Demand-zero stack growth (any access; also covers EL1
            // writes like wait4's status pointer).
            let frame = pmm::alloc().ok_or("out of frames")?;
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, 4096);
                *pte = page_desc(frame, true, false);
            }
            mmu::flush_tlb();
            return Ok(());
        }
        return Err("not-present access outside stack region");
    }

    if !is_write {
        return Err("read fault on present page");
    }

    // Write to a read-only page: copy-on-write.
    let frame = pte_frame(pte_val);
    if pmm::refcount(frame) == 1 {
        // Last sharer: just re-enable write.
        unsafe { *pte = (pte_val & !(AP_RW | AP_RO)) | AP_RW };
        mmu::flush_tlb();
        return Ok(());
    }
    let new = pmm::alloc().ok_or("out of frames")?;
    unsafe {
        core::ptr::copy_nonoverlapping(frame as *const u8, new as *mut u8, 4096);
        *pte = page_desc(new, true, in_text(va));
    }
    pmm::free(frame); // drop our share of the old frame
    mmu::flush_tlb();
    Ok(())
}

/// Fork: child gets empty L3s; every present parent page is shared RO
/// (parent write-protected too — next write traps into `handle_fault`).
pub fn share_user_pages(parent_ttbr: usize, child_ttbr: usize) -> Result<(), ()> {
    for slot in 0..2usize {
        let p_l3 = l3_of(parent_ttbr, slot)?;
        let c_l3 = l3_of(child_ttbr, slot)?;
        unsafe {
            for i in 0..512usize {
                let p = *p_l3.add(i);
                if !pte_present(p) {
                    continue;
                }
                pmm::inc_ref(pte_frame(p));
                let ro = (p & !(AP_RW | AP_RO)) | AP_RO;
                *p_l3.add(i) = ro;
                *c_l3.add(i) = ro;
            }
        }
    }
    mmu::flush_tlb(); // parent may have cached RW translations
    Ok(())
}

/// Physical address of the child-space L3 for user region `slot` (0 text, 1 stack).
fn l3_of(ttbr: usize, slot: usize) -> Result<*mut u64, ()> {
    unsafe {
        let l0 = ttbr as *const u64;
        let e0 = *l0.add(0);
        if e0 & TBL != TBL {
            return Err(());
        }
        let l1 = (e0 & DESC_MASK) as *const u64;
        let e1 = *l1.add(crate::arch::mmu::L1_USER_SLOT);
        if e1 & TBL != TBL {
            return Err(());
        }
        let l2 = (e1 & DESC_MASK) as *const u64;
        let e2 = *l2.add(slot);
        if e2 & TBL != TBL {
            return Err(());
        }
        Ok((e2 & DESC_MASK) as *mut u64)
    }
}

/// Release an address space: drop references on all present user pages,
/// then free the six table frames.
pub fn free_space(tables: &[usize]) {
    if let Ok(l3t) = l3_of(tables[0], 0) {
        drop_region(l3t);
    }
    if let Ok(l3s) = l3_of(tables[0], 1) {
        drop_region(l3s);
    }
    for &f in tables {
        pmm::free(f);
    }
}

fn drop_region(l3: *mut u64) {
    unsafe {
        for i in 0..512usize {
            let p = *l3.add(i);
            if pte_present(p) {
                pmm::free(pte_frame(p));
            }
        }
    }
}

/// Change permissions of present pages in [addr, addr+len):
/// prot bits — 1=read, 2=write, 4=exec (Linux PROT_*).
pub fn set_perms(ttbr: usize, addr: u64, len: u64, prot: u32) -> Result<(), ()> {
    let start = addr & !0xfff;
    let end = (addr + len + 0xfff) & !0xfff;
    let mut va = start;
    while va < end {
        if let Some(pte) = walk(ttbr, va as usize) {
            let p = unsafe { *pte };
            if pte_present(p) {
                let ap = if prot & 2 != 0 { AP_RW } else { AP_RO };
                let mut np = (p & !(AP_RW | AP_RO)) | ap;
                if prot & 4 != 0 {
                    np &= !UXN; // executable for EL0
                } else {
                    np |= UXN;
                }
                unsafe { *pte = np };
            }
        }
        va += 0x1000;
    }
    mmu::flush_tlb();
    Ok(())
}

/// Free present pages in [addr, addr+len) and clear their PTEs.
pub fn unmap(ttbr: usize, addr: u64, len: u64) -> Result<(), ()> {
    let start = addr & !0xfff;
    let end = (addr + len + 0xfff) & !0xfff;
    let mut va = start;
    while va < end {
        if let Some(pte) = walk(ttbr, va as usize) {
            let p = unsafe { *pte };
            if pte_present(p) {
                pmm::free(pte_frame(p));
                unsafe { *pte = 0 };
            }
        }
        va += 0x1000;
    }
    mmu::flush_tlb();
    Ok(())
}
