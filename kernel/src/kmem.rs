//! Kernel heap: first-fit free list over PMM-allocated contiguous regions,
//! with block splitting and address-ordered coalescing.
//!
//! Serves alignments ≤ 16 (Vec/String/Box); 4 KiB-aligned page tables
//! continue to come straight from the PMM.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::mm::pmm;

const FRAME: usize = 4096;
const HEAP_FRAMES: usize = 1024; // 4 MiB per grow()
const HDR: usize = 32; // 16-aligned; payload starts at block + HDR
const MIN_SPLIT: usize = 64; // don't create slivers smaller than this

#[repr(C)]
struct Header {
    /// Total block size (header + payload), multiple of 16.
    size: usize,
    /// Address-ordered links, valid only while the block is free.
    prev: *mut Header,
    next: *mut Header,
    free: bool,
}

fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

/// Head of the address-ordered free list; regions may be non-contiguous,
/// coalescing only fires when blocks are physically adjacent.
static mut FREE_HEAD: *mut Header = ptr::null_mut();

fn free_head() -> *mut Header {
    unsafe { FREE_HEAD }
}

fn set_free_head(h: *mut Header) {
    unsafe { FREE_HEAD = h }
}

unsafe fn unlink(h: *mut Header) {
    unsafe {
        let (p, n) = ((*h).prev, (*h).next);
        if p.is_null() {
            set_free_head(n);
        } else {
            (*p).next = n;
        }
        if !n.is_null() {
            (*n).prev = p;
        }
    }
}

/// Insert into the address-ordered free list.
unsafe fn link_sorted(h: *mut Header) {
    unsafe {
        (*h).free = true;
        (*h).prev = ptr::null_mut();
        (*h).next = ptr::null_mut();
        let mut cur = free_head();
        let mut tail: *mut Header = ptr::null_mut();
        while !cur.is_null() && (cur as usize) < (h as usize) {
            tail = cur;
            cur = (*cur).next;
        }
        (*h).prev = tail;
        (*h).next = cur;
        if tail.is_null() {
            set_free_head(h);
        } else {
            (*tail).next = h;
        }
        if !cur.is_null() {
            (*cur).prev = h;
        }
    }
}

/// Add at least `need` bytes of free heap in ONE contiguous run.
///
/// The run size has to track the request: a fixed HEAP_FRAMES chunk means a
/// request larger than one chunk can never be satisfied, because the heap
/// grows in place-anchored runs and the caller gets one retry -- a 6 MiB
/// image against a 4 MiB grow() failed with "allocation of 6333952 bytes"
/// even with hundreds of MiB free.
unsafe fn grow(need: usize) -> bool {
    let frames = (need + FRAME - 1) / FRAME;
    let frames = frames.max(HEAP_FRAMES);
    unsafe {
        let Some(base) = pmm::alloc_contiguous(frames) else {
            return false;
        };
        let h = base as *mut Header;
        (*h).size = frames * FRAME;
        link_sorted(h);
        true
    }
}

unsafe fn alloc_inner(need: usize) -> *mut u8 {
    unsafe {
        if free_head().is_null() && !grow(need) {
            return ptr::null_mut();
        }
        let mut b = free_head();
        while !b.is_null() {
            if (*b).size >= need {
                if (*b).size >= need + MIN_SPLIT {
                    // Split: [b .. need) allocated, remainder stays free.
                    let rem = (b as usize + need) as *mut Header;
                    (*rem).size = (*b).size - need;
                    let (old_prev, old_next) = ((*b).prev, (*b).next);
                    (*rem).prev = old_prev;
                    (*rem).next = old_next;
                    if old_prev.is_null() {
                        set_free_head(rem);
                    } else {
                        (*old_prev).next = rem;
                    }
                    if !old_next.is_null() {
                        (*old_next).prev = rem;
                    }
                    (*b).size = need;
                    (*b).free = false;
                } else {
                    unlink(b);
                    (*b).free = false;
                }
                return (b as *mut u8).add(HDR);
            }
            b = (*b).next;
        }
        if !grow(need) {
            return ptr::null_mut();
        }
        alloc_inner(need) // one retry after extending
    }
}

unsafe fn free_inner(p: *mut u8) {
    unsafe {
        let mut h = p.sub(HDR) as *mut Header;
        link_sorted(h);

        // Coalesce with address-adjacent neighbours (list is address-ordered,
        // so list neighbours are the nearest free blocks in memory).
        let prev = (*h).prev;
        if !prev.is_null() && (prev as usize) + (*prev).size == (h as usize) {
            (*prev).size += (*h).size;
            unlink(h);
            h = prev;
        }
        let next = (*h).next;
        if !next.is_null() && (h as usize) + (*h).size == (next as usize) {
            let nsize = (*next).size;
            unlink(next);
            (*h).size += nsize;
        }
    }
}

pub struct Heap;

#[global_allocator]
pub static ALLOCATOR: Heap = Heap;

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        assert!(layout.align() <= 16, "heap serves align <= 16 only");
        let need = align_up(HDR + layout.size(), 16);
        unsafe { alloc_inner(need.max(MIN_SPLIT)) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { free_inner(ptr) }
    }
}
