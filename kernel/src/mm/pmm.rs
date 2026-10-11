//! Physical frame allocator: first-fit bitmap over QEMU virt RAM,
//! with per-frame reference counts for copy-on-write sharing.

use tihkali_hal::kprintln;
use tihkali_hal::platform::{RAM_BASE, RAM_SIZE};

const FRAME: usize = 4096;
const NUM_FRAMES: usize = RAM_SIZE / FRAME;
const BITMAP_WORDS: usize = NUM_FRAMES / 64;
/// First 16 MiB hold QEMU's DTB and the kernel image — never handed out.
const RESERVED_FRAMES: usize = (16 * 1024 * 1024) / FRAME;

static mut BITMAP: [u64; BITMAP_WORDS] = [u64::MAX; BITMAP_WORDS];
/// 0 = free; 1..=255 = reference count while allocated.
static mut REFCOUNTS: [u8; NUM_FRAMES] = [0; NUM_FRAMES];

fn bitmap() -> &'static mut [u64; BITMAP_WORDS] {
    unsafe { &mut *core::ptr::addr_of_mut!(BITMAP) }
}

fn refcounts() -> &'static mut [u8; NUM_FRAMES] {
    unsafe { &mut *core::ptr::addr_of_mut!(REFCOUNTS) }
}

fn is_free(bm: &[u64; BITMAP_WORDS], i: usize) -> bool {
    bm[i / 64] & (1 << (i % 64)) == 0
}

pub fn init() {
    let bm = bitmap();
    let rc = refcounts();
    bm.fill(u64::MAX);
    rc.fill(0);
    for i in RESERVED_FRAMES..NUM_FRAMES {
        bm[i / 64] &= !(1 << (i % 64));
    }
    let free = NUM_FRAMES - RESERVED_FRAMES;
    kprintln!(
        "pmm: {} frames free ({} MiB), first 16 MiB reserved",
        free,
        free * FRAME / (1024 * 1024)
    );
}

/// Allocate a 4 KiB frame (refcount 1); returns its identity-mapped address.
pub fn alloc() -> Option<usize> {
    let bm = bitmap();
    for (w, &word) in bm.iter().enumerate() {
        if word != u64::MAX {
            let bit = (!word).trailing_zeros() as usize;
            let idx = w * 64 + bit;
            bm[w] |= 1 << bit;
            refcounts()[idx] = 1;
            return Some(RAM_BASE + idx * FRAME);
        }
    }
    None
}

/// Drop one reference; the frame returns to the free list at zero.
pub fn free(addr: usize) {
    assert!(addr >= RAM_BASE + RESERVED_FRAMES * FRAME, "freeing reserved frame");
    assert!(addr < RAM_BASE + RAM_SIZE, "free out of range");
    assert!(addr % FRAME == 0, "freeing non-aligned address");
    let idx = (addr - RAM_BASE) / FRAME;
    let rc = &mut refcounts()[idx];
    assert!(*rc > 0, "double free");
    *rc -= 1;
    if *rc == 0 {
        let bm = bitmap();
        bm[idx / 64] &= !(1 << (idx % 64));
    }
}

/// Share an allocated frame (copy-on-write / shared mappings).
pub fn inc_ref(addr: usize) {
    assert!(addr % FRAME == 0, "inc_ref: not frame-aligned");
    let idx = (addr - RAM_BASE) / FRAME;
    assert!(idx < NUM_FRAMES, "inc_ref: out of range");
    let rc = &mut refcounts()[idx];
    assert!(*rc > 0, "inc_ref: frame not allocated");
    *rc += 1;
}

pub fn refcount(addr: usize) -> u8 {
    let idx = (addr - RAM_BASE) / FRAME;
    refcounts()[idx]
}

/// Allocate a run of `count` contiguous frames (heap regions).
pub fn alloc_contiguous(count: usize) -> Option<usize> {
    let bm = bitmap();
    let mut run = 0usize;
    for i in 0..NUM_FRAMES {
        if is_free(bm, i) {
            run += 1;
            if run == count {
                let start = i + 1 - count;
                for j in start..=i {
                    bm[j / 64] |= 1 << (j % 64);
                    refcounts()[j] = 1;
                }
                return Some(RAM_BASE + start * FRAME);
            }
        } else {
            run = 0;
        }
    }
    None
}

/// Smoke test: distinctness, alignment, data round-trip, free/reuse.
pub fn test() {
    let a = alloc().expect("pmm: alloc a");
    let b = alloc().expect("pmm: alloc b");
    let c = alloc().expect("pmm: alloc c");
    assert!(a != b && b != c && a != c, "pmm: alloc returned duplicates");
    for &f in &[a, b, c] {
        assert!(f % FRAME == 0, "pmm: misaligned frame");
        assert!(
            f >= RAM_BASE + RESERVED_FRAMES * FRAME && f < RAM_BASE + RAM_SIZE,
            "pmm: frame out of range"
        );
    }

    unsafe {
        (a as *mut u64).write_volatile(0x71A1_1A11_71A1_1A11);
        (b as *mut u64).write_volatile(0xDEAD_BEEF_CAFE_F00D);
        assert!(
            (a as *mut u64).read_volatile() == 0x71A1_1A11_71A1_1A11,
            "pmm: data mismatch a"
        );
        assert!((b as *mut u64).read_volatile() == 0xDEAD_BEEF_CAFE_F00D, "pmm: data mismatch b");
    }

    // refcount behaviour
    inc_ref(a);
    assert_eq!(refcount(a), 2);
    free(a);
    assert_eq!(refcount(a), 1, "free with ref>0 must keep the frame");
    let again = alloc().expect("pmm: alloc after partial free");
    assert!(again != a, "frame with ref>0 must not be handed out");
    free(again);
    free(a);
    free(b);
    free(c);

    let a2 = alloc().expect("pmm: realloc");
    assert!(a2 == a, "pmm: first-fit reuse broken ({a2:#x} != {a:#x})");
    free(a2);
    kprintln!("pmm: alloc/write/refcount/reuse test ok (frame {a:#x})");
}
