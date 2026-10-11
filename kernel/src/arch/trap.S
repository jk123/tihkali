// tihkali EL1 exception vectors + trap frame save/restore.
// Frame layout must match `TrapFrame` in trap.rs (repr(C), u64 fields):
//   x[0..29] paired @0..239, x30 @240, elr @248, spsr @256, esr @264, size 272.

.macro SAVE_FRAME
    sub     sp, sp, #272
    stp     x0, x1,   [sp, #16 * 0]
    stp     x2, x3,   [sp, #16 * 1]
    stp     x4, x5,   [sp, #16 * 2]
    stp     x6, x7,   [sp, #16 * 3]
    stp     x8, x9,   [sp, #16 * 4]
    stp     x10, x11, [sp, #16 * 5]
    stp     x12, x13, [sp, #16 * 6]
    stp     x14, x15, [sp, #16 * 7]
    stp     x16, x17, [sp, #16 * 8]
    stp     x18, x19, [sp, #16 * 9]
    stp     x20, x21, [sp, #16 * 10]
    stp     x22, x23, [sp, #16 * 11]
    stp     x24, x25, [sp, #16 * 12]
    stp     x26, x27, [sp, #16 * 13]
    stp     x28, x29, [sp, #16 * 14]
    str     x30,      [sp, #240]
    mrs     x0, elr_el1
    str     x0,       [sp, #248]
    mrs     x0, spsr_el1
    str     x0,       [sp, #256]
    mrs     x0, esr_el1
    str     x0,       [sp, #264]
.endm

.macro RESTORE_FRAME
    ldr     x9, [sp, #248]
    msr     elr_el1, x9
    ldr     x9, [sp, #256]
    msr     spsr_el1, x9
    ldp     x0, x1,   [sp, #16 * 0]
    ldp     x2, x3,   [sp, #16 * 1]
    ldp     x4, x5,   [sp, #16 * 2]
    ldp     x6, x7,   [sp, #16 * 3]
    ldp     x8, x9,   [sp, #16 * 4]
    ldp     x10, x11, [sp, #16 * 5]
    ldp     x12, x13, [sp, #16 * 6]
    ldp     x14, x15, [sp, #16 * 7]
    ldp     x16, x17, [sp, #16 * 8]
    ldp     x18, x19, [sp, #16 * 9]
    ldp     x20, x21, [sp, #16 * 10]
    ldp     x22, x23, [sp, #16 * 11]
    ldp     x24, x25, [sp, #16 * 12]
    ldp     x26, x27, [sp, #16 * 13]
    ldp     x28, x29, [sp, #16 * 14]
    ldr     x30,      [sp, #240]
    add     sp, sp, #272
    eret
.endm

.p2align 11
.global vectors
vectors:
    b       bad_exc             // 0x000 Synchronous, SP0
    .p2align 7
    b       bad_exc             // 0x080 IRQ, SP0
    .p2align 7
    b       bad_exc             // 0x100 FIQ, SP0
    .p2align 7
    b       bad_exc             // 0x180 SError, SP0
    .p2align 7
    b       sync_entry          // 0x200 Synchronous, SPx
    .p2align 7
    b       irq_entry           // 0x280 IRQ, SPx
    .p2align 7
    b       bad_exc             // 0x300 FIQ, SPx
    .p2align 7
    b       bad_exc             // 0x380 SError, SPx
    .p2align 7
    b       sync_entry          // 0x400 Synchronous, lower EL AArch64
    .p2align 7
    b       irq_entry           // 0x480 IRQ, lower EL AArch64
    .p2align 7
    b       bad_exc             // 0x500 FIQ, lower EL AArch64
    .p2align 7
    b       bad_exc             // 0x580 SError, lower EL AArch64
    .p2align 7
    b       bad_exc             // 0x600 Synchronous, lower EL AArch32
    .p2align 7
    b       bad_exc             // 0x680 IRQ, lower EL AArch32
    .p2align 7
    b       bad_exc             // 0x700 FIQ, lower EL AArch32
    .p2align 7
    b       bad_exc             // 0x780 SError, lower EL AArch32

sync_entry:
    SAVE_FRAME
    mov     x0, sp
    bl      rust_sync_handler
    // Fatal paths diverge in Rust; svc dispatch returns here.
    RESTORE_FRAME

irq_entry:
    SAVE_FRAME
    mov     x0, sp
    bl      rust_irq_handler
    RESTORE_FRAME

bad_exc:
    wfe
    b       bad_exc
