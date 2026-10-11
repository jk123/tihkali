// tihkali aarch64 boot: enter at any EL, drop to EL1, clear BSS, call Rust.
// x19 = EL we were entered at (survives eret), passed to kernel_main as arg0.

.section ".text.boot"
.global _start
_start:
    mrs     x19, CurrentEL
    lsr     x19, x19, #2
    cmp     x19, #3
    b.eq    el3_to_el2
    cmp     x19, #2
    b.eq    el2_to_el1
    b       el1_main

el3_to_el2:
    // Non-secure EL2, AArch64 at lower ELs.
    mov     x0, #(1 << 10) | 1       // SCR_EL3.RW=1, SCR_EL3.NS=1
    msr     scr_el3, x0
    mov     x0, #0x3c9               // EL2h, DAIF masked
    msr     spsr_el3, x0
    adr     x0, el2_to_el1
    msr     elr_el3, x0
    eret

el2_to_el1:
    // EL1 executes AArch64; let EL1 read the physical timer/counter.
    mov     x0, #(1 << 31)           // HCR_EL2.RW=1
    msr     hcr_el2, x0
    mov     x0, #0x3                 // CNTHCTL_EL2: EL1PCEN | EL1PCTEN
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr
    mov     x0, #0x3c5               // EL1h, DAIF masked
    msr     spsr_el2, x0
    adr     x0, el1_main
    msr     elr_el2, x0
    eret

el1_main:
    // Run on SP_EL1 (EL1h); QEMU may start us in EL1t (SPSel=0),
    // which would route IRQs to the SP0 vector slots.
    msr     spsel, #1

    // Enable FP/NEON at EL1 and EL0 (FPEN=0b11): rustc targets aarch64
    // with NEON and will vectorize.
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    // Exception vectors: spin cleanly instead of faulting at VBAR=0.
    adr     x0, vectors
    msr     vbar_el1, x0

    // Stack grows down from __stack_top.
    adrp    x0, __stack_top
    add     x0, x0, :lo12:__stack_top
    mov     sp, x0

    // Clear BSS.
    adrp    x0, __bss_start
    add     x0, x0, :lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, :lo12:__bss_end
1:  cmp     x0, x1
    b.ge    2f
    str     xzr, [x0], #8
    b       1b
2:
    mov     x0, x19                 // arg0: entry EL
    bl      kernel_main

hang:
    wfe
    b       hang
