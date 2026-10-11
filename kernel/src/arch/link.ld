/* tihkali kernel linker script — QEMU virt (aarch64), RAM at 0x4000_0000.
 * QEMU places the DTB near the start of RAM, so the kernel loads at +512 KiB. */

ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x40080000, LENGTH = 32M
}

SECTIONS {
    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > RAM

    .data : ALIGN(4K) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM

    .bss (NOLOAD) : ALIGN(8) {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } > RAM

    .stack (NOLOAD) : ALIGN(16) {
        *(.stack)
        . += 64K;              /* primary kernel stack */
        . = ALIGN(16);
    } > RAM

    . = ALIGN(16);
    __stack_top = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
