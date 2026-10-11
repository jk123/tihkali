/* tihkali kernel linker script — Raspberry Pi 3 (kernel8.bin @ 0x80000). */

ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x80000, LENGTH = 768M
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
