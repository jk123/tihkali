/* tihkali user program — linked at VA 4 GiB (0x1_0000_0000).
 * Chosen so user VAs can never collide with the kernel's identity window
 * (RAM at 0x4000_0000..0x4fff_ffff): per-process page tables translate
 * these VAs to arbitrary frames while the kernel keeps identity access
 * to all of physical RAM. */

ENTRY(_start)

SECTIONS {
    . = 0x100000000;

    .text : ALIGN(4K) {
        *(.text .text.*)
    }

    .rodata : ALIGN(16) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(16) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    .bss (NOLOAD) : ALIGN(16) {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
