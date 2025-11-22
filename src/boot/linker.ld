/* Linker script for bootloader */
ENTRY(_start)

SECTIONS
{
    /* Start at 1MB - standard for kernels */
    . = 0x100000;

    /* Multiboot2 header must be at the beginning */
    .multiboot ALIGN(8) :
    {
        *(.multiboot)
    }

    /* Code section */
    .text ALIGN(4K) :
    {
        *(.text)
        *(.text.*)
    }

    /* Read-only data */
    .rodata ALIGN(4K) :
    {
        *(.rodata)
        *(.rodata.*)
    }

    /* Initialized data */
    .data ALIGN(4K) :
    {
        *(.data)
        *(.data.*)
    }

    /* Uninitialized data */
    .bss ALIGN(4K) :
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    /* ACPI tables */
    .acpi ALIGN(16) :
    {
        *(.acpi)
        *(.acpi.*)
    }

    /* EFI system table */
    .efi ALIGN(16) :
    {
        *(.efi)
        *(.efi.*)
    }

    /* Security data */
    .security ALIGN(16) :
    {
        *(.security)
        *(.security.*)
    }

    /* Module data */
    .modules ALIGN(16) :
    {
        *(.modules)
        *(.modules.*)
    }

    /* Stack */
    .stack ALIGN(16) :
    {
        *(.stack)
    }

    /* Page tables */
    .pagetables ALIGN(4K) :
    {
        *(.pagetables)
    }

    /* Debug information */
    .debug ALIGN(16) :
    {
        *(.debug)
        *(.debug.*)
    }

    /* Comments */
    .comment ALIGN(16) :
    {
        *(.comment)
    }

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.note*)
        *(.eh_frame*)
        *(.jcr)
        *(.got.plt)
        *(.init)
        *(.fini)
        *(.ctors)
        *(.dtors)
    }
}

/* Provide symbols for start and end of sections */
__text_start = ADDR(.text);
__text_end = ADDR(.text) + SIZEOF(.text);
__rodata_start = ADDR(.rodata);
__rodata_end = ADDR(.rodata) + SIZEOF(.rodata);
__data_start = ADDR(.data);
__data_end = ADDR(.data) + SIZEOF(.data);
__bss_start = ADDR(.bss);
__bss_end = ADDR(.bss) + SIZEOF(.bss);
__multiboot_start = ADDR(.multiboot);
__multiboot_end = ADDR(.multiboot) + SIZEOF(.multiboot);
__modules_start = ADDR(.modules);
__modules_end = ADDR(.modules) + SIZEOF(.modules);
__stack_start = ADDR(.stack);
__stack_end = ADDR(.stack) + SIZEOF(.stack);
__pagetables_start = ADDR(.pagetables);
__pagetables_end = ADDR(.pagetables) + SIZEOF(.pagetables);