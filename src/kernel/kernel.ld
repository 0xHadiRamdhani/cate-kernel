/* Linker script for kernel */
ENTRY(kernel_main)

SECTIONS
{
    /* Start at higher half - standard for 64-bit kernels */
    . = 0xFFFFFFFF80000000;

    /* Multiboot header (if needed) */
    .multiboot ALIGN(8) :
    {
        *(.multiboot)
    }

    /* Code section */
    .text ALIGN(4K) :
    {
        *(.text)
        *(.text.*)
        *(.stub)
        *(.glue_7)
        *(.glue_7t)
    }

    /* Read-only data */
    .rodata ALIGN(4K) :
    {
        *(.rodata)
        *(.rodata.*)
        *(.eh_frame_hdr)
        *(.eh_frame)
    }

    /* Constructor and destructor lists */
    .ctors ALIGN(4K) :
    {
        *(.ctors)
        *(.ctor)
        *(.init)
    }

    .dtors ALIGN(4K) :
    {
        *(.dtors)
        *(.dtor)
        *(.fini)
    }

    /* Initialized data */
    .data ALIGN(4K) :
    {
        *(.data)
        *(.data.*)
        *(.got)
        *(.got.plt)
    }

    /* Uninitialized data (BSS) */
    .bss ALIGN(4K) :
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    /* Kernel heap */
    .heap ALIGN(4K) :
    {
        *(.heap)
        *(.heap.*)
    }

    /* Kernel stack */
    .stack ALIGN(16) :
    {
        *(.stack)
        *(.stack.*)
    }

    /* Page tables */
    .pagetables ALIGN(4K) :
    {
        *(.pagetables)
        *(.pagetables.*)
    }

    /* Interrupt descriptors */
    .idt ALIGN(16) :
    {
        *(.idt)
        *(.idt.*)
    }

    /* Global descriptor table */
    .gdt ALIGN(16) :
    {
        *(.gdt)
        *(.gdt.*)
    }

    /* Task state segment */
    .tss ALIGN(16) :
    {
        *(.tss)
        *(.tss.*)
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

    /* Pentesting data */
    .pentest ALIGN(16) :
    {
        *(.pentest)
        *(.pentest.*)
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
        *(.comment*)
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
__heap_start = ADDR(.heap);
__heap_end = ADDR(.heap) + SIZEOF(.heap);
__stack_start = ADDR(.stack);
__stack_end = ADDR(.stack) + SIZEOF(.stack);
__pagetables_start = ADDR(.pagetables);
__pagetables_end = ADDR(.pagetables) + SIZEOF(.pagetables);
__idt_start = ADDR(.idt);
__idt_end = ADDR(.idt) + SIZEOF(.idt);
__gdt_start = ADDR(.gdt);
__gdt_end = ADDR(.gdt) + SIZEOF(.gdt);
__tss_start = ADDR(.tss);
__tss_end = ADDR(.tss) + SIZEOF(.tss);
__acpi_start = ADDR(.acpi);
__acpi_end = ADDR(.acpi) + SIZEOF(.acpi);
__efi_start = ADDR(.efi);
__efi_end = ADDR(.efi) + SIZEOF(.efi);
__security_start = ADDR(.security);
__security_end = ADDR(.security) + SIZEOF(.security);
__modules_start = ADDR(.modules);
__modules_end = ADDR(.modules) + SIZEOF(.modules);
__pentest_start = ADDR(.pentest);
__pentest_end = ADDR(.pentest) + SIZEOF(.pentest);