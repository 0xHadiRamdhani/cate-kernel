; Multiboot2 compliant bootloader for x86_64 kernel OS pentester
; Provides framebuffer, memory map, ACPI, EFI support, and modular payload system

BITS 32
SECTION .multiboot
ALIGN 8

; Multiboot2 header
multiboot_header:
    dd 0xE85250D6                ; Magic number
    dd 0                         ; Architecture (0 = i386)
    dd multiboot_header_end - multiboot_header  ; Header length
    dd -(0xE85250D6 + 0 + (multiboot_header_end - multiboot_header))  ; Checksum

; Information request tag
info_request_tag:
    dw 1                         ; Type: information request
    dw 0                         ; Flags
    dd 20                        ; Size
    dd 4                         ; Request memory map
    dd 5                         ; Request boot device
    dd 6                         ; Request memory map
    dd 8                         ; Request framebuffer
    dd 14                        ; Request ACPI old
    dd 15                        ; Request ACPI new
    dd 11                        ; Request EFI32
    dd 12                        ; Request EFI64
    dd 0                         ; End of requests

; Framebuffer tag
framebuffer_tag:
    dw 5                         ; Type: framebuffer
    dw 0                         ; Flags
    dd 20                        ; Size
    dd 1024                      ; Width
    dd 768                       ; Height
    dd 32                        ; Depth

; Entry address tag
entry_address_tag:
    dw 3                         ; Type: entry address
    dw 0                         ; Flags
    dd 12                        ; Size
    dd _start                    ; Entry address

; Module alignment tag
module_align_tag:
    dw 6                         ; Type: module alignment
    dw 0                         ; Flags
    dd 8                         ; Size

; End tag
end_tag:
    dw 0                         ; Type: end
    dw 0                         ; Flags
    dd 8                         ; Size

multiboot_header_end:

SECTION .bss
ALIGN 16
stack_bottom:
    resb 16384                   ; 16KB stack
stack_top:

SECTION .text
BITS 32
GLOBAL _start

; Entry point for bootloader
_start:
    ; Set up stack
    mov esp, stack_top
    mov ebp, esp

    ; Save multiboot info pointer
    push ebx                     ; Multiboot info
    push eax                     ; Multiboot magic

    ; Clear direction flag
    cld

    ; Save CPU state
    pushad
    pushfd

    ; Check if we have CPUID support
    call check_cpuid
    jc no_cpuid

    ; Check for long mode support
    call check_long_mode
    jc no_long_mode

    ; Enable SSE for performance
    call enable_sse

    ; Setup temporary GDT for 64-bit transition
    call setup_gdt32

    ; Enable PAE (Physical Address Extension)
    call enable_pae

    ; Setup page tables for 64-bit mode
    call setup_page_tables

    ; Enable long mode
    call enable_long_mode

    ; Enable paging
    call enable_paging32

    ; Load 64-bit GDT
    call load_gdt64

    ; Jump to 64-bit code
    jmp 0x08:long_mode_start

; Check for CPUID support
check_cpuid:
    ; Try to flip ID bit in EFLAGS
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd
    xor eax, ecx
    jz no_cpuid
    clc
    ret

no_cpuid:
    mov eax, 0xDEADBEEF
    hlt

; Check for long mode support
check_long_mode:
    ; Check extended processor info
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb no_long_mode

    ; Check long mode feature
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz no_long_mode
    clc
    ret

no_long_mode:
    mov eax, 0xCAFEBABE
    hlt

; Enable SSE instructions
enable_sse:
    ; Set CR4.OSFXSR and CR4.OSXMMEXCPT
    mov eax, cr4
    or eax, (1 << 9) | (1 << 10)
    mov cr4, eax
    ret

; Setup temporary 32-bit GDT
setup_gdt32:
    ; GDT entries
    lgdt [gdt32_ptr]
    ret

; Enable PAE
enable_pae:
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    ret

; Setup page tables for 64-bit mode
setup_page_tables:
    ; Map first PML4 entry
    mov eax, pdp_table
    or eax, 0x03 ; Present + writable
    mov [pml4_table], eax

    ; Map first PDP entry
    mov eax, pd_table
    or eax, 0x03 ; Present + writable
    mov [pdp_table], eax

    ; Map first PD entry
    mov eax, pt_table
    or eax, 0x03 ; Present + writable
    mov [pd_table], eax

    ; Map all PT entries (4MB)
    mov ecx, 0
.map_pt:
    mov eax, 0x200000  ; 2MB pages
    mul ecx
    or eax, 0x83     ; Present + writable + huge
    mov [pt_table + ecx * 8], eax
    inc ecx
    cmp ecx, 512
    jne .map_pt

    ret

; Enable long mode
enable_long_mode:
    ; Set EFER.LME (Long Mode Enable)
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr
    ret

; Enable paging in 32-bit mode
enable_paging32:
    ; Load PML4
    mov eax, pml4_table
    mov cr3, eax

    ; Enable paging
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax
    ret

; Load 64-bit GDT
load_gdt64:
    lgdt [gdt64_ptr]
    ret

; 64-bit code starts here
[BITS 64]
long_mode_start:
    ; Setup 64-bit segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Clear registers
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor rbp, rbp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    ; Setup new stack for 64-bit mode
    mov rsp, 0x200000

    ; Call C kernel entry point
    extern kernel_main_64
    mov rdi, [rsp + 8]  ; Multiboot info
    call kernel_main_64

    ; Halt if kernel returns
    cli
.halt:
    hlt
    jmp .halt

; 32-bit GDT
gdt32:
    dq 0                           ; Null descriptor
    dq 0x00CF9A000000FFFF          ; Code segment
    dq 0x00CF92000000FFFF          ; Data segment

gdt32_ptr:
    dw gdt32_ptr - gdt32 - 1
    dd gdt32

; 64-bit GDT
gdt64:
    dq 0                           ; Null descriptor
    dq 0x00AF9A000000FFFF          ; Code segment (64-bit)
    dq 0x00AF92000000FFFF          ; Data segment
    dq 0x00AF9A000000FFFF          ; User code segment
    dq 0x00AF92000000FFFF          ; User data segment

gdt64_ptr:
    dw gdt64_ptr - gdt64 - 1
    dq gdt64

; Page tables
ALIGN 4096
pml4_table:
    resq 512
    dq 0

pdp_table:
    resq 512
    dq 0

pd_table:
    resq 512
    dq 0

pt_table:
    resq 512
    dq 0

; ACPI RSDP structure
acpi_rsdp:
    db 'RSD PTR '                 ; Signature
    db 0                          ; Checksum
    db 'PENTEST'                  ; OEM ID
    db 2                          ; Revision
    dd 0                          ; RSDT address
    dd 0                          ; Length
    dq 0                          ; XSDT address
    db 0                          ; Extended checksum
    db 0, 0, 0                    ; Reserved

; EFI system table placeholder
efi_system_table:
    resq 64

; Module loading information
module_info:
    dd 0                          ; Module count
    dd 0                          ; Total size
    dq 0                          ; Module list address

; Stack protection canary
stack_canary:
    dq 0xDEADBEEFC0FFEE42

; Boot information structure
boot_info:
    dd 0x4D424F4F                ; 'MOOB' (BOOT backwards)
    dd 0                         ; Version
    dq 0                         ; Kernel base
    dq 0                         ; Kernel size
    dq 0                         ; Module base
    dq 0                         ; Module size
    dq 0                         ; RSDP address
    dq 0                         ; EFI system table
    dd 0                         ; Flags
    dd 0                         ; Reserved