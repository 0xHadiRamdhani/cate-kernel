; Interrupt handlers for x86_64 kernel
; Provides comprehensive interrupt handling with security features

BITS 64
SECTION .text
GLOBAL interrupt_handler_0, interrupt_handler_1, interrupt_handler_2, interrupt_handler_3
GLOBAL interrupt_handler_4, interrupt_handler_5, interrupt_handler_6, interrupt_handler_7
GLOBAL interrupt_handler_8, interrupt_handler_9, interrupt_handler_10, interrupt_handler_11
GLOBAL interrupt_handler_12, interrupt_handler_13, interrupt_handler_14, interrupt_handler_15
GLOBAL interrupt_handler_16, interrupt_handler_17, interrupt_handler_18, interrupt_handler_19
GLOBAL interrupt_handler_20, interrupt_handler_21, interrupt_handler_22, interrupt_handler_23
GLOBAL interrupt_handler_24, interrupt_handler_25, interrupt_handler_26, interrupt_handler_27
GLOBAL interrupt_handler_28, interrupt_handler_29, interrupt_handler_30, interrupt_handler_31

GLOBAL irq_handler_32, irq_handler_33, irq_handler_34, irq_handler_35
GLOBAL irq_handler_36, irq_handler_37, irq_handler_38, irq_handler_39
GLOBAL irq_handler_40, irq_handler_41, irq_handler_42, irq_handler_43
GLOBAL irq_handler_44, irq_handler_45, irq_handler_46, irq_handler_47
GLOBAL irq_handler_48

GLOBAL interrupt_common_handler
GLOBAL interrupt_return
GLOBAL interrupt_load_idt
GLOBAL interrupt_enable
GLOBAL interrupt_disable

; External functions
EXTERN interrupt_default_handler
EXTERN interrupt_page_fault_handler
EXTERN interrupt_general_protection_handler
EXTERN interrupt_double_fault_handler
EXTERN interrupt_stack_fault_handler
EXTERN interrupt_nmi_handler
EXTERN interrupt_machine_check_handler
EXTERN interrupt_spurious_handler

; Memory functions
EXTERN kmalloc
EXTERN kfree

; Security functions
EXTERN security_check_stack_integrity
EXTERN security_validate_frame
EXTERN security_sanitize_frame
EXTERN security_detect_overflow
EXTERN security_check_privilege

; Global variables
EXTERN global_interrupt_context
EXTERN interrupt_count
EXTERN interrupts_enabled

; Interrupt stack
SECTION .bss
ALIGN 16
interrupt_stack_bottom:
    resb 16384                    ; 16KB interrupt stack
interrupt_stack_top:

; Macro for creating interrupt handler
%macro INTERRUPT_HANDLER 1
interrupt_handler_%1:
    ; Save all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    ; Save segment registers
    push fs
    push gs
    
    ; Switch to interrupt stack if needed
    mov rax, rsp
    mov rsp, interrupt_stack_top
    push rax                    ; Save old stack pointer
    
    ; Create interrupt frame
    sub rsp, 256                ; Allocate space for interrupt frame
    mov rdi, rsp                ; Pass frame pointer to handler
    
    ; Store interrupt number
    mov qword [rsp], %1
    
    ; Store error code (0 for most interrupts)
    mov qword [rsp + 8], 0
    
    ; Store registers
    mov [rsp + 16], rax
    mov [rsp + 24], rbx
    mov [rsp + 32], rcx
    mov [rsp + 40], rdx
    mov [rsp + 48], rsi
    mov [rsp + 56], rdi
    mov [rsp + 64], rbp
    mov [rsp + 72], r8
    mov [rsp + 80], r9
    mov [rsp + 88], r10
    mov [rsp + 96], r11
    mov [rsp + 104], r12
    mov [rsp + 112], r13
    mov [rsp + 120], r14
    mov [rsp + 128], r15
    
    ; Store segment registers
    mov [rsp + 136], fs
    mov [rsp + 144], gs
    
    ; Store interrupt number
    mov qword [rsp + 152], %1
    
    ; Store error code (0)
    mov qword [rsp + 160], 0
    
    ; Store instruction pointer (would be set by exception)
    mov qword [rsp + 168], 0
    
    ; Store code segment
    mov qword [rsp + 176], 0x08
    
    ; Store flags
    pushfq
    pop rax
    mov [rsp + 184], rax
    
    ; Store stack pointer
    mov [rsp + 192], rsp
    
    ; Store stack segment
    mov qword [rsp + 200], 0x10
    
    ; Increment interrupt count
    lock inc qword [rel interrupt_count]
    
    ; Security checks
    call security_check_stack_integrity
    call security_validate_frame
    call security_detect_overflow
    call security_check_privilege
    
    ; Call appropriate handler
    mov rax, %1
    cmp rax, 14                    ; Page fault
    je .page_fault
    cmp rax, 13                    ; General protection
    je .general_protection
    cmp rax, 8                     ; Double fault
    je .double_fault
    cmp rax, 12                    ; Stack fault
    je .stack_fault
    cmp rax, 2                     ; NMI
    je .nmi
    cmp rax, 18                    ; Machine check
    je .machine_check
    cmp rax, 15                    ; Spurious
    je .spurious
    
    ; Default handler
    call interrupt_default_handler
    jmp .done
    
.page_fault:
    call interrupt_page_fault_handler
    jmp .done
    
.general_protection:
    call interrupt_general_protection_handler
    jmp .done
    
.double_fault:
    call interrupt_double_fault_handler
    jmp .done
    
.stack_fault:
    call interrupt_stack_fault_handler
    jmp .done
    
.nmi:
    call interrupt_nmi_handler
    jmp .done
    
.machine_check:
    call interrupt_machine_check_handler
    jmp .done
    
.spurious:
    call interrupt_spurious_handler
    jmp .done
    
.done:
    ; Restore old stack pointer
    mov rsp, [rsp + 192]
    add rsp, 256
    
    ; Restore old stack pointer
    pop rsp
    
    ; Restore segment registers
    pop gs
    pop fs
    
    ; Restore all registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ; Return from interrupt
    iretq
%endmacro

; Macro for error code handlers
%macro INTERRUPT_HANDLER_EC 1
interrupt_handler_%1:
    ; Save all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    ; Save segment registers
    push fs
    push gs
    
    ; Get error code
    pop rax                     ; Error code was pushed by CPU
    push rax                    ; Save error code
    
    ; Switch to interrupt stack
    mov rcx, rsp
    mov rsp, interrupt_stack_top
    push rcx                    ; Save old stack pointer
    
    ; Create interrupt frame
    sub rsp, 256
    mov rdi, rsp
    
    ; Store error code
    mov [rsp + 8], rax
    
    ; Store interrupt number
    mov qword [rsp], %1
    
    ; Store registers (similar to above)
    mov [rsp + 16], rax
    mov [rsp + 24], rbx
    mov [rsp + 32], rcx
    mov [rsp + 40], rdx
    mov [rsp + 48], rsi
    mov [rsp + 56], rdi
    mov [rsp + 64], rbp
    mov [rsp + 72], r8
    mov [rsp + 80], r9
    mov [rsp + 88], r10
    mov [rsp + 96], r11
    mov [rsp + 104], r12
    mov [rsp + 112], r13
    mov [rsp + 120], r14
    mov [rsp + 128], r15
    
    ; Store segment registers
    mov [rsp + 136], fs
    mov [rsp + 144], gs
    
    ; Store interrupt number
    mov qword [rsp + 152], %1
    
    ; Store error code
    mov rax, [rsp + 8]
    mov [rsp + 160], rax
    
    ; Store instruction pointer
    mov qword [rsp + 168], 0
    
    ; Store code segment
    mov qword [rsp + 176], 0x08
    
    ; Store flags
    pushfq
    pop rax
    mov [rsp + 184], rax
    
    ; Store stack pointer
    mov [rsp + 192], rsp
    
    ; Store stack segment
    mov qword [rsp + 200], 0x10
    
    ; Increment interrupt count
    lock inc qword [rel interrupt_count]
    
    ; Security checks
    call security_check_stack_integrity
    call security_validate_frame
    call security_detect_overflow
    call security_check_privilege
    
    ; Call appropriate handler
    mov rax, %1
    cmp rax, 14                    ; Page fault
    je .page_fault_ec
    cmp rax, 13                    ; General protection
    je .general_protection_ec
    cmp rax, 8                     ; Double fault
    je .double_fault_ec
    cmp rax, 12                    ; Stack fault
    je .stack_fault_ec
    
    ; Default handler with error code
    call interrupt_default_handler
    jmp .done_ec
    
.page_fault_ec:
    call interrupt_page_fault_handler
    jmp .done_ec
    
.general_protection_ec:
    call interrupt_general_protection_handler
    jmp .done_ec
    
.double_fault_ec:
    call interrupt_double_fault_handler
    jmp .done_ec
    
.stack_fault_ec:
    call interrupt_stack_fault_handler
    jmp .done_ec
    
.done_ec:
    ; Restore old stack pointer
    mov rsp, [rsp + 192]
    add rsp, 256
    
    ; Restore old stack pointer
    pop rsp
    
    ; Restore segment registers
    pop gs
    pop fs
    
    ; Restore all registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ; Return from interrupt
    add rsp, 8                  ; Skip error code
    iretq
%endmacro

; Create interrupt handlers
INTERRUPT_HANDLER 0
INTERRUPT_HANDLER 1
INTERRUPT_HANDLER 2
INTERRUPT_HANDLER 3
INTERRUPT_HANDLER 4
INTERRUPT_HANDLER 5
INTERRUPT_HANDLER 6
INTERRUPT_HANDLER 7
INTERRUPT_HANDLER_EC 8         ; Double fault has error code
INTERRUPT_HANDLER 9
INTERRUPT_HANDLER_EC 10        ; Invalid TSS has error code
INTERRUPT_HANDLER_EC 11        ; Segment not present has error code
INTERRUPT_HANDLER_EC 12        ; Stack fault has error code
INTERRUPT_HANDLER_EC 13        ; General protection has error code
INTERRUPT_HANDLER_EC 14        ; Page fault has error code
INTERRUPT_HANDLER 15
INTERRUPT_HANDLER 16
INTERRUPT_HANDLER_EC 17        ; Alignment check has error code
INTERRUPT_HANDLER_EC 18        ; Machine check has error code
INTERRUPT_HANDLER 19
INTERRUPT_HANDLER 20
INTERRUPT_HANDLER 21

; IRQ handlers (32-48)
%macro IRQ_HANDLER 1
irq_handler_%1:
    ; Save all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    ; Save segment registers
    push fs
    push gs
    
    ; Switch to interrupt stack
    mov rax, rsp
    mov rsp, interrupt_stack_top
    push rax
    
    ; Create interrupt frame
    sub rsp, 256
    mov rdi, rsp
    
    ; Store interrupt number (IRQ)
    mov qword [rsp], %1
    
    ; Store error code (0 for IRQs)
    mov qword [rsp + 8], 0
    
    ; Store registers
    mov [rsp + 16], rax
    mov [rsp + 24], rbx
    mov [rsp + 32], rcx
    mov [rsp + 40], rdx
    mov [rsp + 48], rsi
    mov [rsp + 56], rdi
    mov [rsp + 64], rbp
    mov [rsp + 72], r8
    mov [rsp + 80], r9
    mov [rsp + 88], r10
    mov [rsp + 96], r11
    mov [rsp + 104], r12
    mov [rsp + 112], r13
    mov [rsp + 120], r14
    mov [rsp + 128], r15
    
    ; Store segment registers
    mov [rsp + 136], fs
    mov [rsp + 144], gs
    
    ; Store interrupt number
    mov qword [rsp + 152], %1
    
    ; Store error code
    mov qword [rsp + 160], 0
    
    ; Store instruction pointer
    mov qword [rsp + 168], 0
    
    ; Store code segment
    mov qword [rsp + 176], 0x08
    
    ; Store flags
    pushfq
    pop rax
    mov [rsp + 184], rax
    
    ; Store stack pointer
    mov [rsp + 192], rsp
    
    ; Store stack segment
    mov qword [rsp + 200], 0x10
    
    ; Increment interrupt count
    lock inc qword [rel interrupt_count]
    
    ; Security checks
    call security_check_stack_integrity
    call security_validate_frame
    call security_detect_overflow
    call security_check_privilege
    
    ; Call IRQ handler
    mov rax, %1
    sub rax, 32                 ; Convert to IRQ number
    ; Call handler based on IRQ number
    
    ; Send EOI
    mov rax, %1
    call interrupt_acknowledge
    
    ; Restore old stack pointer
    mov rsp, [rsp + 192]
    add rsp, 256
    
    ; Restore old stack pointer
    pop rsp
    
    ; Restore segment registers
    pop gs
    pop fs
    
    ; Restore all registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ; Return from interrupt
    iretq
%endmacro

; Create IRQ handlers
IRQ_HANDLER 32
IRQ_HANDLER 33
IRQ_HANDLER 34
IRQ_HANDLER 35
IRQ_HANDLER 36
IRQ_HANDLER 37
IRQ_HANDLER 38
IRQ_HANDLER 39
IRQ_HANDLER 40
IRQ_HANDLER 41
IRQ_HANDLER 42
IRQ_HANDLER 43
IRQ_HANDLER 44
IRQ_HANDLER 45
IRQ_HANDLER 46
IRQ_HANDLER 47
IRQ_HANDLER 48

; Common interrupt handler
interrupt_common_handler:
    ; This would be called by all interrupt handlers
    ; For common processing and security checks
    ret

; Interrupt return
interrupt_return:
    ; Common return sequence
    iretq

; Load IDT
interrupt_load_idt:
    ; Load IDT from global context
    mov rax, [rel global_interrupt_context]
    test rax, rax
    jz .no_idt
    
    lea rdx, [rax + interrupt_context_t.idt_pointer]
    lidt [rdx]
    ret
    
.no_idt:
    ret

; Enable interrupts
interrupt_enable:
    sti
    mov byte [rel interrupts_enabled], 1
    ret

; Disable interrupts
interrupt_disable:
    cli
    mov byte [rel interrupts_enabled], 0
    ret

; Data section
SECTION .data
interrupt_handler_addresses:
    dq interrupt_handler_0
    dq interrupt_handler_1
    dq interrupt_handler_2
    dq interrupt_handler_3
    dq interrupt_handler_4
    dq interrupt_handler_5
    dq interrupt_handler_6
    dq interrupt_handler_7
    dq interrupt_handler_8
    dq interrupt_handler_9
    dq interrupt_handler_10
    dq interrupt_handler_11
    dq interrupt_handler_12
    dq interrupt_handler_13
    dq interrupt_handler_14
    dq interrupt_handler_15
    dq interrupt_handler_16
    dq interrupt_handler_17
    dq interrupt_handler_18
    dq interrupt_handler_19
    dq interrupt_handler_20
    dq interrupt_handler_21

irq_handler_addresses:
    dq irq_handler_32
    dq irq_handler_33
    dq irq_handler_34
    dq irq_handler_35
    dq irq_handler_36
    dq irq_handler_37
    dq irq_handler_38
    dq irq_handler_39
    dq irq_handler_40
    dq irq_handler_41
    dq irq_handler_42
    dq irq_handler_43
    dq irq_handler_44
    dq irq_handler_45
    dq irq_handler_46
    dq irq_handler_47
    dq irq_handler_48

; Interrupt messages for debugging
interrupt_messages:
    db "Divide Error", 0
    db "Debug", 0
    db "NMI", 0
    db "Breakpoint", 0
    db "Overflow", 0
    db "Bound Range", 0
    db "Invalid Opcode", 0
    db "Device Not Available", 0
    db "Double Fault", 0
    db "Coprocessor Overrun", 0
    db "Invalid TSS", 0
    db "Segment Not Present", 0
    db "Stack Fault", 0
    db "General Protection", 0
    db "Page Fault", 0
    db "Reserved", 0
    db "FPU Error", 0
    db "Alignment Check", 0
    db "Machine Check", 0
    db "SIMD Error", 0
    db "Virtualization", 0
    db "Security", 0