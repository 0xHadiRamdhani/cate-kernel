#include "interrupt.h"
#include "memory.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Global interrupt context */
interrupt_context_t* global_interrupt_context = NULL;
volatile uint64_t interrupt_count = 0;
volatile bool interrupts_enabled = false;

/* I/O port addresses */
#define PIC_MASTER_COMMAND  0x20
#define PIC_MASTER_DATA     0x21
#define PIC_SLAVE_COMMAND   0xA0
#define PIC_SLAVE_DATA      0xA1

#define PIC_EOI             0x20
#define PIC_INIT            0x11
#define PIC_ICW4            0x01

#define APIC_BASE           0xFEE00000
#define APIC_ID             0x20
#define APIC_VERSION        0x30
#define APIC_TASK_PRIORITY  0x80
#define APIC_EOI            0xB0
#define APIC_SPURIOUS       0xF0
#define APIC_LVT_TIMER      0x320
#define APIC_LVT_LINT0      0x350
#define APIC_LVT_LINT1      0x360
#define APIC_LVT_ERROR      0x370
#define APIC_TIMER_DIVIDE   0x3E0
#define APIC_TIMER_INITIAL  0x380
#define APIC_TIMER_CURRENT  0x390

/* Initialize interrupt subsystem */
void interrupt_init(void) {
    /* Allocate interrupt context */
    global_interrupt_context = (interrupt_context_t*)kmalloc(sizeof(interrupt_context_t));
    if (!global_interrupt_context) {
        return;
    }
    
    memory_zero(global_interrupt_context, sizeof(interrupt_context_t));
    
    /* Setup interrupt stack */
    global_interrupt_context->interrupt_stack_size = 0x4000; /* 16KB */
    global_interrupt_context->interrupt_stack = (uint64_t)kmalloc_aligned(global_interrupt_context->interrupt_stack_size, 16);
    global_interrupt_context->interrupt_stack_top = global_interrupt_context->interrupt_stack + global_interrupt_context->interrupt_stack_size;
    
    /* Initialize IDT */
    interrupt_init_idt();
    
    /* Initialize PIC */
    interrupt_init_pic();
    
    /* Initialize APIC if available */
    if (apic_is_enabled()) {
        interrupt_init_apic();
    }
    
    /* Initialize interrupt routing */
    interrupt_init_routing();
    
    /* Register default handlers */
    interrupt_register_handler(INT_DIVIDE_ERROR, interrupt_default_handler);
    interrupt_register_handler(INT_DEBUG, interrupt_default_handler);
    interrupt_register_handler(INT_NMI, interrupt_nmi_handler);
    interrupt_register_handler(INT_BREAKPOINT, interrupt_default_handler);
    interrupt_register_handler(INT_OVERFLOW, interrupt_default_handler);
    interrupt_register_handler(INT_BOUND_RANGE, interrupt_default_handler);
    interrupt_register_handler(INT_INVALID_OPCODE, interrupt_default_handler);
    interrupt_register_handler(INT_DEVICE_NOT_AVAILABLE, interrupt_default_handler);
    interrupt_register_handler(INT_DOUBLE_FAULT, interrupt_double_fault_handler);
    interrupt_register_handler(INT_INVALID_TSS, interrupt_default_handler);
    interrupt_register_handler(INT_SEGMENT_NOT_PRESENT, interrupt_default_handler);
    interrupt_register_handler(INT_STACK_FAULT, interrupt_stack_fault_handler);
    interrupt_register_handler(INT_GENERAL_PROTECTION, interrupt_general_protection_handler);
    interrupt_register_handler(INT_PAGE_FAULT, interrupt_page_fault_handler);
    interrupt_register_handler(INT_FPU_ERROR, interrupt_default_handler);
    interrupt_register_handler(INT_ALIGNMENT_CHECK, interrupt_default_handler);
    interrupt_register_handler(INT_MACHINE_CHECK, interrupt_machine_check_handler);
    interrupt_register_handler(INT_SIMD_ERROR, interrupt_default_handler);
    
    /* Enable interrupts */
    interrupt_enable();
}

/* Initialize IDT */
void interrupt_init_idt(void) {
    if (!global_interrupt_context) return;
    
    /* Clear IDT */
    memory_zero(global_interrupt_context->idt, sizeof(idt_entry_t) * 256);
    
    /* Setup IDT pointer */
    global_interrupt_context->idt_pointer.limit = sizeof(idt_entry_t) * 256 - 1;
    global_interrupt_context->idt_pointer.base = (uint64_t)global_interrupt_context->idt;
    
    /* Set up interrupt handlers */
    for (int i = 0; i < 32; i++) {
        idt_set_entry(i, (uint64_t)interrupt_handler_0 + (i * 16), 0x08, GATE_TYPE_INTERRUPT);
    }
    
    /* Set up IRQ handlers */
    for (int i = 32; i < 48; i++) {
        idt_set_entry(i, (uint64_t)irq_handler_32 + ((i - 32) * 16), 0x08, GATE_TYPE_INTERRUPT);
    }
    
    /* Load IDT */
    idt_load();
}

/* Initialize PIC */
void interrupt_init_pic(void) {
    if (!global_interrupt_context) return;
    
    /* Initialize PIC */
    pic_init();
    
    /* Mask all interrupts initially */
    interrupt_set_mask(0xFFFF);
    
    global_interrupt_context->pic_enabled = true;
}

/* Initialize APIC */
void interrupt_init_apic(void) {
    if (!global_interrupt_context) return;
    
    /* Check if APIC is available */
    if (!apic_is_enabled()) {
        return;
    }
    
    /* Initialize APIC */
    apic_init();
    
    /* Enable APIC */
    apic_enable();
    
    global_interrupt_context->apic_enabled = true;
}

/* Initialize interrupt routing */
void interrupt_init_routing(void) {
    if (!global_interrupt_context) return;
    
    /* Setup default routing */
    for (int i = 0; i < 256; i++) {
        global_interrupt_context->routing[i].irq = i;
        global_interrupt_context->routing[i].vector = i;
        global_interrupt_context->routing[i].flags = 0;
        global_interrupt_context->routing[i].destination = 0;
    }
    
    /* Setup specific routing for common devices */
    interrupt_set_routing(IRQ_TIMER, 32, 0, 0);
    interrupt_set_routing(IRQ_KEYBOARD, 33, 0, 0);
    interrupt_set_routing(IRQ_CASCADE, 34, 0, 0);
    interrupt_set_routing(IRQ_COM1, 36, 0, 0);
    interrupt_set_routing(IRQ_COM2, 35, 0, 0);
}

/* Enable interrupts */
void interrupt_enable(void) {
    __asm__ volatile ("sti");
    interrupts_enabled = true;
}

/* Disable interrupts */
void interrupt_disable(void) {
    __asm__ volatile ("cli");
    interrupts_enabled = false;
}

/* Enable specific IRQ */
void interrupt_enable_irq(uint8_t irq) {
    if (!global_interrupt_context) return;
    
    uint16_t mask = interrupt_get_mask();
    mask &= ~(1 << irq);
    interrupt_set_mask(mask);
}

/* Disable specific IRQ */
void interrupt_disable_irq(uint8_t irq) {
    if (!global_interrupt_context) return;
    
    uint16_t mask = interrupt_get_mask();
    mask |= (1 << irq);
    interrupt_set_mask(mask);
}

/* Register interrupt handler */
void interrupt_register_handler(uint8_t vector, interrupt_handler_t handler) {
    if (!global_interrupt_context || vector >= 32) return;
    
    global_interrupt_context->interrupt_handlers[vector] = handler;
}

/* Register IRQ handler */
void interrupt_register_irq_handler(uint8_t irq, irq_handler_t handler) {
    if (!global_interrupt_context || irq >= 256) return;
    
    global_interrupt_context->irq_handlers[irq] = handler;
}

/* Unregister handler */
void interrupt_unregister_handler(uint8_t vector) {
    if (!global_interrupt_context) return;
    
    if (vector < 32) {
        global_interrupt_context->interrupt_handlers[vector] = NULL;
    } else {
        global_interrupt_context->irq_handlers[vector] = NULL;
    }
}

/* Unregister IRQ handler */
void interrupt_unregister_irq_handler(uint8_t irq) {
    if (!global_interrupt_context) return;
    
    global_interrupt_context->irq_handlers[irq] = NULL;
}

/* Acknowledge interrupt */
void interrupt_acknowledge(uint8_t irq) {
    if (!global_interrupt_context) return;
    
    if (global_interrupt_context->apic_enabled) {
        apic_send_eoi();
    } else if (global_interrupt_context->pic_enabled) {
        pic_send_eoi(irq);
    }
}

/* End of interrupt */
void interrupt_eoi(uint8_t vector) {
    interrupt_acknowledge(vector);
}

/* Set interrupt mask */
void interrupt_set_mask(uint16_t mask) {
    if (!global_interrupt_context) return;
    
    global_interrupt_context->pic_state.master_mask = mask & 0xFF;
    global_interrupt_context->pic_state.slave_mask = (mask >> 8) & 0xFF;
    
    outb(PIC_MASTER_DATA, global_interrupt_context->pic_state.master_mask);
    outb(PIC_SLAVE_DATA, global_interrupt_context->pic_state.slave_mask);
}

/* Get interrupt mask */
uint16_t interrupt_get_mask(void) {
    if (!global_interrupt_context) return 0;
    
    return (global_interrupt_context->pic_state.slave_mask << 8) | 
           global_interrupt_context->pic_state.master_mask;
}

/* Set interrupt routing */
void interrupt_set_routing(uint8_t irq, uint8_t vector, uint8_t destination, uint8_t flags) {
    if (!global_interrupt_context) return;
    
    global_interrupt_context->routing[irq].irq = irq;
    global_interrupt_context->routing[irq].vector = vector;
    global_interrupt_context->routing[irq].destination = destination;
    global_interrupt_context->routing[irq].flags = flags;
}

/* Get interrupt routing */
interrupt_routing_t* interrupt_get_routing(uint8_t irq) {
    if (!global_interrupt_context || irq >= 256) return NULL;
    
    return &global_interrupt_context->routing[irq];
}

/* Spurious interrupt handler */
void interrupt_spurious_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    global_interrupt_context->stats.spurious_interrupts++;
    
    /* Log spurious interrupt */
    /* Could implement more sophisticated handling here */
}

/* Default interrupt handler */
void interrupt_default_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    uint8_t vector = frame->interrupt_number;
    
    /* Update statistics */
    global_interrupt_context->stats.interrupt_counts[vector]++;
    global_interrupt_context->stats.total_interrupts++;
    
    /* Log interrupt for pentesting analysis */
    interrupt_log_events();
}

/* Page fault handler */
void interrupt_page_fault_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    uint64_t cr2;
    __asm__ volatile ("mov %%cr2, %0" : "=r" (cr2));
    
    /* Log page fault for analysis */
    /* This is crucial for pentesting - can detect buffer overflows, etc. */
    
    /* Check if it's a stack overflow */
    if (cr2 >= 0xFFFF800000000000) {
        /* Kernel space page fault - potential security issue */
        interrupt_detect_overflow(frame);
    }
    
    /* Handle the fault */
    /* For now, just log it */
    interrupt_log_events();
}

/* General protection fault handler */
void interrupt_general_protection_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    /* This is very important for pentesting */
    /* Can detect privilege escalation attempts, invalid memory access, etc. */
    
    uint64_t error_code = frame->error_code;
    
    /* Analyze error code */
    if (error_code & 0x01) {
        /* External event */
    }
    
    if (error_code & 0x02) {
        /* Descriptor Table error */
    }
    
    if (error_code & 0x04) {
        /* Stack fault */
    }
    
    /* Log for analysis */
    interrupt_log_events();
    interrupt_check_privilege(frame);
}

/* Double fault handler */
void interrupt_double_fault_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    /* Double fault is serious - usually indicates stack corruption */
    /* This is critical for pentesting analysis */
    
    interrupt_detect_overflow(frame);
    interrupt_log_events();
    
    /* Halt system for analysis */
    __asm__ volatile ("hlt");
}

/* Stack fault handler */
void interrupt_stack_fault_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    /* Stack faults are often indicators of buffer overflows */
    /* Very important for pentesting */
    
    uint64_t error_code = frame->error_code;
    
    if (error_code & 0x02) {
        /* Stack segment not present */
        interrupt_detect_overflow(frame);
    }
    
    interrupt_log_events();
}

/* NMI handler */
void interrupt_nmi_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    /* NMI can be hardware or software triggered */
    /* Important for hardware-level pentesting */
    
    interrupt_log_events();
}

/* Debug handler */
void interrupt_debug_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    /* Debug exceptions can be used for debugging or malicious purposes */
    /* Monitor for unexpected debug exceptions */
    
    interrupt_log_events();
}

/* Machine check handler */
void interrupt_machine_check_handler(interrupt_frame_t* frame) {
    if (!global_interrupt_context) return;
    
    /* Machine check exceptions indicate hardware errors */
    /* Could be triggered by hardware attacks */
    
    interrupt_log_events();
}

/* IDT management */
void idt_set_entry(uint8_t vector, uint64_t offset, uint16_t selector, uint8_t type) {
    if (!global_interrupt_context) return;
    
    idt_entry_t* entry = &global_interrupt_context->idt[vector];
    
    entry->offset_low = offset & 0xFFFF;
    entry->offset_mid = (offset >> 16) & 0xFFFF;
    entry->offset_high = (offset >> 32) & 0xFFFFFFFF;
    entry->selector = selector;
    entry->ist = 0;
    entry->type_attr = type;
    entry->reserved = 0;
}

void idt_clear_entry(uint8_t vector) {
    if (!global_interrupt_context) return;
    
    memory_zero(&global_interrupt_context->idt[vector], sizeof(idt_entry_t));
}

void idt_load(void) {
    if (!global_interrupt_context) return;
    
    __asm__ volatile ("lidt %0" : : "m"(global_interrupt_context->idt_pointer));
}

void idt_enable(void) {
    __asm__ volatile ("sti");
}

void idt_disable(void) {
    __asm__ volatile ("cli");
}

/* PIC management */
void pic_init(void) {
    if (!global_interrupt_context) return;
    
    /* Save current masks */
    uint8_t master_mask = inb(PIC_MASTER_DATA);
    uint8_t slave_mask = inb(PIC_SLAVE_DATA);
    
    /* Initialize PIC */
    outb(PIC_MASTER_COMMAND, PIC_INIT);
    outb(PIC_SLAVE_COMMAND, PIC_INIT);
    
    /* Set vector offsets */
    outb(PIC_MASTER_DATA, 0x20); /* Master: 0x20-0x27 */
    outb(PIC_SLAVE_DATA, 0x28);  /* Slave: 0x28-0x2F */
    
    /* Setup cascade */
    outb(PIC_MASTER_DATA, 0x04); /* IRQ2 is cascade */
    outb(PIC_SLAVE_DATA, 0x02);  /* Cascade identity */
    
    /* Set mode */
    outb(PIC_MASTER_DATA, PIC_ICW4);
    outb(PIC_SLAVE_DATA, PIC_ICW4);
    
    /* Restore masks */
    outb(PIC_MASTER_DATA, master_mask);
    outb(PIC_SLAVE_DATA, slave_mask);
    
    /* Save state */
    global_interrupt_context->pic_state.master_mask = master_mask;
    global_interrupt_context->pic_state.slave_mask = slave_mask;
}

void pic_remap(uint8_t master_offset, uint8_t slave_offset) {
    /* Save current masks */
    uint8_t master_mask = inb(PIC_MASTER_DATA);
    uint8_t slave_mask = inb(PIC_SLAVE_DATA);
    
    /* Initialize PIC */
    outb(PIC_MASTER_COMMAND, PIC_INIT);
    outb(PIC_SLAVE_COMMAND, PIC_INIT);
    
    /* Set new offsets */
    outb(PIC_MASTER_DATA, master_offset);
    outb(PIC_SLAVE_DATA, slave_offset);
    
    /* Setup cascade */
    outb(PIC_MASTER_DATA, 0x04);
    outb(PIC_SLAVE_DATA, 0x02);
    
    /* Set mode */
    outb(PIC_MASTER_DATA, PIC_ICW4);
    outb(PIC_SLAVE_DATA, PIC_ICW4);
    
    /* Restore masks */
    outb(PIC_MASTER_DATA, master_mask);
    outb(PIC_SLAVE_DATA, slave_mask);
}

void pic_mask_irq(uint8_t irq) {
    if (irq < 8) {
        uint8_t mask = inb(PIC_MASTER_DATA);
        mask |= (1 << irq);
        outb(PIC_MASTER_DATA, mask);
    } else {
        uint8_t mask = inb(PIC_SLAVE_DATA);
        mask |= (1 << (irq - 8));
        outb(PIC_SLAVE_DATA, mask);
    }
}

void pic_unmask_irq(uint8_t irq) {
    if (irq < 8) {
        uint8_t mask = inb(PIC_MASTER_DATA);
        mask &= ~(1 << irq);
        outb(PIC_MASTER_DATA, mask);
    } else {
        uint8_t mask = inb(PIC_SLAVE_DATA);
        mask &= ~(1 << (irq - 8));
        outb(PIC_SLAVE_DATA, mask);
    }
}

void pic_send_eoi(uint8_t irq) {
    if (irq >= 8) {
        outb(PIC_SLAVE_COMMAND, PIC_EOI);
    }
    outb(PIC_MASTER_COMMAND, PIC_EOI);
}

void pic_disable(void) {
    /* Mask all interrupts */
    outb(PIC_MASTER_DATA, 0xFF);
    outb(PIC_SLAVE_DATA, 0xFF);
}

/* APIC management */
void apic_init(void) {
    if (!global_interrupt_context) return;
    
    /* Check if APIC is available */
    uint32_t version = apic_read(APIC_VERSION);
    if ((version & 0xFF000000) == 0) {
        return; /* No APIC */
    }
    
    /* Get APIC ID */
    global_interrupt_context->apic_state.id = apic_read(APIC_ID);
    global_interrupt_context->apic_state.version = version & 0xFF;
    
    /* Setup spurious interrupt vector */
    apic_write(APIC_SPURIOUS, 0x1FF); /* Vector 0xFF, enable APIC */
}

void apic_enable(void) {
    if (!global_interrupt_context) return;
    
    /* Enable APIC */
    uint32_t spurious = apic_read(APIC_SPURIOUS);
    spurious |= 0x100; /* Enable bit */
    apic_write(APIC_SPURIOUS, spurious);
    
    global_interrupt_context->apic_enabled = true;
}

void apic_disable(void) {
    if (!global_interrupt_context) return;
    
    /* Disable APIC */
    uint32_t spurious = apic_read(APIC_SPURIOUS);
    spurious &= ~0x100; /* Disable bit */
    apic_write(APIC_SPURIOUS, spurious);
    
    global_interrupt_context->apic_enabled = false;
}

void apic_send_eoi(void) {
    apic_write(APIC_EOI, 0);
}

void apic_set_timer(uint32_t count) {
    apic_write(APIC_TIMER_INITIAL, count);
}

uint32_t apic_get_timer(void) {
    return apic_read(APIC_TIMER_CURRENT);
}

void apic_timer_handler(interrupt_frame_t* frame) {
    /* Handle APIC timer interrupt */
    interrupt_default_handler(frame);
}

void apic_spurious_handler(interrupt_frame_t* frame) {
    /* Handle APIC spurious interrupt */
    interrupt_spurious_handler(frame);
}

bool apic_is_enabled(void) {
    if (!global_interrupt_context) return false;
    return global_interrupt_context->apic_enabled;
}

uint32_t apic_read(uint32_t reg) {
    volatile uint32_t* apic_reg = (volatile uint32_t*)(APIC_BASE + reg);
    return *apic_reg;
}

void apic_write(uint32_t reg, uint32_t value) {
    volatile uint32_t* apic_reg = (volatile uint32_t*)(APIC_BASE + reg);
    *apic_reg = value;
}

/* Pentesting specific functions */
void interrupt_inject_fault(uint8_t vector) {
    /* Inject a fault for testing purposes */
    /* This is useful for testing fault handlers and security features */
}

void interrupt_trigger_spurious(void) {
    /* Trigger a spurious interrupt */
    /* Useful for testing interrupt handling robustness */
}

void interrupt_test_handlers(void) {
    /* Test all interrupt handlers */
    /* Comprehensive testing of interrupt subsystem */
}

void interrupt_fuzz_vectors(void) {
    /* Fuzz interrupt vectors to find vulnerabilities */
    /* Important for pentesting - can reveal handler vulnerabilities */
}

void interrupt_capture_state(void) {
    /* Capture current interrupt state */
    /* Useful for forensics and debugging */
}

void interrupt_analyze_patterns(void) {
    /* Analyze interrupt patterns for anomalies */
    /* Can detect attacks or unusual behavior */
}

void interrupt_detect_anomalies(void) {
    /* Detect anomalous interrupt behavior */
    /* Important for intrusion detection */
}

void interrupt_log_events(void) {
    /* Log interrupt events for analysis */
    /* Crucial for pentesting and forensics */
}

/* Security functions */
void interrupt_enable_security(void) {
    if (!global_interrupt_context) return;
    
    /* Enable security features */
    /* Stack integrity checking, frame validation, etc. */
}

void interrupt_disable_security(void) {
    if (!global_interrupt_context) return;
    
    /* Disable security features */
    /* For performance or debugging */
}

bool interrupt_check_stack_integrity(void) {
    if (!global_interrupt_context) return false;
    
    /* Check stack integrity */
    /* Return true if stack is intact */
    return true;
}

bool interrupt_validate_frame(interrupt_frame_t* frame) {
    if (!frame) return false;
    
    /* Validate interrupt frame */
    /* Check for corruption or tampering */
    
    return true;
}

void interrupt_sanitize_frame(interrupt_frame_t* frame) {
    if (!frame) return;
    
    /* Sanitize frame to prevent information leakage */
    /* Important for security */
}

void interrupt_detect_overflow(interrupt_frame_t* frame) {
    if (!frame) return;
    
    /* Detect stack overflow */
    /* Check stack canary, guard pages, etc. */
}

void interrupt_check_privilege(interrupt_frame_t* frame) {
    if (!frame) return;
    
    /* Check privilege level */
    /* Detect privilege escalation attempts */
}

void interrupt_audit_handlers(void) {
    if (!global_interrupt_context) return;
    
    /* Audit all interrupt handlers */
    /* Check for vulnerabilities, backdoors, etc. */
}