#ifndef INTERRUPT_H
#define INTERRUPT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Interrupt vector numbers */
#define INT_DIVIDE_ERROR        0
#define INT_DEBUG               1
#define INT_NMI                 2
#define INT_BREAKPOINT          3
#define INT_OVERFLOW            4
#define INT_BOUND_RANGE         5
#define INT_INVALID_OPCODE      6
#define INT_DEVICE_NOT_AVAILABLE 7
#define INT_DOUBLE_FAULT        8
#define INT_COPROCESSOR_OVERRUN 9
#define INT_INVALID_TSS         10
#define INT_SEGMENT_NOT_PRESENT 11
#define INT_STACK_FAULT         12
#define INT_GENERAL_PROTECTION  13
#define INT_PAGE_FAULT          14
#define INT_RESERVED            15
#define INT_FPU_ERROR           16
#define INT_ALIGNMENT_CHECK     17
#define INT_MACHINE_CHECK       18
#define INT_SIMD_ERROR          19
#define INT_VIRTUALIZATION      20
#define INT_SECURITY            21

/* IRQ numbers */
#define IRQ_TIMER               32
#define IRQ_KEYBOARD            33
#define IRQ_CASCADE             34
#define IRQ_COM2                35
#define IRQ_COM1                36
#define IRQ_LPT2                37
#define IRQ_FLOPPY              38
#define IRQ_LPT1                39
#define IRQ_RTC                 40
#define IRQ_ACPI                41
#define IRQ_OPEN                42
#define IRQ_NOT_USED1           43
#define IRQ_NOT_USED2           44
#define IRQ_MOUSE               45
#define IRQ_FPU                 46
#define IRQ_PRIMARY_ATA         47
#define IRQ_SECONDARY_ATA       48

/* IDT entry flags */
#define IDT_FLAG_PRESENT        0x80
#define IDT_FLAG_RING0          0x00
#define IDT_FLAG_RING1          0x20
#define IDT_FLAG_RING2          0x40
#define IDT_FLAG_RING3          0x60
#define IDT_FLAG_32BIT          0x0E
#define IDT_FLAG_64BIT          0x0E

/* Interrupt gate types */
#define GATE_TYPE_INTERRUPT     0x8E
#define GATE_TYPE_TRAP          0x8F
#define GATE_TYPE_CALL          0x8C
#define GATE_TYPE_TASK          0x85

/* IDT entry structure */
typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed)) idt_entry_t;

/* IDT pointer structure */
typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idt_pointer_t;

/* Interrupt frame structure */
typedef struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbp;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;
    uint64_t interrupt_number;
    uint64_t error_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
} __attribute__((packed)) interrupt_frame_t;

/* IRQ handler function type */
typedef void (*irq_handler_t)(interrupt_frame_t* frame);

/* Interrupt handler function type */
typedef void (*interrupt_handler_t)(interrupt_frame_t* frame);

/* PIC (Programmable Interrupt Controller) */
typedef struct {
    uint8_t master_command;
    uint8_t master_data;
    uint8_t slave_command;
    uint8_t slave_data;
    uint8_t master_mask;
    uint8_t slave_mask;
} pic_state_t;

/* APIC (Advanced Programmable Interrupt Controller) */
typedef struct {
    uint32_t id;
    uint32_t version;
    uint32_t task_priority;
    uint32_t arbitration_priority;
    uint32_t processor_priority;
    uint32_t eoi;
    uint32_t remote_read;
    uint32_t logical_destination;
    uint32_t destination_format;
    uint32_t spurious_interrupt_vector;
    uint32_t in_service[8];
    uint32_t trigger_mode[8];
    uint32_t interrupt_request[8];
    uint32_t error_status;
    uint32_t lvt_timer;
    uint32_t lvt_thermal;
    uint32_t lvt_performance;
    uint32_t lvt_lint0;
    uint32_t lvt_lint1;
    uint32_t lvt_error;
    uint32_t initial_count;
    uint32_t current_count;
    uint32_t divide_configuration;
} apic_state_t;

/* Interrupt routing */
typedef struct {
    uint8_t irq;
    uint8_t vector;
    uint8_t flags;
    uint8_t destination;
} interrupt_routing_t;

/* Interrupt statistics */
typedef struct {
    uint64_t total_interrupts;
    uint64_t spurious_interrupts;
    uint64_t unhandled_interrupts;
    uint64_t interrupt_counts[256];
    uint64_t interrupt_times[256];
    uint64_t last_interrupt_time;
    uint64_t max_interrupt_time;
    uint64_t min_interrupt_time;
} interrupt_stats_t;

/* Interrupt context */
typedef struct {
    idt_entry_t idt[256];
    idt_pointer_t idt_pointer;
    irq_handler_t irq_handlers[256];
    interrupt_handler_t interrupt_handlers[32];
    pic_state_t pic_state;
    apic_state_t apic_state;
    interrupt_routing_t routing[256];
    interrupt_stats_t stats;
    bool apic_enabled;
    bool pic_enabled;
    uint8_t current_irq;
    uint8_t current_vector;
    uint64_t interrupt_stack;
    uint64_t interrupt_stack_top;
    uint64_t interrupt_stack_size;
} interrupt_context_t;

/* Function prototypes */
void interrupt_init(void);
void interrupt_init_idt(void);
void interrupt_init_pic(void);
void interrupt_init_apic(void);
void interrupt_enable(void);
void interrupt_disable(void);
void interrupt_enable_irq(uint8_t irq);
void interrupt_disable_irq(uint8_t irq);
void interrupt_register_handler(uint8_t vector, interrupt_handler_t handler);
void interrupt_register_irq_handler(uint8_t irq, irq_handler_t handler);
void interrupt_unregister_handler(uint8_t vector);
void interrupt_unregister_irq_handler(uint8_t irq);
void interrupt_acknowledge(uint8_t irq);
void interrupt_eoi(uint8_t vector);
void interrupt_set_mask(uint16_t mask);
uint16_t interrupt_get_mask(void);
void interrupt_route_irq(uint8_t irq, uint8_t vector, uint8_t destination);
void interrupt_spurious_handler(interrupt_frame_t* frame);
void interrupt_default_handler(interrupt_frame_t* frame);
void interrupt_page_fault_handler(interrupt_frame_t* frame);
void interrupt_general_protection_handler(interrupt_frame_t* frame);
void interrupt_double_fault_handler(interrupt_frame_t* frame);
void interrupt_stack_fault_handler(interrupt_frame_t* frame);
void interrupt_debug_handler(interrupt_frame_t* frame);
void interrupt_nmi_handler(interrupt_frame_t* frame);
void interrupt_machine_check_handler(interrupt_frame_t* frame);

/* IDT management */
void idt_set_entry(uint8_t vector, uint64_t offset, uint16_t selector, uint8_t type);
void idt_clear_entry(uint8_t vector);
void idt_load(void);
void idt_enable(void);
void idt_disable(void);

/* PIC management */
void pic_init(void);
void pic_remap(uint8_t master_offset, uint8_t slave_offset);
void pic_mask_irq(uint8_t irq);
void pic_unmask_irq(uint8_t irq);
void pic_send_eoi(uint8_t irq);
void pic_disable(void);

/* APIC management */
void apic_init(void);
void apic_enable(void);
void apic_disable(void);
void apic_send_eoi(void);
void apic_set_timer(uint32_t count);
uint32_t apic_get_timer(void);
void apic_timer_handler(interrupt_frame_t* frame);
void apic_spurious_handler(interrupt_frame_t* frame);
bool apic_is_enabled(void);
uint32_t apic_read(uint32_t reg);
void apic_write(uint32_t reg, uint32_t value);

/* Interrupt routing */
void interrupt_set_routing(uint8_t irq, uint8_t vector, uint8_t destination, uint8_t flags);
interrupt_routing_t* interrupt_get_routing(uint8_t irq);
void interrupt_init_routing(void);

/* Advanced features */
void interrupt_init_ioapic(void);
void interrupt_init_msi(void);
void interrupt_init_msix(void);
void interrupt_init_priority(void);
void interrupt_init_affinity(void);
void interrupt_balance_load(void);
void interrupt_monitor_performance(void);
void interrupt_dump_stats(void);
void interrupt_save_context(interrupt_frame_t* frame);
void interrupt_restore_context(interrupt_frame_t* frame);

/* Pentesting specific features */
void interrupt_inject_fault(uint8_t vector);
void interrupt_trigger_spurious(void);
void interrupt_test_handlers(void);
void interrupt_fuzz_vectors(void);
void interrupt_capture_state(void);
void interrupt_analyze_patterns(void);
void interrupt_detect_anomalies(void);
void interrupt_log_events(void);

/* Security features */
void interrupt_enable_security(void);
void interrupt_disable_security(void);
bool interrupt_check_stack_integrity(void);
bool interrupt_validate_frame(interrupt_frame_t* frame);
void interrupt_sanitize_frame(interrupt_frame_t* frame);
void interrupt_detect_overflow(interrupt_frame_t* frame);
void interrupt_check_privilege(interrupt_frame_t* frame);
void interrupt_audit_handlers(void);

/* Global variables */
extern interrupt_context_t* global_interrupt_context;
extern volatile uint64_t interrupt_count;
extern volatile bool interrupts_enabled;

/* Assembly functions */
extern void interrupt_handler_0(void);
extern void interrupt_handler_1(void);
extern void interrupt_handler_2(void);
extern void interrupt_handler_3(void);
extern void interrupt_handler_4(void);
extern void interrupt_handler_5(void);
extern void interrupt_handler_6(void);
extern void interrupt_handler_7(void);
extern void interrupt_handler_8(void);
extern void interrupt_handler_9(void);
extern void interrupt_handler_10(void);
extern void interrupt_handler_11(void);
extern void interrupt_handler_12(void);
extern void interrupt_handler_13(void);
extern void interrupt_handler_14(void);
extern void interrupt_handler_15(void);
extern void interrupt_handler_16(void);
extern void interrupt_handler_17(void);
extern void interrupt_handler_18(void);
extern void interrupt_handler_19(void);
extern void interrupt_handler_20(void);
extern void interrupt_handler_21(void);
extern void interrupt_handler_22(void);
extern void interrupt_handler_23(void);
extern void interrupt_handler_24(void);
extern void interrupt_handler_25(void);
extern void interrupt_handler_26(void);
extern void interrupt_handler_27(void);
extern void interrupt_handler_28(void);
extern void interrupt_handler_29(void);
extern void interrupt_handler_30(void);
extern void interrupt_handler_31(void);

extern void irq_handler_32(void);
extern void irq_handler_33(void);
extern void irq_handler_34(void);
extern void irq_handler_35(void);
extern void irq_handler_36(void);
extern void irq_handler_37(void);
extern void irq_handler_38(void);
extern void irq_handler_39(void);
extern void irq_handler_40(void);
extern void irq_handler_41(void);
extern void irq_handler_42(void);
extern void irq_handler_43(void);
extern void irq_handler_44(void);
extern void irq_handler_45(void);
extern void irq_handler_46(void);
extern void irq_handler_47(void);
extern void irq_handler_48(void);

/* I/O port access */
static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t value;
    __asm__ volatile ("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline uint32_t inl(uint16_t port) {
    uint32_t value;
    __asm__ volatile ("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile ("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile ("outl %0, %1" : : "a"(value), "Nd"(port));
}

#endif /* INTERRUPT_H */