#ifndef INTERRUPT_H
#define INTERRUPT_H

#include <stdint.h>
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
#define INT_FLOATING_POINT      16
#define INT_ALIGNMENT_CHECK     17
#define INT_MACHINE_CHECK       18
#define INT_SIMD_FLOATING_POINT 19
#define INT_VIRTUALIZATION      20
#define INT_SECURITY            21
#define INT_MAX                 255

/* IRQ numbers */
#define IRQ_TIMER               0
#define IRQ_KEYBOARD            1
#define IRQ_CASCADE             2
#define IRQ_COM2                3
#define IRQ_COM1                4
#define IRQ_LPT2                5
#define IRQ_FLOPPY              6
#define IRQ_LPT1                7
#define IRQ_RTC                 8
#define IRQ_FREE1               9
#define IRQ_FREE2               10
#define IRQ_FREE3               11
#define IRQ_MOUSE               12
#define IRQ_FPU                 13
#define IRQ_PRIMARY_ATA         14
#define IRQ_SECONDARY_ATA       15
#define IRQ_MAX                 16

/* Interrupt flags */
#define INT_FLAG_PRESENT        0x80
#define INT_FLAG_DPL0           0x00
#define INT_FLAG_DPL1           0x20
#define INT_FLAG_DPL2           0x40
#define INT_FLAG_DPL3           0x60
#define INT_FLAG_STORAGE        0x10
#define INT_FLAG_TYPE_INTERRUPT 0x0E
#define INT_FLAG_TYPE_TRAP      0x0F
#define INT_FLAG_TYPE_TASK      0x05

/* IDT entry structure */
typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed)) idt_entry_t;

/* IDT register structure */
typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idt_register_t;

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

/* Interrupt handler function type */
typedef void (*interrupt_handler_t)(interrupt_frame_t* frame);

/* Interrupt statistics */
typedef struct {
    uint64_t total_interrupts;
    uint64_t exceptions;
    uint64_t hardware_interrupts;
    uint64_t software_interrupts;
    uint64_t spurious_interrupts;
    uint64_t unhandled_interrupts;
    uint64_t interrupt_counts[INT_MAX + 1];
    uint64_t irq_counts[IRQ_MAX + 1];
} interrupt_stats_t;

/* Initialize interrupt handling */
void interrupt_init(void);

/* Shutdown interrupt handling */
void interrupt_shutdown(void);

/* Enable/disable interrupts */
void enable_interrupts(void);
void disable_interrupts(void);

/* Check if interrupts are enabled */
bool interrupts_enabled(void);

/* Register interrupt handler */
bool register_interrupt_handler(uint8_t vector, interrupt_handler_t handler);
bool unregister_interrupt_handler(uint8_t vector);

/* Register IRQ handler */
bool register_irq_handler(uint8_t irq, interrupt_handler_t handler);
bool unregister_irq_handler(uint8_t irq);

/* Send end of interrupt */
void send_eoi(uint8_t irq);

/* Mask/unmask IRQ */
void mask_irq(uint8_t irq);
void unmask_irq(uint8_t irq);
bool is_irq_masked(uint8_t irq);

/* Get interrupt statistics */
void get_interrupt_stats(interrupt_stats_t* stats);
void reset_interrupt_stats(void);

/* Interrupt utilities */
const char* get_interrupt_name(uint8_t vector);
const char* get_irq_name(uint8_t irq);
bool is_valid_interrupt(uint8_t vector);
bool is_valid_irq(uint8_t irq);

/* Interrupt priority */
typedef enum {
    INT_PRIORITY_LOWEST = 0,
    INT_PRIORITY_LOW = 1,
    INT_PRIORITY_NORMAL = 2,
    INT_PRIORITY_HIGH = 3,
    INT_PRIORITY_HIGHEST = 4
} interrupt_priority_t;

void set_interrupt_priority(uint8_t vector, interrupt_priority_t priority);
interrupt_priority_t get_interrupt_priority(uint8_t vector);

/* Interrupt nesting */
void enable_interrupt_nesting(void);
void disable_interrupt_nesting(void);
bool is_interrupt_nesting_enabled(void);

/* Interrupt context */
typedef struct {
    bool in_interrupt;
    uint8_t current_vector;
    uint8_t current_irq;
    uint64_t interrupt_count;
    uint64_t nested_count;
    interrupt_frame_t* current_frame;
} interrupt_context_t;

void get_interrupt_context(interrupt_context_t* context);
bool in_interrupt_context(void);

/* Interrupt safety */
#define IN_INTERRUPT() in_interrupt_context()
#define ASSERT_NOT_IN_INTERRUPT() \
    do { \
        if (IN_INTERRUPT()) { \
            panic("Operation not allowed in interrupt context"); \
        } \
    } while (0)

#define ASSERT_IN_INTERRUPT() \
    do { \
        if (!IN_INTERRUPT()) { \
            panic("Operation must be called in interrupt context"); \
        } \
    } while (0)

/* Interrupt macros */
#define ENABLE_INTERRUPTS() enable_interrupts()
#define DISABLE_INTERRUPTS() disable_interrupts()
#define CLI() disable_interrupts()
#define STI() enable_interrupts()

/* Interrupt flags */
#define IF_FLAG 0x200

/* Check interrupt flag */
static inline bool get_interrupt_flag(void) {
    uint64_t rflags;
    __asm__ __volatile__("pushf; pop %0" : "=r"(rflags));
    return (rflags & IF_FLAG) != 0;
}

/* Save/restore interrupt state */
typedef struct {
    bool interrupts_enabled;
    uint64_t rflags;
} interrupt_state_t;

static inline interrupt_state_t save_interrupt_state(void) {
    interrupt_state_t state;
    state.interrupts_enabled = get_interrupt_flag();
    __asm__ __volatile__("pushf; pop %0" : "=r"(state.rflags));
    return state;
}

static inline void restore_interrupt_state(interrupt_state_t state) {
    if (state.interrupts_enabled) {
        enable_interrupts();
    } else {
        disable_interrupts();
    }
}

/* Critical section */
typedef struct {
    interrupt_state_t saved_state;
    bool active;
} critical_section_t;

static inline void enter_critical_section(critical_section_t* cs) {
    cs->saved_state = save_interrupt_state();
    disable_interrupts();
    cs->active = true;
}

static inline void leave_critical_section(critical_section_t* cs) {
    if (cs->active) {
        restore_interrupt_state(cs->saved_state);
        cs->active = false;
    }
}

/* Interrupt-safe operations */
#define ATOMIC_INC(var) \
    __asm__ __volatile__("lock incq %0" : "+m"(var))

#define ATOMIC_DEC(var) \
    __asm__ __volatile__("lock decq %0" : "+m"(var))

#define ATOMIC_ADD(var, val) \
    __asm__ __volatile__("lock addq %1, %0" : "+m"(var) : "r"(val))

#define ATOMIC_SUB(var, val) \
    __asm__ __volatile__("lock subq %1, %0" : "+m"(var) : "r"(val))

#define ATOMIC_OR(var, val) \
    __asm__ __volatile__("lock orq %1, %0" : "+m"(var) : "r"(val))

#define ATOMIC_AND(var, val) \
    __asm__ __volatile__("lock andq %1, %0" : "+m"(var) : "r"(val))

#define ATOMIC_XOR(var, val) \
    __asm__ __volatile__("lock xorq %1, %0" : "+m"(var) : "r"(val))

/* Memory barriers */
#define MEMORY_BARRIER() __asm__ __volatile__("mfence" ::: "memory")
#define READ_BARRIER() __asm__ __volatile__("lfence" ::: "memory")
#define WRITE_BARRIER() __asm__ __volatile__("sfence" ::: "memory")

/* CPU pause */
#define CPU_PAUSE() __asm__ __volatile__("pause")

/* Interrupt testing */
void test_interrupts(void);
void test_exceptions(void);
void test_irqs(void);
void test_interrupt_handlers(void);

/* Interrupt debugging */
void dump_interrupt_frame(const interrupt_frame_t* frame);
void dump_idt(void);
void dump_interrupt_stats(void);

/* Interrupt configuration */
typedef struct {
    bool enable_exceptions;
    bool enable_irqs;
    bool enable_software_interrupts;
    bool enable_spurious_detection;
    bool enable_nesting;
    bool enable_priority;
    uint32_t spurious_threshold;
    uint32_t nesting_limit;
} interrupt_config_t;

void get_interrupt_config(interrupt_config_t* config);
void set_interrupt_config(const interrupt_config_t* config);

/* Interrupt error handling */
typedef enum {
    INT_ERROR_NONE = 0,
    INT_ERROR_INVALID_VECTOR = 1,
    INT_ERROR_INVALID_IRQ = 2,
    INT_ERROR_HANDLER_NOT_FOUND = 3,
    INT_ERROR_STACK_OVERFLOW = 4,
    INT_ERROR_NESTING_OVERFLOW = 5,
    INT_ERROR_SPURIOUS = 6
} interrupt_error_t;

const char* get_interrupt_error_string(interrupt_error_t error);
void handle_interrupt_error(interrupt_error_t error, uint8_t vector);

/* Interrupt hooks */
typedef void (*interrupt_hook_t)(uint8_t vector, interrupt_frame_t* frame);
bool register_interrupt_hook(interrupt_hook_t hook);
bool unregister_interrupt_hook(interrupt_hook_t hook);

/* Interrupt profiling */
typedef struct {
    uint64_t total_time;
    uint64_t min_time;
    uint64_t max_time;
    uint64_t avg_time;
    uint64_t call_count;
} interrupt_profile_t;

void start_interrupt_profiling(uint8_t vector);
void stop_interrupt_profiling(uint8_t vector);
void get_interrupt_profile(uint8_t vector, interrupt_profile_t* profile);
void reset_interrupt_profile(uint8_t vector);

/* Interrupt tracing */
#ifdef DEBUG
#define INT_TRACE_ENABLED
void enable_interrupt_tracing(void);
void disable_interrupt_tracing(void);
bool is_interrupt_tracing_enabled(void);
void trace_interrupt(uint8_t vector, const interrupt_frame_t* frame);
void dump_interrupt_trace(void);
#endif

#endif /* INTERRUPT_H */