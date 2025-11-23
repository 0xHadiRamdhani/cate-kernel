#include "debug.h"
#include "memory.h"
#include "string.h"
#include "logging.h"
#include "../drivers/vga.h"

/* Debug levels */
typedef enum {
    DEBUG_LEVEL_NONE = 0,
    DEBUG_LEVEL_ERROR = 1,
    DEBUG_LEVEL_WARNING = 2,
    DEBUG_LEVEL_INFO = 3,
    DEBUG_LEVEL_DEBUG = 4,
    DEBUG_LEVEL_TRACE = 5
} debug_level_t;

/* Debug flags */
typedef struct {
    bool enabled;
    debug_level_t level;
    bool memory_debug;
    bool interrupt_debug;
    bool syscall_debug;
    bool driver_debug;
    bool network_debug;
    bool forensics_debug;
    bool security_debug;
    bool performance_debug;
    bool kernel_debug;
    bool boot_debug;
    bool test_debug;
    bool verbose_output;
    bool color_output;
    bool timestamp_output;
    bool file_output;
    bool console_output;
    uint32_t max_log_size;
    uint32_t max_backtrace_depth;
    char log_filename[256];
} debug_config_t;

/* Global debug configuration */
static debug_config_t debug_config = {
    .enabled = true,
    .level = DEBUG_LEVEL_INFO,
    .memory_debug = true,
    .interrupt_debug = true,
    .syscall_debug = true,
    .driver_debug = true,
    .network_debug = true,
    .forensics_debug = true,
    .security_debug = true,
    .performance_debug = true,
    .kernel_debug = true,
    .boot_debug = true,
    .test_debug = true,
    .verbose_output = true,
    .color_output = true,
    .timestamp_output = true,
    .file_output = false,
    .console_output = true,
    .max_log_size = 1048576, /* 1MB */
    .max_backtrace_depth = 32,
    .log_filename = "debug.log"
};

/* Debug buffer for temporary storage */
static char debug_buffer[4096];
static uint32_t debug_buffer_pos = 0;

/* Stack trace structure */
typedef struct {
    uint64_t rbp;
    uint64_t rip;
    uint64_t rsp;
    const char* function_name;
    const char* file_name;
    uint32_t line_number;
} stack_frame_t;

/* Initialize debug subsystem */
void debug_init(void) {
    kernel_log(LOG_INFO, "Debug", "Initializing debug subsystem");
    
    /* Initialize debug configuration */
    debug_config.enabled = true;
    debug_config.level = DEBUG_LEVEL_INFO;
    
    /* Clear debug buffer */
    memset(debug_buffer, 0, sizeof(debug_buffer));
    debug_buffer_pos = 0;
    
    kernel_log(LOG_INFO, "Debug", "Debug subsystem initialized");
    kernel_log(LOG_INFO, "Debug", "Debug level: %d", debug_config.level);
    kernel_log(LOG_INFO, "Debug", "Max backtrace depth: %u", debug_config.max_backtrace_depth);
}

/* Shutdown debug subsystem */
void debug_shutdown(void) {
    kernel_log(LOG_INFO, "Debug", "Shutting down debug subsystem");
    
    /* Flush any remaining debug output */
    if (debug_buffer_pos > 0) {
        debug_flush();
    }
    
    debug_config.enabled = false;
    
    kernel_log(LOG_INFO, "Debug", "Debug subsystem shutdown");
}

/* Check if debug is enabled */
bool debug_is_enabled(void) {
    return debug_config.enabled;
}

/* Set debug level */
void debug_set_level(debug_level_t level) {
    debug_config.level = level;
    kernel_log(LOG_INFO, "Debug", "Debug level set to: %d", level);
}

/* Get debug level */
debug_level_t debug_get_level(void) {
    return debug_config.level;
}

/* Enable/disable debug categories */
void debug_enable_category(debug_category_t category, bool enable) {
    switch (category) {
        case DEBUG_CATEGORY_MEMORY:
            debug_config.memory_debug = enable;
            break;
        case DEBUG_CATEGORY_INTERRUPT:
            debug_config.interrupt_debug = enable;
            break;
        case DEBUG_CATEGORY_SYSCALL:
            debug_config.syscall_debug = enable;
            break;
        case DEBUG_CATEGORY_DRIVER:
            debug_config.driver_debug = enable;
            break;
        case DEBUG_CATEGORY_NETWORK:
            debug_config.network_debug = enable;
            break;
        case DEBUG_CATEGORY_FORENSICS:
            debug_config.forensics_debug = enable;
            break;
        case DEBUG_CATEGORY_SECURITY:
            debug_config.security_debug = enable;
            break;
        case DEBUG_CATEGORY_PERFORMANCE:
            debug_config.performance_debug = enable;
            break;
        case DEBUG_CATEGORY_KERNEL:
            debug_config.kernel_debug = enable;
            break;
        case DEBUG_CATEGORY_BOOT:
            debug_config.boot_debug = enable;
            break;
        case DEBUG_CATEGORY_TEST:
            debug_config.test_debug = enable;
            break;
        default:
            kernel_log(LOG_WARNING, "Debug", "Unknown debug category: %d", category);
            break;
    }
    
    kernel_log(LOG_INFO, "Debug", "Debug category %d %s", category, enable ? "enabled" : "disabled");
}

/* Check if debug category is enabled */
bool debug_is_category_enabled(debug_category_t category) {
    switch (category) {
        case DEBUG_CATEGORY_MEMORY:
            return debug_config.memory_debug;
        case DEBUG_CATEGORY_INTERRUPT:
            return debug_config.interrupt_debug;
        case DEBUG_CATEGORY_SYSCALL:
            return debug_config.syscall_debug;
        case DEBUG_CATEGORY_DRIVER:
            return debug_config.driver_debug;
        case DEBUG_CATEGORY_NETWORK:
            return debug_config.network_debug;
        case DEBUG_CATEGORY_FORENSICS:
            return debug_config.forensics_debug;
        case DEBUG_CATEGORY_SECURITY:
            return debug_config.security_debug;
        case DEBUG_CATEGORY_PERFORMANCE:
            return debug_config.performance_debug;
        case DEBUG_CATEGORY_KERNEL:
            return debug_config.kernel_debug;
        case DEBUG_CATEGORY_BOOT:
            return debug_config.boot_debug;
        case DEBUG_CATEGORY_TEST:
            return debug_config.test_debug;
        default:
            return false;
    }
}

/* Format debug message */
static void format_debug_message(debug_level_t level, debug_category_t category, const char* format, va_list args) {
    /* Check if debug is enabled and level is appropriate */
    if (!debug_config.enabled || level > debug_config.level) {
        return;
    }
    
    /* Check if category is enabled */
    if (!debug_is_category_enabled(category)) {
        return;
    }
    
    /* Clear buffer */
    debug_buffer_pos = 0;
    
    /* Add timestamp if enabled */
    if (debug_config.timestamp_output) {
        uint64_t timestamp = get_current_time();
        debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                    sizeof(debug_buffer) - debug_buffer_pos,
                                    "[%llu] ", timestamp);
    }
    
    /* Add category prefix */
    const char* category_str = "";
    switch (category) {
        case DEBUG_CATEGORY_MEMORY:
            category_str = "[MEMORY] ";
            break;
        case DEBUG_CATEGORY_INTERRUPT:
            category_str = "[INTERRUPT] ";
            break;
        case DEBUG_CATEGORY_SYSCALL:
            category_str = "[SYSCALL] ";
            break;
        case DEBUG_CATEGORY_DRIVER:
            category_str = "[DRIVER] ";
            break;
        case DEBUG_CATEGORY_NETWORK:
            category_str = "[NETWORK] ";
            break;
        case DEBUG_CATEGORY_FORENSICS:
            category_str = "[FORENSICS] ";
            break;
        case DEBUG_CATEGORY_SECURITY:
            category_str = "[SECURITY] ";
            break;
        case DEBUG_CATEGORY_PERFORMANCE:
            category_str = "[PERFORMANCE] ";
            break;
        case DEBUG_CATEGORY_KERNEL:
            category_str = "[KERNEL] ";
            break;
        case DEBUG_CATEGORY_BOOT:
            category_str = "[BOOT] ";
            break;
        case DEBUG_CATEGORY_TEST:
            category_str = "[TEST] ";
            break;
        default:
            category_str = "[UNKNOWN] ";
            break;
    }
    
    debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                sizeof(debug_buffer) - debug_buffer_pos,
                                "%s", category_str);
    
    /* Add level prefix with color */
    if (debug_config.color_output) {
        switch (level) {
            case DEBUG_LEVEL_ERROR:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "\033[31m[ERROR]\033[0m ");
                break;
            case DEBUG_LEVEL_WARNING:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "\033[33m[WARNING]\033[0m ");
                break;
            case DEBUG_LEVEL_INFO:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "\033[32m[INFO]\033[0m ");
                break;
            case DEBUG_LEVEL_DEBUG:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "\033[36m[DEBUG]\033[0m ");
                break;
            case DEBUG_LEVEL_TRACE:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "\033[35m[TRACE]\033[0m ");
                break;
            default:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "[UNKNOWN] ");
                break;
        }
    } else {
        switch (level) {
            case DEBUG_LEVEL_ERROR:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "[ERROR] ");
                break;
            case DEBUG_LEVEL_WARNING:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "[WARNING] ");
                break;
            case DEBUG_LEVEL_INFO:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "[INFO] ");
                break;
            case DEBUG_LEVEL_DEBUG:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "[DEBUG] ");
                break;
            case DEBUG_LEVEL_TRACE:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "[TRACE] ");
                break;
            default:
                debug_buffer_pos += snprintf(debug_buffer + debug_buffer_pos, 
                                            sizeof(debug_buffer) - debug_buffer_pos,
                                            "[UNKNOWN] ");
                break;
        }
    }
    
    /* Add formatted message */
    va_list args_copy;
    va_copy(args_copy, args);
    debug_buffer_pos += vsnprintf(debug_buffer + debug_buffer_pos, 
                                 sizeof(debug_buffer) - debug_buffer_pos,
                                 format, args_copy);
    va_end(args_copy);
    
    /* Ensure null termination */
    if (debug_buffer_pos >= sizeof(debug_buffer) - 1) {
        debug_buffer_pos = sizeof(debug_buffer) - 1;
    }
    debug_buffer[debug_buffer_pos] = '\0';
}

/* Output debug message */
static void output_debug_message(void) {
    /* Output to console if enabled */
    if (debug_config.console_output) {
        vga_printf("%s\n", debug_buffer);
    }
    
    /* Output to file if enabled */
    if (debug_config.file_output) {
        /* This would write to a debug log file */
        /* Implementation depends on file system support */
    }
}

/* Flush debug buffer */
void debug_flush(void) {
    if (debug_buffer_pos > 0) {
        output_debug_message();
        debug_buffer_pos = 0;
    }
}

/* Debug print functions */
void debug_print(debug_level_t level, debug_category_t category, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_debug_message(level, category, format, args);
    output_debug_message();
    
    va_end(args);
}

/* Memory debug functions */
void debug_memory_alloc(void* ptr, size_t size, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_MEMORY)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_MEMORY, 
               "Memory allocated: ptr=%p, size=%zu at %s:%u in %s()", 
               ptr, size, file, line, function);
}

void debug_memory_free(void* ptr, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_MEMORY)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_MEMORY, 
               "Memory freed: ptr=%p at %s:%u in %s()", 
               ptr, file, line, function);
}

void debug_memory_leak(void* ptr, size_t size, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_MEMORY)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_WARNING, DEBUG_CATEGORY_MEMORY, 
               "Memory leak detected: ptr=%p, size=%zu at %s:%u in %s()", 
               ptr, size, file, line, function);
}

/* Interrupt debug functions */
void debug_interrupt(uint8_t interrupt_num, uint64_t rip, uint64_t rsp, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_INTERRUPT)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_INTERRUPT, 
               "Interrupt %u triggered: RIP=0x%llX, RSP=0x%llX at %s:%u in %s()", 
               interrupt_num, rip, rsp, file, line, function);
}

void debug_exception(uint8_t exception_num, uint64_t error_code, uint64_t rip, uint64_t rsp, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_INTERRUPT)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_ERROR, DEBUG_CATEGORY_INTERRUPT, 
               "Exception %u (error=0x%llX): RIP=0x%llX, RSP=0x%llX at %s:%u in %s()", 
               exception_num, error_code, rip, rsp, file, line, function);
}

/* System call debug functions */
void debug_syscall(uint64_t syscall_num, uint64_t arg1, uint64_t arg2, uint64_t arg3, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_SYSCALL)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_SYSCALL, 
               "System call %llu: args=(0x%llX, 0x%llX, 0x%llX) at %s:%u in %s()", 
               syscall_num, arg1, arg2, arg3, file, line, function);
}

/* Driver debug functions */
void debug_driver_init(const char* driver_name, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_DRIVER)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_DRIVER, 
               "Driver initialized: %s at %s:%u in %s()", 
               driver_name, file, line, function);
}

void debug_driver_error(const char* driver_name, const char* error_msg, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_DRIVER)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_ERROR, DEBUG_CATEGORY_DRIVER, 
               "Driver error in %s: %s at %s:%u in %s()", 
               driver_name, error_msg, file, line, function);
}

/* Network debug functions */
void debug_network_packet(const uint8_t* packet, size_t size, const char* direction, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_NETWORK)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_NETWORK, 
               "Network packet %s: size=%zu at %s:%u in %s()", 
               direction, size, file, line, function);
    
    /* Print packet hex dump if verbose */
    if (debug_config.verbose_output && size <= 64) {
        debug_hex_dump(packet, size, 16);
    }
}

void debug_network_connection(const char* src_ip, uint16_t src_port, const char* dest_ip, uint16_t dest_port, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_NETWORK)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_NETWORK, 
               "Network connection: %s:%u -> %s:%u at %s:%u in %s()", 
               src_ip, src_port, dest_ip, dest_port, file, line, function);
}

/* Forensics debug functions */
void debug_forensics_analysis(const char* tool_name, const char* evidence_id, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_FORENSICS)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_FORENSICS, 
               "Forensics analysis: tool=%s, evidence=%s at %s:%u in %s()", 
               tool_name, evidence_id, file, line, function);
}

void debug_forensics_evidence(const char* evidence_type, const char* evidence_id, size_t size, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_FORENSICS)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_FORENSICS, 
               "Forensics evidence: type=%s, id=%s, size=%zu at %s:%u in %s()", 
               evidence_type, evidence_id, size, file, line, function);
}

/* Security debug functions */
void debug_security_violation(const char* violation_type, const char* details, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_SECURITY)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_ERROR, DEBUG_CATEGORY_SECURITY, 
               "Security violation: type=%s, details=%s at %s:%u in %s()", 
               violation_type, details, file, line, function);
}

void debug_security_check(const char* check_type, bool passed, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_SECURITY)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_SECURITY, 
               "Security check: type=%s, result=%s at %s:%u in %s()", 
               check_type, passed ? "PASSED" : "FAILED", file, line, function);
}

/* Performance debug functions */
void debug_performance_start(const char* operation, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_PERFORMANCE)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_PERFORMANCE, 
               "Performance start: operation=%s at %s:%u in %s()", 
               operation, file, line, function);
}

void debug_performance_end(const char* operation, uint64_t duration, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_PERFORMANCE)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_DEBUG, DEBUG_CATEGORY_PERFORMANCE, 
               "Performance end: operation=%s, duration=%llu ms at %s:%u in %s()", 
               operation, duration, file, line, function);
}

/* Kernel debug functions */
void debug_kernel_init(const char* component, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_KERNEL)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, 
               "Kernel component initialized: %s at %s:%u in %s()", 
               component, file, line, function);
}

void debug_kernel_error(const char* component, const char* error_msg, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_KERNEL)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_ERROR, DEBUG_CATEGORY_KERNEL, 
               "Kernel error in %s: %s at %s:%u in %s()", 
               component, error_msg, file, line, function);
}

/* Boot debug functions */
void debug_boot_stage(const char* stage, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_BOOT)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_BOOT, 
               "Boot stage: %s at %s:%u in %s()", 
               stage, file, line, function);
}

void debug_boot_error(const char* stage, const char* error_msg, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_BOOT)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_ERROR, DEBUG_CATEGORY_BOOT, 
               "Boot error in %s: %s at %s:%u in %s()", 
               stage, error_msg, file, line, function);
}

/* Test debug functions */
void debug_test_start(const char* test_name, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_TEST)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_TEST, 
               "Test started: %s at %s:%u in %s()", 
               test_name, file, line, function);
}

void debug_test_end(const char* test_name, const char* result, const char* function, const char* file, uint32_t line) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_TEST)) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_TEST, 
               "Test completed: %s, result=%s at %s:%u in %s()", 
               test_name, result, file, line, function);
}

/* Hex dump function */
void debug_hex_dump(const void* data, size_t size, size_t bytes_per_line) {
    if (data == NULL || size == 0) {
        return;
    }
    
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0;
    
    while (offset < size) {
        /* Print offset */
        vga_printf("%08zX: ", offset);
        
        /* Print hex bytes */
        for (size_t i = 0; i < bytes_per_line && offset + i < size; i++) {
            vga_printf("%02X ", bytes[offset + i]);
        }
        
        /* Print padding if needed */
        for (size_t i = size - offset; i < bytes_per_line; i++) {
            vga_printf("   ");
        }
        
        vga_printf(" |");
        
        /* Print ASCII representation */
        for (size_t i = 0; i < bytes_per_line && offset + i < size; i++) {
            uint8_t byte = bytes[offset + i];
            if (byte >= 32 && byte <= 126) {
                vga_printf("%c", byte);
            } else {
                vga_printf(".");
            }
        }
        
        vga_printf("|\n");
        
        offset += bytes_per_line;
    }
}

/* Stack trace function */
void debug_stack_trace(void) {
    if (!debug_config.enabled) {
        return;
    }
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, "Stack trace:");
    
    /* Get current stack pointer */
    uint64_t rbp, rip;
    asm volatile("mov %%rbp, %0" : "=r"(rbp));
    
    /* Walk the stack */
    uint32_t frame_count = 0;
    while (rbp != 0 && frame_count < debug_config.max_backtrace_depth) {
        /* Get return address */
        rip = *(uint64_t*)(rbp + 8);
        
        if (rip == 0) {
            break;
        }
        
        /* Print frame information */
        debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, 
                   "  Frame %u: RIP=0x%llX, RBP=0x%llX", 
                   frame_count, rip, rbp);
        
        /* Move to next frame */
        rbp = *(uint64_t*)rbp;
        frame_count++;
    }
}

/* Memory statistics */
void debug_memory_stats(void) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_MEMORY)) {
        return;
    }
    
    uint64_t total_memory = get_total_memory();
    uint64_t free_memory = get_free_memory();
    uint64_t used_memory = total_memory - free_memory;
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_MEMORY, 
               "Memory statistics: total=%llu KB, free=%llu KB, used=%llu KB", 
               total_memory / 1024, free_memory / 1024, used_memory / 1024);
}

/* Performance statistics */
void debug_performance_stats(void) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_PERFORMANCE)) {
        return;
    }
    
    uint64_t cpu_usage = get_cpu_usage();
    uint64_t uptime = get_uptime();
    
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_PERFORMANCE, 
               "Performance statistics: CPU=%llu%%, uptime=%llu ms", 
               cpu_usage, uptime);
}

/* System information */
void debug_system_info(void) {
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, "=== SYSTEM INFORMATION ===");
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, "Kernel Version: %s", get_kernel_version());
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, "Build Date: %s", get_build_date());
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, "Architecture: %s", get_architecture());
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, "CPU Count: %u", get_cpu_count());
    debug_print(DEBUG_LEVEL_INFO, DEBUG_CATEGORY_KERNEL, "Memory Size: %llu MB", get_total_memory() / (1024 * 1024));
    
    debug_memory_stats();
    debug_performance_stats();
}

/* Panic function with debug information */
void debug_panic(const char* format, ...) {
    /* Disable interrupts */
    disable_interrupts();
    
    /* Print panic header */
    vga_set_color(VGA_COLOR_RED, VGA_COLOR_BLACK);
    vga_printf("\n\n=== KERNEL PANIC ===\n");
    
    /* Print panic message */
    va_list args;
    va_start(args, format);
    vga_vprintf(format, args);
    va_end(args);
    vga_printf("\n");
    
    /* Print debug information */
    debug_print(DEBUG_LEVEL_ERROR, DEBUG_CATEGORY_KERNEL, "Kernel panic occurred");
    
    /* Print stack trace */
    debug_stack_trace();
    
    /* Print memory statistics */
    debug_memory_stats();
    
    /* Print system information */
    debug_system_info();
    
    /* Halt the system */
    vga_printf("\nSystem halted. Press any key to reboot...\n");
    
    /* Wait for key press and reboot */
    wait_for_key();
    reboot_system();
    
    /* Should never reach here */
    while (1) {
        halt();
    }
}

/* Assert function */
void debug_assert(bool condition, const char* expression, const char* function, const char* file, uint32_t line) {
    if (!condition) {
        debug_panic("Assertion failed: %s in %s at %s:%u", expression, function, file, line);
    }
}

/* Memory validation */
bool debug_validate_memory(const void* ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return false;
    }
    
    /* Basic validation - check if pointer is in valid memory range */
    if ((uintptr_t)ptr < 0x1000) { /* Avoid NULL and low memory */
        return false;
    }
    
    /* Check if memory is accessible by trying to read it */
    /* This is a simple check - real implementation would be more sophisticated */
    volatile const uint8_t* bytes = (const uint8_t*)ptr;
    for (size_t i = 0; i < size; i += 4096) { /* Check every page */
        volatile uint8_t byte = bytes[i];
        (void)byte; /* Suppress unused variable warning */
    }
    
    return true;
}

/* Buffer overflow detection */
bool debug_check_buffer_overflow(const void* buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        return false;
    }
    
    /* Check for canary values if implemented */
    /* This would check for buffer overflow canaries */
    /* Implementation depends on specific buffer overflow protection */
    
    return true;
}

/* Memory corruption detection */
bool debug_detect_memory_corruption(void) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_MEMORY)) {
        return true;
    }
    
    /* Check for memory corruption patterns */
    /* This would scan memory for corruption indicators */
    /* Implementation depends on memory management system */
    
    return true;
}

/* Performance monitoring */
void debug_start_performance_monitor(const char* operation) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_PERFORMANCE)) {
        return;
    }
    
    debug_performance_start(operation, __FUNCTION__, __FILE__, __LINE__);
}

void debug_end_performance_monitor(const char* operation) {
    if (!debug_is_category_enabled(DEBUG_CATEGORY_PERFORMANCE)) {
        return;
    }
    
    uint64_t duration = get_current_time() - get_operation_start_time(operation);
    debug_performance_end(operation, duration, __FUNCTION__, __FILE__, __LINE__);
}