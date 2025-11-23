#ifndef DEBUG_H
#define DEBUG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* Debug categories */
typedef enum {
    DEBUG_CATEGORY_MEMORY = 0,
    DEBUG_CATEGORY_INTERRUPT = 1,
    DEBUG_CATEGORY_SYSCALL = 2,
    DEBUG_CATEGORY_DRIVER = 3,
    DEBUG_CATEGORY_NETWORK = 4,
    DEBUG_CATEGORY_FORENSICS = 5,
    DEBUG_CATEGORY_SECURITY = 6,
    DEBUG_CATEGORY_PERFORMANCE = 7,
    DEBUG_CATEGORY_KERNEL = 8,
    DEBUG_CATEGORY_BOOT = 9,
    DEBUG_CATEGORY_TEST = 10,
    DEBUG_CATEGORY_MAX
} debug_category_t;

/* Debug levels */
typedef enum {
    DEBUG_LEVEL_NONE = 0,
    DEBUG_LEVEL_ERROR = 1,
    DEBUG_LEVEL_WARNING = 2,
    DEBUG_LEVEL_INFO = 3,
    DEBUG_LEVEL_DEBUG = 4,
    DEBUG_LEVEL_TRACE = 5
} debug_level_t;

/* Debug configuration */
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

/* Debug functions */
void debug_init(void);
void debug_shutdown(void);
bool debug_is_enabled(void);
void debug_set_level(debug_level_t level);
debug_level_t debug_get_level(void);
void debug_enable_category(debug_category_t category, bool enable);
bool debug_is_category_enabled(debug_category_t category);
void debug_flush(void);
void debug_print(debug_level_t level, debug_category_t category, const char* format, ...);

/* Memory debug functions */
void debug_memory_alloc(void* ptr, size_t size, const char* function, const char* file, uint32_t line);
void debug_memory_free(void* ptr, const char* function, const char* file, uint32_t line);
void debug_memory_leak(void* ptr, size_t size, const char* function, const char* file, uint32_t line);

/* Interrupt debug functions */
void debug_interrupt(uint8_t interrupt_num, uint64_t rip, uint64_t rsp, const char* function, const char* file, uint32_t line);
void debug_exception(uint8_t exception_num, uint64_t error_code, uint64_t rip, uint64_t rsp, const char* function, const char* file, uint32_t line);

/* System call debug functions */
void debug_syscall(uint64_t syscall_num, uint64_t arg1, uint64_t arg2, uint64_t arg3, const char* function, const char* file, uint32_t line);

/* Driver debug functions */
void debug_driver_init(const char* driver_name, const char* function, const char* file, uint32_t line);
void debug_driver_error(const char* driver_name, const char* error_msg, const char* function, const char* file, uint32_t line);

/* Network debug functions */
void debug_network_packet(const uint8_t* packet, size_t size, const char* direction, const char* function, const char* file, uint32_t line);
void debug_network_connection(const char* src_ip, uint16_t src_port, const char* dest_ip, uint16_t dest_port, const char* function, const char* file, uint32_t line);

/* Forensics debug functions */
void debug_forensics_analysis(const char* tool_name, const char* evidence_id, const char* function, const char* file, uint32_t line);
void debug_forensics_evidence(const char* evidence_type, const char* evidence_id, size_t size, const char* function, const char* file, uint32_t line);

/* Security debug functions */
void debug_security_violation(const char* violation_type, const char* details, const char* function, const char* file, uint32_t line);
void debug_security_check(const char* check_type, bool passed, const char* function, const char* file, uint32_t line);

/* Performance debug functions */
void debug_performance_start(const char* operation, const char* function, const char* file, uint32_t line);
void debug_performance_end(const char* operation, uint64_t duration, const char* function, const char* file, uint32_t line);

/* Kernel debug functions */
void debug_kernel_init(const char* component, const char* function, const char* file, uint32_t line);
void debug_kernel_error(const char* component, const char* error_msg, const char* function, const char* file, uint32_t line);

/* Boot debug functions */
void debug_boot_stage(const char* stage, const char* function, const char* file, uint32_t line);
void debug_boot_error(const char* stage, const char* error_msg, const char* function, const char* file, uint32_t line);

/* Test debug functions */
void debug_test_start(const char* test_name, const char* function, const char* file, uint32_t line);
void debug_test_end(const char* test_name, const char* result, const char* function, const char* file, uint32_t line);

/* Utility debug functions */
void debug_hex_dump(const void* data, size_t size, size_t bytes_per_line);
void debug_stack_trace(void);
void debug_memory_stats(void);
void debug_performance_stats(void);
void debug_system_info(void);

/* Panic and assert functions */
void debug_panic(const char* format, ...);
void debug_assert(bool condition, const char* expression, const char* function, const char* file, uint32_t line);

/* Memory validation functions */
bool debug_validate_memory(const void* ptr, size_t size);
bool debug_check_buffer_overflow(const void* buffer, size_t size);
bool debug_detect_memory_corruption(void);

/* Performance monitoring */
void debug_start_performance_monitor(const char* operation);
void debug_end_performance_monitor(const char* operation);

/* Helper functions that need to be implemented elsewhere */
uint64_t get_current_time(void);
uint64_t get_total_memory(void);
uint64_t get_free_memory(void);
uint64_t get_cpu_usage(void);
uint64_t get_uptime(void);
const char* get_kernel_version(void);
const char* get_build_date(void);
const char* get_architecture(void);
uint32_t get_cpu_count(void);
uint64_t get_operation_start_time(const char* operation);
void disable_interrupts(void);
void enable_interrupts(void);
void wait_for_key(void);
void reboot_system(void);
void halt(void);

/* Convenience macros */
#define DEBUG_INIT() debug_init()
#define DEBUG_SHUTDOWN() debug_shutdown()
#define DEBUG_ENABLED() debug_is_enabled()
#define DEBUG_SET_LEVEL(level) debug_set_level(level)
#define DEBUG_ENABLE_CATEGORY(category, enable) debug_enable_category(category, enable)
#define DEBUG_CATEGORY_ENABLED(category) debug_is_category_enabled(category)

/* Debug print macros */
#define DEBUG_ERROR(category, format, ...) \
    debug_print(DEBUG_LEVEL_ERROR, category, format, ##__VA_ARGS__)
#define DEBUG_WARNING(category, format, ...) \
    debug_print(DEBUG_LEVEL_WARNING, category, format, ##__VA_ARGS__)
#define DEBUG_INFO(category, format, ...) \
    debug_print(DEBUG_LEVEL_INFO, category, format, ##__VA_ARGS__)
#define DEBUG_DEBUG(category, format, ...) \
    debug_print(DEBUG_LEVEL_DEBUG, category, format, ##__VA_ARGS__)
#define DEBUG_TRACE(category, format, ...) \
    debug_print(DEBUG_LEVEL_TRACE, category, format, ##__VA_ARGS__)

/* Memory debug macros */
#define DEBUG_MEMORY_ALLOC(ptr, size) \
    debug_memory_alloc(ptr, size, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_MEMORY_FREE(ptr) \
    debug_memory_free(ptr, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_MEMORY_LEAK(ptr, size) \
    debug_memory_leak(ptr, size, __FUNCTION__, __FILE__, __LINE__)

/* Interrupt debug macros */
#define DEBUG_INTERRUPT(num, rip, rsp) \
    debug_interrupt(num, rip, rsp, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_EXCEPTION(num, error, rip, rsp) \
    debug_exception(num, error, rip, rsp, __FUNCTION__, __FILE__, __LINE__)

/* System call debug macros */
#define DEBUG_SYSCALL(num, arg1, arg2, arg3) \
    debug_syscall(num, arg1, arg2, arg3, __FUNCTION__, __FILE__, __LINE__)

/* Driver debug macros */
#define DEBUG_DRIVER_INIT(name) \
    debug_driver_init(name, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_DRIVER_ERROR(name, msg) \
    debug_driver_error(name, msg, __FUNCTION__, __FILE__, __LINE__)

/* Network debug macros */
#define DEBUG_NETWORK_PACKET(packet, size, direction) \
    debug_network_packet(packet, size, direction, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_NETWORK_CONNECTION(src_ip, src_port, dest_ip, dest_port) \
    debug_network_connection(src_ip, src_port, dest_ip, dest_port, __FUNCTION__, __FILE__, __LINE__)

/* Forensics debug macros */
#define DEBUG_FORENSICS_ANALYSIS(tool, evidence) \
    debug_forensics_analysis(tool, evidence, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_FORENSICS_EVIDENCE(type, id, size) \
    debug_forensics_evidence(type, id, size, __FUNCTION__, __FILE__, __LINE__)

/* Security debug macros */
#define DEBUG_SECURITY_VIOLATION(type, details) \
    debug_security_violation(type, details, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_SECURITY_CHECK(type, passed) \
    debug_security_check(type, passed, __FUNCTION__, __FILE__, __LINE__)

/* Performance debug macros */
#define DEBUG_PERFORMANCE_START(operation) \
    debug_performance_start(operation, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_PERFORMANCE_END(operation, duration) \
    debug_performance_end(operation, duration, __FUNCTION__, __FILE__, __LINE__)

/* Kernel debug macros */
#define DEBUG_KERNEL_INIT(component) \
    debug_kernel_init(component, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_KERNEL_ERROR(component, msg) \
    debug_kernel_error(component, msg, __FUNCTION__, __FILE__, __LINE__)

/* Boot debug macros */
#define DEBUG_BOOT_STAGE(stage) \
    debug_boot_stage(stage, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_BOOT_ERROR(stage, msg) \
    debug_boot_error(stage, msg, __FUNCTION__, __FILE__, __LINE__)

/* Test debug macros */
#define DEBUG_TEST_START(name) \
    debug_test_start(name, __FUNCTION__, __FILE__, __LINE__)
#define DEBUG_TEST_END(name, result) \
    debug_test_end(name, result, __FUNCTION__, __FILE__, __LINE__)

/* Panic and assert macros */
#define PANIC(format, ...) \
    debug_panic(format, ##__VA_ARGS__)
#define ASSERT(condition) \
    debug_assert(condition, #condition, __FUNCTION__, __FILE__, __LINE__)
#define ASSERT_MSG(condition, msg) \
    debug_assert(condition, msg, __FUNCTION__, __FILE__, __LINE__)

/* Memory validation macros */
#define VALIDATE_MEMORY(ptr, size) \
    debug_validate_memory(ptr, size)
#define CHECK_BUFFER_OVERFLOW(buffer, size) \
    debug_check_buffer_overflow(buffer, size)
#define DETECT_MEMORY_CORRUPTION() \
    debug_detect_memory_corruption()

/* Performance monitoring macros */
#define START_PERFORMANCE_MONITOR(operation) \
    debug_start_performance_monitor(operation)
#define END_PERFORMANCE_MONITOR(operation) \
    debug_end_performance_monitor(operation)

/* Debug utility macros */
#define DEBUG_HEX_DUMP(data, size, bytes_per_line) \
    debug_hex_dump(data, size, bytes_per_line)
#define DEBUG_STACK_TRACE() \
    debug_stack_trace()
#define DEBUG_MEMORY_STATS() \
    debug_memory_stats()
#define DEBUG_PERFORMANCE_STATS() \
    debug_performance_stats()
#define DEBUG_SYSTEM_INFO() \
    debug_system_info()

#endif /* DEBUG_H */