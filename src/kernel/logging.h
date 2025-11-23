#ifndef LOGGING_H
#define LOGGING_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* Log levels */
typedef enum {
    LOG_FATAL = 0,    /* System is unusable */
    LOG_ERROR = 1,    /* Error conditions */
    LOG_WARNING = 2,  /* Warning conditions */
    LOG_INFO = 3,     /* Informational messages */
    LOG_DEBUG = 4,    /* Debug-level messages */
    LOG_TRACE = 5     /* Trace-level messages */
} log_level_t;

/* Log output options */
typedef enum {
    LOG_OUTPUT_CONSOLE = 0,
    LOG_OUTPUT_FILE = 1,
    LOG_OUTPUT_TIMESTAMP = 2,
    LOG_OUTPUT_COLOR = 3,
    LOG_OUTPUT_COMPONENT = 4
} log_output_t;

/* Log callback function type */
typedef void (*log_callback_t)(const char* message, void* data);

/* Log statistics */
typedef struct {
    log_level_t current_level;
    bool console_output;
    bool file_output;
    bool timestamp_output;
    bool color_output;
    bool component_output;
    uint32_t current_log_size;
    uint32_t max_log_size;
    uint32_t log_rotation_count;
} log_statistics_t;

/* Log configuration */
typedef struct {
    log_level_t current_level;
    bool console_output;
    bool file_output;
    bool timestamp_output;
    bool color_output;
    bool component_output;
    char log_file[256];
    uint32_t max_log_size;
    uint32_t log_rotation_count;
} log_config_t;

/* Initialize logging system */
void log_init(void);

/* Shutdown logging system */
void log_shutdown(void);

/* Set log level */
void log_set_level(log_level_t level);

/* Get log level */
log_level_t log_get_level(void);

/* Enable/disable log output */
void log_enable_output(log_output_t output, bool enable);

/* Set log file */
void log_set_file(const char* filename);

/* Set custom log callback */
void log_set_callback(log_callback_t callback, void* data);

/* Flush log buffer */
void log_flush(void);

/* Main logging function */
void kernel_log(log_level_t level, const char* component, const char* format, ...);

/* Convenience functions for different log levels */
void kernel_fatal(const char* component, const char* format, ...);
void kernel_error(const char* component, const char* format, ...);
void kernel_warning(const char* component, const char* format, ...);
void kernel_info(const char* component, const char* format, ...);
void kernel_debug(const char* component, const char* format, ...);
void kernel_trace(const char* component, const char* format, ...);

/* Log statistics */
void log_get_statistics(log_statistics_t* stats);

/* Log configuration */
void log_get_config(log_config_t* config);
void log_set_config(const log_config_t* config);

/* Log rotation */
void log_rotate(void);

/* Clear log */
void log_clear(void);

/* Emergency log function (works even if system is in bad state) */
void kernel_emergency_log(const char* format, ...);

/* Panic log function */
void kernel_panic_log(const char* format, ...);

/* Convenience macros */
#define LOG_INIT() log_init()
#define LOG_SHUTDOWN() log_shutdown()
#define LOG_SET_LEVEL(level) log_set_level(level)
#define LOG_GET_LEVEL() log_get_level()
#define LOG_ENABLE_OUTPUT(output, enable) log_enable_output(output, enable)
#define LOG_SET_FILE(filename) log_set_file(filename)
#define LOG_SET_CALLBACK(callback, data) log_set_callback(callback, data)
#define LOG_FLUSH() log_flush()

/* Log level macros */
#define LOG_FATAL(component, format, ...) \
    kernel_fatal(component, format, ##__VA_ARGS__)
#define LOG_ERROR(component, format, ...) \
    kernel_error(component, format, ##__VA_ARGS__)
#define LOG_WARNING(component, format, ...) \
    kernel_warning(component, format, ##__VA_ARGS__)
#define LOG_INFO(component, format, ...) \
    kernel_info(component, format, ##__VA_ARGS__)
#define LOG_DEBUG(component, format, ...) \
    kernel_debug(component, format, ##__VA_ARGS__)
#define LOG_TRACE(component, format, ...) \
    kernel_trace(component, format, ##__VA_ARGS__)

/* Component-specific log macros */
#define KERNEL_LOG(level, format, ...) \
    kernel_log(level, "Kernel", format, ##__VA_ARGS__)
#define MEMORY_LOG(level, format, ...) \
    kernel_log(level, "Memory", format, ##__VA_ARGS__)
#define INTERRUPT_LOG(level, format, ...) \
    kernel_log(level, "Interrupt", format, ##__VA_ARGS__)
#define SYSCALL_LOG(level, format, ...) \
    kernel_log(level, "Syscall", format, ##__VA_ARGS__)
#define DRIVER_LOG(level, format, ...) \
    kernel_log(level, "Driver", format, ##__VA_ARGS__)
#define NETWORK_LOG(level, format, ...) \
    kernel_log(level, "Network", format, ##__VA_ARGS__)
#define SECURITY_LOG(level, format, ...) \
    kernel_log(level, "Security", format, ##__VA_ARGS__)
#define FORENSICS_LOG(level, format, ...) \
    kernel_log(level, "Forensics", format, ##__VA_ARGS__)
#define BOOT_LOG(level, format, ...) \
    kernel_log(level, "Boot", format, ##__VA_ARGS__)
#define TEST_LOG(level, format, ...) \
    kernel_log(level, "Test", format, ##__VA_ARGS__)

/* Emergency and panic macros */
#define EMERGENCY_LOG(format, ...) \
    kernel_emergency_log(format, ##__VA_ARGS__)
#define PANIC_LOG(format, ...) \
    kernel_panic_log(format, ##__VA_ARGS__)

/* Log statistics macros */
#define LOG_GET_STATISTICS(stats) log_get_statistics(stats)
#define LOG_GET_CONFIG(config) log_get_config(config)
#define LOG_SET_CONFIG(config) log_set_config(config)
#define LOG_ROTATE() log_rotate()
#define LOG_CLEAR() log_clear()

/* Helper functions that need to be implemented elsewhere */
void disable_interrupts(void);
void enable_interrupts(void);
void halt(void);
int snprintf(char* str, size_t size, const char* format, ...);
int vsnprintf(char* str, size_t size, const char* format, va_list args);
size_t strlen(const char* str);
char* strcpy(char* dest, const char* src);
void vga_vprintf(const char* format, va_list args);

#endif /* LOGGING_H */