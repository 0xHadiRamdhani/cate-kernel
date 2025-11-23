#include "logging.h"
#include "string.h"
#include "../drivers/vga.h"

/* Log levels */
typedef enum {
    LOG_LEVEL_FATAL = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4,
    LOG_LEVEL_TRACE = 5
} log_level_internal_t;

/* Log configuration */
static struct {
    log_level_t current_level;
    bool console_output;
    bool file_output;
    bool timestamp_output;
    bool color_output;
    bool component_output;
    char log_file[256];
    uint32_t max_log_size;
    uint32_t current_log_size;
    uint32_t log_rotation_count;
    log_callback_t custom_callback;
    void* callback_data;
} log_config = {
    .current_level = LOG_INFO,
    .console_output = true,
    .file_output = false,
    .timestamp_output = true,
    .color_output = true,
    .component_output = true,
    .log_file = "kernel.log",
    .max_log_size = 1048576, /* 1MB */
    .current_log_size = 0,
    .log_rotation_count = 5,
    .custom_callback = NULL,
    .callback_data = NULL
};

/* Log buffer for formatting */
static char log_buffer[4096];
static uint32_t log_buffer_pos = 0;

/* Initialize logging system */
void log_init(void) {
    /* Initialize with default configuration */
    log_config.current_level = LOG_INFO;
    log_config.console_output = true;
    log_config.file_output = false;
    log_config.timestamp_output = true;
    log_config.color_output = true;
    log_config.component_output = true;
    strcpy(log_config.log_file, "kernel.log");
    log_config.max_log_size = 1048576;
    log_config.current_log_size = 0;
    log_config.log_rotation_count = 5;
    log_config.custom_callback = NULL;
    log_config.callback_data = NULL;
    
    /* Clear log buffer */
    memset(log_buffer, 0, sizeof(log_buffer));
    log_buffer_pos = 0;
    
    /* Log initialization message */
    kernel_log(LOG_INFO, "Logging", "Logging system initialized");
}

/* Shutdown logging system */
void log_shutdown(void) {
    kernel_log(LOG_INFO, "Logging", "Logging system shutting down");
    
    /* Flush any remaining log output */
    if (log_buffer_pos > 0) {
        log_flush();
    }
    
    /* Reset configuration */
    log_config.current_level = LOG_INFO;
    log_config.console_output = false;
    log_config.file_output = false;
}

/* Set log level */
void log_set_level(log_level_t level) {
    log_config.current_level = level;
    kernel_log(LOG_INFO, "Logging", "Log level set to: %d", level);
}

/* Get log level */
log_level_t log_get_level(void) {
    return log_config.current_level;
}

/* Enable/disable log output */
void log_enable_output(log_output_t output, bool enable) {
    switch (output) {
        case LOG_OUTPUT_CONSOLE:
            log_config.console_output = enable;
            break;
        case LOG_OUTPUT_FILE:
            log_config.file_output = enable;
            break;
        case LOG_OUTPUT_TIMESTAMP:
            log_config.timestamp_output = enable;
            break;
        case LOG_OUTPUT_COLOR:
            log_config.color_output = enable;
            break;
        case LOG_OUTPUT_COMPONENT:
            log_config.component_output = enable;
            break;
        default:
            kernel_log(LOG_WARNING, "Logging", "Unknown log output option: %d", output);
            break;
    }
}

/* Set log file */
void log_set_file(const char* filename) {
    if (filename != NULL && strlen(filename) < sizeof(log_config.log_file)) {
        strcpy(log_config.log_file, filename);
        kernel_log(LOG_INFO, "Logging", "Log file set to: %s", filename);
    }
}

/* Set custom log callback */
void log_set_callback(log_callback_t callback, void* data) {
    log_config.custom_callback = callback;
    log_config.callback_data = data;
    kernel_log(LOG_INFO, "Logging", "Custom log callback set");
}

/* Get current timestamp */
static uint64_t get_timestamp(void) {
    /* This would get the current system time */
    /* For now, return a simple counter */
    static uint64_t timestamp = 0;
    return ++timestamp;
}

/* Format log message */
static void format_log_message(log_level_t level, const char* component, const char* format, va_list args) {
    /* Check if log level is enabled */
    if (level > log_config.current_level) {
        return;
    }
    
    /* Clear buffer */
    log_buffer_pos = 0;
    
    /* Add timestamp if enabled */
    if (log_config.timestamp_output) {
        uint64_t timestamp = get_timestamp();
        log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                  sizeof(log_buffer) - log_buffer_pos,
                                  "[%llu] ", timestamp);
    }
    
    /* Add log level with color */
    if (log_config.color_output) {
        switch (level) {
            case LOG_FATAL:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "\033[31m[FATAL]\033[0m ");
                break;
            case LOG_ERROR:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "\033[31m[ERROR]\033[0m ");
                break;
            case LOG_WARNING:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "\033[33m[WARNING]\033[0m ");
                break;
            case LOG_INFO:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "\033[32m[INFO]\033[0m ");
                break;
            case LOG_DEBUG:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "\033[36m[DEBUG]\033[0m ");
                break;
            case LOG_TRACE:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "\033[35m[TRACE]\033[0m ");
                break;
            default:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[UNKNOWN] ");
                break;
        }
    } else {
        switch (level) {
            case LOG_FATAL:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[FATAL] ");
                break;
            case LOG_ERROR:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[ERROR] ");
                break;
            case LOG_WARNING:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[WARNING] ");
                break;
            case LOG_INFO:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[INFO] ");
                break;
            case LOG_DEBUG:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[DEBUG] ");
                break;
            case LOG_TRACE:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[TRACE] ");
                break;
            default:
                log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                          sizeof(log_buffer) - log_buffer_pos,
                                          "[UNKNOWN] ");
                break;
        }
    }
    
    /* Add component if enabled */
    if (log_config.component_output && component != NULL) {
        log_buffer_pos += snprintf(log_buffer + log_buffer_pos, 
                                  sizeof(log_buffer) - log_buffer_pos,
                                  "[%s] ", component);
    }
    
    /* Add formatted message */
    va_list args_copy;
    va_copy(args_copy, args);
    log_buffer_pos += vsnprintf(log_buffer + log_buffer_pos, 
                               sizeof(log_buffer) - log_buffer_pos,
                               format, args_copy);
    va_end(args_copy);
    
    /* Ensure null termination */
    if (log_buffer_pos >= sizeof(log_buffer) - 1) {
        log_buffer_pos = sizeof(log_buffer) - 1;
    }
    log_buffer[log_buffer_pos] = '\0';
}

/* Output log message */
static void output_log_message(void) {
    /* Call custom callback if set */
    if (log_config.custom_callback != NULL) {
        log_config.custom_callback(log_buffer, log_config.callback_data);
    }
    
    /* Output to console if enabled */
    if (log_config.console_output) {
        vga_printf("%s\n", log_buffer);
    }
    
    /* Output to file if enabled */
    if (log_config.file_output) {
        /* This would write to a log file */
        /* Implementation depends on file system support */
        /* For now, just increment size counter */
        log_config.current_log_size += log_buffer_pos;
        
        /* Check for log rotation */
        if (log_config.current_log_size >= log_config.max_log_size) {
            /* This would rotate log files */
            log_config.current_log_size = 0;
        }
    }
}

/* Flush log buffer */
void log_flush(void) {
    if (log_buffer_pos > 0) {
        output_log_message();
        log_buffer_pos = 0;
    }
}

/* Main logging function */
void kernel_log(log_level_t level, const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_log_message(level, component, format, args);
    output_log_message();
    
    va_end(args);
}

/* Convenience functions for different log levels */
void kernel_fatal(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_log_message(LOG_FATAL, component, format, args);
    output_log_message();
    
    va_end(args);
}

void kernel_error(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_log_message(LOG_ERROR, component, format, args);
    output_log_message();
    
    va_end(args);
}

void kernel_warning(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_log_message(LOG_WARNING, component, format, args);
    output_log_message();
    
    va_end(args);
}

void kernel_info(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_log_message(LOG_INFO, component, format, args);
    output_log_message();
    
    va_end(args);
}

void kernel_debug(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_log_message(LOG_DEBUG, component, format, args);
    output_log_message();
    
    va_end(args);
}

void kernel_trace(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    format_log_message(LOG_TRACE, component, format, args);
    output_log_message();
    
    va_end(args);
}

/* Log statistics */
void log_get_statistics(log_statistics_t* stats) {
    if (stats == NULL) {
        return;
    }
    
    stats->current_level = log_config.current_level;
    stats->console_output = log_config.console_output;
    stats->file_output = log_config.file_output;
    stats->timestamp_output = log_config.timestamp_output;
    stats->color_output = log_config.color_output;
    stats->component_output = log_config.component_output;
    stats->current_log_size = log_config.current_log_size;
    stats->max_log_size = log_config.max_log_size;
    stats->log_rotation_count = log_config.log_rotation_count;
}

/* Log configuration */
void log_get_config(log_config_t* config) {
    if (config == NULL) {
        return;
    }
    
    config->current_level = log_config.current_level;
    config->console_output = log_config.console_output;
    config->file_output = log_config.file_output;
    config->timestamp_output = log_config.timestamp_output;
    config->color_output = log_config.color_output;
    config->component_output = log_config.component_output;
    strcpy(config->log_file, log_config.log_file);
    config->max_log_size = log_config.max_log_size;
    config->log_rotation_count = log_config.log_rotation_count;
}

/* Set log configuration */
void log_set_config(const log_config_t* config) {
    if (config == NULL) {
        return;
    }
    
    log_config.current_level = config->current_level;
    log_config.console_output = config->console_output;
    log_config.file_output = config->file_output;
    log_config.timestamp_output = config->timestamp_output;
    log_config.color_output = config->color_output;
    log_config.component_output = config->component_output;
    strcpy(log_config.log_file, config->log_file);
    log_config.max_log_size = config->max_log_size;
    log_config.log_rotation_count = config->log_rotation_count;
    
    kernel_log(LOG_INFO, "Logging", "Log configuration updated");
}

/* Log rotation */
void log_rotate(void) {
    kernel_log(LOG_INFO, "Logging", "Rotating log files");
    
    /* This would implement log rotation */
    /* For now, just reset the current log size */
    log_config.current_log_size = 0;
}

/* Clear log */
void log_clear(void) {
    kernel_log(LOG_INFO, "Logging", "Clearing log");
    
    /* This would clear the log file */
    /* For now, just reset the current log size */
    log_config.current_log_size = 0;
}

/* Emergency log function (works even if system is in bad state) */
void kernel_emergency_log(const char* format, ...) {
    /* Disable interrupts to ensure atomic operation */
    disable_interrupts();
    
    /* Format message directly to VGA */
    vga_set_color(VGA_COLOR_RED, VGA_COLOR_BLACK);
    vga_printf("EMERGENCY: ");
    
    va_list args;
    va_start(args, format);
    vga_vprintf(format, args);
    va_end(args);
    
    vga_printf("\n");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    
    /* Re-enable interrupts */
    enable_interrupts();
}

/* Panic log function */
void kernel_panic_log(const char* format, ...) {
    /* Disable interrupts */
    disable_interrupts();
    
    /* Print panic header */
    vga_set_color(VGA_COLOR_RED, VGA_COLOR_BLACK);
    vga_printf("\n=== KERNEL PANIC ===\n");
    
    /* Print panic message */
    va_list args;
    va_start(args, format);
    vga_vprintf(format, args);
    va_end(args);
    vga_printf("\n");
    
    /* Print system information */
    vga_printf("System halted. Debug information:\n");
    
    /* This would print more debug information */
    
    /* Halt the system */
    while (1) {
        halt();
    }
}