#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <stdbool.h>

/* System call numbers */
typedef enum {
    /* Memory management syscalls */
    SYSCALL_MALLOC = 0,
    SYSCALL_FREE = 1,
    SYSCALL_MMAP = 2,
    SYSCALL_MUNMAP = 3,
    SYSCALL_MPROTECT = 4,
    
    /* Process management syscalls */
    SYSCALL_FORK = 10,
    SYSCALL_EXIT = 11,
    SYSCALL_WAIT = 12,
    SYSCALL_EXEC = 13,
    SYSCALL_GETPID = 14,
    SYSCALL_GETPPID = 15,
    
    /* File system syscalls */
    SYSCALL_OPEN = 20,
    SYSCALL_CLOSE = 21,
    SYSCALL_READ = 22,
    SYSCALL_WRITE = 23,
    SYSCALL_LSEEK = 24,
    SYSCALL_STAT = 25,
    SYSCALL_UNLINK = 26,
    SYSCALL_MKDIR = 27,
    SYSCALL_RMDIR = 28,
    
    /* Device I/O syscalls */
    SYSCALL_IOCTL = 30,
    SYSCALL_READV = 31,
    SYSCALL_WRITEV = 32,
    
    /* Network syscalls */
    SYSCALL_SOCKET = 40,
    SYSCALL_BIND = 41,
    SYSCALL_LISTEN = 42,
    SYSCALL_ACCEPT = 43,
    SYSCALL_CONNECT = 44,
    SYSCALL_SEND = 45,
    SYSCALL_RECV = 46,
    SYSCALL_SENDTO = 47,
    SYSCALL_RECVFROM = 48,
    SYSCALL_SHUTDOWN = 49,
    SYSCALL_SETSOCKOPT = 50,
    SYSCALL_GETSOCKOPT = 51,
    
    /* Security syscalls */
    SYSCALL_GETUID = 60,
    SYSCALL_SETUID = 61,
    SYSCALL_GETGID = 62,
    SYSCALL_SETGID = 63,
    SYSCALL_GETEUID = 64,
    SYSCALL_SETEUID = 65,
    SYSCALL_GETEGID = 66,
    SYSCALL_SETEGID = 67,
    
    /* Time syscalls */
    SYSCALL_TIME = 70,
    SYSCALL_GETTIMEOFDAY = 71,
    SYSCALL_SETTIMEOFDAY = 72,
    SYSCALL_NANOSLEEP = 73,
    
    /* Signal syscalls */
    SYSCALL_KILL = 80,
    SYSCALL_SIGNAL = 81,
    SYSCALL_SIGACTION = 82,
    SYSCALL_SIGPROCMASK = 83,
    SYSCALL_SIGPENDING = 84,
    SYSCALL_SIGSUSPEND = 85,
    
    /* Pentesting syscalls */
    SYSCALL_SCAN_NETWORK = 100,
    SYSCALL_SCAN_PORT = 101,
    SYSCALL_SCAN_VULNERABILITY = 102,
    SYSCALL_EXPLOIT_EXECUTE = 103,
    SYSCALL_EXPLOIT_DEVELOP = 104,
    SYSCALL_INJECT_PAYLOAD = 105,
    SYSCALL_CAPTURE_PACKET = 106,
    SYSCALL_ANALYZE_TRAFFIC = 107,
    SYSCALL_FORENSICS_ANALYZE = 108,
    SYSCALL_FORENSICS_RECOVER = 109,
    SYSCALL_SECURITY_AUDIT = 110,
    SYSCALL_SECURITY_SCAN = 111,
    SYSCALL_AUTHENTICATE = 112,
    SYSCALL_AUTHORIZE = 113,
    SYSCALL_ENCRYPT = 114,
    SYSCALL_DECRYPT = 115,
    SYSCALL_HASH = 116,
    SYSCALL_SIGN = 117,
    SYSCALL_VERIFY = 118,
    
    /* Debug syscalls */
    SYSCALL_DEBUG_LOG = 120,
    SYSCALL_DEBUG_DUMP = 121,
    SYSCALL_DEBUG_BREAK = 122,
    SYSCALL_DEBUG_TRACE = 123,
    
    /* Test syscalls */
    SYSCALL_TEST_RUN = 130,
    SYSCALL_TEST_REPORT = 131,
    SYSCALL_TEST_ASSERT = 132,
    
    /* System information syscalls */
    SYSCALL_GET_SYSTEM_INFO = 140,
    SYSCALL_GET_MEMORY_INFO = 141,
    SYSCALL_GET_CPU_INFO = 142,
    SYSCALL_GET_DEVICE_INFO = 143,
    
    /* Configuration syscalls */
    SYSCALL_GET_CONFIG = 150,
    SYSCALL_SET_CONFIG = 151,
    
    /* Maximum syscall number */
    SYSCALL_MAX = 200
} syscall_number_t;

/* Syscall return codes */
#define SYSCALL_SUCCESS 0
#define SYSCALL_ERROR -1
#define SYSCALL_INVALID -2
#define SYSCALL_NOT_IMPLEMENTED -3
#define SYSCALL_ACCESS_DENIED -4
#define SYSCALL_OUT_OF_MEMORY -5
#define SYSCALL_INVALID_PARAM -6
#define SYSCALL_TIMEOUT -7
#define SYSCALL_BUSY -8
#define SYSCALL_NOT_FOUND -9

/* Syscall parameters */
typedef struct {
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
} syscall_args_t;

/* Syscall result */
typedef struct {
    int64_t result;
    int32_t error;
    uint32_t flags;
} syscall_result_t;

/* Syscall handler function type */
typedef syscall_result_t (*syscall_handler_t)(const syscall_args_t* args);

/* Initialize system calls */
void syscall_init(void);

/* Shutdown system calls */
void syscall_shutdown(void);

/* Register syscall handler */
bool register_syscall(uint32_t number, syscall_handler_t handler);
bool unregister_syscall(uint32_t number);

/* Execute syscall */
syscall_result_t syscall_execute(uint32_t number, const syscall_args_t* args);

/* Process pending syscalls */
void syscall_process_pending(void);

/* Get syscall statistics */
typedef struct {
    uint64_t total_calls;
    uint64_t successful_calls;
    uint64_t failed_calls;
    uint64_t syscall_counts[SYSCALL_MAX];
    uint64_t syscall_times[SYSCALL_MAX];
    uint64_t min_time;
    uint64_t max_time;
    uint64_t avg_time;
} syscall_stats_t;

void get_syscall_stats(syscall_stats_t* stats);
void reset_syscall_stats(void);

/* Get syscall name */
const char* get_syscall_name(uint32_t number);
bool is_valid_syscall(uint32_t number);

/* Syscall security */
typedef struct {
    bool require_privilege;
    uint32_t min_privilege;
    bool require_authentication;
    bool audit_enabled;
    bool logging_enabled;
    uint32_t max_calls_per_second;
    uint32_t timeout_ms;
} syscall_security_t;

void set_syscall_security(uint32_t number, const syscall_security_t* security);
void get_syscall_security(uint32_t number, syscall_security_t* security);

/* Syscall auditing */
typedef struct {
    uint32_t syscall_number;
    uint64_t timestamp;
    uint32_t process_id;
    uint32_t user_id;
    uint64_t args_hash;
    int64_t result;
    int32_t error;
    uint32_t flags;
} syscall_audit_entry_t;

void enable_syscall_auditing(void);
void disable_syscall_auditing(void);
bool is_syscall_auditing_enabled(void);
void log_syscall_audit(const syscall_audit_entry_t* entry);
void dump_syscall_audit_log(void);

/* Syscall debugging */
#ifdef DEBUG
#define SYSCALL_DEBUG_ENABLED
void enable_syscall_debugging(void);
void disable_syscall_debugging(void);
bool is_syscall_debugging_enabled(void);
void debug_syscall(uint32_t number, const syscall_args_t* args, const syscall_result_t* result);
#endif

/* Syscall tracing */
typedef void (*syscall_trace_callback_t)(uint32_t number, const syscall_args_t* args, const syscall_result_t* result);
bool register_syscall_trace_callback(syscall_trace_callback_t callback);
bool unregister_syscall_trace_callback(syscall_trace_callback_t callback);

/* Syscall hooks */
typedef void (*syscall_hook_t)(uint32_t number, const syscall_args_t* args, syscall_result_t* result);
bool register_syscall_hook(uint32_t number, syscall_hook_t hook);
bool unregister_syscall_hook(uint32_t number, syscall_hook_t hook);

/* Syscall profiling */
typedef struct {
    uint64_t call_count;
    uint64_t total_time;
    uint64_t min_time;
    uint64_t max_time;
    uint64_t avg_time;
    uint64_t errors;
    double success_rate;
} syscall_profile_t;

void start_syscall_profiling(uint32_t number);
void stop_syscall_profiling(uint32_t number);
void get_syscall_profile(uint32_t number, syscall_profile_t* profile);
void reset_syscall_profile(uint32_t number);

/* Syscall testing */
typedef struct {
    uint32_t syscall_number;
    syscall_args_t args;
    syscall_result_t expected_result;
    const char* test_name;
    const char* test_description;
} syscall_test_case_t;

bool run_syscall_test(const syscall_test_case_t* test_case);
bool run_syscall_tests(const syscall_test_case_t* test_cases, size_t count);
void dump_syscall_test_results(void);

/* Syscall configuration */
typedef struct {
    bool enable_security;
    bool enable_auditing;
    bool enable_debugging;
    bool enable_tracing;
    bool enable_profiling;
    bool enable_testing;
    uint32_t max_concurrent_calls;
    uint32_t timeout_ms;
    uint32_t retry_count;
    uint32_t retry_delay_ms;
} syscall_config_t;

void get_syscall_config(syscall_config_t* config);
void set_syscall_config(const syscall_config_t* config);

/* Syscall error handling */
typedef enum {
    SYSCALL_ERROR_NONE = 0,
    SYSCALL_ERROR_INVALID_NUMBER = 1,
    SYSCALL_ERROR_INVALID_HANDLER = 2,
    SYSCALL_ERROR_ACCESS_DENIED = 3,
    SYSCALL_ERROR_TIMEOUT = 4,
    SYSCALL_ERROR_RESOURCE_EXHAUSTED = 5,
    SYSCALL_ERROR_INTERNAL = 6
} syscall_error_t;

const char* get_syscall_error_string(syscall_error_t error);
void handle_syscall_error(syscall_error_t error, uint32_t number);

/* Syscall macros */
#define SYSCALL(number, ...) \
    syscall_execute(number, &(syscall_args_t){__VA_ARGS__})

#define SYSCALL0(number) \
    syscall_execute(number, &(syscall_args_t){0, 0, 0, 0, 0, 0})

#define SYSCALL1(number, a1) \
    syscall_execute(number, &(syscall_args_t){(uint64_t)(a1), 0, 0, 0, 0, 0})

#define SYSCALL2(number, a1, a2) \
    syscall_execute(number, &(syscall_args_t){(uint64_t)(a1), (uint64_t)(a2), 0, 0, 0, 0})

#define SYSCALL3(number, a1, a2, a3) \
    syscall_execute(number, &(syscall_args_t){(uint64_t)(a1), (uint64_t)(a2), (uint64_t)(a3), 0, 0, 0})

#define SYSCALL4(number, a1, a2, a3, a4) \
    syscall_execute(number, &(syscall_args_t){(uint64_t)(a1), (uint64_t)(a2), (uint64_t)(a3), (uint64_t)(a4), 0, 0})

#define SYSCALL5(number, a1, a2, a3, a4, a5) \
    syscall_execute(number, &(syscall_args_t){(uint64_t)(a1), (uint64_t)(a2), (uint64_t)(a3), (uint64_t)(a4), (uint64_t)(a5), 0})

#define SYSCALL6(number, a1, a2, a3, a4, a5, a6) \
    syscall_execute(number, &(syscall_args_t){(uint64_t)(a1), (uint64_t)(a2), (uint64_t)(a3), (uint64_t)(a4), (uint64_t)(a5), (uint64_t)(a6)})

/* Syscall result checking */
#define SYSCALL_SUCCESS(result) ((result).result >= 0)
#define SYSCALL_FAILED(result) ((result).result < 0)
#define SYSCALL_ERROR_CODE(result) ((result).error)
#define SYSCALL_RESULT_VALUE(result) ((result).result)

/* Syscall error checking */
#define SYSCALL_CHECK(result, error_label) \
    do { \
        if (SYSCALL_FAILED(result)) { \
            goto error_label; \
        } \
    } while (0)

#define SYSCALL_CHECK_MSG(result, msg, error_label) \
    do { \
        if (SYSCALL_FAILED(result)) { \
            error(msg); \
            goto error_label; \
        } \
    } while (0)

/* Syscall assertions */
#define SYSCALL_ASSERT_SUCCESS(result) \
    do { \
        if (SYSCALL_FAILED(result)) { \
            panic("Syscall failed: %s", get_syscall_error_string(SYSCALL_ERROR_CODE(result))); \
        } \
    } while (0)

/* Syscall debugging */
#ifdef DEBUG
#define SYSCALL_DEBUG(number, args, result) \
    do { \
        if (is_syscall_debugging_enabled()) { \
            debug_syscall(number, args, result); \
        } \
    } while (0)
#else
#define SYSCALL_DEBUG(number, args, result) do {} while (0)
#endif

#endif /* SYSCALL_H */