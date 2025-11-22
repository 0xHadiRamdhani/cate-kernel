#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* System call numbers */
#define SYS_READ            0
#define SYS_WRITE           1
#define SYS_OPEN            2
#define SYS_CLOSE           3
#define SYS_STAT            4
#define SYS_FSTAT           5
#define SYS_LSTAT           6
#define SYS_POLL            7
#define SYS_LSEEK           8
#define SYS_MMAP            9
#define SYS_MPROTECT        10
#define SYS_MUNMAP          11
#define SYS_BRK             12
#define SYS_SIGACTION       13
#define SYS_SIGPROCMASK     14
#define SYS_IOCTL           16
#define SYS_ACCESS          21
#define SYS_PIPE            22
#define SYS_SELECT          23
#define SYS_YIELD           24
#define SYS_MREMAP          25
#define SYS_MSYNC           26
#define SYS_MINCORE         27
#define SYS_MADVISE         28
#define SYS_SHMGET          29
#define SYS_SHMAT           30
#define SYS_SHMCTL          31
#define SYS_DUP             32
#define SYS_DUP2            33
#define SYS_PAUSE           34
#define SYS_NANOSLEEP       35
#define SYS_GETITIMER       36
#define SYS_ALARM           37
#define SYS_SETITIMER       38
#define SYS_GETPID          39
#define SYS_FORK            57
#define SYS_VFORK           58
#define SYS_EXECVE          59
#define SYS_EXIT            60
#define SYS_WAIT4           61
#define SYS_KILL            62
#define SYS_UNAME           63
#define SYS_GETUID          102
#define SYS_GETGID          104
#define SYS_GETEUID         107
#define SYS_GETEGID         108
#define SYS_SETUID          105
#define SYS_SETGID          106
#define SYS_GETPPID         110
#define SYS_SETSID          112
#define SYS_SIGRETURN       119
#define SYS_CLONE           120
#define SYS_MLOCK           149
#define SYS_MUNLOCK         150
#define SYS_MLOCKALL        151
#define SYS_MUNLOCKALL      152
#define SYS_VHANGUP         153
#define SYS_PRCTL           157
#define SYS_ARCH_PRCTL      158
#define SYS_GETTID          186
#define SYS_TIME            201
#define SYS_FUTEX           202
#define SYS_SET_TID_ADDRESS 218
#define SYS_EXIT_GROUP      231
#define SYS_CLOCK_GETTIME   228
#define SYS_CLOCK_NANOSLEEP 230
#define SYS_CLOCK_GETRES    229

/* Pentesting specific system calls */
#define SYS_PENTEST_SCAN        1000
#define SYS_PENTEST_EXPLOIT     1001
#define SYS_PENTEST_INJECT      1002
#define SYS_PENTEST_CAPTURE     1003
#define SYS_PENTEST_ANALYZE     1004
#define SYS_PENTEST_FORENSICS   1005
#define SYS_PENTEST_CRYPTO      1006
#define SYS_PENTEST_NETWORK     1007
#define SYS_PENTEST_MEMORY      1008
#define SYS_PENTEST_PRIVILEGE   1009
#define SYS_PENTEST_ESCALATE    1010
#define SYS_PENTEST_BACKDOOR    1011
#define SYS_PENTEST_STEALTH     1012
#define SYS_PENTEST_EVASION     1013
#define SYS_PENTEST_FUZZ        1014
#define SYS_PENTEST_REVERSE     1015
#define SYS_PENTEST_DEBUG       1016
#define SYS_PENTEST_MONITOR     1017
#define SYS_PENTEST_AUDIT       1018
#define SYS_PENTEST_VALIDATE    1019

/* System call flags */
#define SYSCALL_FLAG_SECURE     (1 << 0)
#define SYSCALL_FLAG_AUDIT      (1 << 1)
#define SYSCALL_FLAG_LOG        (1 << 2)
#define SYSCALL_FLAG_VALIDATE   (1 << 3)
#define SYSCALL_FLAG_PRIVILEGED (1 << 4)
#define SYSCALL_FLAG_USER       (1 << 5)
#define SYSCALL_FLAG_KERNEL     (1 << 6)
#define SYSCALL_FLAG_DEBUG      (1 << 7)

/* System call return codes */
#define SYSCALL_SUCCESS         0
#define SYSCALL_ERROR          -1
#define SYSCALL_INVALID        -2
#define SYSCALL_PERMISSION     -3
#define SYSCALL_MEMORY         -4
#define SYSCALL_NOT_FOUND      -5
#define SYSCALL_BUSY           -6
#define SYSCALL_TIMEOUT        -7
#define SYSCALL_INTERRUPTED    -8
#define SYSCALL_WOULD_BLOCK    -9

/* System call context */
typedef struct {
    uint64_t rax;    /* Return value */
    uint64_t rbx;    /* Callee saved */
    uint64_t rcx;    /* Argument 4 */
    uint64_t rdx;    /* Argument 3 */
    uint64_t rsi;    /* Argument 2 */
    uint64_t rdi;    /* Argument 1 */
    uint64_t rbp;    /* Frame pointer */
    uint64_t rsp;    /* Stack pointer */
    uint64_t r8;     /* Argument 5 */
    uint64_t r9;     /* Argument 6 */
    uint64_t r10;    /* Temporary */
    uint64_t r11;    /* Temporary */
    uint64_t r12;    /* Callee saved */
    uint64_t r13;    /* Callee saved */
    uint64_t r14;    /* Callee saved */
    uint64_t r15;    /* Callee saved */
    uint64_t rip;    /* Instruction pointer */
    uint64_t rflags; /* Flags */
    uint64_t cs;     /* Code segment */
    uint64_t ss;     /* Stack segment */
    uint64_t fs;     /* FS segment */
    uint64_t gs;     /* GS segment */
} syscall_context_t;

/* System call arguments */
typedef struct {
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
} syscall_args_t;

/* System call information */
typedef struct {
    uint64_t number;
    const char* name;
    uint32_t flags;
    uint64_t (*handler)(syscall_args_t* args, syscall_context_t* context);
    uint64_t call_count;
    uint64_t error_count;
    uint64_t total_time;
    uint64_t max_time;
    uint64_t min_time;
} syscall_info_t;

/* System call audit log */
typedef struct {
    uint64_t timestamp;
    uint64_t pid;
    uint64_t tid;
    uint64_t syscall_number;
    uint64_t args[6];
    uint64_t result;
    uint64_t duration;
    uint32_t flags;
    uint32_t security_flags;
    char process_name[64];
} syscall_audit_log_t;

/* System call security context */
typedef struct {
    uint32_t security_level;
    uint32_t audit_level;
    uint32_t log_level;
    bool privilege_escalation_detected;
    bool suspicious_activity_detected;
    uint64_t suspicious_call_count;
    uint64_t privilege_escalation_count;
    uint64_t audit_log_count;
    uint64_t max_audit_logs;
    syscall_audit_log_t* audit_logs;
} syscall_security_context_t;

/* System call statistics */
typedef struct {
    uint64_t total_calls;
    uint64_t total_errors;
    uint64_t total_time;
    uint64_t max_time;
    uint64_t min_time;
    uint64_t calls_per_second;
    uint64_t errors_per_second;
    uint64_t privilege_escalations;
    uint64_t suspicious_activities;
    uint64_t security_violations;
    uint64_t audit_events;
} syscall_stats_t;

/* System call context */
typedef struct {
    syscall_info_t* syscalls;
    syscall_security_context_t* security;
    syscall_stats_t* stats;
    uint64_t syscall_count;
    uint64_t max_syscalls;
    bool auditing_enabled;
    bool security_enabled;
    bool logging_enabled;
    uint64_t syscall_stack;
    uint64_t syscall_stack_size;
    uint64_t user_stack;
    uint64_t kernel_stack;
    uint64_t current_pid;
    uint64_t current_tid;
    uint32_t current_privilege;
    uint64_t syscall_enter_time;
    uint64_t syscall_exit_time;
} syscall_context_global_t;

/* Function prototypes */
void syscall_init(void);
void syscall_init_handlers(void);
void syscall_init_security(void);
void syscall_init_auditing(void);
void syscall_enable(void);
void syscall_disable(void);
void syscall_enable_security(void);
void syscall_disable_security(void);
void syscall_enable_auditing(void);
void syscall_disable_auditing(void);
void syscall_enable_logging(void);
void syscall_disable_logging(void);
uint64_t syscall_handler(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_dispatcher(uint64_t number, syscall_args_t* args, syscall_context_t* context);
void syscall_register(uint64_t number, const char* name, uint32_t flags, 
                     uint64_t (*handler)(syscall_args_t*, syscall_context_t*));
void syscall_unregister(uint64_t number);
syscall_info_t* syscall_get_info(uint64_t number);
const char* syscall_get_name(uint64_t number);
uint64_t syscall_get_flags(uint64_t number);
bool syscall_is_valid(uint64_t number);
bool syscall_is_secure(uint64_t number);
bool syscall_is_privileged(uint64_t number);
void syscall_validate_args(syscall_args_t* args, syscall_context_t* context);
void syscall_validate_context(syscall_context_t* context);
void syscall_validate_security(syscall_args_t* args, syscall_context_t* context);
void syscall_audit_call(syscall_args_t* args, syscall_context_t* context, uint64_t result);
void syscall_log_call(syscall_args_t* args, syscall_context_t* context, uint64_t result);
void syscall_check_privilege(syscall_args_t* args, syscall_context_t* context);
void syscall_detect_suspicious(syscall_args_t* args, syscall_context_t* context);
void syscall_handle_security_violation(syscall_args_t* args, syscall_context_t* context);
void syscall_dump_stats(void);
void syscall_dump_audit_log(void);
void syscall_dump_security_context(void);

/* Standard system calls */
uint64_t syscall_read(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_write(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_open(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_close(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_mmap(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_munmap(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_mprotect(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_brk(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_exit(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_fork(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_execve(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_getpid(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_getuid(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_getgid(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_kill(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_wait4(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_nanosleep(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_gettimeofday(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_clock_gettime(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_ioctl(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_futex(syscall_args_t* args, syscall_context_t* context);

/* Pentesting specific system calls */
uint64_t syscall_pentest_scan(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_exploit(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_inject(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_capture(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_analyze(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_forensics(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_crypto(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_network(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_memory(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_privilege(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_escalate(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_backdoor(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_stealth(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_evasion(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_fuzz(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_reverse(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_debug(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_monitor(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_audit(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_pentest_validate(syscall_args_t* args, syscall_context_t* context);

/* Security functions */
uint64_t syscall_security_check(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_security_validate(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_security_audit(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_security_monitor(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_security_log(syscall_args_t* args, syscall_context_t* context);
uint64_t syscall_security_alert(syscall_args_t* args, syscall_context_t* context);

/* Assembly functions */
extern uint64_t syscall_enter(void);
extern uint64_t syscall_exit(void);
extern void syscall_handler_asm(void);
extern void syscall_dispatcher_asm(void);

/* Global variables */
extern syscall_context_global_t* global_syscall_context;
extern volatile uint64_t syscall_count;
extern volatile bool syscalls_enabled;

#endif /* SYSCALL_H */