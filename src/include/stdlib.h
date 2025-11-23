#ifndef STDLIB_H
#define STDLIB_H

#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"

/* Standard library functions for kernel */

/* Memory allocation functions */
void* malloc(size_t size);
void* calloc(size_t nmemb, size_t size);
void* realloc(void* ptr, size_t size);
void free(void* ptr);

/* Memory allocation with alignment */
void* aligned_alloc(size_t alignment, size_t size);
void* memalign(size_t alignment, size_t size);

/* Memory allocation for kernel */
void* kmalloc(size_t size);
void* kcalloc(size_t nmemb, size_t size);
void* krealloc(void* ptr, size_t size);
void kfree(void* ptr);

/* Memory allocation with zeroing */
void* mallocz(size_t size);
void* kallocz(size_t size);

/* Memory allocation for arrays */
void* malloc_array(size_t nmemb, size_t size);
void* kalloc_array(size_t nmemb, size_t size);

/* Memory validation */
bool malloc_validate(const void* ptr);
bool kalloc_validate(const void* ptr);

/* Memory statistics */
typedef struct {
    size_t total_allocated;
    size_t total_freed;
    size_t current_usage;
    size_t peak_usage;
    size_t allocation_count;
    size_t free_count;
    size_t fragmentation;
} malloc_stats_t;

void malloc_get_stats(malloc_stats_t* stats);
void kalloc_get_stats(malloc_stats_t* stats);

/* Memory debugging */
void malloc_dump_stats(void);
void kalloc_dump_stats(void);
void malloc_check_leaks(void);
void kalloc_check_leaks(void);

/* String conversion functions */
int atoi(const char* str);
long atol(const char* str);
long long atoll(const char* str);
double atof(const char* str);

/* String to number conversion with error checking */
bool str_to_int(const char* str, int* value);
bool str_to_long(const char* str, long* value);
bool str_to_llong(const char* str, long long* value);
bool str_to_double(const char* str, double* value);

/* Number to string conversion */
char* itoa(int value, char* str, int base);
char* ltoa(long value, char* str, int base);
char* lltoa(long long value, char* str, int base);
char* dtoa(double value, char* str, size_t size);

/* Random number generation */
int rand(void);
void srand(unsigned int seed);
int rand_range(int min, int max);
double rand_double(void);

/* Random number generation for kernel */
u32 krand32(void);
u64 krand64(void);
void ksrand(u64 seed);
int krand_range(int min, int max);
double krand_double(void);

/* Environment functions */
char* getenv(const char* name);
int setenv(const char* name, const char* value, int overwrite);
int unsetenv(const char* name);
void clearenv(void);

/* Process control functions */
void exit(int status);
void abort(void);
int atexit(void (*func)(void));
int at_quick_exit(void (*func)(void));
void quick_exit(int status);

/* Kernel process control */
void kexit(int status);
void kabort(void);
int katexit(void (*func)(void));

/* System functions */
char* getcwd(char* buf, size_t size);
int chdir(const char* path);
int system(const char* command);

/* Kernel system functions */
char* kgetcwd(char* buf, size_t size);
int kchdir(const char* path);

/* Search and sort functions */
void* bsearch(const void* key, const void* base, size_t nmemb, size_t size,
              int (*compar)(const void*, const void*));
void qsort(void* base, size_t nmemb, size_t size,
           int (*compar)(const void*, const void*));

/* Kernel search and sort functions */
void* kbsearch(const void* key, const void* base, size_t nmemb, size_t size,
               int (*compar)(const void*, const void*));
void kqsort(void* base, size_t nmemb, size_t size,
            int (*compar)(const void*, const void*));

/* Integer arithmetic functions */
int abs(int x);
long labs(long x);
long long llabs(long long x);

div_t div(int numer, int denom);
ldiv_t ldiv(long numer, long denom);
lldiv_t lldiv(long long numer, long long denom);

/* Kernel integer arithmetic functions */
int kabs(int x);
long klabs(long x);
long long kllabs(long long x);

kdiv_t kdiv(int numer, int denom);
kldiv_t kldiv(long numer, long denom);
klldiv_t klldiv(long long numer, long long denom);

/* Multibyte character functions */
int mblen(const char* s, size_t n);
int mbtowc(wchar_t* pwc, const char* s, size_t n);
int wctomb(char* s, wchar_t wchar);
size_t mbstowcs(wchar_t* pwcs, const char* s, size_t n);
size_t wcstombs(char* s, const wchar_t* pwcs, size_t n);

/* Kernel multibyte character functions */
int kmblen(const char* s, size_t n);
int kmbtowc(wchar_t* pwc, const char* s, size_t n);
int kwctomb(char* s, wchar_t wchar);
size_t kmbstowcs(wchar_t* pwcs, const char* s, size_t n);
size_t kwcstombs(char* s, const wchar_t* pwcs, size_t n);

/* Error handling */
void perror(const char* s);
char* strerror(int errnum);
int strerror_r(int errnum, char* buf, size_t buflen);

/* Kernel error handling */
void kperror(const char* s);
char* kstrerror(int errnum);
int kstrerror_r(int errnum, char* buf, size_t buflen);

/* Memory alignment */
#define ALIGNMENT_DEFAULT 8
#define ALIGNMENT_CACHE_LINE 64
#define ALIGNMENT_PAGE 4096

size_t malloc_alignment(void);
size_t kalloc_alignment(void);

/* Memory allocation strategies */
typedef enum {
    MALLOC_STRATEGY_FIRST_FIT,
    MALLOC_STRATEGY_BEST_FIT,
    MALLOC_STRATEGY_WORST_FIT,
    MALLOC_STRATEGY_NEXT_FIT
} malloc_strategy_t;

void malloc_set_strategy(malloc_strategy_t strategy);
malloc_strategy_t malloc_get_strategy(void);

void kalloc_set_strategy(malloc_strategy_t strategy);
malloc_strategy_t kalloc_get_strategy(void);

/* Memory allocation limits */
#define MALLOC_MAX_SIZE (1024 * 1024 * 1024) /* 1GB */
#define MALLOC_MAX_COUNT 1000000

size_t malloc_get_max_size(void);
size_t malloc_get_max_count(void);
size_t kalloc_get_max_size(void);
size_t kalloc_get_max_count(void);

/* Memory allocation debugging */
#define MALLOC_DEBUG_ENABLED
#define MALLOC_DEBUG_LEAK_DETECTION
#define MALLOC_DEBUG_CORRUPTION_DETECTION
#define MALLOC_DEBUG_STATISTICS

void malloc_debug_enable(bool enable);
bool malloc_debug_is_enabled(void);
void malloc_debug_dump(void);
void malloc_debug_check(void);

void kalloc_debug_enable(bool enable);
bool kalloc_debug_is_enabled(void);
void kalloc_debug_dump(void);
void kalloc_debug_check(void);

/* Memory allocation validation */
bool malloc_validate_all(void);
bool kalloc_validate_all(void);
void malloc_validate_and_repair(void);
void kalloc_validate_and_repair(void);

/* Memory allocation cleanup */
void malloc_cleanup(void);
void kalloc_cleanup(void);

/* Memory allocation statistics */
typedef struct {
    size_t total_allocated;
    size_t total_freed;
    size_t current_usage;
    size_t peak_usage;
    size_t allocation_count;
    size_t free_count;
    size_t failed_allocations;
    size_t fragmentation;
    double average_allocation_size;
    double allocation_success_rate;
} malloc_detailed_stats_t;

void malloc_get_detailed_stats(malloc_detailed_stats_t* stats);
void kalloc_get_detailed_stats(malloc_detailed_stats_t* stats);

/* Memory allocation tracing */
#define MALLOC_TRACE_ENABLED
#define MALLOC_TRACE_ALLOCATIONS
#define MALLOC_TRACE_FREES
#define MALLOC_TRACE_FAILURES

void malloc_trace_enable(bool enable);
bool malloc_trace_is_enabled(void);
void malloc_trace_dump(void);

void kalloc_trace_enable(bool enable);
bool kalloc_trace_is_enabled(void);
void kalloc_trace_dump(void);

/* Memory allocation profiling */
#define MALLOC_PROFILE_ENABLED
#define MALLOC_PROFILE_ALLOCATIONS
#define MALLOC_PROFILE_FREES

void malloc_profile_enable(bool enable);
bool malloc_profile_is_enabled(void);
void malloc_profile_dump(void);

void kalloc_profile_enable(bool enable);
bool kalloc_profile_is_enabled(void);
void kalloc_profile_dump(void);

/* Memory allocation security */
#define MALLOC_SECURITY_ENABLED
#define MALLOC_SECURITY_CANARIES
#define MALLOC_SECURITY_GUARD_PAGES
#define MALLOC_SECURITY_RANDOMIZATION

void malloc_security_enable(bool enable);
bool malloc_security_is_enabled(void);
void malloc_security_check(void);

void kalloc_security_enable(bool enable);
bool kalloc_security_is_enabled(void);
void kalloc_security_check(void);

/* Memory allocation performance */
#define MALLOC_PERFORMANCE_ENABLED
#define MALLOC_PERFORMANCE_TIMING
#define MALLOC_PERFORMANCE_COUNTERS

void malloc_performance_enable(bool enable);
bool malloc_performance_is_enabled(void);
void malloc_performance_dump(void);

void kalloc_performance_enable(bool enable);
bool kalloc_performance_is_enabled(void);
void kalloc_performance_dump(void);

#endif /* STDLIB_H */