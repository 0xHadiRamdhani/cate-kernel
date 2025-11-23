#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Common type definitions */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;

/* Boolean type */
typedef bool     bool_t;

/* Size type */
typedef size_t   size_t;

/* Pointer types */
typedef uintptr_t uintptr_t;
typedef intptr_t  intptr_t;

/* Common constants */
#ifndef NULL
#define NULL ((void*)0)
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef ABS
#define ABS(x) ((x) < 0 ? -(x) : (x))
#endif

#ifndef CLAMP
#define CLAMP(x, min, max) (MAX(min, MIN(max, x)))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

/* Common macros */
#define BIT(n) (1ULL << (n))
#define BIT_SET(x, n) ((x) |= BIT(n))
#define BIT_CLEAR(x, n) ((x) &= ~BIT(n))
#define BIT_TOGGLE(x, n) ((x) ^= BIT(n))
#define BIT_TEST(x, n) ((x) & BIT(n))

/* Alignment macros */
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

/* Memory barriers */
#define barrier() __asm__ __volatile__("" ::: "memory")
#define mb() __asm__ __volatile__("mfence" ::: "memory")
#define rmb() __asm__ __volatile__("lfence" ::: "memory")
#define wmb() __asm__ __volatile__("sfence" ::: "memory")

/* CPU pause */
#define cpu_pause() __asm__ __volatile__("pause")

/* Likely/unlikely macros */
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Return codes */
#define SUCCESS 0
#define FAILURE -1
#define ERROR_INVALID_PARAM -2
#define ERROR_OUT_OF_MEMORY -3
#define ERROR_NOT_FOUND -4
#define ERROR_ALREADY_EXISTS -5
#define ERROR_ACCESS_DENIED -6
#define ERROR_TIMEOUT -7
#define ERROR_BUSY -8
#define ERROR_NOT_SUPPORTED -9
#define ERROR_IO -10

/* Status codes */
#define STATUS_OK 0
#define STATUS_ERROR 1
#define STATUS_WARNING 2
#define STATUS_INFO 3
#define STATUS_DEBUG 4

/* Common structures */
typedef struct {
    u64 low;
    u64 high;
} u128_t;

typedef struct {
    i64 low;
    i64 high;
} i128_t;

typedef struct {
    void* data;
    size_t size;
} buffer_t;

typedef struct {
    const void* data;
    size_t size;
} const_buffer_t;

typedef struct {
    u64 address;
    size_t size;
    u32 type;
    u32 flags;
} memory_region_t;

typedef struct {
    u64 start;
    u64 end;
    u64 size;
} range_t;

typedef struct {
    u32 major;
    u32 minor;
    u32 patch;
} version_t;

typedef struct {
    u64 timestamp;
    u32 id;
    u32 type;
    const char* message;
} event_t;

typedef struct {
    u64 total;
    u64 used;
    u64 free;
    u64 peak;
} usage_stats_t;

/* Common functions */
static inline u64 swap64(u64 x) {
    return __builtin_bswap64(x);
}

static inline u32 swap32(u32 x) {
    return __builtin_bswap32(x);
}

static inline u16 swap16(u16 x) {
    return __builtin_bswap16(x);
}

static inline u64 rol64(u64 x, int n) {
    return (x << n) | (x >> (64 - n));
}

static inline u64 ror64(u64 x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline u32 rol32(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline u32 ror32(u32 x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline int popcount64(u64 x) {
    return __builtin_popcountll(x);
}

static inline int popcount32(u32 x) {
    return __builtin_popcount(x);
}

static inline int clz64(u64 x) {
    return __builtin_clzll(x);
}

static inline int clz32(u32 x) {
    return __builtin_clz(x);
}

static inline int ctz64(u64 x) {
    return __builtin_ctzll(x);
}

static inline int ctz32(u32 x) {
    return __builtin_ctz(x);
}

/* Common assertions */
#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            panic("Assertion failed: " #cond " at " __FILE__ ":" __LINE__); \
        } \
    } while (0)

#define ASSERT_MSG(cond, msg) \
    do { \
        if (!(cond)) { \
            panic("Assertion failed: " #cond " - " msg " at " __FILE__ ":" __LINE__); \
        } \
    } while (0)

/* Common error handling */
#define CHECK(cond, err) \
    do { \
        if (!(cond)) { \
            return (err); \
        } \
    } while (0)

#define CHECK_MSG(cond, err, msg) \
    do { \
        if (!(cond)) { \
            error(msg); \
            return (err); \
        } \
    } while (0)

/* Common logging */
#define LOG(level, format, ...) \
    log(level, __FUNCTION__, format, ##__VA_ARGS__)

#define LOG_ERROR(format, ...) LOG(LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) LOG(LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) LOG(LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) LOG(LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)

/* Common debugging */
#ifdef DEBUG
#define DEBUG_LOG(format, ...) LOG_DEBUG(format, ##__VA_ARGS__)
#define DEBUG_DUMP(ptr, size) debug_dump(ptr, size)
#else
#define DEBUG_LOG(format, ...) do {} while (0)
#define DEBUG_DUMP(ptr, size) do {} while (0)
#endif

/* Common validation */
#define VALIDATE_PTR(ptr) \
    do { \
        if ((ptr) == NULL) { \
            return ERROR_INVALID_PARAM; \
        } \
    } while (0)

#define VALIDATE_SIZE(size) \
    do { \
        if ((size) == 0) { \
            return ERROR_INVALID_PARAM; \
        } \
    } while (0)

#define VALIDATE_RANGE(val, min, max) \
    do { \
        if ((val) < (min) || (val) > (max)) { \
            return ERROR_INVALID_PARAM; \
        } \
    } while (0)

/* Common memory operations */
#define ZERO_STRUCT(ptr) memset((ptr), 0, sizeof(*(ptr)))
#define COPY_STRUCT(dst, src) memcpy((dst), (src), sizeof(*(dst)))
#define COMPARE_STRUCT(a, b) (memcmp((a), (b), sizeof(*(a))) == 0)

/* Common string operations */
#define STR_EQUAL(a, b) (strcmp((a), (b)) == 0)
#define STR_PREFIX(str, prefix) (strncmp((str), (prefix), strlen(prefix)) == 0)
#define STR_SUFFIX(str, suffix) (strlen(str) >= strlen(suffix) && strcmp((str) + strlen(str) - strlen(suffix), (suffix)) == 0)

/* Common time operations */
#define TIME_MS_TO_NS(ms) ((ms) * 1000000ULL)
#define TIME_US_TO_NS(us) ((us) * 1000ULL)
#define TIME_NS_TO_MS(ns) ((ns) / 1000000ULL)
#define TIME_NS_TO_US(ns) ((ns) / 1000ULL)

/* Common mathematical operations */
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ROUND_UP(n, d) (DIV_ROUND_UP(n, d) * (d))
#define IS_POWER_OF_2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)
#define NEXT_POWER_OF_2(x) (1ULL << (64 - clz64((x) - 1)))

/* Common compiler attributes */
#define PACKED __attribute__((packed))
#define ALIGNED(x) __attribute__((aligned(x)))
#define NORETURN __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define USED __attribute__((used))
#define WEAK __attribute__((weak))
#define CONST __attribute__((const))
#define PURE __attribute__((pure))
#define HOT __attribute__((hot))
#define COLD __attribute__((cold))

/* Common function attributes */
#define INLINE static inline
#define ALWAYS_INLINE static inline __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))

/* Common section attributes */
#define SECTION(x) __attribute__((section(x)))
#define INIT_SECTION SECTION(".init")
#define EXIT_SECTION SECTION(".exit")
#define DATA_SECTION SECTION(".data")
#define BSS_SECTION SECTION(".bss")
#define RODATA_SECTION SECTION(".rodata")
#define TEXT_SECTION SECTION(".text")

/* Common error handling functions */
void panic(const char* message);
void error(const char* message);
void warning(const char* message);
void info(const char* message);
void debug(const char* message);

/* Common utility functions */
u64 get_timestamp(void);
u32 get_random_u32(void);
u64 get_random_u64(void);
bool is_valid_pointer(const void* ptr);
bool is_valid_range(const void* ptr, size_t size);

/* Common string utility functions */
bool str_to_u64(const char* str, u64* value);
bool str_to_u32(const char* str, u32* value);
bool str_to_bool(const char* str, bool* value);
char* u64_to_str(u64 value, char* buffer, size_t size);
char* u32_to_str(u32 value, char* buffer, size_t size);

/* Common memory utility functions */
void* safe_memcpy(void* dest, const void* src, size_t n);
void* safe_memset(void* dest, int value, size_t n);
int safe_memcmp(const void* ptr1, const void* ptr2, size_t n);
bool memory_is_zero(const void* ptr, size_t size);

/* Common mathematical utility functions */
u64 gcd(u64 a, u64 b);
u64 lcm(u64 a, u64 b);
u64 next_power_of_2(u64 x);
bool is_power_of_2(u64 x);
u32 log2_u32(u32 x);
u64 log2_u64(u64 x);

#endif /* COMMON_H */