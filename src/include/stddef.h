#ifndef STDDEF_H
#define STDDEF_H

/* Size type */
typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;

/* Wide character types */
typedef __WCHAR_TYPE__ wchar_t;

/* Null pointer */
#define NULL ((void*)0)

/* Offsetof macro */
#define offsetof(type, member) __builtin_offsetof(type, member)

/* Common constants */
#define SIZE_MAX __SIZE_MAX__
#define PTRDIFF_MAX __PTRDIFF_MAX__
#define PTRDIFF_MIN __PTRDIFF_MIN__

/* Common macros */
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Alignment macros */
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

/* Common type definitions */
typedef size_t size_t;
typedef ptrdiff_t ptrdiff_t;
typedef wchar_t wchar_t;

/* Maximum values */
#define SIZE_MAX ((size_t)-1)
#define PTRDIFF_MAX ((ptrdiff_t)(SIZE_MAX / 2))
#define PTRDIFF_MIN ((ptrdiff_t)(-SIZE_MAX / 2 - 1))

/* Common utility macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ABS(x) ((x) < 0 ? -(x) : (x))
#define CLAMP(x, min, max) (MAX(min, MIN(max, x)))

/* Round up/down macros */
#define ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ROUND_DOWN(n, d) ((n) / (d))

/* Division with rounding */
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_CLOSEST(n, d) (((n) + ((d) / 2)) / (d))

/* Bit manipulation macros */
#define BIT(n) (1ULL << (n))
#define BIT_SET(x, n) ((x) |= BIT(n))
#define BIT_CLEAR(x, n) ((x) &= ~BIT(n))
#define BIT_TOGGLE(x, n) ((x) ^= BIT(n))
#define BIT_TEST(x, n) ((x) & BIT(n))

/* Field manipulation macros */
#define FIELD_GET(mask, reg) (((reg) & (mask)) >> __builtin_ctz(mask))
#define FIELD_SET(mask, val) (((val) << __builtin_ctz(mask)) & (mask))
#define FIELD_CLEAR(mask) (~(mask))

/* Common alignment values */
#define ALIGN_1 1
#define ALIGN_2 2
#define ALIGN_4 4
#define ALIGN_8 8
#define ALIGN_16 16
#define ALIGN_32 32
#define ALIGN_64 64
#define ALIGN_128 128
#define ALIGN_256 256
#define ALIGN_512 512
#define ALIGN_1024 1024
#define ALIGN_4096 4096

/* Common buffer sizes */
#define BUFFER_SIZE_64 64
#define BUFFER_SIZE_128 128
#define BUFFER_SIZE_256 256
#define BUFFER_SIZE_512 512
#define BUFFER_SIZE_1K 1024
#define BUFFER_SIZE_2K 2048
#define BUFFER_SIZE_4K 4096
#define BUFFER_SIZE_8K 8192
#define BUFFER_SIZE_16K 16384

/* Common string lengths */
#define STRING_LENGTH_32 32
#define STRING_LENGTH_64 64
#define STRING_LENGTH_128 128
#define STRING_LENGTH_256 256
#define STRING_LENGTH_512 512
#define STRING_LENGTH_1K 1024

/* Common time values */
#define TIME_MS_PER_SEC 1000
#define TIME_US_PER_MS 1000
#define TIME_NS_PER_US 1000
#define TIME_NS_PER_MS 1000000
#define TIME_NS_PER_SEC 1000000000

/* Common memory sizes */
#define SIZE_1K 1024
#define SIZE_2K 2048
#define SIZE_4K 4096
#define SIZE_8K 8192
#define SIZE_16K 16384
#define SIZE_32K 32768
#define SIZE_64K 65536
#define SIZE_128K 131072
#define SIZE_256K 262144
#define SIZE_512K 524288
#define SIZE_1M 1048576
#define SIZE_2M 2097152
#define SIZE_4M 4194304
#define SIZE_8M 8388608
#define SIZE_16M 16777216
#define SIZE_32M 33554432
#define SIZE_64M 67108864
#define SIZE_128M 134217728
#define SIZE_256M 268435456
#define SIZE_512M 536870912
#define SIZE_1G 1073741824

/* Common page sizes */
#define PAGE_SIZE_4K 4096
#define PAGE_SIZE_8K 8192
#define PAGE_SIZE_16K 16384
#define PAGE_SIZE_64K 65536
#define PAGE_SIZE_2M 2097152
#define PAGE_SIZE_4M 4194304
#define PAGE_SIZE_1G 1073741824

/* Common error codes */
#define OK 0
#define ERR -1
#define ERR_INVALID -2
#define ERR_NOMEM -3
#define ERR_NOTFOUND -4
#define ERR_EXISTS -5
#define ERR_ACCESS -6
#define ERR_TIMEOUT -7
#define ERR_BUSY -8
#define ERR_NOSUPPORT -9
#define ERR_IO -10

/* Common status codes */
#define STATUS_OK 0
#define STATUS_ERROR 1
#define STATUS_WARNING 2
#define STATUS_INFO 3
#define STATUS_DEBUG 4

#endif /* STDDEF_H */