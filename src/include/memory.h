#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Memory constants */
#define PAGE_SIZE           4096
#define PAGE_SHIFT          12
#define PAGE_MASK           0xFFF
#define LARGE_PAGE_SIZE     0x200000  /* 2MB */
#define HUGE_PAGE_SIZE      0x40000000 /* 1GB */

/* Memory alignment */
#define PAGE_ALIGN(addr)    (((addr) + PAGE_MASK) & ~PAGE_MASK)
#define PAGE_ALIGN_DOWN(addr) ((addr) & ~PAGE_MASK)
#define IS_PAGE_ALIGNED(addr) (((addr) & PAGE_MASK) == 0)

/* Page table flags */
#define PAGE_PRESENT        0x001
#define PAGE_WRITABLE       0x002
#define PAGE_USER           0x004
#define PAGE_WRITETHROUGH   0x008
#define PAGE_CACHE_DISABLE  0x010
#define PAGE_ACCESSED       0x020
#define PAGE_DIRTY          0x040
#define PAGE_HUGE_PAGE      0x080
#define PAGE_GLOBAL         0x100
#define PAGE_COPY_ON_WRITE  0x200
#define PAGE_NO_EXECUTE     0x8000000000000000ULL

/* Memory regions */
#define KERNEL_BASE         0xFFFFFFFF80000000ULL
#define KERNEL_SIZE         0x40000000 /* 1GB */
#define USER_BASE           0x0000000000400000ULL
#define USER_SIZE           0x7FFFFC0000 /* 128GB */
#define KERNEL_HEAP_BASE    0xFFFFFFFFC0000000ULL
#define KERNEL_HEAP_SIZE    0x10000000 /* 256MB */
#define KERNEL_HEAP_LIMIT   (KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE)

/* Page table locations */
#define KERNEL_PAGE_DIR     0xFFFFFFFFC0100000ULL
#define KERNEL_PAGE_TABLES  0xFFFFFFFFC0200000ULL

/* Invalid page address */
#define INVALID_PAGE        0xFFFFFFFFFFFFFFFFULL

/* Memory map types */
#define MEMORY_AVAILABLE    1
#define MEMORY_RESERVED     2
#define MEMORY_ACPI_RECLAIM 3
#define MEMORY_ACPI_NVS     4
#define MEMORY_BAD          5

/* Heap block structure */
typedef struct heap_block {
    size_t size;
    bool free;
    struct heap_block* next;
    struct heap_block* prev;
} heap_block_t;

/* Memory statistics */
typedef struct {
    uint64_t total_memory;
    uint64_t free_memory;
    uint64_t used_memory;
    uint64_t reserved_memory;
    uint64_t total_pages;
    uint64_t free_pages;
    uint64_t used_pages;
    uint64_t reserved_pages;
    uint64_t heap_size;
    uint64_t heap_used;
    uint64_t heap_free;
    uint32_t allocation_count;
    uint32_t free_count;
} memory_statistics_t;

/* Initialize memory management */
void memory_init(uint64_t total_memory);

/* Basic memory allocation */
void* kmalloc(size_t size);
void kfree(void* ptr);

/* Aligned memory allocation */
void* kmalloc_aligned(size_t size, size_t alignment);
void kfree_aligned(void* ptr);

/* Physical memory management */
uint64_t allocate_physical_pages(uint64_t page_count);
void free_physical_pages(uint64_t physical_addr, uint64_t page_count);

/* Virtual memory management */
bool map_virtual_page(uint64_t virtual_addr, uint64_t physical_addr, uint64_t flags);
void unmap_virtual_page(uint64_t virtual_addr);

/* Memory statistics */
void get_memory_statistics(memory_statistics_t* stats);
uint64_t get_total_memory(void);
uint64_t get_free_memory(void);
uint64_t get_used_memory(void);

/* Memory validation */
bool validate_memory(const void* ptr, size_t size);

/* Memory utilities */
void memory_dump(const void* ptr, size_t size, size_t bytes_per_line);
void memory_test(void);
void memory_defragment(void);
void memory_cleanup(void);
void memory_manager_info(void);

/* Memory allocation macros */
#define KMALLOC(size) kmalloc(size)
#define KFREE(ptr) kfree(ptr)
#define KMALLOC_ALIGNED(size, alignment) kmalloc_aligned(size, alignment)
#define KFREE_ALIGNED(ptr) kfree_aligned(ptr)

/* Page allocation macros */
#define ALLOCATE_PAGES(count) allocate_physical_pages(count)
#define FREE_PAGES(addr, count) free_physical_pages(addr, count)

/* Memory validation macros */
#define VALIDATE_MEMORY(ptr, size) validate_memory(ptr, size)
#define IS_VALID_POINTER(ptr) ((ptr) != NULL)

/* Memory debugging macros */
#define MEMORY_DUMP(ptr, size) memory_dump(ptr, size, 16)
#define MEMORY_TEST() memory_test()
#define MEMORY_INFO() memory_manager_info()

/* Memory constants for debugging */
#define MEMORY_DEBUG_ENABLED
#define MEMORY_LEAK_DETECTION
#define MEMORY_CORRUPTION_DETECTION
#define MEMORY_STATISTICS

/* Memory allocation tracking */
#ifdef MEMORY_DEBUG_ENABLED
#define KMALLOC_DEBUG(size, file, line) ({ \
    void* ptr = kmalloc(size); \
    if (ptr != NULL) { \
        DEBUG_MEMORY_ALLOC(ptr, size, __FUNCTION__, file, line); \
    } \
    ptr; \
})

#define KFREE_DEBUG(ptr, file, line) do { \
    if (ptr != NULL) { \
        DEBUG_MEMORY_FREE(ptr, __FUNCTION__, file, line); \
    } \
    kfree(ptr); \
} while (0)
#else
#define KMALLOC_DEBUG(size, file, line) kmalloc(size)
#define KFREE_DEBUG(ptr, file, line) kfree(ptr)
#endif

/* Memory allocation with zeroing */
static inline void* kmallocz(size_t size) {
    void* ptr = kmalloc(size);
    if (ptr != NULL) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/* Memory allocation for arrays */
static inline void* kmalloc_array(size_t nmemb, size_t size) {
    if (nmemb == 0 || size == 0) {
        return NULL;
    }
    if (nmemb > SIZE_MAX / size) {
        return NULL; /* Overflow check */
    }
    return kmalloc(nmemb * size);
}

/* Memory reallocation */
void* krealloc(void* ptr, size_t new_size);

/* Memory allocation with cleanup */
#define KMALLOC_CLEANUP(size, cleanup) ({ \
    void* ptr = kmalloc(size); \
    if (ptr == NULL) { \
        cleanup; \
    } \
    ptr; \
})

/* Memory allocation with error handling */
#define KMALLOC_CHECK(size, error_label) ({ \
    void* ptr = kmalloc(size); \
    if (ptr == NULL) { \
        KERNEL_LOG(LOG_ERROR, "Memory", "Failed to allocate %zu bytes", size); \
        goto error_label; \
    } \
    ptr; \
})

/* Memory allocation with assertion */
#define KMALLOC_ASSERT(size) ({ \
    void* ptr = kmalloc(size); \
    ASSERT(ptr != NULL); \
    ptr; \
})

#endif /* MEMORY_H */