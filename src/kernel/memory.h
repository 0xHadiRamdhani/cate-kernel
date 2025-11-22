#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Memory constants */
#define PAGE_SIZE 4096
#define PAGE_SIZE_2MB (2 * 1024 * 1024)
#define PAGE_SIZE_1GB (1024 * 1024 * 1024)

#define KERNEL_BASE 0xFFFFFFFF80000000ULL
#define KERNEL_HEAP_BASE 0xFFFF800000000000ULL
#define USER_BASE 0x400000

/* Page table entry flags */
#define PAGE_PRESENT    (1 << 0)
#define PAGE_WRITABLE   (1 << 1)
#define PAGE_USER       (1 << 2)
#define PAGE_WRITETHROUGH (1 << 3)
#define PAGE_CACHE_DISABLE (1 << 4)
#define PAGE_ACCESSED   (1 << 5)
#define PAGE_DIRTY      (1 << 6)
#define PAGE_HUGEPAGE   (1 << 7)
#define PAGE_GLOBAL     (1 << 8)
#define PAGE_NX         (1 << 63)

/* Memory types */
#define MEMORY_TYPE_AVAILABLE   1
#define MEMORY_TYPE_RESERVED    2
#define MEMORY_TYPE_ACPI_RECLAIM 3
#define MEMORY_TYPE_ACPI_NVS    4
#define MEMORY_TYPE_BAD_MEMORY  5
#define MEMORY_TYPE_KERNEL      6
#define MEMORY_TYPE_BOOTLOADER  7

/* Physical memory regions */
typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t type;
    uint32_t flags;
} memory_region_t;

/* Virtual memory area */
typedef struct vma {
    uint64_t start;
    uint64_t end;
    uint64_t flags;
    struct vma* next;
} vma_t;

/* Page structure */
typedef struct page {
    uint64_t physical_addr;
    uint64_t virtual_addr;
    uint32_t flags;
    uint32_t ref_count;
    struct page* next;
} page_t;

/* Memory context */
typedef struct {
    uint64_t* pml4;
    uint64_t* pdpt;
    uint64_t* pd;
    uint64_t* pt;
    vma_t* vma_list;
    page_t* page_list;
    uint64_t total_pages;
    uint64_t free_pages;
    uint64_t used_pages;
    uint64_t kernel_heap_start;
    uint64_t kernel_heap_end;
    uint64_t user_heap_start;
    uint64_t user_heap_end;
} memory_context_t;

/* Page table structures */
typedef struct {
    uint64_t entries[512];
} page_table_t;

typedef struct {
    page_table_t pml4;
    page_table_t pdpt;
    page_table_t pd;
    page_table_t pt;
} page_directory_t;

/* Function prototypes */
void memory_init(void);
void memory_init_paging(void);
void memory_init_heap(void);
void* memory_alloc_pages(uint32_t pages, uint32_t flags);
void memory_free_pages(void* addr, uint32_t pages);
void* memory_alloc_page(uint32_t flags);
void memory_free_page(void* addr);
uint64_t memory_get_physical_address(uint64_t virtual_addr);
uint64_t memory_get_virtual_address(uint64_t physical_addr);
bool memory_is_page_present(uint64_t addr);
bool memory_is_page_writable(uint64_t addr);
void memory_map_page(uint64_t virtual_addr, uint64_t physical_addr, uint32_t flags);
void memory_unmap_page(uint64_t virtual_addr);
void memory_protect_page(uint64_t addr, uint32_t flags);
void memory_flush_tlb(void);
void memory_enable_nx_bit(void);
void memory_enable_global_pages(void);

/* Physical memory management */
void pmm_init(uint64_t total_memory);
void* pmm_alloc_page(void);
void pmm_free_page(void* page);
uint64_t pmm_get_free_pages(void);
uint64_t pmm_get_used_pages(void);
uint64_t pmm_get_total_pages(void);

/* Virtual memory management */
void vmm_init(void);
void* vmm_alloc_pages(uint32_t pages, uint32_t flags);
void vmm_free_pages(void* addr, uint32_t pages);
void* vmm_map_physical(uint64_t physical_addr, uint32_t pages, uint32_t flags);
void vmm_unmap_physical(void* virtual_addr, uint32_t pages);
vma_t* vmm_find_vma(uint64_t addr);
vma_t* vmm_create_vma(uint64_t start, uint64_t end, uint64_t flags);
void vmm_destroy_vma(vma_t* vma);

/* Kernel heap management */
void* kmalloc(size_t size);
void* kmalloc_aligned(size_t size, uint32_t alignment);
void* kcalloc(size_t num, size_t size);
void* krealloc(void* ptr, size_t new_size);
void kfree(void* ptr);
void* kmap_page(uint64_t physical_addr);
void* kmap_pages(uint64_t physical_addr, uint32_t pages);
void kunmap_page(void* virtual_addr);
void kunmap_pages(void* virtual_addr, uint32_t pages);

/* User heap management */
void* umalloc(size_t size);
void* ucalloc(size_t num, size_t size);
void* urealloc(void* ptr, size_t new_size);
void ufree(void* ptr);

/* Memory utilities */
void memory_copy(void* dest, const void* src, size_t n);
void memory_set(void* dest, int value, size_t n);
int memory_compare(const void* s1, const void* s2, size_t n);
void memory_zero(void* dest, size_t n);

/* Memory debugging */
void memory_dump_page(uint64_t addr);
void memory_dump_region(uint64_t start, uint64_t end);
void memory_stats(void);
void memory_check_integrity(void);

/* Advanced features */
void memory_defragment(void);
void memory_compact(void);
void memory_swap_out(uint64_t addr);
void memory_swap_in(uint64_t addr);
bool memory_is_swapped(uint64_t addr);

/* Memory protection */
void memory_set_protection(uint64_t addr, uint32_t protection);
uint32_t memory_get_protection(uint64_t addr);
void memory_enable_protection(void);
void memory_disable_protection(void);

/* Huge pages support */
void memory_enable_huge_pages(void);
void* memory_alloc_huge_page(uint32_t flags);
void memory_free_huge_page(void* addr);
bool memory_is_huge_page(uint64_t addr);

/* Global variables */
extern memory_context_t* kernel_memory_context;
extern uint64_t total_physical_memory;
extern uint64_t available_physical_memory;
extern uint64_t kernel_physical_start;
extern uint64_t kernel_physical_end;

#endif /* MEMORY_H */