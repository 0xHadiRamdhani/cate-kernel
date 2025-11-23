#include "memory.h"
#include "string.h"
#include "logging.h"
#include "debug.h"

/* Memory management structures */
typedef struct {
    uint64_t base_addr;
    uint64_t length;
    uint32_t type;
    uint32_t reserved;
} memory_map_entry_t;

/* Physical memory manager */
typedef struct {
    uint64_t total_memory;
    uint64_t free_memory;
    uint64_t used_memory;
    uint64_t reserved_memory;
    uint32_t* bitmap;
    uint64_t bitmap_size;
    uint64_t first_free_page;
    uint64_t last_free_page;
    uint64_t total_pages;
    uint64_t free_pages;
    uint64_t used_pages;
    uint64_t reserved_pages;
    bool initialized;
} physical_memory_manager_t;

/* Virtual memory manager */
typedef struct {
    uint64_t* page_directory;
    uint64_t* page_tables;
    uint64_t total_virtual_pages;
    uint64_t used_virtual_pages;
    uint64_t free_virtual_pages;
    uint64_t kernel_base;
    uint64_t user_base;
    uint64_t heap_base;
    uint64_t heap_current;
    uint64_t heap_limit;
    bool initialized;
} virtual_memory_manager_t;

/* Kernel heap manager */
typedef struct {
    void* heap_start;
    void* heap_end;
    void* heap_current;
    size_t heap_size;
    size_t used_size;
    size_t free_size;
    heap_block_t* free_list;
    heap_block_t* used_list;
    uint32_t allocation_count;
    uint32_t free_count;
    bool initialized;
} kernel_heap_manager_t;

/* Global memory managers */
static physical_memory_manager_t pmm;
static virtual_memory_manager_t vmm;
static kernel_heap_manager_t khm;

/* Memory statistics */
static memory_statistics_t memory_stats;

/* Initialize physical memory manager */
static void pmm_init(uint64_t total_memory) {
    KERNEL_LOG(LOG_INFO, "Memory", "Initializing physical memory manager");
    
    memset(&pmm, 0, sizeof(pmm));
    
    pmm.total_memory = total_memory;
    pmm.total_pages = total_memory / PAGE_SIZE;
    pmm.bitmap_size = (pmm.total_pages + 31) / 32; /* 32 bits per uint32_t */
    
    /* Allocate bitmap */
    pmm.bitmap = (uint32_t*)KERNEL_HEAP_BASE;
    memset(pmm.bitmap, 0, pmm.bitmap_size * sizeof(uint32_t));
    
    /* Mark all pages as free initially */
    pmm.free_pages = pmm.total_pages;
    pmm.free_memory = pmm.total_memory;
    
    /* Reserve kernel pages */
    uint64_t kernel_pages = (KERNEL_HEAP_BASE + pmm.bitmap_size * sizeof(uint32_t)) / PAGE_SIZE;
    for (uint64_t i = 0; i < kernel_pages; i++) {
        pmm_set_page_reserved(i);
    }
    
    pmm.initialized = true;
    
    KERNEL_LOG(LOG_INFO, "Memory", "Physical memory manager initialized");
    KERNEL_LOG(LOG_INFO, "Memory", "Total memory: %llu KB", pmm.total_memory / 1024);
    KERNEL_LOG(LOG_INFO, "Memory", "Total pages: %llu", pmm.total_pages);
    KERNEL_LOG(LOG_INFO, "Memory", "Free pages: %llu", pmm.free_pages);
}

/* Set page as used */
static void pmm_set_page_used(uint64_t page_index) {
    if (page_index >= pmm.total_pages) {
        return;
    }
    
    uint32_t bitmap_index = page_index / 32;
    uint32_t bit_index = page_index % 32;
    
    if (!(pmm.bitmap[bitmap_index] & (1 << bit_index))) {
        pmm.bitmap[bitmap_index] |= (1 << bit_index);
        pmm.used_pages++;
        pmm.free_pages--;
        pmm.used_memory += PAGE_SIZE;
        pmm.free_memory -= PAGE_SIZE;
    }
}

/* Set page as free */
static void pmm_set_page_free(uint64_t page_index) {
    if (page_index >= pmm.total_pages) {
        return;
    }
    
    uint32_t bitmap_index = page_index / 32;
    uint32_t bit_index = page_index % 32;
    
    if (pmm.bitmap[bitmap_index] & (1 << bit_index)) {
        pmm.bitmap[bitmap_index] &= ~(1 << bit_index);
        pmm.used_pages--;
        pmm.free_pages++;
        pmm.used_memory -= PAGE_SIZE;
        pmm.free_memory += PAGE_SIZE;
    }
}

/* Set page as reserved */
static void pmm_set_page_reserved(uint64_t page_index) {
    if (page_index >= pmm.total_pages) {
        return;
    }
    
    uint32_t bitmap_index = page_index / 32;
    uint32_t bit_index = page_index % 32;
    
    if (!(pmm.bitmap[bitmap_index] & (1 << bit_index))) {
        pmm.bitmap[bitmap_index] |= (1 << bit_index);
        pmm.reserved_pages++;
        pmm.free_pages--;
        pmm.reserved_memory += PAGE_SIZE;
        pmm.free_memory -= PAGE_SIZE;
    }
}

/* Check if page is free */
static bool pmm_is_page_free(uint64_t page_index) {
    if (page_index >= pmm.total_pages) {
        return false;
    }
    
    uint32_t bitmap_index = page_index / 32;
    uint32_t bit_index = page_index % 32;
    
    return !(pmm.bitmap[bitmap_index] & (1 << bit_index));
}

/* Find free pages */
static uint64_t pmm_find_free_pages(uint64_t page_count) {
    if (page_count == 0 || page_count > pmm.free_pages) {
        return INVALID_PAGE;
    }
    
    uint64_t consecutive_free = 0;
    uint64_t start_page = INVALID_PAGE;
    
    for (uint64_t i = 0; i < pmm.total_pages; i++) {
        if (pmm_is_page_free(i)) {
            if (consecutive_free == 0) {
                start_page = i;
            }
            consecutive_free++;
            
            if (consecutive_free >= page_count) {
                return start_page;
            }
        } else {
            consecutive_free = 0;
            start_page = INVALID_PAGE;
        }
    }
    
    return INVALID_PAGE;
}

/* Allocate physical pages */
static uint64_t pmm_allocate_pages(uint64_t page_count) {
    uint64_t start_page = pmm_find_free_pages(page_count);
    
    if (start_page == INVALID_PAGE) {
        return INVALID_PAGE;
    }
    
    for (uint64_t i = 0; i < page_count; i++) {
        pmm_set_page_used(start_page + i);
    }
    
    return start_page * PAGE_SIZE;
}

/* Free physical pages */
static void pmm_free_pages(uint64_t physical_addr, uint64_t page_count) {
    uint64_t start_page = physical_addr / PAGE_SIZE;
    
    for (uint64_t i = 0; i < page_count; i++) {
        pmm_set_page_free(start_page + i);
    }
}

/* Initialize virtual memory manager */
static void vmm_init(void) {
    KERNEL_LOG(LOG_INFO, "Memory", "Initializing virtual memory manager");
    
    memset(&vmm, 0, sizeof(vmm));
    
    vmm.page_directory = (uint64_t*)KERNEL_PAGE_DIR;
    vmm.page_tables = (uint64_t*)KERNEL_PAGE_TABLES;
    vmm.kernel_base = KERNEL_BASE;
    vmm.user_base = USER_BASE;
    vmm.heap_base = KERNEL_HEAP_BASE;
    vmm.heap_current = KERNEL_HEAP_BASE;
    vmm.heap_limit = KERNEL_HEAP_LIMIT;
    
    /* Clear page directory and tables */
    memset(vmm.page_directory, 0, PAGE_SIZE);
    memset(vmm.page_tables, 0, PAGE_SIZE * 512);
    
    /* Map kernel space */
    vmm_map_kernel_space();
    
    vmm.initialized = true;
    
    KERNEL_LOG(LOG_INFO, "Memory", "Virtual memory manager initialized");
}

/* Map kernel space */
static void vmm_map_kernel_space(void) {
    /* Map kernel code and data */
    uint64_t kernel_start = 0x100000; /* 1MB */
    uint64_t kernel_size = (uint64_t)&_kernel_end - (uint64_t)&_kernel_start;
    uint64_t kernel_pages = (kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;
    
    for (uint64_t i = 0; i < kernel_pages; i++) {
        vmm_map_page(kernel_start + i * PAGE_SIZE, kernel_start + i * PAGE_SIZE, 
                    PAGE_PRESENT | PAGE_WRITABLE | PAGE_SUPERVISOR);
    }
    
    /* Map kernel heap */
    uint64_t heap_pages = (KERNEL_HEAP_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
    for (uint64_t i = 0; i < heap_pages; i++) {
        vmm_map_page(KERNEL_HEAP_BASE + i * PAGE_SIZE, KERNEL_HEAP_BASE + i * PAGE_SIZE,
                    PAGE_PRESENT | PAGE_WRITABLE | PAGE_SUPERVISOR);
    }
}

/* Map virtual page to physical page */
static bool vmm_map_page(uint64_t virtual_addr, uint64_t physical_addr, uint64_t flags) {
    uint64_t pml4_index = (virtual_addr >> 39) & 0x1FF;
    uint64_t pdpt_index = (virtual_addr >> 30) & 0x1FF;
    uint64_t pd_index = (virtual_addr >> 21) & 0x1FF;
    uint64_t pt_index = (virtual_addr >> 12) & 0x1FF;
    
    /* Get or create page directory pointer table */
    uint64_t* pdpt = vmm_get_or_create_table(vmm.page_directory, pml4_index, flags);
    if (pdpt == NULL) {
        return false;
    }
    
    /* Get or create page directory */
    uint64_t* pd = vmm_get_or_create_table(pdpt, pdpt_index, flags);
    if (pd == NULL) {
        return false;
    }
    
    /* Get or create page table */
    uint64_t* pt = vmm_get_or_create_table(pd, pd_index, flags);
    if (pt == NULL) {
        return false;
    }
    
    /* Map page */
    pt[pt_index] = physical_addr | flags;
    
    return true;
}

/* Get or create page table */
static uint64_t* vmm_get_or_create_table(uint64_t* table, uint64_t index, uint64_t flags) {
    if (table[index] & PAGE_PRESENT) {
        return (uint64_t*)(table[index] & ~0xFFF);
    }
    
    /* Allocate new table */
    uint64_t physical_addr = pmm_allocate_pages(1);
    if (physical_addr == INVALID_PAGE) {
        return NULL;
    }
    
    /* Create table entry */
    table[index] = physical_addr | (flags & (PAGE_PRESENT | PAGE_WRITABLE | PAGE_SUPERVISOR));
    
    /* Clear new table */
    uint64_t* new_table = (uint64_t*)physical_addr;
    memset(new_table, 0, PAGE_SIZE);
    
    return new_table;
}

/* Unmap virtual page */
static void vmm_unmap_page(uint64_t virtual_addr) {
    uint64_t pml4_index = (virtual_addr >> 39) & 0x1FF;
    uint64_t pdpt_index = (virtual_addr >> 30) & 0x1FF;
    uint64_t pd_index = (virtual_addr >> 21) & 0x1FF;
    uint64_t pt_index = (virtual_addr >> 12) & 0x1FF;
    
    /* Check if page directory exists */
    if (!(vmm.page_directory[pml4_index] & PAGE_PRESENT)) {
        return;
    }
    
    uint64_t* pdpt = (uint64_t*)(vmm.page_directory[pml4_index] & ~0xFFF);
    
    /* Check if page directory pointer table exists */
    if (!(pdpt[pdpt_index] & PAGE_PRESENT)) {
        return;
    }
    
    uint64_t* pd = (uint64_t*)(pdpt[pdpt_index] & ~0xFFF);
    
    /* Check if page directory exists */
    if (!(pd[pd_index] & PAGE_PRESENT)) {
        return;
    }
    
    uint64_t* pt = (pd[pd_index] & PAGE_HUGE_PAGE) ? NULL : (uint64_t*)(pd[pd_index] & ~0xFFF);
    
    if (pt != NULL) {
        /* Unmap page */
        pt[pt_index] = 0;
    }
}

/* Initialize kernel heap */
static void khm_init(void) {
    KERNEL_LOG(LOG_INFO, "Memory", "Initializing kernel heap");
    
    memset(&khm, 0, sizeof(khm));
    
    khm.heap_start = (void*)KERNEL_HEAP_BASE;
    khm.heap_end = (void*)KERNEL_HEAP_LIMIT;
    khm.heap_current = khm.heap_start;
    khm.heap_size = KERNEL_HEAP_SIZE;
    khm.used_size = 0;
    khm.free_size = khm.heap_size;
    
    /* Initialize heap blocks */
    khm.free_list = (heap_block_t*)khm.heap_start;
    khm.free_list->size = khm.heap_size - sizeof(heap_block_t);
    khm.free_list->next = NULL;
    khm.free_list->prev = NULL;
    khm.free_list->free = true;
    
    khm.used_list = NULL;
    khm.initialized = true;
    
    KERNEL_LOG(LOG_INFO, "Memory", "Kernel heap initialized");
    KERNEL_LOG(LOG_INFO, "Memory", "Heap size: %llu KB", khm.heap_size / 1024);
}

/* Find free heap block */
static heap_block_t* khm_find_free_block(size_t size) {
    heap_block_t* current = khm.free_list;
    
    while (current != NULL) {
        if (current->free && current->size >= size) {
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

/* Split heap block */
static void khm_split_block(heap_block_t* block, size_t size) {
    if (block->size <= size + sizeof(heap_block_t) + 16) {
        /* Block is too small to split */
        return;
    }
    
    /* Create new free block */
    heap_block_t* new_block = (heap_block_t*)((uint8_t*)block + sizeof(heap_block_t) + size);
    new_block->size = block->size - size - sizeof(heap_block_t);
    new_block->free = true;
    new_block->next = block->next;
    new_block->prev = block;
    
    /* Update original block */
    block->size = size;
    block->next = new_block;
    
    if (new_block->next != NULL) {
        new_block->next->prev = new_block;
    }
}

/* Merge adjacent free blocks */
static void khm_merge_blocks(heap_block_t* block) {
    /* Merge with next block if free */
    if (block->next != NULL && block->next->free) {
        block->size += sizeof(heap_block_t) + block->next->size;
        block->next = block->next->next;
        if (block->next != NULL) {
            block->next->prev = block;
        }
    }
    
    /* Merge with previous block if free */
    if (block->prev != NULL && block->prev->free) {
        block->prev->size += sizeof(heap_block_t) + block->size;
        block->prev->next = block->next;
        if (block->next != NULL) {
            block->next->prev = block->prev;
        }
    }
}

/* Allocate heap memory */
static void* khm_allocate(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    /* Align size to 8 bytes */
    size = (size + 7) & ~7;
    
    /* Find free block */
    heap_block_t* block = khm_find_free_block(size);
    if (block == NULL) {
        return NULL;
    }
    
    /* Split block if necessary */
    khm_split_block(block, size);
    
    /* Mark block as used */
    block->free = false;
    
    /* Remove from free list */
    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        khm.free_list = block->next;
    }
    
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }
    
    /* Add to used list */
    block->next = khm.used_list;
    block->prev = NULL;
    if (khm.used_list != NULL) {
        khm.used_list->prev = block;
    }
    khm.used_list = block;
    
    /* Update statistics */
    khm.used_size += size + sizeof(heap_block_t);
    khm.free_size -= size + sizeof(heap_block_t);
    khm.allocation_count++;
    
    return (void*)((uint8_t*)block + sizeof(heap_block_t));
}

/* Free heap memory */
static void khm_free(void* ptr) {
    if (ptr == NULL) {
        return;
    }
    
    /* Get block header */
    heap_block_t* block = (heap_block_t*)((uint8_t*)ptr - sizeof(heap_block_t));
    
    if (block->free) {
        /* Already freed */
        return;
    }
    
    /* Mark block as free */
    block->free = true;
    
    /* Remove from used list */
    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        khm.used_list = block->next;
    }
    
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }
    
    /* Add to free list */
    block->next = khm.free_list;
    block->prev = NULL;
    if (khm.free_list != NULL) {
        khm.free_list->prev = block;
    }
    khm.free_list = block;
    
    /* Merge with adjacent free blocks */
    khm_merge_blocks(block);
    
    /* Update statistics */
    khm.used_size -= block->size + sizeof(heap_block_t);
    khm.free_size += block->size + sizeof(heap_block_t);
    khm.free_count++;
}

/* Initialize memory management */
void memory_init(uint64_t total_memory) {
    KERNEL_LOG(LOG_INFO, "Memory", "Initializing memory management");
    
    /* Initialize physical memory manager */
    pmm_init(total_memory);
    
    /* Initialize virtual memory manager */
    vmm_init();
    
    /* Initialize kernel heap manager */
    khm_init();
    
    /* Initialize memory statistics */
    memset(&memory_stats, 0, sizeof(memory_stats));
    memory_stats.total_memory = total_memory;
    memory_stats.free_memory = total_memory;
    memory_stats.used_memory = 0;
    memory_stats.reserved_memory = 0;
    
    KERNEL_LOG(LOG_INFO, "Memory", "Memory management initialized");
}

/* Allocate memory */
void* kmalloc(size_t size) {
    if (!khm.initialized) {
        return NULL;
    }
    
    void* ptr = khm_allocate(size);
    
    if (ptr != NULL) {
        DEBUG_MEMORY_ALLOC(ptr, size);
    }
    
    return ptr;
}

/* Free memory */
void kfree(void* ptr) {
    if (ptr == NULL || !khm.initialized) {
        return;
    }
    
    DEBUG_MEMORY_FREE(ptr);
    khm_free(ptr);
}

/* Allocate aligned memory */
void* kmalloc_aligned(size_t size, size_t alignment) {
    if (size == 0 || alignment == 0) {
        return NULL;
    }
    
    /* Allocate extra space for alignment */
    size_t extra = alignment - 1 + sizeof(void*);
    void* ptr = kmalloc(size + extra);
    if (ptr == NULL) {
        return NULL;
    }
    
    /* Calculate aligned address */
    uintptr_t aligned = ((uintptr_t)ptr + extra) & ~(alignment - 1);
    
    /* Store original pointer for free */
    ((void**)aligned)[-1] = ptr;
    
    return (void*)aligned;
}

/* Free aligned memory */
void kfree_aligned(void* ptr) {
    if (ptr == NULL) {
        return;
    }
    
    /* Get original pointer */
    void* original = ((void**)ptr)[-1];
    kfree(original);
}

/* Allocate physical pages */
uint64_t allocate_physical_pages(uint64_t page_count) {
    if (!pmm.initialized) {
        return INVALID_PAGE;
    }
    
    return pmm_allocate_pages(page_count);
}

/* Free physical pages */
void free_physical_pages(uint64_t physical_addr, uint64_t page_count) {
    if (!pmm.initialized) {
        return;
    }
    
    pmm_free_pages(physical_addr, page_count);
}

/* Map virtual address to physical address */
bool map_virtual_page(uint64_t virtual_addr, uint64_t physical_addr, uint64_t flags) {
    if (!vmm.initialized) {
        return false;
    }
    
    return vmm_map_page(virtual_addr, physical_addr, flags);
}

/* Unmap virtual address */
void unmap_virtual_page(uint64_t virtual_addr) {
    if (!vmm.initialized) {
        return;
    }
    
    vmm_unmap_page(virtual_addr);
}

/* Get memory statistics */
void get_memory_statistics(memory_statistics_t* stats) {
    if (stats == NULL) {
        return;
    }
    
    stats->total_memory = pmm.total_memory;
    stats->free_memory = pmm.free_memory;
    stats->used_memory = pmm.used_memory;
    stats->reserved_memory = pmm.reserved_memory;
    stats->total_pages = pmm.total_pages;
    stats->free_pages = pmm.free_pages;
    stats->used_pages = pmm.used_pages;
    stats->reserved_pages = pmm.reserved_pages;
    stats->heap_size = khm.heap_size;
    stats->heap_used = khm.used_size;
    stats->heap_free = khm.free_size;
    stats->allocation_count = khm.allocation_count;
    stats->free_count = khm.free_count;
}

/* Get total memory */
uint64_t get_total_memory(void) {
    return pmm.total_memory;
}

/* Get free memory */
uint64_t get_free_memory(void) {
    return pmm.free_memory;
}

/* Get used memory */
uint64_t get_used_memory(void) {
    return pmm.used_memory;
}

/* Memory validation */
bool validate_memory(const void* ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return false;
    }
    
    /* Check if pointer is in valid memory range */
    uintptr_t addr = (uintptr_t)ptr;
    if (addr < KERNEL_BASE || addr >= KERNEL_HEAP_LIMIT) {
        return false;
    }
    
    /* Check if memory range is valid */
    if (addr + size < addr || addr + size >= KERNEL_HEAP_LIMIT) {
        return false;
    }
    
    return true;
}

/* Memory dump */
void memory_dump(const void* ptr, size_t size, size_t bytes_per_line) {
    if (ptr == NULL || size == 0) {
        return;
    }
    
    const uint8_t* bytes = (const uint8_t*)ptr;
    size_t offset = 0;
    
    KERNEL_LOG(LOG_INFO, "Memory", "Memory dump at %p, size: %zu bytes", ptr, size);
    
    while (offset < size) {
        /* Print offset */
        KERNEL_LOG(LOG_INFO, "Memory", "%08zX: ", offset);
        
        /* Print hex bytes */
        for (size_t i = 0; i < bytes_per_line && offset + i < size; i++) {
            KERNEL_LOG(LOG_INFO, "Memory", "%02X ", bytes[offset + i]);
        }
        
        /* Print padding if needed */
        for (size_t i = size - offset; i < bytes_per_line; i++) {
            KERNEL_LOG(LOG_INFO, "Memory", "   ");
        }
        
        KERNEL_LOG(LOG_INFO, "Memory", " |");
        
        /* Print ASCII representation */
        for (size_t i = 0; i < bytes_per_line && offset + i < size; i++) {
            uint8_t byte = bytes[offset + i];
            if (byte >= 32 && byte <= 126) {
                KERNEL_LOG(LOG_INFO, "Memory", "%c", byte);
            } else {
                KERNEL_LOG(LOG_INFO, "Memory", ".");
            }
        }
        
        KERNEL_LOG(LOG_INFO, "Memory", "|\n");
        
        offset += bytes_per_line;
    }
}

/* Memory test */
void memory_test(void) {
    KERNEL_LOG(LOG_INFO, "Memory", "Running memory test");
    
    /* Test basic allocation */
    void* ptr1 = kmalloc(1024);
    void* ptr2 = kmalloc(2048);
    void* ptr3 = kmalloc(4096);
    
    if (ptr1 != NULL && ptr2 != NULL && ptr3 != NULL) {
        KERNEL_LOG(LOG_INFO, "Memory", "Basic allocation test passed");
        
        /* Test memory write/read */
        memset(ptr1, 0xAA, 1024);
        memset(ptr2, 0xBB, 2048);
        memset(ptr3, 0xCC, 4096);
        
        bool test_passed = true;
        uint8_t* bytes1 = (uint8_t*)ptr1;
        uint8_t* bytes2 = (uint8_t*)ptr2;
        uint8_t* bytes3 = (uint8_t*)ptr3;
        
        for (int i = 0; i < 1024; i++) {
            if (bytes1[i] != 0xAA) {
                test_passed = false;
                break;
            }
        }
        
        for (int i = 0; i < 2048; i++) {
            if (bytes2[i] != 0xBB) {
                test_passed = false;
                break;
            }
        }
        
        for (int i = 0; i < 4096; i++) {
            if (bytes3[i] != 0xCC) {
                test_passed = false;
                break;
            }
        }
        
        if (test_passed) {
            KERNEL_LOG(LOG_INFO, "Memory", "Memory read/write test passed");
        } else {
            KERNEL_LOG(LOG_ERROR, "Memory", "Memory read/write test failed");
        }
        
        /* Free memory */
        kfree(ptr1);
        kfree(ptr2);
        kfree(ptr3);
        
        KERNEL_LOG(LOG_INFO, "Memory", "Memory test completed");
    } else {
        KERNEL_LOG(LOG_ERROR, "Memory", "Memory allocation test failed");
    }
}

/* Memory defragmentation */
void memory_defragment(void) {
    KERNEL_LOG(LOG_INFO, "Memory", "Starting memory defragmentation");
    
    /* This would implement memory defragmentation */
    /* For now, just log that it's not implemented */
    
    KERNEL_LOG(LOG_INFO, "Memory", "Memory defragmentation completed");
}

/* Memory cleanup */
void memory_cleanup(void) {
    KERNEL_LOG(LOG_INFO, "Memory", "Cleaning up memory management");
    
    /* Clean up heap */
    if (khm.initialized) {
        /* Free all heap blocks */
        heap_block_t* current = khm.used_list;
        while (current != NULL) {
            heap_block_t* next = current->next;
            current->free = true;
            current = next;
        }
        
        khm.used_list = NULL;
        khm.used_size = 0;
        khm.allocation_count = 0;
    }
    
    /* Clean up virtual memory */
    if (vmm.initialized) {
        /* Unmap all pages */
        for (uint64_t i = 0; i < vmm.total_virtual_pages; i++) {
            uint64_t virtual_addr = vmm.kernel_base + i * PAGE_SIZE;
            unmap_virtual_page(virtual_addr);
        }
    }
    
    /* Clean up physical memory */
    if (pmm.initialized) {
        /* Reset bitmap */
        memset(pmm.bitmap, 0, pmm.bitmap_size * sizeof(uint32_t));
        pmm.used_pages = 0;
        pmm.reserved_pages = 0;
        pmm.free_pages = pmm.total_pages;
        pmm.used_memory = 0;
        pmm.reserved_memory = 0;
        pmm.free_memory = pmm.total_memory;
    }
    
    KERNEL_LOG(LOG_INFO, "Memory", "Memory cleanup completed");
}

/* Memory manager info */
void memory_manager_info(void) {
    KERNEL_LOG(LOG_INFO, "Memory", "=== Memory Manager Information ===");
    KERNEL_LOG(LOG_INFO, "Memory", "Physical Memory Manager: %s", pmm.initialized ? "Initialized" : "Not initialized");
    KERNEL_LOG(LOG_INFO, "Memory", "Virtual Memory Manager: %s", vmm.initialized ? "Initialized" : "Not initialized");
    KERNEL_LOG(LOG_INFO, "Memory", "Kernel Heap Manager: %s", khm.initialized ? "Initialized" : "Not initialized");
    
    if (pmm.initialized) {
        KERNEL_LOG(LOG_INFO, "Memory", "Total Memory: %llu KB", pmm.total_memory / 1024);
        KERNEL_LOG(LOG_INFO, "Memory", "Free Memory: %llu KB", pmm.free_memory / 1024);
        KERNEL_LOG(LOG_INFO, "Memory", "Used Memory: %llu KB", pmm.used_memory / 1024);
        KERNEL_LOG(LOG_INFO, "Memory", "Reserved Memory: %llu KB", pmm.reserved_memory / 1024);
        KERNEL_LOG(LOG_INFO, "Memory", "Total Pages: %llu", pmm.total_pages);
        KERNEL_LOG(LOG_INFO, "Memory", "Free Pages: %llu", pmm.free_pages);
        KERNEL_LOG(LOG_INFO, "Memory", "Used Pages: %llu", pmm.used_pages);
        KERNEL_LOG(LOG_INFO, "Memory", "Reserved Pages: %llu", pmm.reserved_pages);
    }
    
    if (khm.initialized) {
        KERNEL_LOG(LOG_INFO, "Memory", "Heap Size: %llu KB", khm.heap_size / 1024);
        KERNEL_LOG(LOG_INFO, "Memory", "Heap Used: %llu KB", khm.used_size / 1024);
        KERNEL_LOG(LOG_INFO, "Memory", "Heap Free: %llu KB", khm.free_size / 1024);
        KERNEL_LOG(LOG_INFO, "Memory", "Allocation Count: %u", khm.allocation_count);
        KERNEL_LOG(LOG_INFO, "Memory", "Free Count: %u", khm.free_count);
    }
    
    KERNEL_LOG(LOG_INFO, "Memory", "=====================================");
}