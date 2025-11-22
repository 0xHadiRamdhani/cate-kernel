#include "memory.h"
#include "../boot/multiboot2.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Global memory context */
memory_context_t* kernel_memory_context = NULL;
uint64_t total_physical_memory = 0;
uint64_t available_physical_memory = 0;
uint64_t kernel_physical_start = 0;
uint64_t kernel_physical_end = 0;

/* Physical memory bitmap */
static uint32_t* physical_memory_bitmap = NULL;
static uint64_t physical_memory_bitmap_size = 0;
static uint64_t total_physical_pages = 0;
static uint64_t used_physical_pages = 0;

/* Kernel heap */
static uint8_t* kernel_heap_start = NULL;
static uint8_t* kernel_heap_end = NULL;
static uint8_t* kernel_heap_current = NULL;
static size_t kernel_heap_size = 0;

/* Page table structures */
static page_directory_t* kernel_page_directory = NULL;
static uint64_t* kernel_pml4 = NULL;
static uint64_t* kernel_pdpt = NULL;
static uint64_t* kernel_pd = NULL;
static uint64_t* kernel_pt = NULL;

/* Memory regions from bootloader */
static memory_region_t memory_regions[64];
static uint32_t memory_region_count = 0;

/* Function prototypes */
static void memory_map_region(uint64_t start, uint64_t end, uint32_t flags);
static void memory_unmap_region(uint64_t start, uint64_t end);
static uint64_t memory_find_free_page(void);
static void memory_mark_page_used(uint64_t page);
static void memory_mark_page_free(uint64_t page);
static bool memory_is_page_free(uint64_t page);
static void memory_setup_page_tables(void);
static void memory_enable_paging(void);

/* Initialize memory management */
void memory_init(void) {
    /* Initialize physical memory management */
    pmm_init(total_physical_memory);
    
    /* Initialize virtual memory management */
    vmm_init();
    
    /* Initialize kernel heap */
    memory_init_heap();
    
    /* Setup page tables */
    memory_setup_page_tables();
    
    /* Enable paging */
    memory_enable_paging();
    
    /* Enable security features */
    memory_enable_nx_bit();
    memory_enable_global_pages();
    
    /* Create kernel memory context */
    kernel_memory_context = (memory_context_t*)kmalloc(sizeof(memory_context_t));
    if (kernel_memory_context) {
        kernel_memory_context->pml4 = kernel_pml4;
        kernel_memory_context->pdpt = kernel_pdpt;
        kernel_memory_context->pd = kernel_pd;
        kernel_memory_context->pt = kernel_pt;
        kernel_memory_context->vma_list = NULL;
        kernel_memory_context->page_list = NULL;
        kernel_memory_context->total_pages = total_physical_pages;
        kernel_memory_context->free_pages = total_physical_pages - used_physical_pages;
        kernel_memory_context->used_pages = used_physical_pages;
        kernel_memory_context->kernel_heap_start = (uint64_t)kernel_heap_start;
        kernel_memory_context->kernel_heap_end = (uint64_t)kernel_heap_end;
    }
}

/* Initialize physical memory management */
void pmm_init(uint64_t total_memory) {
    total_physical_memory = total_memory;
    total_physical_pages = total_memory / PAGE_SIZE;
    
    /* Calculate bitmap size (1 bit per page) */
    physical_memory_bitmap_size = (total_physical_pages + 31) / 32;
    physical_memory_bitmap_size = (physical_memory_bitmap_size + 4095) & ~4095; /* Align to page */
    
    /* Allocate bitmap at end of kernel */
    physical_memory_bitmap = (uint32_t*)0x200000; /* 2MB mark */
    memory_zero(physical_memory_bitmap, physical_memory_bitmap_size * 4);
    
    /* Mark kernel space as used */
    uint64_t kernel_pages = (kernel_physical_end - kernel_physical_start + PAGE_SIZE - 1) / PAGE_SIZE;
    for (uint64_t i = 0; i < kernel_pages; i++) {
        memory_mark_page_used(i);
    }
    
    /* Mark bitmap space as used */
    uint64_t bitmap_pages = (physical_memory_bitmap_size * 4 + PAGE_SIZE - 1) / PAGE_SIZE;
    for (uint64_t i = 0; i < bitmap_pages; i++) {
        memory_mark_page_used(i + (0x200000 / PAGE_SIZE));
    }
    
    available_physical_memory = total_physical_memory - (kernel_pages * PAGE_SIZE) - (bitmap_pages * PAGE_SIZE);
}

/* Initialize virtual memory management */
void vmm_init(void) {
    /* Setup kernel page directory */
    kernel_page_directory = (page_directory_t*)memory_alloc_page(PAGE_PRESENT | PAGE_WRITABLE);
    if (!kernel_page_directory) {
        return;
    }
    
    kernel_pml4 = (uint64_t*)&kernel_page_directory->pml4;
    kernel_pdpt = (uint64_t*)&kernel_page_directory->pdpt;
    kernel_pd = (uint64_t*)&kernel_page_directory->pd;
    kernel_pt = (uint64_t*)&kernel_page_directory->pt;
    
    /* Identity map first 2MB for kernel */
    memory_map_region(0x0, 0x200000, PAGE_PRESENT | PAGE_WRITABLE);
    
    /* Map kernel space to higher half */
    memory_map_region(KERNEL_BASE, KERNEL_BASE + 0x200000, PAGE_PRESENT | PAGE_WRITABLE);
}

/* Initialize kernel heap */
void memory_init_heap(void) {
    kernel_heap_size = 0x100000; /* 1MB initial heap */
    kernel_heap_start = (uint8_t*)0x300000; /* 3MB mark */
    kernel_heap_end = kernel_heap_start + kernel_heap_size;
    kernel_heap_current = kernel_heap_start;
    
    /* Map heap pages */
    uint64_t heap_pages = kernel_heap_size / PAGE_SIZE;
    for (uint64_t i = 0; i < heap_pages; i++) {
        uint64_t physical_addr = (uint64_t)memory_alloc_page(PAGE_PRESENT | PAGE_WRITABLE);
        uint64_t virtual_addr = KERNEL_HEAP_BASE + (i * PAGE_SIZE);
        memory_map_page(virtual_addr, physical_addr, PAGE_PRESENT | PAGE_WRITABLE);
    }
}

/* Setup page tables */
static void memory_setup_page_tables(void) {
    /* Clear all page tables */
    memory_zero(kernel_pml4, sizeof(page_table_t));
    memory_zero(kernel_pdpt, sizeof(page_table_t));
    memory_zero(kernel_pd, sizeof(page_table_t));
    memory_zero(kernel_pt, sizeof(page_table_t));
    
    /* Setup PML4 entries */
    kernel_pml4[0] = ((uint64_t)kernel_pdpt - KERNEL_BASE) | PAGE_PRESENT | PAGE_WRITABLE;
    kernel_pml4[256] = ((uint64_t)kernel_pdpt - KERNEL_BASE) | PAGE_PRESENT | PAGE_WRITABLE;
    
    /* Setup PDPT entries */
    kernel_pdpt[0] = ((uint64_t)kernel_pd - KERNEL_BASE) | PAGE_PRESENT | PAGE_WRITABLE;
    kernel_pdpt[0] |= PAGE_HUGEPAGE; /* Use 2MB pages */
    
    /* Setup PD entries for 2MB pages */
    for (int i = 0; i < 512; i++) {
        kernel_pd[i] = (i * 0x200000) | PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGEPAGE;
    }
}

/* Enable paging */
static void memory_enable_paging(void) {
    /* Load PML4 into CR3 */
    __asm__ volatile ("mov %0, %%cr3" : : "r" (kernel_pml4));
    
    /* Enable PAE in CR4 */
    uint64_t cr4;
    __asm__ volatile ("mov %%cr4, %0" : "=r" (cr4));
    cr4 |= (1 << 5); /* PAE bit */
    __asm__ volatile ("mov %0, %%cr4" : : "r" (cr4));
    
    /* Enable long mode in EFER */
    uint64_t efer;
    __asm__ volatile ("rdmsr" : "=A" (efer) : "c" (0xC0000080));
    efer |= (1 << 8); /* LME bit */
    __asm__ volatile ("wrmsr" : : "A" (efer), "c" (0xC0000080));
    
    /* Enable paging in CR0 */
    uint64_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r" (cr0));
    cr0 |= (1 << 31); /* PG bit */
    __asm__ volatile ("mov %0, %%cr0" : : "r" (cr0));
}

/* Allocate pages */
void* memory_alloc_pages(uint32_t pages, uint32_t flags) {
    uint64_t allocated_pages = 0;
    uint64_t start_page = 0;
    
    /* Find contiguous free pages */
    for (uint64_t i = 0; i < total_physical_pages; i++) {
        if (memory_is_page_free(i)) {
            if (allocated_pages == 0) {
                start_page = i;
            }
            allocated_pages++;
            
            if (allocated_pages == pages) {
                /* Found enough pages */
                for (uint64_t j = 0; j < pages; j++) {
                    memory_mark_page_used(start_page + j);
                }
                
                /* Map pages to virtual address */
                uint64_t virtual_addr = KERNEL_HEAP_BASE + (start_page * PAGE_SIZE);
                for (uint64_t j = 0; j < pages; j++) {
                    uint64_t physical_addr = (start_page + j) * PAGE_SIZE;
                    memory_map_page(virtual_addr + (j * PAGE_SIZE), physical_addr, flags);
                }
                
                return (void*)virtual_addr;
            }
        } else {
            allocated_pages = 0;
            start_page = 0;
        }
    }
    
    return NULL;
}

/* Free pages */
void memory_free_pages(void* addr, uint32_t pages) {
    if (!addr) return;
    
    uint64_t virtual_addr = (uint64_t)addr;
    uint64_t start_page = (virtual_addr - KERNEL_HEAP_BASE) / PAGE_SIZE;
    
    for (uint32_t i = 0; i < pages; i++) {
        uint64_t page = start_page + i;
        if (page < total_physical_pages) {
            memory_mark_page_free(page);
            memory_unmap_page(KERNEL_HEAP_BASE + (page * PAGE_SIZE));
        }
    }
}

/* Allocate single page */
void* memory_alloc_page(uint32_t flags) {
    return memory_alloc_pages(1, flags);
}

/* Free single page */
void memory_free_page(void* addr) {
    memory_free_pages(addr, 1);
}

/* Map virtual page to physical page */
void memory_map_page(uint64_t virtual_addr, uint64_t physical_addr, uint32_t flags) {
    uint64_t pml4_index = (virtual_addr >> 39) & 0x1FF;
    uint64_t pdpt_index = (virtual_addr >> 30) & 0x1FF;
    uint64_t pd_index = (virtual_addr >> 21) & 0x1FF;
    uint64_t pt_index = (virtual_addr >> 12) & 0x1FF;
    
    /* For now, use simple mapping - this would need proper page table walking */
    if (virtual_addr < 0x200000) {
        /* Identity mapping for low memory */
        /* Implementation would walk page tables properly */
    }
}

/* Unmap virtual page */
void memory_unmap_page(uint64_t virtual_addr) {
    /* Implementation would clear page table entry and flush TLB */
    (void)virtual_addr;
}

/* Get physical address from virtual */
uint64_t memory_get_physical_address(uint64_t virtual_addr) {
    if (virtual_addr >= KERNEL_BASE) {
        return virtual_addr - KERNEL_BASE;
    }
    return virtual_addr;
}

/* Get virtual address from physical */
uint64_t memory_get_virtual_address(uint64_t physical_addr) {
    return physical_addr + KERNEL_BASE;
}

/* Check if page is present */
bool memory_is_page_present(uint64_t addr) {
    /* Check page table entry */
    return false; /* Simplified for now */
}

/* Check if page is writable */
bool memory_is_page_writable(uint64_t addr) {
    /* Check page table entry flags */
    return false; /* Simplified for now */
}

/* Protect page */
void memory_protect_page(uint64_t addr, uint32_t flags) {
    /* Update page table entry with new flags */
    (void)addr;
    (void)flags;
}

/* Flush TLB */
void memory_flush_tlb(void) {
    __asm__ volatile ("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax");
}

/* Enable NX bit */
void memory_enable_nx_bit(void) {
    uint64_t efer;
    __asm__ volatile ("rdmsr" : "=A" (efer) : "c" (0xC0000080));
    efer |= (1 << 11); /* NXE bit */
    __asm__ volatile ("wrmsr" : : "A" (efer), "c" (0xC0000080));
}

/* Enable global pages */
void memory_enable_global_pages(void) {
    uint64_t cr4;
    __asm__ volatile ("mov %%cr4, %0" : "=r" (cr4));
    cr4 |= (1 << 7); /* PGE bit */
    __asm__ volatile ("mov %0, %%cr4" : : "r" (cr4));
}

/* Physical memory management functions */
void* pmm_alloc_page(void) {
    uint64_t page = memory_find_free_page();
    if (page != (uint64_t)-1) {
        memory_mark_page_used(page);
        return (void*)(page * PAGE_SIZE);
    }
    return NULL;
}

void pmm_free_page(void* page) {
    if (page) {
        uint64_t page_num = (uint64_t)page / PAGE_SIZE;
        if (page_num < total_physical_pages) {
            memory_mark_page_free(page_num);
        }
    }
}

uint64_t pmm_get_free_pages(void) {
    return total_physical_pages - used_physical_pages;
}

uint64_t pmm_get_used_pages(void) {
    return used_physical_pages;
}

uint64_t pmm_get_total_pages(void) {
    return total_physical_pages;
}

/* Virtual memory management functions */
void* vmm_alloc_pages(uint32_t pages, uint32_t flags) {
    return memory_alloc_pages(pages, flags);
}

void vmm_free_pages(void* addr, uint32_t pages) {
    memory_free_pages(addr, pages);
}

void* vmm_map_physical(uint64_t physical_addr, uint32_t pages, uint32_t flags) {
    /* Map physical pages to virtual address space */
    uint64_t virtual_addr = KERNEL_HEAP_BASE + (physical_addr & 0xFFF);
    for (uint32_t i = 0; i < pages; i++) {
        memory_map_page(virtual_addr + (i * PAGE_SIZE), 
                       physical_addr + (i * PAGE_SIZE), flags);
    }
    return (void*)virtual_addr;
}

void vmm_unmap_physical(void* virtual_addr, uint32_t pages) {
    for (uint32_t i = 0; i < pages; i++) {
        memory_unmap_page((uint64_t)virtual_addr + (i * PAGE_SIZE));
    }
}

vma_t* vmm_find_vma(uint64_t addr) {
    vma_t* vma = kernel_memory_context->vma_list;
    while (vma) {
        if (addr >= vma->start && addr < vma->end) {
            return vma;
        }
        vma = vma->next;
    }
    return NULL;
}

vma_t* vmm_create_vma(uint64_t start, uint64_t end, uint64_t flags) {
    vma_t* vma = (vma_t*)kmalloc(sizeof(vma_t));
    if (vma) {
        vma->start = start;
        vma->end = end;
        vma->flags = flags;
        vma->next = kernel_memory_context->vma_list;
        kernel_memory_context->vma_list = vma;
    }
    return vma;
}

void vmm_destroy_vma(vma_t* vma) {
    if (vma) {
        /* Remove from list */
        vma_t** current = &kernel_memory_context->vma_list;
        while (*current) {
            if (*current == vma) {
                *current = vma->next;
                break;
            }
            current = &(*current)->next;
        }
        kfree(vma);
    }
}

/* Kernel heap management */
void* kmalloc(size_t size) {
    if (size == 0) return NULL;
    
    /* Align to 8 bytes */
    size = (size + 7) & ~7;
    
    if (kernel_heap_current + size > kernel_heap_end) {
        /* Need to allocate more heap pages */
        uint32_t pages_needed = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        void* new_heap = memory_alloc_pages(pages_needed, PAGE_PRESENT | PAGE_WRITABLE);
        if (!new_heap) return NULL;
        
        kernel_heap_end = (uint8_t*)new_heap + (pages_needed * PAGE_SIZE);
    }
    
    void* ptr = kernel_heap_current;
    kernel_heap_current += size;
    
    return ptr;
}

void* kmalloc_aligned(size_t size, uint32_t alignment) {
    if (alignment <= 8) return kmalloc(size);
    
    /* Allocate extra space for alignment */
    size_t total_size = size + alignment;
    void* ptr = kmalloc(total_size);
    if (!ptr) return NULL;
    
    /* Align the pointer */
    uint64_t aligned_ptr = ((uint64_t)ptr + alignment - 1) & ~(alignment - 1);
    
    return (void*)aligned_ptr;
}

void* kcalloc(size_t num, size_t size) {
    size_t total_size = num * size;
    void* ptr = kmalloc(total_size);
    if (ptr) {
        memory_zero(ptr, total_size);
    }
    return ptr;
}

void* krealloc(void* ptr, size_t new_size) {
    if (!ptr) return kmalloc(new_size);
    if (new_size == 0) {
        kfree(ptr);
        return NULL;
    }
    
    /* Simple implementation - allocate new and copy */
    void* new_ptr = kmalloc(new_size);
    if (new_ptr) {
        /* Copy old data (size would need to be tracked) */
        /* For now, just return new pointer */
        return new_ptr;
    }
    
    return NULL;
}

void kfree(void* ptr) {
    /* Simple allocator - no free for now */
    (void)ptr;
}

void* kmap_page(uint64_t physical_addr) {
    return vmm_map_physical(physical_addr, 1, PAGE_PRESENT | PAGE_WRITABLE);
}

void* kmap_pages(uint64_t physical_addr, uint32_t pages) {
    return vmm_map_physical(physical_addr, pages, PAGE_PRESENT | PAGE_WRITABLE);
}

void kunmap_page(void* virtual_addr) {
    vmm_unmap_physical(virtual_addr, 1);
}

void kunmap_pages(void* virtual_addr, uint32_t pages) {
    vmm_unmap_physical(virtual_addr, pages);
}

/* Memory utilities */
void memory_copy(void* dest, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

void memory_set(void* dest, int value, size_t n) {
    uint8_t* p = (uint8_t*)dest;
    uint8_t val = (uint8_t)value;
    
    for (size_t i = 0; i < n; i++) {
        p[i] = val;
    }
}

int memory_compare(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = (const uint8_t*)s1;
    const uint8_t* p2 = (const uint8_t*)s2;
    
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    
    return 0;
}

void memory_zero(void* dest, size_t n) {
    memory_set(dest, 0, n);
}

/* Helper functions */
static void memory_map_region(uint64_t start, uint64_t end, uint32_t flags) {
    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        memory_map_page(addr, addr, flags);
    }
}

static void memory_unmap_region(uint64_t start, uint64_t end) {
    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        memory_unmap_page(addr);
    }
}

static uint64_t memory_find_free_page(void) {
    for (uint64_t i = 0; i < total_physical_pages; i++) {
        if (memory_is_page_free(i)) {
            return i;
        }
    }
    return (uint64_t)-1;
}

static void memory_mark_page_used(uint64_t page) {
    if (page < total_physical_pages) {
        uint32_t index = page / 32;
        uint32_t bit = page % 32;
        physical_memory_bitmap[index] |= (1 << bit);
        used_physical_pages++;
    }
}

static void memory_mark_page_free(uint64_t page) {
    if (page < total_physical_pages) {
        uint32_t index = page / 32;
        uint32_t bit = page % 32;
        physical_memory_bitmap[index] &= ~(1 << bit);
        if (used_physical_pages > 0) {
            used_physical_pages--;
        }
    }
}

static bool memory_is_page_free(uint64_t page) {
    if (page >= total_physical_pages) return false;
    uint32_t index = page / 32;
    uint32_t bit = page % 32;
    return !(physical_memory_bitmap[index] & (1 << bit));
}

/* Memory debugging functions */
void memory_dump_page(uint64_t addr) {
    /* Dump contents of a page for debugging */
    (void)addr;
}

void memory_dump_region(uint64_t start, uint64_t end) {
    /* Dump memory region for debugging */
    (void)start;
    (void)end;
}

void memory_stats(void) {
    /* Print memory statistics */
}

void memory_check_integrity(void) {
    /* Check memory integrity */
}

/* Advanced features (placeholders) */
void memory_defragment(void) {}
void memory_compact(void) {}
void memory_swap_out(uint64_t addr) { (void)addr; }
void memory_swap_in(uint64_t addr) { (void)addr; }
bool memory_is_swapped(uint64_t addr) { (void)addr; return false; }

void memory_set_protection(uint64_t addr, uint32_t protection) { (void)addr; (void)protection; }
uint32_t memory_get_protection(uint64_t addr) { (void)addr; return 0; }
void memory_enable_protection(void) {}
void memory_disable_protection(void) {}

void memory_enable_huge_pages(void) {}
void* memory_alloc_huge_page(uint32_t flags) { (void)flags; return NULL; }
void memory_free_huge_page(void* addr) { (void)addr; }
bool memory_is_huge_page(uint64_t addr) { (void)addr; return false; }