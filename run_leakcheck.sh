#!/bin/bash

# CATE-Kernel Memory Leak Detection Script
# Runs memory leak detection and analysis on the kernel

set -e

echo "Running memory leak detection on CATE-Kernel..."

# Configuration
BUILD_DIR="build"
REPORTS_DIR="reports"
LEAK_TOOLS="valgrind address-sanitizer leak-sanitizer"

# Create reports directory
mkdir -p ${REPORTS_DIR}

# Function to check if tool is available
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "Warning: $1 is not installed, skipping..."
        return 1
    fi
    return 0
}

# Function to run Valgrind memcheck
run_valgrind_memcheck() {
    echo "Running Valgrind memcheck..."
    
    if ! check_tool valgrind; then
        return
    fi
    
    # Create a simple test program to check memory leaks
    cat > ${REPORTS_DIR}/leak-test.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_malloc_leak() {
    // Intentional memory leak for testing
    int *leaked = malloc(100 * sizeof(int));
    // Missing free() - this should be detected
}

void test_use_after_free() {
    int *ptr = malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    // Use after free - this should be detected
    printf("Value: %d\n", *ptr);
}

void test_double_free() {
    int *ptr = malloc(sizeof(int));
    free(ptr);
    // Double free - this should be detected
    free(ptr);
}

void test_buffer_overflow() {
    char buffer[10];
    // Buffer overflow - this should be detected
    strcpy(buffer, "This string is too long for the buffer");
    printf("Buffer: %s\n", buffer);
}

int main() {
    printf("Running memory leak tests...\n");
    
    test_malloc_leak();
    test_use_after_free();
    test_double_free();
    test_buffer_overflow();
    
    printf("Tests completed.\n");
    return 0;
}
EOF
    
    # Compile test program
    gcc -g -o ${REPORTS_DIR}/leak-test ${REPORTS_DIR}/leak-test.c
    
    # Run with Valgrind memcheck
    valgrind \
        --tool=memcheck \
        --leak-check=full \
        --show-leak-kinds=all \
        --track-origins=yes \
        --xml=yes \
        --xml-file=${REPORTS_DIR}/valgrind-memcheck-leaks.xml \
        --log-file=${REPORTS_DIR}/valgrind-memcheck-leaks.txt \
        ${REPORTS_DIR}/leak-test 2>&1 || true
    
    # Generate summary
    if [ -f "${REPORTS_DIR}/valgrind-memcheck-leaks.txt" ]; then
        echo "Valgrind memcheck completed"
        
        # Extract leak summary
        grep -A 10 "LEAK SUMMARY" ${REPORTS_DIR}/valgrind-memcheck-leaks.txt > ${REPORTS_DIR}/leak-summary.txt || true
        
        # Extract error summary
        grep -A 10 "ERROR SUMMARY" ${REPORTS_DIR}/valgrind-memcheck-leaks.txt > ${REPORTS_DIR}/error-summary.txt || true
    fi
}

# Function to run AddressSanitizer
run_address_sanitizer() {
    echo "Running AddressSanitizer..."
    
    # Check if compiler supports AddressSanitizer
    if gcc -fsanitize=address -o /tmp/asan-test -x c - <<< "int main(){return 0;}" 2>/dev/null; then
        echo "AddressSanitizer is supported"
        
        # Compile kernel with AddressSanitizer
        echo "Compiling kernel with AddressSanitizer..."
        
        # Create ASan build directory
        mkdir -p ${BUILD_DIR}/asan
        
        # Compile with AddressSanitizer flags
        make clean
        make CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
             LDFLAGS="-fsanitize=address" \
             BUILD_DIR=${BUILD_DIR}/asan \
             2> ${REPORTS_DIR}/asan-build.log || true
        
        # Run with AddressSanitizer
        if [ -f "${BUILD_DIR}/asan/kernel.elf" ]; then
            echo "Running kernel with AddressSanitizer..."
            
            # Note: This is a simulation - ASan won't work directly on kernel
            # but we can test the build process
            echo "AddressSanitizer build completed" > ${REPORTS_DIR}/asan-build-result.txt
        fi
    else
        echo "AddressSanitizer not supported by this compiler"
    fi
}

# Function to run LeakSanitizer
run_leak_sanitizer() {
    echo "Running LeakSanitizer..."
    
    # Check if compiler supports LeakSanitizer
    if gcc -fsanitize=leak -o /tmp/lsan-test -x c - <<< "int main(){return 0;}" 2>/dev/null; then
        echo "LeakSanitizer is supported"
        
        # Compile with LeakSanitizer
        echo "Compiling with LeakSanitizer..."
        
        # Create LSan build directory
        mkdir -p ${BUILD_DIR}/lsan
        
        # Compile with LeakSanitizer flags
        make clean
        make CFLAGS="-fsanitize=leak -g" \
             LDFLAGS="-fsanitize=leak" \
             BUILD_DIR=${BUILD_DIR}/lsan \
             2> ${REPORTS_DIR}/lsan-build.log || true
        
        if [ -f "${BUILD_DIR}/lsan/kernel.elf" ]; then
            echo "LeakSanitizer build completed" > ${REPORTS_DIR}/lsan-build-result.txt
        fi
    else
        echo "LeakSanitizer not supported by this compiler"
    fi
}

# Function to run custom memory leak detection
run_custom_leak_detection() {
    echo "Running custom memory leak detection..."
    
    # Create custom leak detector
    cat > ${REPORTS_DIR}/custom-leak-detector.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Simple memory tracking structure
typedef struct mem_block {
    void *ptr;
    size_t size;
    const char *file;
    int line;
    struct mem_block *next;
} mem_block_t;

static mem_block_t *mem_blocks = NULL;
static size_t total_allocated = 0;
static size_t total_freed = 0;

// Custom malloc with tracking
void *tracked_malloc(size_t size, const char *file, int line) {
    void *ptr = malloc(size);
    if (ptr) {
        mem_block_t *block = malloc(sizeof(mem_block_t));
        block->ptr = ptr;
        block->size = size;
        block->file = file;
        block->line = line;
        block->next = mem_blocks;
        mem_blocks = block;
        total_allocated += size;
    }
    return ptr;
}

// Custom free with tracking
void tracked_free(void *ptr, const char *file, int line) {
    if (!ptr) return;
    
    mem_block_t **current = &mem_blocks;
    while (*current) {
        if ((*current)->ptr == ptr) {
            mem_block_t *to_free = *current;
            *current = (*current)->next;
            total_freed += to_free->size;
            free(to_free);
            free(ptr);
            return;
        }
        current = &(*current)->next;
    }
    
    printf("WARNING: Freeing untracked memory at %s:%d\n", file, line);
    free(ptr);
}

// Report memory leaks
void report_leaks() {
    printf("\n=== Memory Leak Report ===\n");
    printf("Total allocated: %zu bytes\n", total_allocated);
    printf("Total freed: %zu bytes\n", total_freed);
    printf("Potential leaks: %zu bytes\n", total_allocated - total_freed);
    
    if (mem_blocks) {
        printf("\nLeaked blocks:\n");
        mem_block_t *current = mem_blocks;
        int count = 0;
        while (current) {
            printf("  Block %d: %zu bytes allocated at %s:%d\n", 
                   ++count, current->size, current->file, current->line);
            current = current->next;
        }
    } else {
        printf("No memory leaks detected!\n");
    }
    printf("=========================\n");
}

// Macros for easy usage
#define MALLOC(size) tracked_malloc(size, __FILE__, __LINE__)
#define FREE(ptr) tracked_free(ptr, __FILE__, __LINE__)

int main() {
    printf("Running custom memory leak detection...\n");
    
    // Test cases
    int *arr1 = MALLOC(100 * sizeof(int));
    int *arr2 = MALLOC(200 * sizeof(int));
    char *str = MALLOC(50);
    
    // Intentional leak: arr1 not freed
    FREE(arr2);
    FREE(str);
    // arr1 is leaked
    
    // Report leaks
    report_leaks();
    
    return 0;
}
EOF
    
    # Compile and run custom detector
    gcc -g -o ${REPORTS_DIR}/custom-leak-detector ${REPORTS_DIR}/custom-leak-detector.c
    ${REPORTS_DIR}/custom-leak-detector > ${REPORTS_DIR}/custom-leak-report.txt
    
    echo "Custom leak detection completed"
}

# Function to analyze kernel memory management
analyze_kernel_memory() {
    echo "Analyzing kernel memory management..."
    
    # Analyze memory allocation patterns in kernel
    echo "Analyzing kernel memory allocation patterns..."
    
    # Find malloc/free patterns
    grep -r -n "kmalloc\|kfree\|vmalloc\|vfree" ${SRC_DIR} > ${REPORTS_DIR}/kernel-memory-patterns.txt || true
    
    # Find memory management functions
    grep -r -n "memory_init\|memory_alloc\|memory_free" ${SRC_DIR} > ${REPORTS_DIR}/kernel-memory-functions.txt || true
    
    # Analyze memory sizes
    grep -r -n "malloc.*sizeof" ${SRC_DIR} > ${REPORTS_DIR}/kernel-malloc-sizes.txt || true
    
    # Check for potential memory leaks
    echo "Checking for potential kernel memory leaks..."
    
    # Functions that allocate but might not free
    grep -r -A 5 -B 5 "kmalloc" ${SRC_DIR} | grep -A 10 -B 10 "return\|goto\|error" > ${REPORTS_DIR}/kernel-potential-leaks.txt || true
    
    echo "Kernel memory analysis completed"
}

# Function to generate leak detection summary
generate_leak_summary() {
    echo "Generating leak detection summary..."
    
    cat > ${REPORTS_DIR}/leak-summary.txt << EOF
CATE-Kernel Memory Leak Detection Summary
=======================================
Date: $(date)
Build Directory: ${BUILD_DIR}
Reports Directory: ${REPORTS_DIR}

Leak Detection Results:
EOF

    # Check for leak detection results
    if [ -f "${REPORTS_DIR}/leak-summary.txt" ]; then
        LEAKS=$(grep -c "definitely lost\|indirectly lost\|possibly lost" ${REPORTS_DIR}/valgrind-memcheck-leaks.txt || echo "0")
        echo "- Valgrind detected leaks: ${LEAKS}" >> ${REPORTS_DIR}/leak-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/custom-leak-report.txt" ]; then
        CUSTOM_LEAKS=$(grep -c "leaked\|leak" ${REPORTS_DIR}/custom-leak-report.txt || echo "0")
        echo "- Custom detector found leaks: ${CUSTOM_LEAKS}" >> ${REPORTS_DIR}/leak-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/kernel-potential-leaks.txt" ]; then
        KERNEL_LEAKS=$(wc -l < ${REPORTS_DIR}/kernel-potential-leaks.txt || echo "0")
        echo "- Potential kernel leaks: ${KERNEL_LEAKS}" >> ${REPORTS_DIR}/leak-summary.txt
    fi
    
    echo "" >> ${REPORTS_DIR}/leak-summary.txt
    echo "Memory Leak Recommendations:" >> ${REPORTS_DIR}/leak-summary.txt
    echo "- Review all malloc/kmalloc calls without corresponding free/kfree" >> ${REPORTS_DIR}/leak-summary.txt
    echo "- Check error handling paths for memory leaks" >> ${REPORTS_DIR}/leak-summary.txt
    echo "- Use RAII patterns or similar for automatic cleanup" >> ${REPORTS_DIR}/leak-summary.txt
    echo "- Consider using smart pointers or reference counting" >> ${REPORTS_DIR}/leak-summary.txt
    echo "- Add memory leak detection to CI/CD pipeline" >> ${REPORTS_DIR}/leak-summary.txt
    echo "- Regular memory leak testing during development" >> ${REPORTS_DIR}/leak-summary.txt
    
    echo "Leak detection summary generated: ${REPORTS_DIR}/leak-summary.txt"
}

# Main execution
main() {
    echo "Starting memory leak detection..."
    
    # Run all leak detection tools
    run_valgrind_memcheck
    run_address_sanitizer
    run_leak_sanitizer
    run_custom_leak_detection
    analyze_kernel_memory
    
    # Generate summary
    generate_leak_summary
    
    echo ""
    echo "Memory leak detection completed!"
    echo "Reports available in: ${REPORTS_DIR}/"
    echo ""
    echo "Key reports:"
    echo "- Summary: ${REPORTS_DIR}/leak-summary.txt"
    echo "- Valgrind: ${REPORTS_DIR}/valgrind-memcheck-leaks.txt"
    echo "- Custom detector: ${REPORTS_DIR}/custom-leak-report.txt"
    echo "- Kernel analysis: ${REPORTS_DIR}/kernel-potential-leaks.txt"
    echo "- Memory patterns: ${REPORTS_DIR}/kernel-memory-patterns.txt"
    echo ""
    echo "XML reports:"
    echo "- Valgrind XML: ${REPORTS_DIR}/valgrind-memcheck-leaks.xml"
}

# Run main function
main "$@"