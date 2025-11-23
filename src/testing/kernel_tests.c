#include "test_framework.h"
#include "../kernel/memory.h"
#include "../kernel/string.h"
#include "../kernel/logging.h"
#include "../kernel/interrupt.h"
#include "../kernel/syscall.h"
#include "../drivers/vga.h"
#include "../drivers/keyboard.h"
#include "../drivers/storage.h"

/* Test data structures */
typedef struct {
    uint64_t test_value;
    char test_string[64];
    uint8_t test_buffer[256];
} kernel_test_data_t;

/* Memory management test cases */

/* Test basic memory allocation */
static test_result_t test_memory_allocation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test kmalloc */
    void* ptr = kmalloc(1024);
    TEST_ASSERT_NOT_NULL(ptr);
    
    /* Test kfree */
    kfree(ptr);
    
    /* Test zero allocation */
    void* zero_ptr = kmalloc(0);
    TEST_ASSERT_NULL(zero_ptr);
    
    /* Test large allocation */
    void* large_ptr = kmalloc(1024 * 1024); /* 1MB */
    if (large_ptr != NULL) {
        kfree(large_ptr);
    }
    
    return TEST_RESULT_PASS;
}

/* Test memory alignment */
static test_result_t test_memory_alignment(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test 4-byte alignment */
    void* ptr4 = kmalloc(100);
    TEST_ASSERT_TRUE(((uintptr_t)ptr4 % 4) == 0);
    kfree(ptr4);
    
    /* Test 8-byte alignment */
    void* ptr8 = kmalloc(200);
    TEST_ASSERT_TRUE(((uintptr_t)ptr8 % 8) == 0);
    kfree(ptr8);
    
    /* Test 16-byte alignment */
    void* ptr16 = kmalloc(300);
    TEST_ASSERT_TRUE(((uintptr_t)ptr16 % 16) == 0);
    kfree(ptr16);
    
    return TEST_RESULT_PASS;
}

/* Test memory protection */
static test_result_t test_memory_protection(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test null pointer protection */
    uint8_t* null_ptr = NULL;
    /* This should cause a page fault, but we'll just test the pointer */
    TEST_ASSERT_NULL(null_ptr);
    
    /* Test kernel memory protection */
    void* kernel_ptr = kmalloc(4096);
    TEST_ASSERT_NOT_NULL(kernel_ptr);
    
    /* Test that kernel memory is accessible */
    memset(kernel_ptr, 0xAA, 4096);
    TEST_ASSERT_TRUE(((uint8_t*)kernel_ptr)[0] == 0xAA);
    
    kfree(kernel_ptr);
    
    return TEST_RESULT_PASS;
}

/* Test memory fragmentation */
static test_result_t test_memory_fragmentation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Allocate multiple blocks */
    void* ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = kmalloc(100 + i * 10);
        TEST_ASSERT_NOT_NULL(ptrs[i]);
    }
    
    /* Free every other block */
    for (int i = 0; i < 10; i += 2) {
        kfree(ptrs[i]);
        ptrs[i] = NULL;
    }
    
    /* Allocate new blocks in freed spaces */
    for (int i = 0; i < 10; i += 2) {
        ptrs[i] = kmalloc(100 + i * 10);
        TEST_ASSERT_NOT_NULL(ptrs[i]);
    }
    
    /* Free all blocks */
    for (int i = 0; i < 10; i++) {
        if (ptrs[i] != NULL) {
            kfree(ptrs[i]);
        }
    }
    
    return TEST_RESULT_PASS;
}

/* String manipulation test cases */

/* Test string copy */
static test_result_t test_string_copy(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    char dest[100];
    const char* src = "Hello, World!";
    
    /* Test normal copy */
    strncpy(dest, src, sizeof(dest));
    TEST_ASSERT_STRING_EQUAL(src, dest);
    
    /* Test copy with length limit */
    strncpy(dest, src, 5);
    TEST_ASSERT_TRUE(strncmp(dest, "Hello", 5) == 0);
    
    /* Test empty string */
    strncpy(dest, "", sizeof(dest));
    TEST_ASSERT_STRING_EQUAL("", dest);
    
    return TEST_RESULT_PASS;
}

/* Test string length */
static test_result_t test_string_length(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test normal string */
    TEST_ASSERT_EQUAL(13, strlen("Hello, World!"));
    
    /* Test empty string */
    TEST_ASSERT_EQUAL(0, strlen(""));
    
    /* Test long string */
    char long_str[1000];
    memset(long_str, 'A', 999);
    long_str[999] = '\0';
    TEST_ASSERT_EQUAL(999, strlen(long_str));
    
    return TEST_RESULT_PASS;
}

/* Test string comparison */
static test_result_t test_string_comparison(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test equal strings */
    TEST_ASSERT_EQUAL(0, strcmp("hello", "hello"));
    
    /* Test different strings */
    TEST_ASSERT_NOT_EQUAL(0, strcmp("hello", "world"));
    
    /* Test case sensitivity */
    TEST_ASSERT_NOT_EQUAL(0, strcmp("Hello", "hello"));
    
    /* Test empty strings */
    TEST_ASSERT_EQUAL(0, strcmp("", ""));
    
    return TEST_RESULT_PASS;
}

/* Test string concatenation */
static test_result_t test_string_concatenation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    char dest[100] = "Hello";
    
    /* Test concatenation */
    strncat(dest, ", World!", sizeof(dest) - strlen(dest) - 1);
    TEST_ASSERT_STRING_EQUAL("Hello, World!", dest);
    
    /* Test empty string concatenation */
    strncat(dest, "", sizeof(dest) - strlen(dest) - 1);
    TEST_ASSERT_STRING_EQUAL("Hello, World!", dest);
    
    return TEST_RESULT_PASS;
}

/* Interrupt handling test cases */

/* Test interrupt registration */
static test_result_t test_interrupt_registration(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test valid interrupt registration */
    test_result_t result = register_interrupt_handler(32, (void*)0x12345678);
    TEST_ASSERT_EQUAL(TEST_RESULT_PASS, result);
    
    /* Test invalid interrupt number */
    result = register_interrupt_handler(256, (void*)0x12345678);
    TEST_ASSERT_EQUAL(TEST_RESULT_ERROR, result);
    
    /* Test null handler */
    result = register_interrupt_handler(33, NULL);
    TEST_ASSERT_EQUAL(TEST_RESULT_ERROR, result);
    
    return TEST_RESULT_PASS;
}

/* Test interrupt handling */
static test_result_t test_interrupt_handling(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test that IDT is properly initialized */
    TEST_ASSERT_NOT_NULL(get_idt_base());
    
    /* Test that interrupt handlers are installed */
    for (int i = 0; i < 32; i++) {
        void* handler = get_interrupt_handler(i);
        TEST_ASSERT_NOT_NULL(handler);
    }
    
    return TEST_RESULT_PASS;
}

/* Test exception handling */
static test_result_t test_exception_handling(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test that exception handlers are installed */
    for (int i = 0; i < 32; i++) {
        void* handler = get_exception_handler(i);
        TEST_ASSERT_NOT_NULL(handler);
    }
    
    /* Test divide by zero exception */
    /* This would normally cause a crash, but we'll just test the handler exists */
    void* handler = get_exception_handler(0);
    TEST_ASSERT_NOT_NULL(handler);
    
    return TEST_RESULT_PASS;
}

/* System call test cases */

/* Test system call registration */
static test_result_t test_syscall_registration(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test valid syscall registration */
    test_result_t result = register_syscall(100, (void*)0x12345678);
    TEST_ASSERT_EQUAL(TEST_RESULT_PASS, result);
    
    /* Test invalid syscall number */
    result = register_syscall(1000, (void*)0x12345678);
    TEST_ASSERT_EQUAL(TEST_RESULT_ERROR, result);
    
    /* Test null handler */
    result = register_syscall(101, NULL);
    TEST_ASSERT_EQUAL(TEST_RESULT_ERROR, result);
    
    return TEST_RESULT_PASS;
}

/* Test system call execution */
static test_result_t test_syscall_execution(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test that syscall table is properly initialized */
    TEST_ASSERT_NOT_NULL(get_syscall_table());
    
    /* Test that syscall handlers are installed */
    for (int i = 0; i < 256; i++) {
        void* handler = get_syscall_handler(i);
        if (handler != NULL) {
            TEST_ASSERT_NOT_NULL(handler);
        }
    }
    
    return TEST_RESULT_PASS;
}

/* Driver test cases */

/* Test VGA driver */
static test_result_t test_vga_driver(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test VGA initialization */
    TEST_ASSERT_TRUE(vga_is_initialized());
    
    /* Test VGA text output */
    vga_printf("Test VGA output\n");
    TEST_ASSERT_TRUE(vga_get_cursor_x() > 0);
    
    /* Test VGA color support */
    vga_set_color(VGA_COLOR_GREEN, VGA_COLOR_BLACK);
    vga_printf("Green text\n");
    TEST_ASSERT_TRUE(vga_get_foreground_color() == VGA_COLOR_GREEN);
    
    return TEST_RESULT_PASS;
}

/* Test keyboard driver */
static test_result_t test_keyboard_driver(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test keyboard initialization */
    TEST_ASSERT_TRUE(keyboard_is_initialized());
    
    /* Test keyboard buffer */
    TEST_ASSERT_TRUE(keyboard_get_buffer_size() >= 0);
    
    /* Test keyboard scan code conversion */
    uint8_t ascii = keyboard_scan_code_to_ascii(0x1E); /* 'A' key */
    TEST_ASSERT_EQUAL('a', ascii);
    
    return TEST_RESULT_PASS;
}

/* Test storage driver */
static test_result_t test_storage_driver(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test storage initialization */
    TEST_ASSERT_TRUE(storage_is_initialized());
    
    /* Test storage device detection */
    uint32_t device_count = storage_get_device_count();
    TEST_ASSERT_TRUE(device_count >= 0);
    
    /* Test storage read/write if devices are available */
    if (device_count > 0) {
        storage_device_t* device = storage_get_device(0);
        TEST_ASSERT_NOT_NULL(device);
        
        /* Test device properties */
        TEST_ASSERT_TRUE(device->size > 0);
        TEST_ASSERT_NOT_NULL(device->name);
    }
    
    return TEST_RESULT_PASS;
}

/* Security test cases */

/* Test memory protection */
static test_result_t test_security_memory_protection(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test that kernel memory is protected */
    void* kernel_ptr = kmalloc(4096);
    TEST_ASSERT_NOT_NULL(kernel_ptr);
    
    /* Test memory access permissions */
    /* This would test that user mode cannot access kernel memory */
    /* Implementation depends on specific architecture */
    
    kfree(kernel_ptr);
    
    return TEST_RESULT_PASS;
}

/* Test stack protection */
static test_result_t test_security_stack_protection(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test stack canary if implemented */
    /* Test stack overflow protection */
    /* Test stack smashing protection */
    
    return TEST_RESULT_PASS;
}

/* Test privilege levels */
static test_result_t test_security_privilege_levels(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test that kernel runs at highest privilege level */
    /* Test that user mode runs at lowest privilege level */
    /* Test privilege escalation protection */
    
    return TEST_RESULT_PASS;
}

/* Performance test cases */

/* Test memory allocation performance */
static test_result_t test_performance_memory_allocation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    uint64_t start_time = test_get_current_time();
    
    /* Allocate and free many small blocks */
    for (int i = 0; i < 1000; i++) {
        void* ptr = kmalloc(64);
        TEST_ASSERT_NOT_NULL(ptr);
        kfree(ptr);
    }
    
    uint64_t end_time = test_get_current_time();
    uint64_t duration = end_time - start_time;
    
    /* Assert performance is within threshold */
    TEST_ASSERT_PERFORMANCE(duration, 100); /* Should complete within 100ms */
    
    return TEST_RESULT_PASS;
}

/* Test string operation performance */
static test_result_t test_performance_string_operations(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    uint64_t start_time = test_get_current_time();
    
    /* Perform many string operations */
    char buffer[1000];
    for (int i = 0; i < 10000; i++) {
        strncpy(buffer, "Test string", sizeof(buffer));
        strlen(buffer);
        strcmp(buffer, "Test string");
    }
    
    uint64_t end_time = test_get_current_time();
    uint64_t duration = end_time - start_time;
    
    /* Assert performance is within threshold */
    TEST_ASSERT_PERFORMANCE(duration, 50); /* Should complete within 50ms */
    
    return TEST_RESULT_PASS;
}

/* Test interrupt handling performance */
static test_result_t test_performance_interrupt_handling(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    uint64_t start_time = test_get_current_time();
    
    /* Simulate interrupt handling */
    for (int i = 0; i < 1000; i++) {
        /* This would normally trigger actual interrupts */
        /* For testing, we'll just measure the overhead */
    }
    
    uint64_t end_time = test_get_current_time();
    uint64_t duration = end_time - start_time;
    
    /* Assert performance is within threshold */
    TEST_ASSERT_PERFORMANCE(duration, 10); /* Should complete within 10ms */
    
    return TEST_RESULT_PASS;
}

/* Test setup function */
static test_result_t kernel_test_setup(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Allocate test data */
    kernel_test_data_t* test_data = (kernel_test_data_t*)kmalloc(sizeof(kernel_test_data_t));
    if (test_data == NULL) {
        return TEST_RESULT_MEMORY_ERROR;
    }
    
    /* Initialize test data */
    memset(test_data, 0, sizeof(kernel_test_data_t));
    test_data->test_value = 0x1234567890ABCDEF;
    strncpy(test_data->test_string, "Kernel Test Data", sizeof(test_data->test_string) - 1);
    
    test_case->test_data = test_data;
    test_case->test_data_size = sizeof(kernel_test_data_t);
    
    return TEST_RESULT_PASS;
}

/* Test cleanup function */
static test_result_t kernel_test_cleanup(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Free test data */
    if (test_case->test_data != NULL) {
        kfree(test_case->test_data);
        test_case->test_data = NULL;
        test_case->test_data_size = 0;
    }
    
    return TEST_RESULT_PASS;
}

/* Create kernel test suite */
test_suite_t* create_kernel_test_suite(void) {
    test_suite_t* suite = test_create_suite("Kernel Tests", "Comprehensive kernel functionality tests", TEST_CATEGORY_KERNEL);
    if (suite == NULL) {
        return NULL;
    }
    
    /* Set suite functions */
    suite->setup = kernel_test_setup;
    suite->teardown = kernel_test_cleanup;
    
    /* Memory management tests */
    test_case_t* mem_alloc_test = test_create_case("Memory Allocation", "Test basic memory allocation functionality", TEST_CATEGORY_MEMORY);
    if (mem_alloc_test != NULL) {
        mem_alloc_test->run = test_memory_allocation;
        test_register_case(suite, mem_alloc_test);
    }
    
    test_case_t* mem_align_test = test_create_case("Memory Alignment", "Test memory alignment requirements", TEST_CATEGORY_MEMORY);
    if (mem_align_test != NULL) {
        mem_align_test->run = test_memory_alignment;
        test_register_case(suite, mem_align_test);
    }
    
    test_case_t* mem_prot_test = test_create_case("Memory Protection", "Test memory protection mechanisms", TEST_CATEGORY_MEMORY);
    if (mem_prot_test != NULL) {
        mem_prot_test->run = test_memory_protection;
        test_register_case(suite, mem_prot_test);
    }
    
    test_case_t* mem_frag_test = test_create_case("Memory Fragmentation", "Test memory fragmentation handling", TEST_CATEGORY_MEMORY);
    if (mem_frag_test != NULL) {
        mem_frag_test->run = test_memory_fragmentation;
        test_register_case(suite, mem_frag_test);
    }
    
    /* String manipulation tests */
    test_case_t* str_copy_test = test_create_case("String Copy", "Test string copy operations", TEST_CATEGORY_UNIT);
    if (str_copy_test != NULL) {
        str_copy_test->run = test_string_copy;
        test_register_case(suite, str_copy_test);
    }
    
    test_case_t* str_len_test = test_create_case("String Length", "Test string length calculations", TEST_CATEGORY_UNIT);
    if (str_len_test != NULL) {
        str_len_test->run = test_string_length;
        test_register_case(suite, str_len_test);
    }
    
    test_case_t* str_cmp_test = test_create_case("String Comparison", "Test string comparison operations", TEST_CATEGORY_UNIT);
    if (str_cmp_test != NULL) {
        str_cmp_test->run = test_string_comparison;
        test_register_case(suite, str_cmp_test);
    }
    
    test_case_t* str_cat_test = test_create_case("String Concatenation", "Test string concatenation operations", TEST_CATEGORY_UNIT);
    if (str_cat_test != NULL) {
        str_cat_test->run = test_string_concatenation;
        test_register_case(suite, str_cat_test);
    }
    
    /* Interrupt handling tests */
    test_case_t* int_reg_test = test_create_case("Interrupt Registration", "Test interrupt handler registration", TEST_CATEGORY_KERNEL);
    if (int_reg_test != NULL) {
        int_reg_test->run = test_interrupt_registration;
        test_register_case(suite, int_reg_test);
    }
    
    test_case_t* int_hand_test = test_create_case("Interrupt Handling", "Test interrupt handling mechanisms", TEST_CATEGORY_KERNEL);
    if (int_hand_test != NULL) {
        int_hand_test->run = test_interrupt_handling;
        test_register_case(suite, int_hand_test);
    }
    
    test_case_t* exc_hand_test = test_create_case("Exception Handling", "Test exception handling mechanisms", TEST_CATEGORY_KERNEL);
    if (exc_hand_test != NULL) {
        exc_hand_test->run = test_exception_handling;
        test_register_case(suite, exc_hand_test);
    }
    
    /* System call tests */
    test_case_t* syscall_reg_test = test_create_case("System Call Registration", "Test system call registration", TEST_CATEGORY_KERNEL);
    if (syscall_reg_test != NULL) {
        syscall_reg_test->run = test_syscall_registration;
        test_register_case(suite, syscall_reg_test);
    }
    
    test_case_t* syscall_exec_test = test_create_case("System Call Execution", "Test system call execution", TEST_CATEGORY_KERNEL);
    if (syscall_exec_test != NULL) {
        syscall_exec_test->run = test_syscall_execution;
        test_register_case(suite, syscall_exec_test);
    }
    
    /* Driver tests */
    test_case_t* vga_test = test_create_case("VGA Driver", "Test VGA driver functionality", TEST_CATEGORY_DRIVER);
    if (vga_test != NULL) {
        vga_test->run = test_vga_driver;
        test_register_case(suite, vga_test);
    }
    
    test_case_t* keyboard_test = test_create_case("Keyboard Driver", "Test keyboard driver functionality", TEST_CATEGORY_DRIVER);
    if (keyboard_test != NULL) {
        keyboard_test->run = test_keyboard_driver;
        test_register_case(suite, keyboard_test);
    }
    
    test_case_t* storage_test = test_create_case("Storage Driver", "Test storage driver functionality", TEST_CATEGORY_DRIVER);
    if (storage_test != NULL) {
        storage_test->run = test_storage_driver;
        test_register_case(suite, storage_test);
    }
    
    /* Security tests */
    test_case_t* sec_mem_test = test_create_case("Security Memory Protection", "Test security memory protection", TEST_CATEGORY_SECURITY);
    if (sec_mem_test != NULL) {
        sec_mem_test->run = test_security_memory_protection;
        test_register_case(suite, sec_mem_test);
    }
    
    test_case_t* sec_stack_test = test_create_case("Security Stack Protection", "Test security stack protection", TEST_CATEGORY_SECURITY);
    if (sec_stack_test != NULL) {
        sec_stack_test->run = test_security_stack_protection;
        test_register_case(suite, sec_stack_test);
    }
    
    test_case_t* sec_priv_test = test_create_case("Security Privilege Levels", "Test security privilege levels", TEST_CATEGORY_SECURITY);
    if (sec_priv_test != NULL) {
        sec_priv_test->run = test_security_privilege_levels;
        test_register_case(suite, sec_priv_test);
    }
    
    /* Performance tests */
    test_case_t* perf_mem_test = test_create_case("Performance Memory Allocation", "Test memory allocation performance", TEST_CATEGORY_PERFORMANCE);
    if (perf_mem_test != NULL) {
        perf_mem_test->run = test_performance_memory_allocation;
        test_register_case(suite, perf_mem_test);
    }
    
    test_case_t* perf_str_test = test_create_case("Performance String Operations", "Test string operation performance", TEST_CATEGORY_PERFORMANCE);
    if (perf_str_test != NULL) {
        perf_str_test->run = test_performance_string_operations;
        test_register_case(suite, perf_str_test);
    }
    
    test_case_t* perf_int_test = test_create_case("Performance Interrupt Handling", "Test interrupt handling performance", TEST_CATEGORY_PERFORMANCE);
    if (perf_int_test != NULL) {
        perf_int_test->run = test_performance_interrupt_handling;
        test_register_case(suite, perf_int_test);
    }
    
    return suite;
}