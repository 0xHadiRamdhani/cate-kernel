#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* Test result codes */
typedef enum {
    TEST_RESULT_PASSED = 0,
    TEST_RESULT_FAILED = 1,
    TEST_RESULT_SKIPPED = 2,
    TEST_RESULT_TIMEOUT = 3,
    TEST_RESULT_ERROR = 4
} test_result_t;

/* Test categories */
typedef enum {
    TEST_CATEGORY_UNIT = 0,
    TEST_CATEGORY_INTEGRATION = 1,
    TEST_CATEGORY_SYSTEM = 2,
    TEST_CATEGORY_PERFORMANCE = 3,
    TEST_CATEGORY_SECURITY = 4,
    TEST_CATEGORY_MEMORY = 5,
    TEST_CATEGORY_NETWORK = 6,
    TEST_CATEGORY_DRIVER = 7,
    TEST_CATEGORY_KERNEL = 8,
    TEST_CATEGORY_BOOT = 9,
    TEST_CATEGORY_FORENSICS = 10,
    TEST_CATEGORY_MAX
} test_category_t;

/* Test priorities */
typedef enum {
    TEST_PRIORITY_LOW = 0,
    TEST_PRIORITY_MEDIUM = 1,
    TEST_PRIORITY_HIGH = 2,
    TEST_PRIORITY_CRITICAL = 3
} test_priority_t;

/* Test log levels */
typedef enum {
    TEST_LOG_ERROR = 0,
    TEST_LOG_WARNING = 1,
    TEST_LOG_INFO = 2,
    TEST_LOG_DEBUG = 3,
    TEST_LOG_TRACE = 4
} test_log_level_t;

/* Test configuration options */
typedef enum {
    TEST_CONFIG_VERBOSE = 0,
    TEST_CONFIG_STOP_ON_FAILURE = 1,
    TEST_CONFIG_RANDOMIZE_ORDER = 2,
    TEST_CONFIG_PARALLEL_EXECUTION = 3,
    TEST_CONFIG_MAX_PARALLEL_TESTS = 4,
    TEST_CONFIG_MEMORY_TRACKING = 5,
    TEST_CONFIG_PERFORMANCE_TRACKING = 6,
    TEST_CONFIG_COVERAGE_TRACKING = 7,
    TEST_CONFIG_LEAK_DETECTION = 8,
    TEST_CONFIG_TIMEOUT = 9,
    TEST_CONFIG_RETRY_COUNT = 10,
    TEST_CONFIG_RETRY_DELAY = 11,
    TEST_CONFIG_TEST_FILTER = 12,
    TEST_CONFIG_TEST_EXCLUDE = 13,
    TEST_CONFIG_OUTPUT_FILE = 14,
    TEST_CONFIG_LOG_LEVEL = 15
} test_config_option_t;

/* Test function signature */
typedef test_result_t (*test_function_t)(void);

/* Test case structure */
typedef struct test_case {
    char* name;
    char* description;
    test_function_t function;
    test_category_t category;
    test_priority_t priority;
    uint32_t timeout;
    bool enabled;
    uint32_t retry_count;
    
    /* Test results */
    test_result_t last_result;
    uint64_t last_duration;
    uint32_t run_count;
    uint32_t pass_count;
    uint32_t fail_count;
    uint32_t skip_count;
    uint32_t failed_assertions;
    
    /* Test data */
    void* test_data;
    size_t test_data_size;
} test_case_t;

/* Test category structure */
typedef struct {
    char* name;
    char* description;
    uint32_t test_count;
    uint32_t passed_count;
    uint32_t failed_count;
    uint32_t skipped_count;
} test_category_t;

/* Test suite structure */
typedef struct test_suite {
    char* name;
    char* description;
    test_case_t* tests[MAX_TESTS];
    uint32_t test_count;
    uint32_t passed_count;
    uint32_t failed_count;
    uint32_t skipped_count;
} test_suite_t;

/* Memory statistics */
typedef struct {
    uint64_t total_allocated;
    uint64_t total_freed;
    uint64_t current_usage;
    uint64_t peak_usage;
    uint32_t allocation_count;
    uint32_t free_count;
} memory_stats_t;

/* Performance statistics */
typedef struct {
    uint64_t total_duration;
    uint64_t average_duration;
    uint64_t min_duration;
    uint64_t max_duration;
    uint32_t test_count;
} performance_stats_t;

/* Coverage statistics */
typedef struct {
    uint32_t lines_covered;
    uint32_t lines_total;
    uint32_t branches_covered;
    uint32_t branches_total;
    float line_coverage;
    float branch_coverage;
} coverage_stats_t;

/* Test framework state */
typedef struct {
    bool initialized;
    test_case_t* current_test;
    uint32_t test_count;
    uint32_t passed_count;
    uint32_t failed_count;
    uint32_t skipped_count;
    uint32_t total_assertions;
    uint32_t passed_assertions;
    uint32_t failed_assertions;
    uint64_t start_time;
    uint64_t current_test_start_time;
    uint32_t max_test_name_length;
    
    /* Configuration */
    bool verbose_output;
    bool stop_on_failure;
    bool randomize_order;
    bool parallel_execution;
    uint32_t max_parallel_tests;
    bool memory_tracking;
    bool performance_tracking;
    bool coverage_tracking;
    bool leak_detection;
    uint32_t timeout_seconds;
    uint32_t retry_count;
    uint32_t retry_delay_ms;
    char test_filter[256];
    char test_exclude[256];
    char output_file[256];
    test_log_level_t log_level;
} test_framework_state_t;

/* Test statistics */
typedef struct {
    uint32_t total_tests;
    uint32_t passed_tests;
    uint32_t failed_tests;
    uint32_t skipped_tests;
    uint32_t total_assertions;
    uint32_t passed_assertions;
    uint32_t failed_assertions;
    uint64_t total_duration;
    float success_rate;
} test_statistics_t;

/* Exception structure for test failures */
typedef struct {
    const char* message;
    const char* file;
    uint32_t line;
    const char* function;
} exception_t;

/* Maximum values */
#define MAX_TESTS 1024
#define MAX_CATEGORIES 32
#define MAX_SUITES 64
#define MAX_TESTS_PER_SUITE 256

/* Test framework functions */
void test_framework_init(void);
void test_framework_shutdown(void);
bool test_register(const char* name, test_function_t function, const char* description, test_category_t category, test_priority_t priority, uint32_t timeout);
bool test_category_register(const char* name, const char* description);
bool test_suite_register(const char* name, const char* description);
bool test_suite_add_test(const char* suite_name, const char* test_name);
test_result_t test_run_all(void);
test_result_t test_run_suite(const char* suite_name);
test_result_t test_run_by_name(const char* test_name);

/* Test assertion functions */
void test_assert(bool condition, const char* expression, const char* message, const char* file, uint32_t line);
void test_assert_equal_int(int64_t expected, int64_t actual, const char* expression, const char* message, const char* file, uint32_t line);
void test_assert_equal_uint(uint64_t expected, uint64_t actual, const char* expression, const char* message, const char* file, uint32_t line);
void test_assert_equal_string(const char* expected, const char* actual, const char* expression, const char* message, const char* file, uint32_t line);
void test_assert_not_null(const void* pointer, const char* expression, const char* message, const char* file, uint32_t line);
void test_assert_null(const void* pointer, const char* expression, const char* message, const char* file, uint32_t line);
void test_assert_true(bool condition, const char* expression, const char* message, const char* file, uint32_t line);
void test_assert_false(bool condition, const char* expression, const char* message, const char* file, uint32_t line);

/* Test utility functions */
void test_generate_report(void);
void test_set_config(test_config_option_t option, void* value);
void test_get_statistics(test_statistics_t* stats);
void test_list_tests(void);
void test_list_categories(void);
void test_list_suites(void);

/* Memory and performance tracking */
void get_memory_stats(memory_stats_t* stats);
void get_performance_stats(performance_stats_t* stats);
void get_coverage_stats(coverage_stats_t* stats);

/* Helper functions that need to be implemented elsewhere */
uint64_t get_current_time(void);
void* kmalloc(size_t size);
void kfree(void* ptr);
char* strcpy(char* dest, const char* src);
size_t strlen(const char* str);
int strcmp(const char* str1, const char* str2);
char* strstr(const char* haystack, const char* needle);
int snprintf(char* str, size_t size, const char* format, ...);
void memset(void* dest, int value, size_t size);
void kernel_log(int level, const char* component, const char* format, ...);
void debug_stack_trace(void);

/* Convenience macros */
#define TEST_ASSERT(condition) \
    test_assert(condition, #condition, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_MSG(condition, message) \
    test_assert(condition, #condition, message, __FILE__, __LINE__)

#define TEST_ASSERT_EQUAL_INT(expected, actual) \
    test_assert_equal_int(expected, actual, #actual, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_EQUAL_INT_MSG(expected, actual, message) \
    test_assert_equal_int(expected, actual, #actual, message, __FILE__, __LINE__)

#define TEST_ASSERT_EQUAL_UINT(expected, actual) \
    test_assert_equal_uint(expected, actual, #actual, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_EQUAL_UINT_MSG(expected, actual, message) \
    test_assert_equal_uint(expected, actual, #actual, message, __FILE__, __LINE__)

#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    test_assert_equal_string(expected, actual, #actual, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_EQUAL_STRING_MSG(expected, actual, message) \
    test_assert_equal_string(expected, actual, #actual, message, __FILE__, __LINE__)

#define TEST_ASSERT_NOT_NULL(pointer) \
    test_assert_not_null(pointer, #pointer, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_NOT_NULL_MSG(pointer, message) \
    test_assert_not_null(pointer, #pointer, message, __FILE__, __LINE__)

#define TEST_ASSERT_NULL(pointer) \
    test_assert_null(pointer, #pointer, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_NULL_MSG(pointer, message) \
    test_assert_null(pointer, #pointer, message, __FILE__, __LINE__)

#define TEST_ASSERT_TRUE(condition) \
    test_assert_true(condition, #condition, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_TRUE_MSG(condition, message) \
    test_assert_true(condition, #condition, message, __FILE__, __LINE__)

#define TEST_ASSERT_FALSE(condition) \
    test_assert_false(condition, #condition, NULL, __FILE__, __LINE__)

#define TEST_ASSERT_FALSE_MSG(condition, message) \
    test_assert_false(condition, #condition, message, __FILE__, __LINE__)

#define TEST_SKIP(message) \
    do { \
        kernel_log(LOG_INFO, "TestFramework", "Test skipped: %s", message); \
        return TEST_RESULT_SKIPPED; \
    } while (0)

#define TEST_FAIL(message) \
    do { \
        test_assert(false, "TEST_FAIL", message, __FILE__, __LINE__); \
        return TEST_RESULT_FAILED; \
    } while (0)

#define TEST_REGISTER(name, function, description, category, priority, timeout) \
    test_register(name, function, description, category, priority, timeout)

#define TEST_REGISTER_SIMPLE(name, function) \
    test_register(name, function, NULL, TEST_CATEGORY_UNIT, TEST_PRIORITY_MEDIUM, 30)

#define TEST_SUITE_REGISTER(name, description) \
    test_suite_register(name, description)

#define TEST_SUITE_ADD_TEST(suite_name, test_name) \
    test_suite_add_test(suite_name, test_name)

#define TEST_CATEGORY_REGISTER(name, description) \
    test_category_register(name, description)

#endif /* TEST_FRAMEWORK_H */