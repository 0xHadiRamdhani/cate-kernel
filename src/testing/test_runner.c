#include "test_framework.h"
#include "../kernel/memory.h"
#include "../kernel/string.h"
#include "../kernel/logging.h"
#include "../drivers/vga.h"

/* External test suite creation functions */
extern test_suite_t* create_kernel_test_suite(void);
extern test_suite_t* create_forensics_test_suite(void);
extern test_suite_t* create_network_test_suite(void);
extern test_suite_t* create_security_test_suite(void);
extern test_suite_t* create_performance_test_suite(void);
extern test_suite_t* create_integration_test_suite(void);
extern test_suite_t* create_stress_test_suite(void);
extern test_suite_t* create_regression_test_suite(void);

/* Test runner configuration */
typedef struct {
    bool run_all_tests;
    bool run_kernel_tests;
    bool run_forensics_tests;
    bool run_network_tests;
    bool run_security_tests;
    bool run_performance_tests;
    bool run_integration_tests;
    bool run_stress_tests;
    bool run_regression_tests;
    test_category_t specific_category;
    test_severity_t specific_severity;
    bool generate_report;
    bool export_results;
    bool memory_profiling;
    bool performance_profiling;
    bool security_checks;
    uint32_t timeout;
    uint32_t memory_threshold;
    uint32_t performance_threshold;
    char report_filename[256];
    char export_filename[256];
} test_runner_config_t;

/* Global test runner configuration */
static test_runner_config_t test_config = {
    .run_all_tests = true,
    .run_kernel_tests = true,
    .run_forensics_tests = true,
    .run_network_tests = true,
    .run_security_tests = true,
    .run_performance_tests = true,
    .run_integration_tests = true,
    .run_stress_tests = false,
    .run_regression_tests = false,
    .specific_category = 0,
    .specific_severity = 0,
    .generate_report = true,
    .export_results = false,
    .memory_profiling = true,
    .performance_profiling = true,
    .security_checks = true,
    .timeout = TEST_DEFAULT_TIMEOUT,
    .memory_threshold = TEST_DEFAULT_MEMORY_THRESHOLD,
    .performance_threshold = TEST_DEFAULT_PERFORMANCE_THRESHOLD,
    .report_filename = "test_report.txt",
    .export_filename = "test_results.json"
};

/* Initialize test runner */
static void test_runner_init(void) {
    kernel_log(LOG_INFO, "TestRunner", "Initializing test runner");
    
    /* Initialize test framework */
    test_framework_init();
    
    /* Configure test framework */
    test_set_verbose(true);
    test_set_timeout(test_config.timeout);
    test_set_memory_threshold(test_config.memory_threshold);
    test_set_performance_threshold(test_config.performance_threshold);
    test_enable_memory_profiling(test_config.memory_profiling);
    test_enable_performance_profiling(test_config.performance_profiling);
    test_enable_security_checks(test_config.security_checks);
    
    kernel_log(LOG_INFO, "TestRunner", "Test runner initialized successfully");
}

/* Shutdown test runner */
static void test_runner_shutdown(void) {
    kernel_log(LOG_INFO, "TestRunner", "Shutting down test runner");
    
    /* Shutdown test framework */
    test_framework_shutdown();
    
    kernel_log(LOG_INFO, "TestRunner", "Test runner shutdown successfully");
}

/* Register all test suites */
static void register_test_suites(void) {
    kernel_log(LOG_INFO, "TestRunner", "Registering test suites");
    
    /* Register kernel test suite */
    if (test_config.run_kernel_tests || test_config.run_all_tests) {
        test_suite_t* kernel_suite = create_kernel_test_suite();
        if (kernel_suite != NULL) {
            test_register_suite(kernel_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered kernel test suite");
        }
    }
    
    /* Register forensics test suite */
    if (test_config.run_forensics_tests || test_config.run_all_tests) {
        test_suite_t* forensics_suite = create_forensics_test_suite();
        if (forensics_suite != NULL) {
            test_register_suite(forensics_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered forensics test suite");
        }
    }
    
    /* Register network test suite */
    if (test_config.run_network_tests || test_config.run_all_tests) {
        test_suite_t* network_suite = create_network_test_suite();
        if (network_suite != NULL) {
            test_register_suite(network_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered network test suite");
        }
    }
    
    /* Register security test suite */
    if (test_config.run_security_tests || test_config.run_all_tests) {
        test_suite_t* security_suite = create_security_test_suite();
        if (security_suite != NULL) {
            test_register_suite(security_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered security test suite");
        }
    }
    
    /* Register performance test suite */
    if (test_config.run_performance_tests || test_config.run_all_tests) {
        test_suite_t* performance_suite = create_performance_test_suite();
        if (performance_suite != NULL) {
            test_register_suite(performance_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered performance test suite");
        }
    }
    
    /* Register integration test suite */
    if (test_config.run_integration_tests || test_config.run_all_tests) {
        test_suite_t* integration_suite = create_integration_test_suite();
        if (integration_suite != NULL) {
            test_register_suite(integration_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered integration test suite");
        }
    }
    
    /* Register stress test suite */
    if (test_config.run_stress_tests) {
        test_suite_t* stress_suite = create_stress_test_suite();
        if (stress_suite != NULL) {
            test_register_suite(stress_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered stress test suite");
        }
    }
    
    /* Register regression test suite */
    if (test_config.run_regression_tests) {
        test_suite_t* regression_suite = create_regression_test_suite();
        if (regression_suite != NULL) {
            test_register_suite(regression_suite);
            kernel_log(LOG_INFO, "TestRunner", "Registered regression test suite");
        }
    }
    
    kernel_log(LOG_INFO, "TestRunner", "Test suites registration completed");
}

/* Print test configuration */
static void print_test_configuration(void) {
    vga_printf("\n=== TEST RUNNER CONFIGURATION ===\n");
    vga_printf("Run All Tests: %s\n", test_config.run_all_tests ? "YES" : "NO");
    vga_printf("Run Kernel Tests: %s\n", test_config.run_kernel_tests ? "YES" : "NO");
    vga_printf("Run Forensics Tests: %s\n", test_config.run_forensics_tests ? "YES" : "NO");
    vga_printf("Run Network Tests: %s\n", test_config.run_network_tests ? "YES" : "NO");
    vga_printf("Run Security Tests: %s\n", test_config.run_security_tests ? "YES" : "NO");
    vga_printf("Run Performance Tests: %s\n", test_config.run_performance_tests ? "YES" : "NO");
    vga_printf("Run Integration Tests: %s\n", test_config.run_integration_tests ? "YES" : "NO");
    vga_printf("Run Stress Tests: %s\n", test_config.run_stress_tests ? "YES" : "NO");
    vga_printf("Run Regression Tests: %s\n", test_config.run_regression_tests ? "YES" : "NO");
    vga_printf("Generate Report: %s\n", test_config.generate_report ? "YES" : "NO");
    vga_printf("Export Results: %s\n", test_config.export_results ? "YES" : "NO");
    vga_printf("Memory Profiling: %s\n", test_config.memory_profiling ? "YES" : "NO");
    vga_printf("Performance Profiling: %s\n", test_config.performance_profiling ? "YES" : "NO");
    vga_printf("Security Checks: %s\n", test_config.security_checks ? "YES" : "NO");
    vga_printf("Timeout: %u ms\n", test_config.timeout);
    vga_printf("Memory Threshold: %u bytes\n", test_config.memory_threshold);
    vga_printf("Performance Threshold: %u ms\n", test_config.performance_threshold);
    vga_printf("Report Filename: %s\n", test_config.report_filename);
    vga_printf("Export Filename: %s\n", test_config.export_filename);
    vga_printf("\n");
}

/* Run tests based on configuration */
static void run_tests(void) {
    kernel_log(LOG_INFO, "TestRunner", "Starting test execution");
    
    /* Print test configuration */
    print_test_configuration();
    
    /* Run tests based on specific category */
    if (test_config.specific_category != 0) {
        kernel_log(LOG_INFO, "TestRunner", "Running tests for specific category: %d", test_config.specific_category);
        test_run_category(test_config.specific_category);
        return;
    }
    
    /* Run tests based on specific severity */
    if (test_config.specific_severity != 0) {
        kernel_log(LOG_INFO, "TestRunner", "Running tests for specific severity: %d", test_config.specific_severity);
        test_run_severity(test_config.specific_severity);
        return;
    }
    
    /* Run all tests */
    if (test_config.run_all_tests) {
        kernel_log(LOG_INFO, "TestRunner", "Running all tests");
        test_run_all();
        return;
    }
    
    /* Run specific test suites */
    uint32_t suites_run = 0;
    
    if (test_config.run_kernel_tests) {
        kernel_log(LOG_INFO, "TestRunner", "Running kernel tests");
        test_run_category(TEST_CATEGORY_KERNEL);
        suites_run++;
    }
    
    if (test_config.run_forensics_tests) {
        kernel_log(LOG_INFO, "TestRunner", "Running forensics tests");
        test_run_category(TEST_CATEGORY_FORENSICS);
        suites_run++;
    }
    
    if (test_config.run_network_tests) {
        kernel_log(LOG_INFO, "TestRunner", "Running network tests");
        test_run_category(TEST_CATEGORY_NETWORK);
        suites_run++;
    }
    
    if (test_config.run_security_tests) {
        kernel_log(LOG_INFO, "TestRunner", "Running security tests");
        test_run_category(TEST_CATEGORY_SECURITY);
        suites_run++;
    }
    
    if (test_config.run_performance_tests) {
        kernel_log(LOG_INFO, "TestRunner", "Running performance tests");
        test_run_category(TEST_CATEGORY_PERFORMANCE);
        suites_run++;
    }
    
    if (test_config.run_integration_tests) {
        kernel_log(LOG_INFO, "TestRunner", "Running integration tests");
        test_run_category(TEST_CATEGORY_INTEGRATION);
        suites_run++;
    }
    
    if (suites_run == 0) {
        kernel_log(LOG_WARNING, "TestRunner", "No test suites selected to run");
    }
}

/* Generate test report */
static void generate_test_report(void) {
    if (!test_config.generate_report) {
        return;
    }
    
    kernel_log(LOG_INFO, "TestRunner", "Generating test report: %s", test_config.report_filename);
    
    /* Generate comprehensive test report */
    test_result_t result = test_generate_report();
    if (result == TEST_RESULT_PASS) {
        kernel_log(LOG_INFO, "TestRunner", "Test report generated successfully");
    } else {
        kernel_log(LOG_ERROR, "TestRunner", "Failed to generate test report");
    }
}

/* Export test results */
static void export_test_results(void) {
    if (!test_config.export_results) {
        return;
    }
    
    kernel_log(LOG_INFO, "TestRunner", "Exporting test results to: %s", test_config.export_filename);
    
    /* Export test results */
    test_result_t result = test_export_results(test_config.export_filename);
    if (result == TEST_RESULT_PASS) {
        kernel_log(LOG_INFO, "TestRunner", "Test results exported successfully");
    } else {
        kernel_log(LOG_ERROR, "TestRunner", "Failed to export test results");
    }
}

/* Print test statistics */
static void print_test_statistics(void) {
    uint32_t total_tests, passed_tests, failed_tests, skipped_tests;
    
    test_get_statistics(&total_tests, &passed_tests, &failed_tests, &skipped_tests);
    
    vga_printf("\n=== FINAL TEST STATISTICS ===\n");
    vga_printf("Total Tests: %u\n", total_tests);
    vga_printf("Passed: %u\n", passed_tests);
    vga_printf("Failed: %u\n", failed_tests);
    vga_printf("Skipped: %u\n", skipped_tests);
    
    if (total_tests > 0) {
        uint32_t pass_rate = (passed_tests * 100) / total_tests;
        vga_printf("Pass Rate: %u%%\n", pass_rate);
        
        if (pass_rate >= 90) {
            vga_printf("Status: EXCELLENT\n");
        } else if (pass_rate >= 80) {
            vga_printf("Status: GOOD\n");
        } else if (pass_rate >= 70) {
            vga_printf("Status: FAIR\n");
        } else {
            vga_printf("Status: POOR\n");
        }
    }
    
    /* Print performance statistics */
    uint64_t total_time, total_memory, total_cpu_time;
    test_get_performance_statistics(&total_time, &total_memory, &total_cpu_time);
    
    vga_printf("\n=== PERFORMANCE STATISTICS ===\n");
    vga_printf("Total Time: %llu ms\n", total_time);
    vga_printf("Total Memory: %llu bytes\n", total_memory);
    vga_printf("Total CPU Time: %llu ms\n", total_cpu_time);
    
    /* Print security statistics */
    uint32_t security_issues, memory_issues, performance_issues;
    test_get_security_statistics(&security_issues, &memory_issues, &performance_issues);
    
    vga_printf("\n=== SECURITY STATISTICS ===\n");
    vga_printf("Security Issues: %u\n", security_issues);
    vga_printf("Memory Issues: %u\n", memory_issues);
    vga_printf("Performance Issues: %u\n", performance_issues);
}

/* Parse command line arguments */
static void parse_command_line_args(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--kernel-only") == 0) {
            test_config.run_all_tests = false;
            test_config.run_kernel_tests = true;
            test_config.run_forensics_tests = false;
            test_config.run_network_tests = false;
            test_config.run_security_tests = false;
            test_config.run_performance_tests = false;
            test_config.run_integration_tests = false;
        } else if (strcmp(argv[i], "--forensics-only") == 0) {
            test_config.run_all_tests = false;
            test_config.run_kernel_tests = false;
            test_config.run_forensics_tests = true;
            test_config.run_network_tests = false;
            test_config.run_security_tests = false;
            test_config.run_performance_tests = false;
            test_config.run_integration_tests = false;
        } else if (strcmp(argv[i], "--network-only") == 0) {
            test_config.run_all_tests = false;
            test_config.run_kernel_tests = false;
            test_config.run_forensics_tests = false;
            test_config.run_network_tests = true;
            test_config.run_security_tests = false;
            test_config.run_performance_tests = false;
            test_config.run_integration_tests = false;
        } else if (strcmp(argv[i], "--security-only") == 0) {
            test_config.run_all_tests = false;
            test_config.run_kernel_tests = false;
            test_config.run_forensics_tests = false;
            test_config.run_network_tests = false;
            test_config.run_security_tests = true;
            test_config.run_performance_tests = false;
            test_config.run_integration_tests = false;
        } else if (strcmp(argv[i], "--performance-only") == 0) {
            test_config.run_all_tests = false;
            test_config.run_kernel_tests = false;
            test_config.run_forensics_tests = false;
            test_config.run_network_tests = false;
            test_config.run_security_tests = false;
            test_config.run_performance_tests = true;
            test_config.run_integration_tests = false;
        } else if (strcmp(argv[i], "--no-report") == 0) {
            test_config.generate_report = false;
        } else if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) {
            test_config.export_results = true;
            strncpy(test_config.export_filename, argv[++i], sizeof(test_config.export_filename) - 1);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            test_config.timeout = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--memory-threshold") == 0 && i + 1 < argc) {
            test_config.memory_threshold = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--performance-threshold") == 0 && i + 1 < argc) {
            test_config.performance_threshold = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            vga_printf("Usage: %s [options]\n", argv[0]);
            vga_printf("Options:\n");
            vga_printf("  --kernel-only           Run only kernel tests\n");
            vga_printf("  --forensics-only        Run only forensics tests\n");
            vga_printf("  --network-only          Run only network tests\n");
            vga_printf("  --security-only         Run only security tests\n");
            vga_printf("  --performance-only      Run only performance tests\n");
            vga_printf("  --no-report             Do not generate test report\n");
            vga_printf("  --export <filename>     Export test results to file\n");
            vga_printf("  --timeout <ms>          Set test timeout in milliseconds\n");
            vga_printf("  --memory-threshold <bytes> Set memory leak threshold\n");
            vga_printf("  --performance-threshold <ms> Set performance threshold\n");
            vga_printf("  --help, -h              Show this help message\n");
            /* Don't run tests if help is requested */
            test_config.run_all_tests = false;
            test_config.run_kernel_tests = false;
            test_config.run_forensics_tests = false;
            test_config.run_network_tests = false;
            test_config.run_security_tests = false;
            test_config.run_performance_tests = false;
            test_config.run_integration_tests = false;
        }
    }
}

/* Main test runner function */
void run_test_runner(int argc, char* argv[]) {
    kernel_log(LOG_INFO, "TestRunner", "Starting PentesterOS Test Runner");
    
    /* Parse command line arguments */
    parse_command_line_args(argc, argv);
    
    /* Check if any tests should be run */
    if (!test_config.run_all_tests && 
        !test_config.run_kernel_tests && 
        !test_config.run_forensics_tests && 
        !test_config.run_network_tests && 
        !test_config.run_security_tests && 
        !test_config.run_performance_tests && 
        !test_config.run_integration_tests &&
        test_config.specific_category == 0 &&
        test_config.specific_severity == 0) {
        
        kernel_log(LOG_INFO, "TestRunner", "No tests selected to run");
        return;
    }
    
    /* Initialize test runner */
    test_runner_init();
    
    /* Register test suites */
    register_test_suites();
    
    /* Run tests */
    run_tests();
    
    /* Generate reports */
    generate_test_report();
    export_test_results();
    
    /* Print final statistics */
    print_test_statistics();
    
    /* Shutdown test runner */
    test_runner_shutdown();
    
    kernel_log(LOG_INFO, "TestRunner", "PentesterOS Test Runner completed");
}

/* Simple test runner for basic testing */
void run_simple_tests(void) {
    kernel_log(LOG_INFO, "TestRunner", "Running simple tests");
    
    /* Initialize test framework */
    test_framework_init();
    
    /* Create and register basic test suites */
    test_suite_t* kernel_suite = create_kernel_test_suite();
    if (kernel_suite != NULL) {
        test_register_suite(kernel_suite);
    }
    
    /* Run basic tests */
    test_run_all();
    
    /* Print summary */
    test_print_summary();
    
    /* Shutdown test framework */
    test_framework_shutdown();
    
    kernel_log(LOG_INFO, "TestRunner", "Simple tests completed");
}

/* Test runner entry point */
void test_runner_main(int argc, char* argv[]) {
    /* Check if we should run the full test runner or simple tests */
    if (argc > 1) {
        /* Run full test runner with command line arguments */
        run_test_runner(argc, argv);
    } else {
        /* Run simple tests */
        run_simple_tests();
    }
}