#include "test_framework.h"
#include "../forensics/forensics.h"
#include "../kernel/memory.h"
#include "../kernel/string.h"
#include "../kernel/logging.h"
#include "../security/crypto.h"

/* Test data structures */
typedef struct {
    uint8_t test_data[1024];
    uint32_t data_size;
    char test_filename[256];
    char test_case_id[64];
    char test_evidence_tag[128];
} forensics_test_data_t;

/* Forensics tool test cases */

/* Test forensics initialization */
static test_result_t test_forensics_init(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test forensics subsystem initialization */
    forensics_init();
    TEST_ASSERT_TRUE(forensics_is_initialized());
    
    /* Test double initialization */
    forensics_init(); /* Should not crash */
    TEST_ASSERT_TRUE(forensics_is_initialized());
    
    return TEST_RESULT_PASS;
}

/* Test forensics shutdown */
static test_result_t test_forensics_shutdown(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    TEST_ASSERT_TRUE(forensics_is_initialized());
    
    /* Test shutdown */
    forensics_shutdown();
    TEST_ASSERT_FALSE(forensics_is_initialized());
    
    /* Test double shutdown */
    forensics_shutdown(); /* Should not crash */
    TEST_ASSERT_FALSE(forensics_is_initialized());
    
    return TEST_RESULT_PASS;
}

/* Test evidence creation */
static test_result_t test_evidence_creation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Test evidence creation */
    forensics_evidence_t* evidence = forensics_create_evidence("TEST_CASE_001", "TEST_EVIDENCE_001", FORENSICS_EVIDENCE_FILE);
    TEST_ASSERT_NOT_NULL(evidence);
    
    /* Verify evidence properties */
    TEST_ASSERT_STRING_EQUAL("TEST_CASE_001", evidence->case_id);
    TEST_ASSERT_STRING_EQUAL("TEST_EVIDENCE_001", evidence->evidence_tag);
    TEST_ASSERT_EQUAL(FORENSICS_EVIDENCE_FILE, evidence->evidence_type);
    
    /* Test evidence destruction */
    forensics_status_t status = forensics_destroy_evidence(evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    return TEST_RESULT_PASS;
}

/* Test tool creation */
static test_result_t test_tool_creation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Test tool creation */
    forensics_tool_t* tool = forensics_create_tool(FORENSICS_ANALYSIS_FILE_CARVING, "FileCarver", "File carving tool");
    TEST_ASSERT_NOT_NULL(tool);
    
    /* Verify tool properties */
    TEST_ASSERT_STRING_EQUAL("FileCarver", tool->name);
    TEST_ASSERT_STRING_EQUAL("File carving tool", tool->description);
    TEST_ASSERT_EQUAL(FORENSICS_ANALYSIS_FILE_CARVING, tool->analysis_type);
    TEST_ASSERT_TRUE(tool->enabled);
    TEST_ASSERT_FALSE(tool->running);
    
    /* Test tool destruction */
    forensics_status_t status = forensics_destroy_tool(tool);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    return TEST_RESULT_PASS;
}

/* Test evidence management */
static test_result_t test_evidence_management(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create multiple evidence items */
    forensics_evidence_t* evidence1 = forensics_create_evidence("CASE_001", "EVIDENCE_001", FORENSICS_EVIDENCE_FILE);
    forensics_evidence_t* evidence2 = forensics_create_evidence("CASE_001", "EVIDENCE_002", FORENSICS_EVIDENCE_MEMORY);
    forensics_evidence_t* evidence3 = forensics_create_evidence("CASE_002", "EVIDENCE_003", FORENSICS_EVIDENCE_NETWORK);
    
    TEST_ASSERT_NOT_NULL(evidence1);
    TEST_ASSERT_NOT_NULL(evidence2);
    TEST_ASSERT_NOT_NULL(evidence3);
    
    /* Add evidence to manager */
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_add_evidence(evidence1));
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_add_evidence(evidence2));
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_add_evidence(evidence3));
    
    /* Test evidence retrieval */
    forensics_evidence_t* found_evidence = forensics_get_evidence(1);
    TEST_ASSERT_NOT_NULL(found_evidence);
    TEST_ASSERT_EQUAL(1, found_evidence->evidence_id);
    
    /* Test evidence retrieval by tag */
    found_evidence = forensics_get_evidence_by_tag("EVIDENCE_002");
    TEST_ASSERT_NOT_NULL(found_evidence);
    TEST_ASSERT_STRING_EQUAL("EVIDENCE_002", found_evidence->evidence_tag);
    
    /* Test evidence count */
    TEST_ASSERT_EQUAL(3, forensics_get_evidence_count());
    
    /* Test evidence removal */
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_remove_evidence(2));
    TEST_ASSERT_EQUAL(2, forensics_get_evidence_count());
    
    return TEST_RESULT_PASS;
}

/* Test tool management */
static test_result_t test_tool_management(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create multiple tools */
    forensics_tool_t* tool1 = forensics_create_tool(FORENSICS_ANALYSIS_FILE_CARVING, "FileCarver", "File carving tool");
    forensics_tool_t* tool2 = forensics_create_tool(FORENSICS_ANALYSIS_MEMORY_ANALYSIS, "MemoryAnalyzer", "Memory analysis tool");
    forensics_tool_t* tool3 = forensics_create_tool(FORENSICS_ANALYSIS_NETWORK_TRAFFIC, "NetworkAnalyzer", "Network analysis tool");
    
    TEST_ASSERT_NOT_NULL(tool1);
    TEST_ASSERT_NOT_NULL(tool2);
    TEST_ASSERT_NOT_NULL(tool3);
    
    /* Register tools */
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_register_tool(tool1));
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_register_tool(tool2));
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_register_tool(tool3));
    
    /* Test tool retrieval */
    forensics_tool_t* found_tool = forensics_get_tool(1);
    TEST_ASSERT_NOT_NULL(found_tool);
    TEST_ASSERT_EQUAL(1, found_tool->tool_id);
    
    /* Test tool retrieval by name */
    found_tool = forensics_get_tool_by_name("MemoryAnalyzer");
    TEST_ASSERT_NOT_NULL(found_tool);
    TEST_ASSERT_STRING_EQUAL("MemoryAnalyzer", found_tool->name);
    
    /* Test tool count */
    TEST_ASSERT_EQUAL(3, forensics_get_tool_count());
    
    /* Test tool unregistration */
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_unregister_tool(2));
    TEST_ASSERT_EQUAL(2, forensics_get_tool_count());
    
    return TEST_RESULT_PASS;
}

/* Test hash calculation */
static test_result_t test_hash_calculation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create evidence */
    forensics_evidence_t* evidence = forensics_create_evidence("TEST_CASE", "TEST_HASH", FORENSICS_EVIDENCE_FILE);
    TEST_ASSERT_NOT_NULL(evidence);
    
    /* Create tool */
    forensics_tool_t* tool = forensics_create_tool(FORENSICS_ANALYSIS_HASH_ANALYSIS, "HashTool", "Hash analysis tool");
    TEST_ASSERT_NOT_NULL(tool);
    
    /* Test hash calculation */
    forensics_status_t status = forensics_calculate_hash(tool, evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Verify hash was calculated */
    TEST_ASSERT_TRUE(evidence->hash_size > 0);
    TEST_ASSERT_NOT_NULL(evidence->hash);
    
    return TEST_RESULT_PASS;
}

/* Test hash verification */
static test_result_t test_hash_verification(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create evidence */
    forensics_evidence_t* evidence = forensics_create_evidence("TEST_CASE", "TEST_HASH_VERIFY", FORENSICS_EVIDENCE_FILE);
    TEST_ASSERT_NOT_NULL(evidence);
    
    /* Create tool */
    forensics_tool_t* tool = forensics_create_tool(FORENSICS_ANALYSIS_HASH_ANALYSIS, "HashTool", "Hash analysis tool");
    TEST_ASSERT_NOT_NULL(tool);
    
    /* Calculate hash */
    forensics_status_t status = forensics_calculate_hash(tool, evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Verify hash */
    status = forensics_verify_hash(tool, evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    return TEST_RESULT_PASS;
}

/* Test hash comparison */
static test_result_t test_hash_comparison(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create tool */
    forensics_tool_t* tool = forensics_create_tool(FORENSICS_ANALYSIS_HASH_ANALYSIS, "HashTool", "Hash analysis tool");
    TEST_ASSERT_NOT_NULL(tool);
    
    /* Create test hashes */
    uint8_t hash1[32] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90};
    uint8_t hash2[32] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90};
    uint8_t hash3[32] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    
    /* Test equal hashes */
    forensics_status_t status = forensics_compare_hash(tool, hash1, hash2, 32);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Test different hashes */
    status = forensics_compare_hash(tool, hash1, hash3, 32);
    TEST_ASSERT_NOT_EQUAL(FORENSICS_STATUS_OK, status);
    
    return TEST_RESULT_PASS;
}

/* Test signature verification */
static test_result_t test_signature_verification(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create evidence */
    forensics_evidence_t* evidence = forensics_create_evidence("TEST_CASE", "TEST_SIGNATURE", FORENSICS_EVIDENCE_FILE);
    TEST_ASSERT_NOT_NULL(evidence);
    
    /* Create tool */
    forensics_tool_t* tool = forensics_create_tool(FORENSICS_ANALYSIS_SIGNATURE_ANALYSIS, "SignatureTool", "Signature analysis tool");
    TEST_ASSERT_NOT_NULL(tool);
    
    /* Test signature verification */
    forensics_status_t status = forensics_verify_signature(tool, evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    return TEST_RESULT_PASS;
}

/* Test chain of custody */
static test_result_t test_chain_of_custody(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create evidence */
    forensics_evidence_t* evidence = forensics_create_evidence("TEST_CASE", "TEST_CUSTODY", FORENSICS_EVIDENCE_FILE);
    TEST_ASSERT_NOT_NULL(evidence);
    
    /* Test custody establishment */
    forensics_status_t status = forensics_establish_custody(evidence, "Investigator_001");
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Verify custody information */
    TEST_ASSERT_EQUAL(FORENSICS_CUSTODY_SECURE, evidence->custody);
    TEST_ASSERT_STRING_EQUAL("Investigator_001", evidence->analyst_name);
    
    /* Test custody transfer */
    status = forensics_transfer_custody(evidence, "Investigator_002");
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Verify new custody information */
    TEST_ASSERT_EQUAL(FORENSICS_CUSTODY_SECURE, evidence->custody);
    TEST_ASSERT_STRING_EQUAL("Investigator_002", evidence->analyst_name);
    
    /* Test custody verification */
    status = forensics_verify_custody(evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    return TEST_RESULT_PASS;
}

/* Test evidence integrity */
static test_result_t test_evidence_integrity(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Create evidence */
    forensics_evidence_t* evidence = forensics_create_evidence("TEST_CASE", "TEST_INTEGRITY", FORENSICS_EVIDENCE_FILE);
    TEST_ASSERT_NOT_NULL(evidence);
    
    /* Test integrity verification */
    forensics_status_t status = forensics_verify_integrity(evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Test integrity hash calculation */
    status = forensics_calculate_integrity_hash(evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Test evidence signing */
    status = forensics_sign_evidence(evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Test signature verification */
    status = forensics_verify_evidence_signature(evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    
    /* Verify integrity status */
    TEST_ASSERT_EQUAL(FORENSICS_INTEGRITY_VERIFIED, forensics_get_integrity_status(evidence));
    
    return TEST_RESULT_PASS;
}

/* Test configuration management */
static test_result_t test_configuration_management(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Test security level setting */
    forensics_status_t status = forensics_set_security_level(3);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_EQUAL(3, forensics_get_security_level());
    
    /* Test encryption enable/disable */
    status = forensics_enable_encryption(true);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_TRUE(forensics_is_encryption_enabled());
    
    status = forensics_enable_encryption(false);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_FALSE(forensics_is_encryption_enabled());
    
    /* Test logging enable/disable */
    status = forensics_enable_logging(true);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_TRUE(forensics_is_logging_enabled());
    
    status = forensics_enable_logging(false);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_FALSE(forensics_is_logging_enabled());
    
    /* Test reporting enable/disable */
    status = forensics_enable_reporting(true);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_TRUE(forensics_is_reporting_enabled());
    
    status = forensics_enable_reporting(false);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_FALSE(forensics_is_reporting_enabled());
    
    /* Test chain of custody enable/disable */
    status = forensics_enable_chain_of_custody(true);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_TRUE(forensics_is_chain_of_custody_enabled());
    
    status = forensics_enable_chain_of_custody(false);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, status);
    TEST_ASSERT_FALSE(forensics_is_chain_of_custody_enabled());
    
    return TEST_RESULT_PASS;
}

/* Test statistics management */
static test_result_t test_statistics_management(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize forensics */
    forensics_init();
    
    /* Get initial statistics */
    uint64_t total_analyses, total_evidence, total_recoveries, total_reports;
    forensics_get_statistics(&total_analyses, &total_evidence, &total_recoveries, &total_reports);
    
    /* Verify initial statistics */
    TEST_ASSERT_EQUAL(0, total_analyses);
    TEST_ASSERT_EQUAL(0, total_evidence);
    TEST_ASSERT_EQUAL(0, total_recoveries);
    TEST_ASSERT_EQUAL(0, total_reports);
    
    /* Create and register evidence */
    forensics_evidence_t* evidence = forensics_create_evidence("TEST_CASE", "TEST_STATS", FORENSICS_EVIDENCE_FILE);
    TEST_ASSERT_NOT_NULL(evidence);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_add_evidence(evidence));
    
    /* Create and register tool */
    forensics_tool_t* tool = forensics_create_tool(FORENSICS_ANALYSIS_FILE_CARVING, "StatsTool", "Statistics test tool");
    TEST_ASSERT_NOT_NULL(tool);
    TEST_ASSERT_EQUAL(FORENSICS_STATUS_OK, forensics_register_tool(tool));
    
    /* Get updated statistics */
    forensics_get_statistics(&total_analyses, &total_evidence, &total_recoveries, &total_reports);
    
    /* Verify statistics were updated */
    TEST_ASSERT_TRUE(total_evidence > 0);
    
    /* Test tool statistics */
    uint64_t tool_analyses, tool_recoveries, tool_verifications;
    forensics_get_tool_statistics(tool, &tool_analyses, &tool_recoveries, &tool_verifications);
    
    /* Test statistics reset */
    forensics_reset_statistics();
    
    /* Verify statistics were reset */
    forensics_get_statistics(&total_analyses, &total_evidence, &total_recoveries, &total_reports);
    TEST_ASSERT_EQUAL(0, total_analyses);
    TEST_ASSERT_EQUAL(0, total_evidence);
    TEST_ASSERT_EQUAL(0, total_recoveries);
    TEST_ASSERT_EQUAL(0, total_reports);
    
    return TEST_RESULT_PASS;
}

/* Test forensics setup function */
static test_result_t forensics_test_setup(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Allocate test data */
    forensics_test_data_t* test_data = (forensics_test_data_t*)kmalloc(sizeof(forensics_test_data_t));
    if (test_data == NULL) {
        return TEST_RESULT_MEMORY_ERROR;
    }
    
    /* Initialize test data */
    memset(test_data, 0, sizeof(forensics_test_data_t));
    test_data->data_size = 1024;
    strncpy(test_data->test_filename, "test_forensics.dat", sizeof(test_data->test_filename) - 1);
    strncpy(test_data->test_case_id, "FORENSICS_TEST_001", sizeof(test_data->test_case_id) - 1);
    strncpy(test_data->test_evidence_tag, "TEST_EVIDENCE_001", sizeof(test_data->test_evidence_tag) - 1);
    
    /* Fill with test pattern */
    for (uint32_t i = 0; i < test_data->data_size; i++) {
        test_data->test_data[i] = (uint8_t)(i & 0xFF);
    }
    
    test_case->test_data = test_data;
    test_case->test_data_size = sizeof(forensics_test_data_t);
    
    return TEST_RESULT_PASS;
}

/* Test forensics cleanup function */
static test_result_t forensics_test_cleanup(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Free test data */
    if (test_case->test_data != NULL) {
        kfree(test_case->test_data);
        test_case->test_data = NULL;
        test_case->test_data_size = 0;
    }
    
    /* Shutdown forensics */
    forensics_shutdown();
    
    return TEST_RESULT_PASS;
}

/* Create forensics test suite */
test_suite_t* create_forensics_test_suite(void) {
    test_suite_t* suite = test_create_suite("Forensics Tests", "Comprehensive forensics functionality tests", TEST_CATEGORY_FORENSICS);
    if (suite == NULL) {
        return NULL;
    }
    
    /* Set suite functions */
    suite->setup = forensics_test_setup;
    suite->teardown = forensics_test_cleanup;
    
    /* Forensics initialization tests */
    test_case_t* forensics_init_test = test_create_case("Forensics Initialization", "Test forensics subsystem initialization", TEST_CATEGORY_FORENSICS);
    if (forensics_init_test != NULL) {
        forensics_init_test->run = test_forensics_init;
        test_register_case(suite, forensics_init_test);
    }
    
    test_case_t* forensics_shutdown_test = test_create_case("Forensics Shutdown", "Test forensics subsystem shutdown", TEST_CATEGORY_FORENSICS);
    if (forensics_shutdown_test != NULL) {
        forensics_shutdown_test->run = test_forensics_shutdown;
        test_register_case(suite, forensics_shutdown_test);
    }
    
    /* Evidence management tests */
    test_case_t* evidence_creation_test = test_create_case("Evidence Creation", "Test evidence creation functionality", TEST_CATEGORY_FORENSICS);
    if (evidence_creation_test != NULL) {
        evidence_creation_test->run = test_evidence_creation;
        test_register_case(suite, evidence_creation_test);
    }
    
    test_case_t* evidence_management_test = test_create_case("Evidence Management", "Test evidence management functionality", TEST_CATEGORY_FORENSICS);
    if (evidence_management_test != NULL) {
        evidence_management_test->run = test_evidence_management;
        test_register_case(suite, evidence_management_test);
    }
    
    /* Tool management tests */
    test_case_t* tool_creation_test = test_create_case("Tool Creation", "Test forensics tool creation functionality", TEST_CATEGORY_FORENSICS);
    if (tool_creation_test != NULL) {
        tool_creation_test->run = test_tool_creation;
        test_register_case(suite, tool_creation_test);
    }
    
    test_case_t* tool_management_test = test_create_case("Tool Management", "Test forensics tool management functionality", TEST_CATEGORY_FORENSICS);
    if (tool_management_test != NULL) {
        tool_management_test->run = test_tool_management;
        test_register_case(suite, tool_management_test);
    }
    
    /* Hash analysis tests */
    test_case_t* hash_calc_test = test_create_case("Hash Calculation", "Test hash calculation functionality", TEST_CATEGORY_FORENSICS);
    if (hash_calc_test != NULL) {
        hash_calc_test->run = test_hash_calculation;
        test_register_case(suite, hash_calc_test);
    }
    
    test_case_t* hash_verify_test = test_create_case("Hash Verification", "Test hash verification functionality", TEST_CATEGORY_FORENSICS);
    if (hash_verify_test != NULL) {
        hash_verify_test->run = test_hash_verification;
        test_register_case(suite, hash_verify_test);
    }
    
    test_case_t* hash_compare_test = test_create_case("Hash Comparison", "Test hash comparison functionality", TEST_CATEGORY_FORENSICS);
    if (hash_compare_test != NULL) {
        hash_compare_test->run = test_hash_comparison;
        test_register_case(suite, hash_compare_test);
    }
    
    /* Signature analysis tests */
    test_case_t* signature_verify_test = test_create_case("Signature Verification", "Test signature verification functionality", TEST_CATEGORY_FORENSICS);
    if (signature_verify_test != NULL) {
        signature_verify_test->run = test_signature_verification;
        test_register_case(suite, signature_verify_test);
    }
    
    /* Chain of custody tests */
    test_case_t* custody_test = test_create_case("Chain of Custody", "Test chain of custody functionality", TEST_CATEGORY_FORENSICS);
    if (custody_test != NULL) {
        custody_test->run = test_chain_of_custody;
        test_register_case(suite, custody_test);
    }
    
    /* Evidence integrity tests */
    test_case_t* integrity_test = test_create_case("Evidence Integrity", "Test evidence integrity functionality", TEST_CATEGORY_FORENSICS);
    if (integrity_test != NULL) {
        integrity_test->run = test_evidence_integrity;
        test_register_case(suite, integrity_test);
    }
    
    /* Configuration management tests */
    test_case_t* config_test = test_create_case("Configuration Management", "Test configuration management functionality", TEST_CATEGORY_FORENSICS);
    if (config_test != NULL) {
        config_test->run = test_configuration_management;
        test_register_case(suite, config_test);
    }
    
    /* Statistics management tests */
    test_case_t* stats_test = test_create_case("Statistics Management", "Test statistics management functionality", TEST_CATEGORY_FORENSICS);
    if (stats_test != NULL) {
        stats_test->run = test_statistics_management;
        test_register_case(suite, stats_test);
    }
    
    return suite;
}