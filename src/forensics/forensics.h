#ifndef FORENSICS_H
#define FORENSICS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forensics evidence types */
typedef enum {
    FORENSICS_EVIDENCE_FILE = 1,
    FORENSICS_EVIDENCE_MEMORY = 2,
    FORENSICS_EVIDENCE_NETWORK = 3,
    FORENSICS_EVIDENCE_STORAGE = 4,
    FORENSICS_EVIDENCE_REGISTRY = 5,
    FORENSICS_EVIDENCE_PROCESS = 6,
    FORENSICS_EVIDENCE_LOG = 7,
    FORENSICS_EVIDENCE_TIMELINE = 8,
    FORENSICS_EVIDENCE_METADATA = 9,
    FORENSICS_EVIDENCE_HASH = 10,
    FORENSICS_EVIDENCE_SIGNATURE = 11,
    FORENSICS_EVIDENCE_ARTIFACT = 12,
    FORENSICS_EVIDENCE_TIMESTOMP = 13,
    FORENSICS_EVIDENCE_DELETED = 14,
    FORENSICS_EVIDENCE_HIDDEN = 15,
    FORENSICS_EVIDENCE_ENCRYPTED = 16,
    FORENSICS_EVIDENCE_COMPRESSED = 17
} forensics_evidence_type_t;

/* Forensics analysis types */
typedef enum {
    FORENSICS_ANALYSIS_FILE_CARVING = 1,
    FORENSICS_ANALYSIS_DATA_RECOVERY = 2,
    FORENSICS_ANALYSIS_TIMELINE = 3,
    FORENSICS_ANALYSIS_NETWORK_TRAFFIC = 4,
    FORENSICS_ANALYSIS_MEMORY_ANALYSIS = 5,
    FORENSICS_ANALYSIS_REGISTRY_ANALYSIS = 6,
    FORENSICS_ANALYSIS_LOG_ANALYSIS = 7,
    FORENSICS_ANALYSIS_HASH_ANALYSIS = 8,
    FORENSICS_ANALYSIS_SIGNATURE_ANALYSIS = 9,
    FORENSICS_ANALYSIS_STEGANOGRAPHY = 10,
    FORENSICS_ANALYSIS_PASSWORD_RECOVERY = 11,
    FORENSICS_ANALYSIS_MALWARE_ANALYSIS = 12,
    FORENSICS_ANALYSIS_ANTIFORENSICS = 13,
    FORENSICS_ANALYSIS_TIMESTOMP_DETECTION = 14,
    FORENSICS_ANALYSIS_DATA_HIDING = 15
} forensics_analysis_type_t;

/* Forensics status codes */
typedef enum {
    FORENSICS_STATUS_OK = 0,
    FORENSICS_STATUS_ERROR = -1,
    FORENSICS_STATUS_TIMEOUT = -2,
    FORENSICS_STATUS_INVALID_PARAM = -3,
    FORENSICS_STATUS_NO_MEMORY = -4,
    FORENSICS_STATUS_NOT_FOUND = -5,
    FORENSICS_STATUS_ACCESS_DENIED = -6,
    FORENSICS_STATUS_CORRUPTED = -7,
    FORENSICS_STATUS_ENCRYPTED = -8,
    FORENSICS_STATUS_COMPRESSED = -9,
    FORENSICS_STATUS_FRAGMENTED = -10,
    FORENSICS_STATUS_INCOMPLETE = -11,
    FORENSICS_STATUS_UNSUPPORTED = -12,
    FORENSICS_STATUS_EVIDENCE_TAMPERED = -13,
    FORENSICS_STATUS_CHAIN_OF_CUSTODY_BROKEN = -14,
    FORENSICS_STATUS_VERIFICATION_FAILED = -15,
    FORENSICS_STATUS_AUTHENTICATION_FAILED = -16
} forensics_status_t;

/* File system types */
typedef enum {
    FORENSICS_FS_UNKNOWN = 0,
    FORENSICS_FS_FAT12 = 1,
    FORENSICS_FS_FAT16 = 2,
    FORENSICS_FS_FAT32 = 3,
    FORENSICS_FS_NTFS = 4,
    FORENSICS_FS_EXT2 = 5,
    FORENSICS_FS_EXT3 = 6,
    FORENSICS_FS_EXT4 = 7,
    FORENSICS_FS_BTRFS = 8,
    FORENSICS_FS_ZFS = 9,
    FORENSICS_FS_HFS = 10,
    FORENSICS_FS_HFS_PLUS = 11,
    FORENSICS_FS_APFS = 12,
    FORENSICS_FS_REFS = 13,
    FORENSICS_FS_RAW = 14
} forensics_filesystem_t;

/* Evidence integrity status */
typedef enum {
    FORENSICS_INTEGRITY_UNKNOWN = 0,
    FORENSICS_INTEGRITY_VERIFIED = 1,
    FORENSICS_INTEGRITY_TAMPERED = 2,
    FORENSICS_INTEGRITY_CORRUPTED = 3,
    FORENSICS_INTEGRITY_PARTIAL = 4,
    FORENSICS_INTEGRITY_AUTHENTIC = 5
} forensics_integrity_t;

/* Chain of custody status */
typedef enum {
    FORENSICS_CUSTODY_UNKNOWN = 0,
    FORENSICS_CUSTODY_SECURE = 1,
    FORENSICS_CUSTODY_BROKEN = 2,
    FORENSICS_CUSTODY_QUESTIONABLE = 3,
    FORENSICS_CUSTODY_VERIFIED = 4
} forensics_custody_t;

/* File metadata structure */
typedef struct {
    char filename[256];
    char path[1024];
    uint64_t size;
    uint64_t created_time;
    uint64_t modified_time;
    uint64_t accessed_time;
    uint32_t attributes;
    uint32_t permissions;
    char owner[64];
    char group[64];
    uint8_t hash[64];
    uint32_t hash_size;
    char signature[256];
    uint32_t signature_size;
    bool deleted;
    bool hidden;
    bool encrypted;
    bool compressed;
    bool fragmented;
    forensics_filesystem_t filesystem;
    forensics_integrity_t integrity;
    uint32_t flags;
} forensics_file_metadata_t;

/* Evidence item structure */
typedef struct {
    uint32_t evidence_id;
    char case_id[64];
    char evidence_tag[128];
    char description[512];
    forensics_evidence_type_t evidence_type;
    forensics_filesystem_t filesystem;
    uint64_t size;
    uint64_t offset;
    uint64_t length;
    uint8_t hash[64];
    uint32_t hash_size;
    char hash_algorithm[32];
    uint8_t signature[256];
    uint32_t signature_size;
    char signature_algorithm[32];
    forensics_integrity_t integrity;
    forensics_custody_t custody;
    uint64_t collected_time;
    uint64_t analyzed_time;
    uint32_t analyst_id;
    char analyst_name[128];
    char location[256];
    char notes[1024];
    uint32_t flags;
} forensics_evidence_t;

/* Timeline entry structure */
typedef struct {
    uint32_t timeline_id;
    uint64_t timestamp;
    char event_type[64];
    char description[512];
    char source[256];
    char user[128];
    char process[256];
    char file[512];
    char registry_key[512];
    char network_connection[256];
    uint32_t process_id;
    uint32_t thread_id;
    uint32_t parent_process_id;
    uint32_t flags;
} forensics_timeline_entry_t;

/* File carving result */
typedef struct {
    uint32_t carve_id;
    uint64_t offset;
    uint64_t size;
    char filename[256];
    char file_type[64];
    char extension[16];
    uint8_t header[64];
    uint32_t header_size;
    uint8_t footer[64];
    uint32_t footer_size;
    uint8_t hash[64];
    uint32_t hash_size;
    bool recovered;
    bool verified;
    bool complete;
    uint32_t confidence;
    uint32_t flags;
} forensics_carve_result_t;

/* Memory analysis result */
typedef struct {
    uint32_t analysis_id;
    uint64_t address;
    uint64_t size;
    char process_name[256];
    uint32_t process_id;
    char data_type[64];
    char description[512];
    uint8_t data[1024];
    uint32_t data_size;
    bool malicious;
    bool suspicious;
    uint32_t confidence;
    uint32_t flags;
} forensics_memory_result_t;

/* Network traffic analysis result */
typedef struct {
    uint32_t analysis_id;
    uint64_t timestamp;
    char source_ip[64];
    char dest_ip[64];
    uint16_t source_port;
    uint16_t dest_port;
    char protocol[16];
    uint64_t packet_size;
    char description[512];
    bool malicious;
    bool suspicious;
    uint32_t confidence;
    uint32_t flags;
} forensics_network_result_t;

/* Registry analysis result */
typedef struct {
    uint32_t analysis_id;
    char key_path[512];
    char value_name[256];
    char value_data[1024];
    uint32_t value_type;
    uint64_t last_modified;
    char description[512];
    bool deleted;
    bool hidden;
    bool suspicious;
    uint32_t confidence;
    uint32_t flags;
} forensics_registry_result_t;

/* Log analysis result */
typedef struct {
    uint32_t analysis_id;
    uint64_t timestamp;
    char log_source[256];
    char event_id[64];
    char event_type[64];
    char description[512];
    char user[128];
    char process[256];
    char file[512];
    bool suspicious;
    bool malicious;
    uint32_t confidence;
    uint32_t flags;
} forensics_log_result_t;

/* Hash analysis result */
typedef struct {
    uint32_t analysis_id;
    uint8_t hash[64];
    uint32_t hash_size;
    char hash_algorithm[32];
    char filename[256];
    uint64_t file_size;
    char file_type[64];
    bool known_malicious;
    bool known_good;
    bool unknown;
    char malware_family[128];
    char malware_type[64];
    uint32_t confidence;
    uint32_t flags;
} forensics_hash_result_t;

/* Forensics tool structure */
typedef struct forensics_tool {
    uint32_t tool_id;
    char name[64];
    char description[256];
    forensics_analysis_type_t analysis_type;
    char version[32];
    char author[128];
    bool enabled;
    bool running;
    uint32_t priority;
    
    /* Tool operations */
    forensics_status_t (*init)(struct forensics_tool* tool);
    forensics_status_t (*cleanup)(struct forensics_tool* tool);
    forensics_status_t (*start)(struct forensics_tool* tool);
    forensics_status_t (*stop)(struct forensics_tool* tool);
    forensics_status_t (*analyze)(struct forensics_tool* tool, forensics_evidence_t* evidence);
    forensics_status_t (*recover)(struct forensics_tool* tool, forensics_evidence_t* evidence);
    forensics_status_t (*verify)(struct forensics_tool* tool, forensics_evidence_t* evidence);
    forensics_status_t (*report)(struct forensics_tool* tool, forensics_evidence_t* evidence);
    
    /* Results */
    forensics_carve_result_t* carve_results;
    uint32_t carve_result_count;
    forensics_memory_result_t* memory_results;
    uint32_t memory_result_count;
    forensics_network_result_t* network_results;
    uint32_t network_result_count;
    forensics_registry_result_t* registry_results;
    uint32_t registry_result_count;
    forensics_log_result_t* log_results;
    uint32_t log_result_count;
    forensics_hash_result_t* hash_results;
    uint32_t hash_result_count;
    forensics_timeline_entry_t* timeline_results;
    uint32_t timeline_result_count;
    
    /* Tool specific data */
    void* private_data;
    uint32_t private_data_size;
    
    /* Statistics */
    uint64_t total_analyses;
    uint64_t total_recoveries;
    uint64_t total_verifications;
    uint64_t total_reports;
    uint64_t total_runtime;
    uint64_t total_bytes_processed;
    uint32_t success_rate;
    uint32_t accuracy;
    
    /* Security */
    bool encryption_enabled;
    bool authentication_required;
    uint8_t security_level;
    uint8_t encryption_key[32];
    
    /* Chain of custody */
    forensics_custody_t custody_status;
    uint32_t custody_chain_length;
    char custody_chain[1024];
    
    /* Linked list */
    struct forensics_tool* next;
} forensics_tool_t;

/* Forensics manager structure */
typedef struct {
    forensics_tool_t* tools;
    uint32_t tool_count;
    forensics_evidence_t* evidence;
    uint32_t evidence_count;
    bool initialized;
    
    /* Configuration */
    uint32_t max_concurrent_analyses;
    uint32_t default_timeout;
    uint32_t default_threads;
    uint8_t default_threat_level;
    bool encryption_enabled;
    bool logging_enabled;
    bool reporting_enabled;
    bool chain_of_custody_enabled;
    
    /* Statistics */
    uint64_t total_analyses;
    uint64_t total_evidence;
    uint64_t total_recoveries;
    uint64_t total_verifications;
    uint64_t total_reports;
    uint64_t total_runtime;
    
    /* Security */
    uint8_t security_level;
    bool authentication_required;
    bool authorization_required;
    bool audit_enabled;
    
    /* Current case */
    char current_case[64];
    char current_investigator[128];
    uint32_t current_case_id;
    
} forensics_manager_t;

/* Forensics functions */
void forensics_init(void);
void forensics_shutdown(void);
bool forensics_is_initialized(void);

/* Tool management */
forensics_tool_t* forensics_create_tool(forensics_analysis_type_t analysis_type, const char* name, const char* description);
forensics_status_t forensics_destroy_tool(forensics_tool_t* tool);
forensics_tool_t* forensics_get_tool(uint32_t tool_id);
forensics_tool_t* forensics_get_tool_by_name(const char* name);
uint32_t forensics_get_tool_count(void);
forensics_status_t forensics_register_tool(forensics_tool_t* tool);
forensics_status_t forensics_unregister_tool(uint32_t tool_id);

/* Evidence management */
forensics_evidence_t* forensics_create_evidence(const char* case_id, const char* evidence_tag, forensics_evidence_type_t evidence_type);
forensics_status_t forensics_destroy_evidence(forensics_evidence_t* evidence);
forensics_evidence_t* forensics_get_evidence(uint32_t evidence_id);
forensics_evidence_t* forensics_get_evidence_by_tag(const char* evidence_tag);
uint32_t forensics_get_evidence_count(void);
forensics_status_t forensics_add_evidence(forensics_evidence_t* evidence);
forensics_status_t forensics_remove_evidence(uint32_t evidence_id);

/* Analysis functions */
forensics_status_t forensics_start_analysis(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_stop_analysis(forensics_tool_t* tool);
forensics_status_t forensics_pause_analysis(forensics_tool_t* tool);
forensics_status_t forensics_resume_analysis(forensics_tool_t* tool);
forensics_status_t forensics_analyze_evidence(forensics_tool_t* tool, forensics_evidence_t* evidence);

/* File carving */
forensics_status_t forensics_carve_files(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_recover_deleted_files(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_recover_formatted_data(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_carve_result_t* forensics_get_carve_results(forensics_tool_t* tool, uint32_t* count);

/* Memory analysis */
forensics_status_t forensics_analyze_memory(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_dump_memory(forensics_tool_t* tool, uint32_t process_id);
forensics_status_t forensics_search_memory(forensics_tool_t* tool, uint8_t* pattern, uint32_t pattern_size);
forensics_memory_result_t* forensics_get_memory_results(forensics_tool_t* tool, uint32_t* count);

/* Network analysis */
forensics_status_t forensics_analyze_network_traffic(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_reconstruct_network_sessions(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_extract_network_artifacts(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_network_result_t* forensics_get_network_results(forensics_tool_t* tool, uint32_t* count);

/* Registry analysis */
forensics_status_t forensics_analyze_registry(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_search_registry_keys(forensics_tool_t* tool, const char* key_pattern);
forensics_status_t forensics_recover_deleted_registry_keys(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_registry_result_t* forensics_get_registry_results(forensics_tool_t* tool, uint32_t* count);

/* Log analysis */
forensics_status_t forensics_analyze_logs(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_correlate_logs(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_timeline_analysis(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_log_result_t* forensics_get_log_results(forensics_tool_t* tool, uint32_t* count);
forensics_timeline_entry_t* forensics_get_timeline_results(forensics_tool_t* tool, uint32_t* count);

/* Hash analysis */
forensics_status_t forensics_calculate_hash(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_verify_hash(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_compare_hash(forensics_tool_t* tool, uint8_t* hash1, uint8_t* hash2, uint32_t hash_size);
forensics_status_t forensics_search_hash_database(forensics_tool_t* tool, uint8_t* hash, uint32_t hash_size);
forensics_hash_result_t* forensics_get_hash_results(forensics_tool_t* tool, uint32_t* count);

/* Signature analysis */
forensics_status_t forensics_verify_signature(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_check_signature(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_search_signatures(forensics_tool_t* tool, forensics_evidence_t* evidence);

/* Anti-forensics detection */
forensics_status_t forensics_detect_timestomp(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_detect_data_hiding(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_detect_log_tampering(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_detect_registry_tampering(forensics_tool_t* tool, forensics_evidence_t* evidence);

/* Chain of custody */
forensics_status_t forensics_establish_custody(forensics_evidence_t* evidence, const char* investigator);
forensics_status_t forensics_transfer_custody(forensics_evidence_t* evidence, const char* new_investigator);
forensics_status_t forensics_verify_custody(forensics_evidence_t* evidence);
forensics_status_t forensics_document_custody(forensics_evidence_t* evidence);
forensics_custody_t forensics_get_custody_status(forensics_evidence_t* evidence);

/* Evidence integrity */
forensics_status_t forensics_verify_integrity(forensics_evidence_t* evidence);
forensics_status_t forensics_calculate_integrity_hash(forensics_evidence_t* evidence);
forensics_status_t forensics_sign_evidence(forensics_evidence_t* evidence);
forensics_status_t forensics_verify_evidence_signature(forensics_evidence_t* evidence);
forensics_integrity_t forensics_get_integrity_status(forensics_evidence_t* evidence);

/* Reporting */
forensics_status_t forensics_generate_report(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_export_evidence(forensics_evidence_t* evidence, const char* filename);
forensics_status_t forensics_import_evidence(forensics_evidence_t* evidence, const char* filename);
forensics_status_t forensics_create_case_report(const char* case_id, const char* filename);

/* Configuration */
forensics_status_t forensics_set_security_level(uint8_t level);
forensics_status_t forensics_enable_encryption(bool enable);
forensics_status_t forensics_enable_logging(bool enable);
forensics_status_t forensics_enable_reporting(bool enable);
forensics_status_t forensics_enable_chain_of_custody(bool enable);
uint8_t forensics_get_security_level(void);
bool forensics_is_encryption_enabled(void);
bool forensics_is_logging_enabled(void);
bool forensics_is_reporting_enabled(void);
bool forensics_is_chain_of_custody_enabled(void);

/* Statistics */
void forensics_get_statistics(uint64_t* total_analyses, uint64_t* total_evidence, uint64_t* total_recoveries, uint64_t* total_reports);
void forensics_get_tool_statistics(forensics_tool_t* tool, uint64_t* total_analyses, uint64_t* total_recoveries, uint64_t* total_verifications);
void forensics_reset_statistics(void);

/* Advanced features */
forensics_status_t forensics_start_automated_analysis(forensics_tool_t* tool, forensics_evidence_t* evidence);
forensics_status_t forensics_compare_evidence(forensics_evidence_t* evidence1, forensics_evidence_t* evidence2);
forensics_status_t forensics_correlate_evidence(forensics_evidence_t* evidence_array, uint32_t count);
forensics_status_t forensics_validate_methodology(forensics_tool_t* tool);
forensics_status_t forensics_test_tool_accuracy(forensics_tool_t* tool);

/* Global forensics manager */
extern forensics_manager_t* global_forensics_manager;

/* Forensics constants */
#define FORENSICS_MAX_EVIDENCE          10000
#define FORENSICS_MAX_TOOLS             256
#define FORENSICS_MAX_CONCURRENT_ANALYSES 4
#define FORENSICS_MAX_TIMELINE_ENTRIES  100000
#define FORENSICS_MAX_CARVE_RESULTS       10000
#define FORENSICS_MAX_MEMORY_RESULTS      50000
#define FORENSICS_MAX_NETWORK_RESULTS     100000
#define FORENSICS_MAX_REGISTRY_RESULTS    50000
#define FORENSICS_MAX_LOG_RESULTS         1000000
#define FORENSICS_MAX_HASH_RESULTS        100000

#define FORENSICS_DEFAULT_TIMEOUT         60000  /* 60 seconds */
#define FORENSICS_DEFAULT_THREADS         2
#define FORENSICS_DEFAULT_SECURITY_LEVEL  3

#define FORENSICS_HASH_MD5                1
#define FORENSICS_HASH_SHA1               2
#define FORENSICS_HASH_SHA256             3
#define FORENSICS_HASH_SHA512             4

#define FORENSICS_SIGNATURE_MD5           1
#define FORENSICS_SIGNATURE_SHA1          2
#define FORENSICS_SIGNATURE_SHA256        3
#define FORENSICS_SIGNATURE_SHA512        4
#define FORENSICS_SIGNATURE_RSA           5
#define FORENSICS_SIGNATURE_ECDSA         6

/* Common file signatures */
#define FORENSICS_SIGNATURE_JPEG          0xFFD8FFE0
#define FORENSICS_SIGNATURE_PNG           0x89504E47
#define FORENSICS_SIGNATURE_GIF            0x47494638
#define FORENSICS_SIGNATURE_PDF            0x25504446
#define FORENSICS_SIGNATURE_ZIP            0x504B0304
#define FORENSICS_SIGNATURE_RAR            0x52617221
#define FORENSICS_SIGNATURE_TAR            0x75737461
#define FORENSICS_SIGNATURE_GZIP           0x1F8B0800

/* Common file extensions */
#define FORENSICS_EXTENSION_JPEG           ".jpg"
#define FORENSICS_EXTENSION_PNG            ".png"
#define FORENSICS_EXTENSION_GIF            ".gif"
#define FORENSICS_EXTENSION_PDF            ".pdf"
#define FORENSICS_EXTENSION_ZIP            ".zip"
#define FORENSICS_EXTENSION_RAR            ".rar"
#define FORENSICS_EXTENSION_TAR            ".tar"
#define FORENSICS_EXTENSION_GZIP           ".gz"

#endif /* FORENSICS_H */