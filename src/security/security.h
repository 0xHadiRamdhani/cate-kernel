#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Security levels */
#define SECURITY_LEVEL_NONE     0
#define SECURITY_LEVEL_LOW      1
#define SECURITY_LEVEL_MEDIUM   2
#define SECURITY_LEVEL_HIGH     3
#define SECURITY_LEVEL_MAXIMUM  4

/* Security policies */
#define SECURITY_POLICY_ALLOW   0
#define SECURITY_POLICY_DENY    1
#define SECURITY_POLICY_ASK     2

/* Security flags */
#define SECURITY_FLAG_READ      0x01
#define SECURITY_FLAG_WRITE     0x02
#define SECURITY_FLAG_EXECUTE   0x04
#define SECURITY_FLAG_DELETE    0x08
#define SECURITY_FLAG_CREATE    0x10
#define SECURITY_FLAG_MODIFY    0x20
#define SECURITY_FLAG_ACCESS    0x40
#define SECURITY_FLAG_ADMIN     0x80

/* Security status codes */
typedef enum {
    SECURITY_STATUS_OK = 0,
    SECURITY_STATUS_ERROR = -1,
    SECURITY_STATUS_ACCESS_DENIED = -2,
    SECURITY_STATUS_PERMISSION_DENIED = -3,
    SECURITY_STATUS_AUTHENTICATION_FAILED = -4,
    SECURITY_STATUS_AUTHORIZATION_FAILED = -5,
    SECURITY_STATUS_INVALID_CREDENTIALS = -6,
    SECURITY_STATUS_INVALID_TOKEN = -7,
    SECURITY_STATUS_EXPIRED_TOKEN = -8,
    SECURITY_STATUS_REVOKED_TOKEN = -9,
    SECURITY_STATUS_INSUFFICIENT_PRIVILEGES = -10,
    SECURITY_STATUS_SECURITY_VIOLATION = -11,
    SECURITY_STATUS_POLICY_VIOLATION = -12,
    SECURITY_STATUS_AUDIT_FAILURE = -13,
    SECURITY_STATUS_ENCRYPTION_ERROR = -14,
    SECURITY_STATUS_DECRYPTION_ERROR = -15,
    SECURITY_STATUS_HASH_ERROR = -16,
    SECURITY_STATUS_SIGNATURE_ERROR = -17,
    SECURITY_STATUS_CERTIFICATE_ERROR = -18,
    SECURITY_STATUS_KEY_ERROR = -19,
    SECURITY_STATUS_RANDOM_ERROR = -20
} security_status_t;

/* Security event types */
typedef enum {
    SECURITY_EVENT_LOGIN = 1,
    SECURITY_EVENT_LOGOUT = 2,
    SECURITY_EVENT_ACCESS = 3,
    SECURITY_EVENT_DENIED = 4,
    SECURITY_EVENT_VIOLATION = 5,
    SECURITY_EVENT_ATTACK = 6,
    SECURITY_EVENT_INTRUSION = 7,
    SECURITY_EVENT_SCAN = 8,
    SECURITY_EVENT_EXPLOIT = 9,
    SECURITY_EVENT_PRIVILEGE = 10,
    SECURITY_EVENT_PASSWORD = 11,
    SECURITY_EVENT_ENCRYPTION = 12,
    SECURITY_EVENT_DECRYPTION = 13,
    SECURITY_EVENT_KEY = 14,
    SECURITY_EVENT_CERTIFICATE = 15,
    SECURITY_EVENT_FIREWALL = 16,
    SECURITY_EVENT_IDS = 17,
    SECURITY_EVENT_AUDIT = 18,
    SECURITY_EVENT_POLICY = 19,
    SECURITY_EVENT_SYSTEM = 20
} security_event_type_t;

/* Security threat levels */
typedef enum {
    SECURITY_THREAT_LOW = 1,
    SECURITY_THREAT_MEDIUM = 2,
    SECURITY_THREAT_HIGH = 3,
    SECURITY_THREAT_CRITICAL = 4,
    SECURITY_THREAT_EMERGENCY = 5
} security_threat_level_t;

/* Security alert types */
typedef enum {
    SECURITY_ALERT_INFO = 1,
    SECURITY_ALERT_WARNING = 2,
    SECURITY_ALERT_ERROR = 3,
    SECURITY_ALERT_CRITICAL = 4,
    SECURITY_ALERT_EMERGENCY = 5
} security_alert_type_t;

/* User roles */
typedef enum {
    USER_ROLE_GUEST = 0,
    USER_ROLE_USER = 1,
    USER_ROLE_POWER_USER = 2,
    USER_ROLE_ADMIN = 3,
    USER_ROLE_SUPER_ADMIN = 4,
    USER_ROLE_SYSTEM = 5
} user_role_t;

/* Privilege levels */
typedef enum {
    PRIVILEGE_NONE = 0,
    PRIVILEGE_USER = 1,
    PRIVILEGE_POWER_USER = 2,
    PRIVILEGE_ADMIN = 3,
    PRIVILEGE_SUPER_ADMIN = 4,
    PRIVILEGE_SYSTEM = 5,
    PRIVILEGE_KERNEL = 6
} privilege_level_t;

/* Security token structure */
typedef struct {
    uint64_t token_id;
    uint32_t user_id;
    user_role_t user_role;
    privilege_level_t privilege_level;
    uint64_t created_time;
    uint64_t expiry_time;
    uint64_t last_used;
    uint32_t usage_count;
    uint8_t session_key[32];
    uint8_t signature[64];
    bool valid;
    bool revoked;
    uint32_t flags;
} security_token_t;

/* User credentials structure */
typedef struct {
    uint32_t user_id;
    char username[64];
    uint8_t password_hash[64];
    uint8_t salt[32];
    user_role_t role;
    privilege_level_t privilege;
    bool enabled;
    bool locked;
    uint32_t failed_attempts;
    uint64_t last_login;
    uint64_t password_changed;
    uint32_t password_expiry_days;
    bool password_expired;
    uint8_t security_questions[3][128];
    uint8_t security_answers[3][64];
    uint32_t session_timeout;
    uint32_t max_sessions;
    uint8_t mfa_secret[32];
    bool mfa_enabled;
    uint8_t backup_codes[10][8];
    uint32_t backup_codes_used;
} user_credentials_t;

/* Security policy structure */
typedef struct {
    uint32_t policy_id;
    char name[64];
    char description[256];
    security_event_type_t event_type;
    security_threat_level_t threat_level;
    uint32_t conditions;
    uint32_t actions;
    bool enabled;
    uint32_t priority;
    uint64_t created_time;
    uint64_t modified_time;
    uint32_t match_count;
    uint32_t action_count;
} security_policy_t;

/* Security audit log entry */
typedef struct {
    uint64_t log_id;
    uint64_t timestamp;
    security_event_type_t event_type;
    security_threat_level_t threat_level;
    uint32_t user_id;
    uint32_t process_id;
    uint32_t object_id;
    security_status_t status;
    char description[512];
    uint8_t details[1024];
    uint32_t details_size;
    uint32_t flags;
} security_audit_log_t;

/* Security alert structure */
typedef struct {
    uint64_t alert_id;
    uint64_t timestamp;
    security_alert_type_t alert_type;
    security_threat_level_t threat_level;
    security_event_type_t event_type;
    uint32_t source_id;
    char source_ip[64];
    char target_ip[64];
    uint32_t source_port;
    uint32_t target_port;
    char description[512];
    char recommendation[256];
    bool acknowledged;
    uint32_t acknowledged_by;
    uint64_t acknowledged_time;
    uint32_t flags;
} security_alert_t;

/* Intrusion detection rule */
typedef struct {
    uint32_t rule_id;
    char name[64];
    char description[256];
    security_event_type_t event_type;
    security_threat_level_t threat_level;
    uint8_t signature[256];
    uint32_t signature_size;
    uint8_t pattern[256];
    uint32_t pattern_size;
    uint32_t conditions;
    uint32_t actions;
    bool enabled;
    uint32_t priority;
    uint64_t created_time;
    uint64_t modified_time;
    uint32_t match_count;
    uint32_t false_positive_count;
    float accuracy;
} intrusion_detection_rule_t;

/* Firewall rule structure */
typedef struct {
    uint32_t rule_id;
    char name[64];
    char description[256];
    uint32_t source_ip;
    uint32_t source_mask;
    uint32_t dest_ip;
    uint32_t dest_mask;
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t protocol;
    uint8_t action;
    bool enabled;
    uint32_t priority;
    uint64_t created_time;
    uint64_t modified_time;
    uint32_t match_count;
    uint32_t packet_count;
    uint64_t byte_count;
} firewall_rule_t;

/* Encryption context */
typedef struct {
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t algorithm;
    uint8_t mode;
    uint8_t key_size;
    uint8_t block_size;
    uint64_t counter;
    bool initialized;
    uint8_t context[256];
} encryption_context_t;

/* Hash context */
typedef struct {
    uint8_t algorithm;
    uint8_t digest_size;
    uint64_t total_size;
    uint8_t buffer[128];
    uint32_t buffer_size;
    uint8_t state[256];
    bool initialized;
} hash_context_t;

/* Digital signature context */
typedef struct {
    uint8_t algorithm;
    uint8_t key_size;
    uint8_t signature_size;
    uint8_t public_key[256];
    uint8_t private_key[256];
    bool initialized;
    uint8_t context[512];
} signature_context_t;

/* Certificate structure */
typedef struct {
    uint32_t certificate_id;
    char subject[256];
    char issuer[256];
    uint8_t public_key[256];
    uint8_t signature[256];
    uint64_t valid_from;
    uint64_t valid_to;
    uint32_t key_usage;
    uint32_t extended_key_usage;
    bool trusted;
    bool revoked;
    uint8_t fingerprint[32];
    uint32_t fingerprint_size;
} security_certificate_t;

/* Security manager structure */
typedef struct {
    /* Authentication */
    user_credentials_t* users;
    uint32_t user_count;
    security_token_t* tokens;
    uint32_t token_count;
    
    /* Authorization */
    security_policy_t* policies;
    uint32_t policy_count;
    
    /* Audit */
    security_audit_log_t* audit_log;
    uint32_t audit_log_size;
    uint32_t audit_log_count;
    uint64_t next_log_id;
    
    /* Alerts */
    security_alert_t* alerts;
    uint32_t alert_count;
    uint64_t next_alert_id;
    
    /* Intrusion detection */
    intrusion_detection_rule_t* ids_rules;
    uint32_t ids_rule_count;
    
    /* Firewall */
    firewall_rule_t* firewall_rules;
    uint32_t firewall_rule_count;
    
    /* Encryption */
    encryption_context_t* encryption_contexts;
    uint32_t encryption_context_count;
    
    /* Hashing */
    hash_context_t* hash_contexts;
    uint32_t hash_context_count;
    
    /* Signatures */
    signature_context_t* signature_contexts;
    uint32_t signature_context_count;
    
    /* Certificates */
    security_certificate_t* certificates;
    uint32_t certificate_count;
    
    /* Security state */
    bool initialized;
    uint32_t security_level;
    bool audit_enabled;
    bool alerts_enabled;
    bool ids_enabled;
    bool firewall_enabled;
    bool encryption_enabled;
    bool secure_boot_enabled;
    bool trusted_platform_enabled;
    
    /* Statistics */
    uint64_t total_logins;
    uint64_t total_failures;
    uint64_t total_violations;
    uint64_t total_alerts;
    uint64_t total_attacks;
    uint64_t total_intrusions;
    uint64_t total_encryptions;
    uint64_t total_decryptions;
    uint64_t total_hashes;
    uint64_t total_signatures;
    
    /* Pentesting specific */
    bool penetration_testing_mode;
    bool vulnerability_assessment_mode;
    bool red_team_mode;
    bool blue_team_mode;
    bool capture_the_flag_mode;
    bool war_gaming_mode;
    
    /* Current user */
    uint32_t current_user_id;
    security_token_t* current_token;
    privilege_level_t current_privilege;
    
} security_manager_t;

/* Security driver functions */
void security_init(void);
void security_shutdown(void);
bool security_is_initialized(void);

/* Authentication functions */
security_status_t security_authenticate(const char* username, const char* password, security_token_t** token);
security_status_t security_logout(security_token_t* token);
security_status_t security_validate_token(security_token_t* token);
security_status_t security_refresh_token(security_token_t* token);
security_status_t security_revoke_token(security_token_t* token);
bool security_is_token_valid(security_token_t* token);
bool security_is_user_authenticated(uint32_t user_id);

/* Authorization functions */
security_status_t security_check_permission(uint32_t user_id, uint32_t object_id, uint32_t requested_permissions);
security_status_t security_check_privilege(uint32_t user_id, privilege_level_t required_privilege);
security_status_t security_authorize_action(uint32_t user_id, security_event_type_t action, void* context);
security_status_t security_enforce_policy(security_policy_t* policy, void* context);
bool security_has_permission(uint32_t user_id, uint32_t permission);
bool security_has_privilege(uint32_t user_id, privilege_level_t privilege);

/* User management */
security_status_t security_create_user(const char* username, const char* password, user_role_t role);
security_status_t security_delete_user(uint32_t user_id);
security_status_t security_update_user(uint32_t user_id, const char* username, const char* password);
security_status_t security_lock_user(uint32_t user_id);
security_status_t security_unlock_user(uint32_t user_id);
security_status_t security_enable_user(uint32_t user_id);
security_status_t security_disable_user(uint32_t user_id);
user_credentials_t* security_get_user(uint32_t user_id);
user_credentials_t* security_get_user_by_name(const char* username);
uint32_t security_get_user_count(void);

/* Audit functions */
security_status_t security_log_event(security_event_type_t event_type, uint32_t user_id, uint32_t object_id, security_status_t status, const char* description);
security_status_t security_log_security_event(security_event_type_t event_type, security_threat_level_t threat_level, const char* description, void* details, uint32_t details_size);
security_status_t security_log_login_attempt(uint32_t user_id, bool success, const char* source_ip);
security_status_t security_log_access_violation(uint32_t user_id, uint32_t object_id, uint32_t requested_permissions);
security_status_t security_log_privilege_escalation(uint32_t user_id, privilege_level_t old_level, privilege_level_t new_level);
security_status_t security_log_attack(security_event_type_t attack_type, const char* source_ip, const char* target_ip, uint32_t source_port, uint32_t target_port);
security_status_t security_log_intrusion(security_event_type_t intrusion_type, const char* description, void* evidence, uint32_t evidence_size);
security_audit_log_t* security_get_audit_log(uint32_t* count);
security_status_t security_clear_audit_log(void);
uint32_t security_get_audit_log_count(void);

/* Alert functions */
security_status_t security_create_alert(security_alert_type_t alert_type, security_threat_level_t threat_level, security_event_type_t event_type, const char* description);
security_status_t security_acknowledge_alert(uint64_t alert_id, uint32_t user_id);
security_status_t security_escalate_alert(uint64_t alert_id, security_threat_level_t new_level);
security_alert_t* security_get_alerts(uint32_t* count);
security_alert_t* security_get_unacknowledged_alerts(uint32_t* count);
security_alert_t* security_get_alerts_by_threat_level(security_threat_level_t threat_level, uint32_t* count);
security_status_t security_clear_alert(uint64_t alert_id);
security_status_t security_clear_all_alerts(void);
uint32_t security_get_alert_count(void);
uint32_t security_get_unacknowledged_alert_count(void);

/* Intrusion detection */
security_status_t security_add_ids_rule(intrusion_detection_rule_t* rule);
security_status_t security_remove_ids_rule(uint32_t rule_id);
security_status_t security_enable_ids_rule(uint32_t rule_id);
security_status_t security_disable_ids_rule(uint32_t rule_id);
intrusion_detection_rule_t* security_get_ids_rules(uint32_t* count);
intrusion_detection_rule_t* security_get_ids_rule(uint32_t rule_id);
security_status_t security_check_intrusion(void* data, uint32_t size, security_event_type_t event_type);
security_status_t security_update_ids_signatures(void);
uint32_t security_get_ids_rule_count(void);

/* Firewall functions */
security_status_t security_add_firewall_rule(firewall_rule_t* rule);
security_status_t security_remove_firewall_rule(uint32_t rule_id);
security_status_t security_enable_firewall_rule(uint32_t rule_id);
security_status_t security_disable_firewall_rule(uint32_t rule_id);
firewall_rule_t* security_get_firewall_rules(uint32_t* count);
firewall_rule_t* security_get_firewall_rule(uint32_t rule_id);
security_status_t security_check_firewall(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port, uint8_t protocol);
security_status_t security_update_firewall_rules(void);
uint32_t security_get_firewall_rule_count(void);

/* Cryptography functions */
security_status_t security_encrypt_data(void* plaintext, uint32_t plaintext_size, void* ciphertext, uint32_t* ciphertext_size, encryption_context_t* context);
security_status_t security_decrypt_data(void* ciphertext, uint32_t ciphertext_size, void* plaintext, uint32_t* plaintext_size, encryption_context_t* context);
security_status_t security_hash_data(void* data, uint32_t size, uint8_t* hash, uint32_t* hash_size, hash_context_t* context);
security_status_t security_sign_data(void* data, uint32_t size, uint8_t* signature, uint32_t* signature_size, signature_context_t* context);
security_status_t security_verify_signature(void* data, uint32_t size, uint8_t* signature, uint32_t signature_size, signature_context_t* context);
security_status_t security_generate_key(encryption_context_t* context, uint32_t key_size);
security_status_t security_generate_random(uint8_t* buffer, uint32_t size);
encryption_context_t* security_create_encryption_context(uint8_t algorithm, uint8_t mode);
hash_context_t* security_create_hash_context(uint8_t algorithm);
signature_context_t* security_create_signature_context(uint8_t algorithm);

/* Certificate functions */
security_status_t security_load_certificate(const char* filename, security_certificate_t* certificate);
security_status_t security_verify_certificate(security_certificate_t* certificate);
security_status_t security_revoke_certificate(uint32_t certificate_id);
security_status_t security_trust_certificate(uint32_t certificate_id);
security_status_t security_untrust_certificate(uint32_t certificate_id);
security_certificate_t* security_get_certificates(uint32_t* count);
security_certificate_t* security_get_certificate(uint32_t certificate_id);
security_status_t security_generate_certificate(const char* subject, uint64_t valid_duration, security_certificate_t* certificate);

/* Pentesting functions */
security_status_t security_enable_penetration_testing_mode(void);
security_status_t security_disable_penetration_testing_mode(void);
security_status_t security_enable_vulnerability_assessment_mode(void);
security_status_t security_disable_vulnerability_assessment_mode(void);
security_status_t security_enable_red_team_mode(void);
security_status_t security_disable_red_team_mode(void);
security_status_t security_enable_blue_team_mode(void);
security_status_t security_disable_blue_team_mode(void);
security_status_t security_enable_capture_the_flag_mode(void);
security_status_t security_disable_capture_the_flag_mode(void);
security_status_t security_enable_war_gaming_mode(void);
security_status_t security_disable_war_gaming_mode(void);
bool security_is_penetration_testing_mode_enabled(void);
bool security_is_vulnerability_assessment_mode_enabled(void);
bool security_is_red_team_mode_enabled(void);
bool security_is_blue_team_mode_enabled(void);
bool security_is_capture_the_flag_mode_enabled(void);
bool security_is_war_gaming_mode_enabled(void);

/* Security analysis */
security_status_t security_analyze_vulnerabilities(void);
security_status_t security_assess_risk(void);
security_status_t security_generate_security_report(void);
security_status_t security_check_compliance(void);
security_status_t security_perform_security_audit(void);
security_status_t security_test_security_controls(void);
security_status_t security_simulate_attack(security_event_type_t attack_type);
security_status_t security_test_intrusion_detection(void);
security_status_t security_test_firewall_rules(void);

/* Memory protection */
security_status_t security_protect_memory(void* address, uint32_t size, uint32_t protection_flags);
security_status_t security_unprotect_memory(void* address, uint32_t size);
security_status_t security_check_memory_protection(void* address, uint32_t size, uint32_t required_flags);
bool security_is_memory_protected(void* address, uint32_t size);

/* Privilege management */
security_status_t security_set_privilege_level(privilege_level_t level);
security_status_t security_get_privilege_level(privilege_level_t* level);
security_status_t security_elevate_privileges(privilege_level_t target_level, security_token_t* token);
security_status_t security_lower_privileges(privilege_level_t target_level);
security_status_t security_check_privilege_escalation(void);
bool security_can_elevate_privileges(security_token_t* token, privilege_level_t target_level);

/* Security utilities */
const char* security_get_status_string(security_status_t status);
const char* security_get_event_type_string(security_event_type_t event_type);
const char* security_get_threat_level_string(security_threat_level_t threat_level);
const char* security_get_alert_type_string(security_alert_type_t alert_type);
const char* security_get_user_role_string(user_role_t role);
const char* security_get_privilege_level_string(privilege_level_t privilege);
uint32_t security_get_current_user_id(void);
privilege_level_t security_get_current_privilege_level(void);
security_token_t* security_get_current_token(void);

/* Statistics */
void security_get_statistics(uint64_t* total_logins, uint64_t* total_failures, uint64_t* total_violations, uint64_t* total_alerts);
void security_get_attack_statistics(uint64_t* total_attacks, uint64_t* total_intrusions, uint64_t* total_scans, uint64_t* total_exploits);
void security_get_encryption_statistics(uint64_t* total_encryptions, uint64_t* total_decryptions, uint64_t* total_hashes, uint64_t* total_signatures);
void security_reset_statistics(void);

/* Global security manager */
extern security_manager_t* global_security_manager;

/* Security constants */
#define SECURITY_MAX_USERS              1024
#define SECURITY_MAX_TOKENS             256
#define SECURITY_MAX_POLICIES           512
#define SECURITY_MAX_AUDIT_LOG_ENTRIES  10000
#define SECURITY_MAX_ALERTS               1000
#define SECURITY_MAX_IDS_RULES            256
#define SECURITY_MAX_FIREWALL_RULES       1024
#define SECURITY_MAX_CERTIFICATES         256

#define SECURITY_PASSWORD_MIN_LENGTH    8
#define SECURITY_PASSWORD_MAX_LENGTH    128
#define SECURITY_SESSION_TIMEOUT_DEFAULT 3600  /* 1 hour */
#define SECURITY_TOKEN_EXPIRY_DEFAULT    86400  /* 24 hours */

#define SECURITY_HASH_SIZE_MD5          16
#define SECURITY_HASH_SIZE_SHA1         20
#define SECURITY_HASH_SIZE_SHA256       32
#define SECURITY_HASH_SIZE_SHA512       64

#define SECURITY_KEY_SIZE_AES128        16
#define SECURITY_KEY_SIZE_AES192        24
#define SECURITY_KEY_SIZE_AES256        32
#define SECURITY_KEY_SIZE_RSA2048        256
#define SECURITY_KEY_SIZE_RSA4096        512

#define SECURITY_SIGNATURE_SIZE_RSA     256
#define SECURITY_SIGNATURE_SIZE_ECDSA     64
#define SECURITY_SIGNATURE_SIZE_DSA       40

/* Pentesting specific security features */
#define SECURITY_PENTEST_MODE_NORMAL        0
#define SECURITY_PENTEST_MODE_RECONNAISSANCE 1
#define SECURITY_PENTEST_MODE_SCANNING       2
#define SECURITY_PENTEST_MODE_EXPLOITATION   3
#define SECURITY_PENTEST_MODE_POST_EXPLOIT   4
#define SECURITY_PENTEST_MODE_REPORTING      5

#define SECURITY_ATTACK_TYPE_RECONNAISSANCE 1
#define SECURITY_ATTACK_TYPE_SCANNING       2
#define SECURITY_ATTACK_TYPE_EXPLOITATION   3
#define SECURITY_ATTACK_TYPE_POST_EXPLOIT   4
#define SECURITY_ATTACK_TYPE_PERSISTENCE    5
#define SECURITY_ATTACK_TYPE_EXFILTRATION   6

#define SECURITY_VULNERABILITY_TYPE_BUFFER_OVERFLOW     1
#define SECURITY_VULNERABILITY_TYPE_SQL_INJECTION       2
#define SECURITY_VULNERABILITY_TYPE_XSS                 3
#define SECURITY_VULNERABILITY_TYPE_DIRECTORY_TRAVERSAL 4
#define SECURITY_VULNERABILITY_TYPE_COMMAND_INJECTION   5
#define SECURITY_VULNERABILITY_TYPE_AUTHENTICATION    6
#define SECURITY_VULNERABILITY_TYPE_AUTHORIZATION     7
#define SECURITY_VULNERABILITY_TYPE_ENCRYPTION        8
#define SECURITY_VULNERABILITY_TYPE_CONFIGURATION     9

#endif /* SECURITY_H */