#include "security.h"
#include "../kernel/memory.h"
#include "../kernel/interrupt.h"
#include "../drivers/vga.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

/* Global security manager */
security_manager_t* global_security_manager = NULL;
bool security_initialized = false;

/* Default admin user */
static const char* default_admin_username = "admin";
static const char* default_admin_password = "pentest2024!";

/* Initialize security subsystem */
void security_init(void) {
    if (security_initialized) return;
    
    /* Allocate security manager */
    global_security_manager = (security_manager_t*)kmalloc(sizeof(security_manager_t));
    if (!global_security_manager) return;
    
    memory_zero(global_security_manager, sizeof(security_manager_t));
    
    /* Initialize manager */
    global_security_manager->initialized = true;
    global_security_manager->security_level = SECURITY_LEVEL_MEDIUM;
    global_security_manager->audit_enabled = true;
    global_security_manager->alerts_enabled = true;
    global_security_manager->ids_enabled = false;
    global_security_manager->firewall_enabled = false;
    global_security_manager->encryption_enabled = true;
    global_security_manager->secure_boot_enabled = true;
    global_security_manager->trusted_platform_enabled = false;
    
    /* Initialize statistics */
    global_security_manager->total_logins = 0;
    global_security_manager->total_failures = 0;
    global_security_manager->total_violations = 0;
    global_security_manager->total_alerts = 0;
    global_security_manager->total_attacks = 0;
    global_security_manager->total_intrusions = 0;
    global_security_manager->total_encryptions = 0;
    global_security_manager->total_decryptions = 0;
    global_security_manager->total_hashes = 0;
    global_security_manager->total_signatures = 0;
    
    /* Initialize pentesting modes */
    global_security_manager->penetration_testing_mode = false;
    global_security_manager->vulnerability_assessment_mode = false;
    global_security_manager->red_team_mode = false;
    global_security_manager->blue_team_mode = false;
    global_security_manager->capture_the_flag_mode = false;
    global_security_manager->war_gaming_mode = false;
    
    /* Initialize current user */
    global_security_manager->current_user_id = 0;
    global_security_manager->current_token = NULL;
    global_security_manager->current_privilege = PRIVILEGE_NONE;
    
    /* Allocate user array */
    global_security_manager->users = (user_credentials_t*)kmalloc(sizeof(user_credentials_t) * SECURITY_MAX_USERS);
    if (global_security_manager->users) {
        memory_zero(global_security_manager->users, sizeof(user_credentials_t) * SECURITY_MAX_USERS);
    }
    
    /* Allocate token array */
    global_security_manager->tokens = (security_token_t*)kmalloc(sizeof(security_token_t) * SECURITY_MAX_TOKENS);
    if (global_security_manager->tokens) {
        memory_zero(global_security_manager->tokens, sizeof(security_token_t) * SECURITY_MAX_TOKENS);
    }
    
    /* Allocate policy array */
    global_security_manager->policies = (security_policy_t*)kmalloc(sizeof(security_policy_t) * SECURITY_MAX_POLICIES);
    if (global_security_manager->policies) {
        memory_zero(global_security_manager->policies, sizeof(security_policy_t) * SECURITY_MAX_POLICIES);
    }
    
    /* Allocate audit log */
    global_security_manager->audit_log = (security_audit_log_t*)kmalloc(sizeof(security_audit_log_t) * SECURITY_MAX_AUDIT_LOG_ENTRIES);
    if (global_security_manager->audit_log) {
        memory_zero(global_security_manager->audit_log, sizeof(security_audit_log_t) * SECURITY_MAX_AUDIT_LOG_ENTRIES);
    }
    
    /* Allocate alerts */
    global_security_manager->alerts = (security_alert_t*)kmalloc(sizeof(security_alert_t) * SECURITY_MAX_ALERTS);
    if (global_security_manager->alerts) {
        memory_zero(global_security_manager->alerts, sizeof(security_alert_t) * SECURITY_MAX_ALERTS);
    }
    
    /* Allocate IDS rules */
    global_security_manager->ids_rules = (intrusion_detection_rule_t*)kmalloc(sizeof(intrusion_detection_rule_t) * SECURITY_MAX_IDS_RULES);
    if (global_security_manager->ids_rules) {
        memory_zero(global_security_manager->ids_rules, sizeof(intrusion_detection_rule_t) * SECURITY_MAX_IDS_RULES);
    }
    
    /* Allocate firewall rules */
    global_security_manager->firewall_rules = (firewall_rule_t*)kmalloc(sizeof(firewall_rule_t) * SECURITY_MAX_FIREWALL_RULES);
    if (global_security_manager->firewall_rules) {
        memory_zero(global_security_manager->firewall_rules, sizeof(firewall_rule_t) * SECURITY_MAX_FIREWALL_RULES);
    }
    
    /* Create default admin user */
    security_create_default_admin();
    
    /* Initialize default security policies */
    security_init_default_policies();
    
    /* Initialize default IDS rules */
    security_init_default_ids_rules();
    
    /* Initialize default firewall rules */
    security_init_default_firewall_rules();
    
    security_initialized = true;
    
    vga_print_success("Security subsystem initialized");
    vga_print_info("Default admin user created: username='admin', password='pentest2024!'");
}

/* Shutdown security subsystem */
void security_shutdown(void) {
    if (!security_initialized || !global_security_manager) return;
    
    /* Log shutdown event */
    security_log_event(SECURITY_EVENT_SYSTEM, 0, 0, SECURITY_STATUS_OK, "Security subsystem shutdown");
    
    /* Revoke all tokens */
    for (uint32_t i = 0; i < global_security_manager->token_count; i++) {
        security_revoke_token(&global_security_manager->tokens[i]);
    }
    
    /* Free all allocated memory */
    if (global_security_manager->users) kfree(global_security_manager->users);
    if (global_security_manager->tokens) kfree(global_security_manager->tokens);
    if (global_security_manager->policies) kfree(global_security_manager->policies);
    if (global_security_manager->audit_log) kfree(global_security_manager->audit_log);
    if (global_security_manager->alerts) kfree(global_security_manager->alerts);
    if (global_security_manager->ids_rules) kfree(global_security_manager->ids_rules);
    if (global_security_manager->firewall_rules) kfree(global_security_manager->firewall_rules);
    
    kfree(global_security_manager);
    global_security_manager = NULL;
    security_initialized = false;
    
    vga_print_info("Security subsystem shutdown");
}

/* Check if initialized */
bool security_is_initialized(void) {
    return security_initialized && global_security_manager && global_security_manager->initialized;
}

/* Create default admin user */
void security_create_default_admin(void) {
    if (!global_security_manager || !global_security_manager->users) return;
    
    user_credentials_t* admin = &global_security_manager->users[0];
    
    strncpy(admin->username, default_admin_username, sizeof(admin->username) - 1);
    admin->user_id = 1;
    admin->role = USER_ROLE_SUPER_ADMIN;
    admin->privilege = PRIVILEGE_SUPER_ADMIN;
    admin->enabled = true;
    admin->locked = false;
    admin->failed_attempts = 0;
    admin->last_login = 0;
    admin->password_changed = get_system_time();
    admin->password_expiry_days = 90;
    admin->password_expired = false;
    admin->session_timeout = SECURITY_SESSION_TIMEOUT_DEFAULT;
    admin->max_sessions = 10;
    admin->mfa_enabled = false;
    admin->backup_codes_used = 0;
    
    /* Generate password hash (simplified) */
    security_hash_password(default_admin_password, admin->password_hash, admin->salt);
    
    global_security_manager->user_count = 1;
    
    vga_print_info("Default admin user created");
}

/* Initialize default security policies */
void security_init_default_policies(void) {
    if (!global_security_manager || !global_security_manager->policies) return;
    
    /* Policy 1: Block privilege escalation attempts */
    security_policy_t* policy = &global_security_manager->policies[0];
    strncpy(policy->name, "Block Privilege Escalation", sizeof(policy->name) - 1);
    strncpy(policy->description, "Block attempts to escalate privileges without proper authorization", sizeof(policy->description) - 1);
    policy->event_type = SECURITY_EVENT_PRIVILEGE;
    policy->threat_level = SECURITY_THREAT_HIGH;
    policy->conditions = 0x01;  /* Unauthorized escalation */
    policy->actions = 0x01;     /* Deny and log */
    policy->enabled = true;
    policy->priority = 100;
    policy->created_time = get_system_time();
    policy->modified_time = policy->created_time;
    
    /* Policy 2: Alert on multiple failed login attempts */
    policy = &global_security_manager->policies[1];
    strncpy(policy->name, "Alert on Brute Force", sizeof(policy->name) - 1);
    strncpy(policy->description, "Alert when multiple failed login attempts are detected", sizeof(policy->description) - 1);
    policy->event_type = SECURITY_EVENT_LOGIN;
    policy->threat_level = SECURITY_THREAT_MEDIUM;
    policy->conditions = 0x02;  /* Multiple failures */
    policy->actions = 0x03;     /* Alert and lock account */
    policy->enabled = true;
    policy->priority = 90;
    policy->created_time = get_system_time();
    policy->modified_time = policy->created_time;
    
    global_security_manager->policy_count = 2;
    
    vga_print_info("Default security policies initialized");
}

/* Initialize default IDS rules */
void security_init_default_ids_rules(void) {
    if (!global_security_manager || !global_security_manager->ids_rules) return;
    
    /* Rule 1: Detect port scanning */
    intrusion_detection_rule_t* rule = &global_security_manager->ids_rules[0];
    strncpy(rule->name, "Port Scan Detection", sizeof(rule->name) - 1);
    strncpy(rule->description, "Detect sequential connection attempts to multiple ports", sizeof(rule->description) - 1);
    rule->event_type = SECURITY_EVENT_SCAN;
    rule->threat_level = SECURITY_THREAT_MEDIUM;
    rule->conditions = 0x01;  /* Multiple ports */
    rule->actions = 0x01;     /* Alert */
    rule->enabled = true;
    rule->priority = 80;
    rule->created_time = get_system_time();
    rule->modified_time = rule->created_time;
    rule->match_count = 0;
    rule->false_positive_count = 0;
    rule->accuracy = 0.85f;
    
    /* Rule 2: Detect exploit attempts */
    rule = &global_security_manager->ids_rules[1];
    strncpy(rule->name, "Exploit Detection", sizeof(rule->name) - 1);
    strncpy(rule->description, "Detect known exploit patterns and signatures", sizeof(rule->description) - 1);
    rule->event_type = SECURITY_EVENT_EXPLOIT;
    rule->threat_level = SECURITY_THREAT_HIGH;
    rule->conditions = 0x02;  /* Known signatures */
    rule->actions = 0x03;     /* Alert and block */
    rule->enabled = true;
    rule->priority = 95;
    rule->created_time = get_system_time();
    rule->modified_time = rule->created_time;
    rule->match_count = 0;
    rule->false_positive_count = 0;
    rule->accuracy = 0.92f;
    
    global_security_manager->ids_rule_count = 2;
    
    vga_print_info("Default IDS rules initialized");
}

/* Initialize default firewall rules */
void security_init_default_firewall_rules(void) {
    if (!global_security_manager || !global_security_manager->firewall_rules) return;
    
    /* Rule 1: Allow loopback */
    firewall_rule_t* rule = &global_security_manager->firewall_rules[0];
    strncpy(rule->name, "Allow Loopback", sizeof(rule->name) - 1);
    strncpy(rule->description, "Allow all traffic on loopback interface", sizeof(rule->description) - 1);
    rule->source_ip = 0x7F000001;  /* 127.0.0.1 */
    rule->source_mask = 0xFFFFFFFF;
    rule->dest_ip = 0x7F000001;    /* 127.0.0.1 */
    rule->dest_mask = 0xFFFFFFFF;
    rule->source_port = 0;
    rule->dest_port = 0;
    rule->protocol = 0;  /* Any protocol */
    rule->action = SECURITY_POLICY_ALLOW;
    rule->enabled = true;
    rule->priority = 100;
    rule->created_time = get_system_time();
    rule->modified_time = rule->created_time;
    
    /* Rule 2: Block external admin access */
    rule = &global_security_manager->firewall_rules[1];
    strncpy(rule->name, "Block External Admin", sizeof(rule->name) - 1);
    strncpy(rule->description, "Block external access to admin ports", sizeof(rule->description) - 1);
    rule->source_ip = 0;
    rule->source_mask = 0;
    rule->dest_ip = 0;
    rule->dest_mask = 0;
    rule->source_port = 0;
    rule->dest_port = 22;  /* SSH */
    rule->protocol = 6;    /* TCP */
    rule->action = SECURITY_POLICY_DENY;
    rule->enabled = true;
    rule->priority = 90;
    rule->created_time = get_system_time();
    rule->modified_time = rule->created_time;
    
    global_security_manager->firewall_rule_count = 2;
    
    vga_print_info("Default firewall rules initialized");
}

/* Authenticate user */
security_status_t security_authenticate(const char* username, const char* password, security_token_t** token) {
    if (!global_security_manager || !username || !password || !token) {
        return SECURITY_STATUS_INVALID_PARAM;
    }
    
    /* Find user */
    user_credentials_t* user = security_get_user_by_name(username);
    if (!user) {
        security_log_login_attempt(0, false, "unknown");
        return SECURITY_STATUS_AUTHENTICATION_FAILED;
    }
    
    /* Check if user is enabled */
    if (!user->enabled) {
        security_log_login_attempt(user->user_id, false, "disabled");
        return SECURITY_STATUS_ACCESS_DENIED;
    }
    
    /* Check if user is locked */
    if (user->locked) {
        security_log_login_attempt(user->user_id, false, "locked");
        return SECURITY_STATUS_ACCESS_DENIED;
    }
    
    /* Verify password */
    uint8_t password_hash[64];
    security_hash_password(password, password_hash, user->salt);
    
    if (memory_compare(user->password_hash, password_hash, 64) != 0) {
        user->failed_attempts++;
        security_log_login_attempt(user->user_id, false, "invalid_password");
        
        /* Lock account after 5 failed attempts */
        if (user->failed_attempts >= 5) {
            user->locked = true;
            security_create_alert(SECURITY_ALERT_CRITICAL, SECURITY_THREAT_HIGH, SECURITY_EVENT_LOGIN, "Account locked due to multiple failed login attempts");
        }
        
        return SECURITY_STATUS_AUTHENTICATION_FAILED;
    }
    
    /* Reset failed attempts */
    user->failed_attempts = 0;
    user->last_login = get_system_time();
    
    /* Create token */
    *token = security_create_token(user);
    if (!*token) {
        security_log_login_attempt(user->user_id, false, "token_creation_failed");
        return SECURITY_STATUS_ERROR;
    }
    
    /* Update current user */
    global_security_manager->current_user_id = user->user_id;
    global_security_manager->current_token = *token;
    global_security_manager->current_privilege = user->privilege;
    
    security_log_login_attempt(user->user_id, true, "success");
    global_security_manager->total_logins++;
    
    vga_printf("User '%s' authenticated successfully\n", username);
    return SECURITY_STATUS_OK;
}

/* Logout user */
security_status_t security_logout(security_token_t* token) {
    if (!token) return SECURITY_STATUS_INVALID_PARAM;
    
    /* Revoke token */
    security_revoke_token(token);
    
    /* Reset current user */
    global_security_manager->current_user_id = 0;
    global_security_manager->current_token = NULL;
    global_security_manager->current_privilege = PRIVILEGE_NONE;
    
    security_log_event(SECURITY_EVENT_LOGOUT, token->user_id, 0, SECURITY_STATUS_OK, "User logged out");
    
    vga_print_info("User logged out");
    return SECURITY_STATUS_OK;
}

/* Validate token */
security_status_t security_validate_token(security_token_t* token) {
    if (!token) return SECURITY_STATUS_INVALID_PARAM;
    
    /* Check if token is valid */
    if (!token->valid) return SECURITY_STATUS_INVALID_TOKEN;
    
    /* Check if token is revoked */
    if (token->revoked) return SECURITY_STATUS_REVOKED_TOKEN;
    
    /* Check if token is expired */
    uint64_t current_time = get_system_time();
    if (current_time > token->expiry_time) return SECURITY_STATUS_EXPIRED_TOKEN;
    
    /* Update token usage */
    token->last_used = current_time;
    token->usage_count++;
    
    return SECURITY_STATUS_OK;
}

/* Create token */
security_token_t* security_create_token(user_credentials_t* user) {
    if (!user || !global_security_manager || !global_security_manager->tokens) return NULL;
    
    /* Find free token slot */
    for (uint32_t i = 0; i < SECURITY_MAX_TOKENS; i++) {
        security_token_t* token = &global_security_manager->tokens[i];
        if (!token->valid) {
            /* Initialize token */
            token->token_id = i + 1;
            token->user_id = user->user_id;
            token->user_role = user->role;
            token->privilege_level = user->privilege;
            token->created_time = get_system_time();
            token->expiry_time = token->created_time + SECURITY_TOKEN_EXPIRY_DEFAULT;
            token->last_used = token->created_time;
            token->usage_count = 0;
            token->valid = true;
            token->revoked = false;
            token->flags = 0;
            
            /* Generate session key */
            security_generate_random(token->session_key, sizeof(token->session_key));
            
            /* Generate signature */
            security_generate_signature(token, token->signature);
            
            global_security_manager->token_count++;
            return token;
        }
    }
    
    return NULL;
}

/* Revoke token */
security_status_t security_revoke_token(security_token_t* token) {
    if (!token) return SECURITY_STATUS_INVALID_PARAM;
    
    token->valid = false;
    token->revoked = true;
    
    return SECURITY_STATUS_OK;
}

/* Check permission */
security_status_t security_check_permission(uint32_t user_id, uint32_t object_id, uint32_t requested_permissions) {
    if (!global_security_manager) return SECURITY_STATUS_ERROR;
    
    /* Get user */
    user_credentials_t* user = security_get_user(user_id);
    if (!user) return SECURITY_STATUS_ACCESS_DENIED;
    
    /* Check if user has required permissions */
    /* This would implement permission checking logic */
    
    return SECURITY_STATUS_OK;
}

/* Check privilege */
security_status_t security_check_privilege(uint32_t user_id, privilege_level_t required_privilege) {
    if (!global_security_manager) return SECURITY_STATUS_ERROR;
    
    /* Get user */
    user_credentials_t* user = security_get_user(user_id);
    if (!user) return SECURITY_STATUS_ACCESS_DENIED;
    
    /* Check if user has required privilege */
    if (user->privilege < required_privilege) {
        return SECURITY_STATUS_INSUFFICIENT_PRIVILEGES;
    }
    
    return SECURITY_STATUS_OK;
}

/* Get user by ID */
user_credentials_t* security_get_user(uint32_t user_id) {
    if (!global_security_manager || !global_security_manager->users) return NULL;
    
    for (uint32_t i = 0; i < global_security_manager->user_count; i++) {
        if (global_security_manager->users[i].user_id == user_id) {
            return &global_security_manager->users[i];
        }
    }
    
    return NULL;
}

/* Get user by name */
user_credentials_t* security_get_user_by_name(const char* username) {
    if (!global_security_manager || !global_security_manager->users || !username) return NULL;
    
    for (uint32_t i = 0; i < global_security_manager->user_count; i++) {
        if (strcmp(global_security_manager->users[i].username, username) == 0) {
            return &global_security_manager->users[i];
        }
    }
    
    return NULL;
}

/* Get user count */
uint32_t security_get_user_count(void) {
    return global_security_manager ? global_security_manager->user_count : 0;
}

/* Log security event */
security_status_t security_log_event(security_event_type_t event_type, uint32_t user_id, uint32_t object_id, security_status_t status, const char* description) {
    if (!global_security_manager || !global_security_manager->audit_log) return SECURITY_STATUS_ERROR;
    
    /* Find free audit log entry */
    if (global_security_manager->audit_log_count >= SECURITY_MAX_AUDIT_LOG_ENTRIES) {
        /* Overwrite oldest entry */
        global_security_manager->audit_log_count = SECURITY_MAX_AUDIT_LOG_ENTRIES - 1;
    }
    
    security_audit_log_t* log = &global_security_manager->audit_log[global_security_manager->audit_log_count++];
    
    /* Fill log entry */
    log->log_id = global_security_manager->next_log_id++;
    log->timestamp = get_system_time();
    log->event_type = event_type;
    log->threat_level = SECURITY_THREAT_LOW;
    log->user_id = user_id;
    log->process_id = 0;  /* Would be current process ID */
    log->object_id = object_id;
    log->status = status;
    
    if (description) {
        strncpy(log->description, description, sizeof(log->description) - 1);
    }
    
    log->details_size = 0;
    log->flags = 0;
    
    return SECURITY_STATUS_OK;
}

/* Log login attempt */
security_status_t security_log_login_attempt(uint32_t user_id, bool success, const char* source_ip) {
    security_event_type_t event_type = success ? SECURITY_EVENT_LOGIN : SECURITY_EVENT_DENIED;
    security_threat_level_t threat_level = success ? SECURITY_THREAT_LOW : SECURITY_THREAT_MEDIUM;
    
    const char* description = success ? "Successful login" : "Failed login attempt";
    
    return security_log_security_event(event_type, threat_level, description, (void*)source_ip, source_ip ? strlen(source_ip) : 0);
}

/* Create alert */
security_status_t security_create_alert(security_alert_type_t alert_type, security_threat_level_t threat_level, security_event_type_t event_type, const char* description) {
    if (!global_security_manager || !global_security_manager->alerts) return SECURITY_STATUS_ERROR;
    
    /* Find free alert slot */
    if (global_security_manager->alert_count >= SECURITY_MAX_ALERTS) {
        /* Overwrite oldest alert */
        global_security_manager->alert_count = SECURITY_MAX_ALERTS - 1;
    }
    
    security_alert_t* alert = &global_security_manager->alerts[global_security_manager->alert_count++];
    
    /* Fill alert */
    alert->alert_id = global_security_manager->next_alert_id++;
    alert->timestamp = get_system_time();
    alert->alert_type = alert_type;
    alert->threat_level = threat_level;
    alert->event_type = event_type;
    alert->source_id = 0;
    alert->source_port = 0;
    alert->target_port = 0;
    alert->acknowledged = false;
    alert->acknowledged_by = 0;
    alert->acknowledged_time = 0;
    alert->flags = 0;
    
    if (description) {
        strncpy(alert->description, description, sizeof(alert->description) - 1);
    }
    
    global_security_manager->total_alerts++;
    
    vga_printf("[SECURITY ALERT] %s - %s\n", security_get_threat_level_string(threat_level), description);
    return SECURITY_STATUS_OK;
}

/* Hash password */
void security_hash_password(const char* password, uint8_t* hash, uint8_t* salt) {
    if (!password || !hash || !salt) return;
    
    /* Generate random salt */
    security_generate_random(salt, 32);
    
    /* Simple password hash (would use proper cryptographic hash in real implementation) */
    uint32_t hash_value = 0;
    for (uint32_t i = 0; password[i]; i++) {
        hash_value = hash_value * 31 + password[i];
    }
    
    /* Mix with salt */
    for (uint32_t i = 0; i < 32; i++) {
        hash[i] = (hash_value + salt[i]) & 0xFF;
        hash[i + 32] = (hash_value ^ salt[i]) & 0xFF;
    }
}

/* Generate random data */
security_status_t security_generate_random(uint8_t* buffer, uint32_t size) {
    if (!buffer || size == 0) return SECURITY_STATUS_INVALID_PARAM;
    
    /* Simple pseudo-random generator (would use proper RNG in real implementation) */
    static uint32_t seed = 12345;
    for (uint32_t i = 0; i < size; i++) {
        seed = seed * 1103515245 + 12345;
        buffer[i] = (seed >> 16) & 0xFF;
    }
    
    return SECURITY_STATUS_OK;
}

/* Generate signature */
void security_generate_signature(security_token_t* token, uint8_t* signature) {
    if (!token || !signature) return;
    
    /* Simple signature generation (would use proper cryptographic signature in real implementation) */
    uint32_t sig_value = token->token_id + token->user_id + token->created_time;
    for (uint32_t i = 0; i < 64; i++) {
        signature[i] = (sig_value + i) & 0xFF;
    }
}

/* Enable penetration testing mode */
security_status_t security_enable_penetration_testing_mode(void) {
    if (!global_security_manager) return SECURITY_STATUS_ERROR;
    
    global_security_manager->penetration_testing_mode = true;
    global_security_manager->security_level = SECURITY_LEVEL_LOW;
    
    vga_print_info("Penetration testing mode enabled");
    security_log_event(SECURITY_EVENT_SYSTEM, 0, 0, SECURITY_STATUS_OK, "Penetration testing mode enabled");
    
    return SECURITY_STATUS_OK;
}

/* Disable penetration testing mode */
security_status_t security_disable_penetration_testing_mode(void) {
    if (!global_security_manager) return SECURITY_STATUS_ERROR;
    
    global_security_manager->penetration_testing_mode = false;
    global_security_manager->security_level = SECURITY_LEVEL_MEDIUM;
    
    vga_print_info("Penetration testing mode disabled");
    security_log_event(SECURITY_EVENT_SYSTEM, 0, 0, SECURITY_STATUS_OK, "Penetration testing mode disabled");
    
    return SECURITY_STATUS_OK;
}

/* Check if penetration testing mode enabled */
bool security_is_penetration_testing_mode_enabled(void) {
    return global_security_manager ? global_security_manager->penetration_testing_mode : false;
}

/* Get status string */
const char* security_get_status_string(security_status_t status) {
    switch (status) {
        case SECURITY_STATUS_OK: return "OK";
        case SECURITY_STATUS_ERROR: return "Error";
        case SECURITY_STATUS_ACCESS_DENIED: return "Access Denied";
        case SECURITY_STATUS_PERMISSION_DENIED: return "Permission Denied";
        case SECURITY_STATUS_AUTHENTICATION_FAILED: return "Authentication Failed";
        case SECURITY_STATUS_AUTHORIZATION_FAILED: return "Authorization Failed";
        case SECURITY_STATUS_INVALID_CREDENTIALS: return "Invalid Credentials";
        case SECURITY_STATUS_INVALID_TOKEN: return "Invalid Token";
        case SECURITY_STATUS_EXPIRED_TOKEN: return "Expired Token";
        case SECURITY_STATUS_REVOKED_TOKEN: return "Revoked Token";
        case SECURITY_STATUS_INSUFFICIENT_PRIVILEGES: return "Insufficient Privileges";
        case SECURITY_STATUS_SECURITY_VIOLATION: return "Security Violation";
        case SECURITY_STATUS_POLICY_VIOLATION: return "Policy Violation";
        case SECURITY_STATUS_AUDIT_FAILURE: return "Audit Failure";
        case SECURITY_STATUS_ENCRYPTION_ERROR: return "Encryption Error";
        case SECURITY_STATUS_DECRYPTION_ERROR: return "Decryption Error";
        case SECURITY_STATUS_HASH_ERROR: return "Hash Error";
        case SECURITY_STATUS_SIGNATURE_ERROR: return "Signature Error";
        case SECURITY_STATUS_CERTIFICATE_ERROR: return "Certificate Error";
        case SECURITY_STATUS_KEY_ERROR: return "Key Error";
        case SECURITY_STATUS_RANDOM_ERROR: return "Random Error";
        default: return "Unknown";
    }
}

/* Get event type string */
const char* security_get_event_type_string(security_event_type_t event_type) {
    switch (event_type) {
        case SECURITY_EVENT_LOGIN: return "Login";
        case SECURITY_EVENT_LOGOUT: return "Logout";
        case SECURITY_EVENT_ACCESS: return "Access";
        case SECURITY_EVENT_DENIED: return "Access Denied";
        case SECURITY_EVENT_VIOLATION: return "Security Violation";
        case SECURITY_EVENT_ATTACK: return "Attack";
        case SECURITY_EVENT_INTRUSION: return "Intrusion";
        case SECURITY_EVENT_SCAN: return "Scan";
        case SECURITY_EVENT_EXPLOIT: return "Exploit";
        case SECURITY_EVENT_PRIVILEGE: return "Privilege";
        case SECURITY_EVENT_PASSWORD: return "Password";
        case SECURITY_EVENT_ENCRYPTION: return "Encryption";
        case SECURITY_EVENT_DECRYPTION: return "Decryption";
        case SECURITY_EVENT_KEY: return "Key";
        case SECURITY_EVENT_CERTIFICATE: return "Certificate";
        case SECURITY_EVENT_FIREWALL: return "Firewall";
        case SECURITY_EVENT_IDS: return "IDS";
        case SECURITY_EVENT_AUDIT: return "Audit";
        case SECURITY_EVENT_POLICY: return "Policy";
        case SECURITY_EVENT_SYSTEM: return "System";
        default: return "Unknown";
    }
}

/* Get threat level string */
const char* security_get_threat_level_string(security_threat_level_t threat_level) {
    switch (threat_level) {
        case SECURITY_THREAT_LOW: return "Low";
        case SECURITY_THREAT_MEDIUM: return "Medium";
        case SECURITY_THREAT_HIGH: return "High";
        case SECURITY_THREAT_CRITICAL: return "Critical";
        case SECURITY_THREAT_EMERGENCY: return "Emergency";
        default: return "Unknown";
    }
}

/* Get current user ID */
uint32_t security_get_current_user_id(void) {
    return global_security_manager ? global_security_manager->current_user_id : 0;
}

/* Get current privilege level */
privilege_level_t security_get_current_privilege_level(void) {
    return global_security_manager ? global_security_manager->current_privilege : PRIVILEGE_NONE;
}

/* Get current token */
security_token_t* security_get_current_token(void) {
    return global_security_manager ? global_security_manager->current_token : NULL;
}

/* Get statistics */
void security_get_statistics(uint64_t* total_logins, uint64_t* total_failures, uint64_t* total_violations, uint64_t* total_alerts) {
    if (!global_security_manager) return;
    
    if (total_logins) *total_logins = global_security_manager->total_logins;
    if (total_failures) *total_failures = global_security_manager->total_failures;
    if (total_violations) *total_violations = global_security_manager->total_violations;
    if (total_alerts) *total_alerts = global_security_manager->total_alerts;
}

/* Log security event */
security_status_t security_log_security_event(security_event_type_t event_type, security_threat_level_t threat_level, const char* description, void* details, uint32_t details_size) {
    return security_log_event(event_type, 0, 0, SECURITY_STATUS_OK, description);
}

/* String comparison */
int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

/* String copy */
char* strncpy(char* dest, const char* src, size_t n) {
    char* original = dest;
    while (n-- && (*dest++ = *src++));
    while (n-- > 0) *dest++ = '\0';
    return original;
}

/* String formatting */
int sprintf(char* str, const char* format, ...) {
    /* Simple sprintf implementation */
    va_list args;
    va_start(args, format);
    
    int count = 0;
    while (*format) {
        if (*format == '%' && *(format + 1) == 's') {
            format += 2;
            char* s = va_arg(args, char*);
            while (*s) {
                *str++ = *s++;
                count++;
            }
        } else if (*format == '%' && *(format + 1) == 'u') {
            format += 2;
            unsigned int num = va_arg(args, unsigned int);
            /* Simple number to string conversion */
            char temp[16];
            int i = 0;
            if (num == 0) {
                temp[i++] = '0';
            } else {
                while (num > 0) {
                    temp[i++] = '0' + (num % 10);
                    num /= 10;
                }
            }
            while (i > 0) {
                *str++ = temp[--i];
                count++;
            }
        } else if (*format == '%' && *(format + 1) == 'l' && *(format + 2) == 'l' && *(format + 3) == 'u') {
            format += 4;
            unsigned long long num = va_arg(args, unsigned long long);
            /* Simple number to string conversion */
            char temp[32];
            int i = 0;
            if (num == 0) {
                temp[i++] = '0';
            } else {
                while (num > 0) {
                    temp[i++] = '0' + (num % 10);
                    num /= 10;
                }
            }
            while (i > 0) {
                *str++ = temp[--i];
                count++;
            }
        } else {
            *str++ = *format++;
            count++;
        }
    }
    
    *str = '\0';
    va_end(args);
    return count;
}

/* Get system time (placeholder) */
uint64_t get_system_time(void) {
    /* This would be implemented by the timer driver */
    return 0;
}

/* Memory functions */
void memory_zero(void* dest, size_t size) {
    uint8_t* d = (uint8_t*)dest;
    while (size--) *d++ = 0;
}

int memory_compare(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = (const uint8_t*)s1;
    const uint8_t* p2 = (const uint8_t*)s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}