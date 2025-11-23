#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "pentest.h"

/* Scanner types */
typedef enum {
    SCANNER_TYPE_PORT = 1,
    SCANNER_TYPE_VULNERABILITY = 2,
    SCANNER_TYPE_SERVICE = 3,
    SCANNER_TYPE_OS = 4,
    SCANNER_TYPE_WEB = 5,
    SCANNER_TYPE_SSL = 6,
    SCANNER_TYPE_NETWORK = 7,
    SCANNER_TYPE_WIRELESS = 8,
    SCANNER_TYPE_BLUETOOTH = 9
} scanner_type_t;

/* Scan techniques */
typedef enum {
    SCAN_TECHNIQUE_TCP_SYN = 1,
    SCAN_TECHNIQUE_TCP_CONNECT = 2,
    SCAN_TECHNIQUE_TCP_FIN = 3,
    SCAN_TECHNIQUE_TCP_XMAS = 4,
    SCAN_TECHNIQUE_TCP_NULL = 5,
    SCAN_TECHNIQUE_TCP_ACK = 6,
    SCAN_TECHNIQUE_TCP_WINDOW = 7,
    SCAN_TECHNIQUE_TCP_MAIMON = 8,
    SCAN_TECHNIQUE_UDP = 9,
    SCAN_TECHNIQUE_SCTP_INIT = 10,
    SCAN_TECHNIQUE_SCTP_COOKIE = 11,
    SCAN_TECHNIQUE_IP_PROTOCOL = 12,
    SCAN_TECHNIQUE_PING = 13,
    SCAN_TECHNIQUE_ARP = 14,
    SCAN_TECHNIQUE_LIST = 15
} scan_technique_t;

/* Scan speeds */
typedef enum {
    SCAN_SPEED_PARANOID = 1,    /* Very slow, very stealthy */
    SCAN_SPEED_SNEAKY = 2,      /* Slow, stealthy */
    SCAN_SPEED_POLITE = 3,      /* Normal speed, polite */
    SCAN_SPEED_NORMAL = 4,      /* Normal speed */
    SCAN_SPEED_AGGRESSIVE = 5, /* Fast, aggressive */
    SCAN_SPEED_INSANE = 6       /* Very fast, very aggressive */
} scan_speed_t;

/* Port states */
typedef enum {
    PORT_STATE_OPEN = 1,
    PORT_STATE_CLOSED = 2,
    PORT_STATE_FILTERED = 3,
    PORT_STATE_UNFILTERED = 4,
    PORT_STATE_OPEN_FILTERED = 5,
    PORT_STATE_CLOSED_FILTERED = 6,
    PORT_STATE_UNKNOWN = 7
} port_state_t;

/* Service information */
typedef struct {
    uint16_t port;
    char service[64];
    char version[128];
    char product[128];
    char extra_info[256];
    char cpe[256];
    char protocol[16];
    uint8_t confidence;
    bool ssl;
    bool tunnel;
    uint32_t flags;
} service_info_t;

/* Port scan result */
typedef struct {
    uint16_t port;
    port_state_t state;
    scan_technique_t technique;
    uint32_t response_time;
    uint8_t confidence;
    service_info_t service;
    uint32_t flags;
} port_scan_result_t;

/* Host discovery result */
typedef struct {
    uint32_t ip_address;
    char hostname[256];
    uint8_t mac_address[6];
    bool alive;
    bool reachable;
    uint32_t response_time;
    uint32_t hop_count;
    uint8_t confidence;
    uint32_t flags;
} host_discovery_result_t;

/* OS detection result */
typedef struct {
    char os_name[128];
    char os_version[128];
    char os_family[64];
    char architecture[32];
    uint8_t accuracy;
    char cpe[256];
    char description[512];
    uint32_t flags;
} os_detection_result_t;

/* Vulnerability scan result */
typedef struct {
    uint32_t vulnerability_id;
    char name[128];
    char description[512];
    char cve_id[32];
    char cvss_score[16];
    float severity;
    uint8_t threat_level;
    char affected_service[128];
    uint16_t affected_port;
    bool confirmed;
    bool exploitable;
    char exploit_reference[256];
    char patch_reference[256];
    uint32_t flags;
} vulnerability_scan_result_t;

/* Scanner configuration */
typedef struct {
    scanner_type_t scanner_type;
    scan_technique_t technique;
    scan_speed_t speed;
    uint16_t start_port;
    uint16_t end_port;
    uint32_t timeout;
    uint32_t retries;
    uint32_t threads;
    uint32_t delay;
    uint32_t rate_limit;
    bool stealth_mode;
    bool evasion_mode;
    bool randomize_ports;
    bool randomize_hosts;
    bool fragment_packets;
    bool decoy_scan;
    uint32_t decoy_count;
    uint32_t decoy_ips[8];
    uint8_t ttl;
    uint8_t tos;
    uint16_t window_size;
    uint32_t flags;
} scanner_config_t;

/* Scanner statistics */
typedef struct {
    uint64_t total_scans;
    uint64_t total_hosts;
    uint64_t total_ports;
    uint64_t total_services;
    uint64_t total_vulnerabilities;
    uint64_t total_packets_sent;
    uint64_t total_packets_received;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    uint64_t total_runtime;
    uint32_t average_speed;
    uint32_t peak_speed;
    uint32_t success_rate;
    uint32_t accuracy;
} scanner_statistics_t;

/* Scanner state */
typedef struct {
    bool initialized;
    bool running;
    bool paused;
    uint32_t current_host;
    uint32_t current_port;
    uint64_t start_time;
    uint64_t pause_time;
    uint64_t total_pause_time;
    uint32_t hosts_scanned;
    uint32_t ports_scanned;
    uint32_t services_discovered;
    uint32_t vulnerabilities_found;
    uint32_t errors;
    uint32_t timeouts;
    uint32_t retries;
    scanner_config_t config;
    scanner_statistics_t statistics;
} scanner_state_t;

/* Scanner tool structure */
typedef struct scanner_tool {
    uint32_t scanner_id;
    char name[64];
    char description[256];
    scanner_type_t scanner_type;
    char version[32];
    char author[128];
    bool enabled;
    bool running;
    uint32_t priority;
    scanner_state_t state;
    
    /* Scanner operations */
    pentest_status_t (*init)(struct scanner_tool* scanner);
    pentest_status_t (*cleanup)(struct scanner_tool* scanner);
    pentest_status_t (*start)(struct scanner_tool* scanner);
    pentest_status_t (*stop)(struct scanner_tool* scanner);
    pentest_status_t (*pause)(struct scanner_tool* scanner);
    pentest_status_t (*resume)(struct scanner_tool* scanner);
    pentest_status_t (*configure)(struct scanner_tool* scanner, scanner_config_t* config);
    pentest_status_t (*scan_host)(struct scanner_tool* scanner, uint32_t ip_address);
    pentest_status_t (*scan_port)(struct scanner_tool* scanner, uint32_t ip_address, uint16_t port);
    pentest_status_t (*scan_service)(struct scanner_tool* scanner, uint32_t ip_address, uint16_t port);
    pentest_status_t (*detect_os)(struct scanner_tool* scanner, uint32_t ip_address);
    pentest_status_t (*scan_vulnerabilities)(struct scanner_tool* scanner, uint32_t ip_address);
    
    /* Results */
    host_discovery_result_t* host_results;
    uint32_t host_result_count;
    port_scan_result_t* port_results;
    uint32_t port_result_count;
    service_info_t* service_results;
    uint32_t service_result_count;
    os_detection_result_t* os_results;
    uint32_t os_result_count;
    vulnerability_scan_result_t* vulnerability_results;
    uint32_t vulnerability_result_count;
    
    /* Scanner specific data */
    void* private_data;
    uint32_t private_data_size;
    
    /* Linked list */
    struct scanner_tool* next;
} scanner_tool_t;

/* Scanner manager structure */
typedef struct {
    scanner_tool_t* scanners;
    uint32_t scanner_count;
    bool initialized;
    
    /* Configuration */
    uint32_t max_concurrent_scans;
    uint32_t default_timeout;
    uint32_t default_threads;
    uint32_t default_retries;
    uint8_t default_threat_level;
    bool stealth_mode;
    bool evasion_mode;
    bool logging_enabled;
    bool reporting_enabled;
    
    /* Statistics */
    scanner_statistics_t statistics;
    
    /* Security */
    uint8_t security_level;
    bool authentication_required;
    bool authorization_required;
    bool audit_enabled;
    
    /* Current scan */
    uint32_t current_scan_id;
    scanner_tool_t* current_scanner;
    
} scanner_manager_t;

/* Scanner functions */
void scanner_init(void);
void scanner_shutdown(void);
bool scanner_is_initialized(void);

/* Scanner tool management */
scanner_tool_t* scanner_create_tool(scanner_type_t scanner_type, const char* name, const char* description);
pentest_status_t scanner_destroy_tool(scanner_tool_t* scanner);
scanner_tool_t* scanner_get_tool(uint32_t scanner_id);
scanner_tool_t* scanner_get_tool_by_name(const char* name);
uint32_t scanner_get_tool_count(void);
pentest_status_t scanner_register_tool(scanner_tool_t* scanner);
pentest_status_t scanner_unregister_tool(uint32_t scanner_id);

/* Scanner operations */
pentest_status_t scanner_start_scan(scanner_tool_t* scanner, uint32_t target_ip);
pentest_status_t scanner_stop_scan(scanner_tool_t* scanner);
pentest_status_t scanner_pause_scan(scanner_tool_t* scanner);
pentest_status_t scanner_resume_scan(scanner_tool_t* scanner);
pentest_status_t scanner_configure_scanner(scanner_tool_t* scanner, scanner_config_t* config);

/* Port scanning */
pentest_status_t scanner_scan_ports(scanner_tool_t* scanner, uint32_t target_ip, uint16_t start_port, uint16_t end_port);
pentest_status_t scanner_scan_tcp_ports(scanner_tool_t* scanner, uint32_t target_ip, uint16_t start_port, uint16_t end_port);
pentest_status_t scanner_scan_udp_ports(scanner_tool_t* scanner, uint32_t target_ip, uint16_t start_port, uint16_t end_port);
pentest_status_t scanner_scan_service_versions(scanner_tool_t* scanner, uint32_t target_ip);

/* Host discovery */
pentest_status_t scanner_discover_hosts(scanner_tool_t* scanner, uint32_t network, uint32_t mask);
pentest_status_t scanner_ping_sweep(scanner_tool_t* scanner, uint32_t start_ip, uint32_t end_ip);
pentest_status_t scanner_arp_scan(scanner_tool_t* scanner, uint32_t network, uint32_t mask);

/* OS detection */
pentest_status_t scanner_detect_os(scanner_tool_t* scanner, uint32_t target_ip);
pentest_status_t scanner_fingerprint_os(scanner_tool_t* scanner, uint32_t target_ip);

/* Vulnerability scanning */
pentest_status_t scanner_scan_vulnerabilities(scanner_tool_t* scanner, uint32_t target_ip);
pentest_status_t scanner_check_vulnerabilities(scanner_tool_t* scanner, uint32_t target_ip, uint16_t port);
pentest_status_t scanner_exploit_check(scanner_tool_t* scanner, uint32_t target_ip, uint32_t vulnerability_id);

/* Service scanning */
pentest_status_t scanner_scan_services(scanner_tool_t* scanner, uint32_t target_ip);
pentest_status_t scanner_enumerate_services(scanner_tool_t* scanner, uint32_t target_ip);
pentest_status_t scanner_banner_grab(scanner_tool_t* scanner, uint32_t target_ip, uint16_t port);

/* Web scanning */
pentest_status_t scanner_scan_web(scanner_tool_t* scanner, uint32_t target_ip, uint16_t port);
pentest_status_t scanner_scan_ssl(scanner_tool_t* scanner, uint32_t target_ip, uint16_t port);
pentest_status_t scanner_scan_directories(scanner_tool_t* scanner, uint32_t target_ip, uint16_t port);

/* Configuration */
pentest_status_t scanner_set_stealth_mode(bool enable);
pentest_status_t scanner_set_evasion_mode(bool enable);
pentest_status_t scanner_set_scan_speed(scan_speed_t speed);
pentest_status_t scanner_set_scan_technique(scan_technique_t technique);
pentest_status_t scanner_configure_timeout(uint32_t timeout);
pentest_status_t scanner_configure_threads(uint32_t threads);
pentest_status_t scanner_configure_retries(uint32_t retries);
bool scanner_is_stealth_mode_enabled(void);
bool scanner_is_evasion_mode_enabled(void);
scan_speed_t scanner_get_scan_speed(void);
scan_technique_t scanner_get_scan_technique(void);

/* Results */
host_discovery_result_t* scanner_get_host_results(scanner_tool_t* scanner, uint32_t* count);
port_scan_result_t* scanner_get_port_results(scanner_tool_t* scanner, uint32_t* count);
service_info_t* scanner_get_service_results(scanner_tool_t* scanner, uint32_t* count);
os_detection_result_t* scanner_get_os_results(scanner_tool_t* scanner, uint32_t* count);
vulnerability_scan_result_t* scanner_get_vulnerability_results(scanner_tool_t* scanner, uint32_t* count);

/* Statistics */
void scanner_get_statistics(scanner_statistics_t* stats);
void scanner_get_tool_statistics(scanner_tool_t* scanner, scanner_statistics_t* stats);
void scanner_reset_statistics(void);
void scanner_reset_tool_statistics(scanner_tool_t* scanner);

/* Advanced features */
pentest_status_t scanner_start_automated_scan(scanner_tool_t* scanner, uint32_t target_ip);
pentest_status_t scanner_schedule_scan(scanner_tool_t* scanner, uint32_t target_ip, uint64_t schedule_time);
pentest_status_t scanner_monitor_target(scanner_tool_t* scanner, uint32_t target_ip);
pentest_status_t scanner_compare_results(scanner_tool_t* scanner1, scanner_tool_t* scanner2);
pentest_status_t scanner_export_results(scanner_tool_t* scanner, const char* filename);
pentest_status_t scanner_import_results(scanner_tool_t* scanner, const char* filename);

/* Global scanner manager */
extern scanner_manager_t* global_scanner_manager;

/* Scanner constants */
#define SCANNER_MAX_CONCURRENT_SCANS    8
#define SCANNER_DEFAULT_TIMEOUT         30000  /* 30 seconds */
#define SCANNER_DEFAULT_THREADS         4
#define SCANNER_DEFAULT_RETRIES         3
#define SCANNER_DEFAULT_DELAY           1000   /* 1 second */
#define SCANNER_DEFAULT_RATE_LIMIT      100    /* packets per second */

#define SCANNER_MAX_HOST_RESULTS        1024
#define SCANNER_MAX_PORT_RESULTS        65536
#define SCANNER_MAX_SERVICE_RESULTS     4096
#define SCANNER_MAX_OS_RESULTS          256
#define SCANNER_MAX_VULNERABILITY_RESULTS 2048

#define SCANNER_MIN_PORT                1
#define SCANNER_MAX_PORT                65535
#define SCANNER_WELL_KNOWN_PORTS_MAX    1024

/* Common port lists */
#define SCANNER_TOP_PORTS_1000          1000
#define SCANNER_TOP_PORTS_100             100
#define SCANNER_TOP_PORTS_10              10

/* Scanner flags */
#define SCANNER_FLAG_STEALTH            0x01
#define SCANNER_FLAG_EVASION            0x02
#define SCANNER_FLAG_RANDOMIZE          0x04
#define SCANNER_FLAG_FRAGMENT           0x08
#define SCANNER_FLAG_DECOY              0x10
#define SCANNER_FLAG_BADSUM             0x20
#define SCANNER_FLAG_URGENT             0x40
#define SCANNER_FLAG_PARANOIA           0x80

#endif /* SCANNER_H */