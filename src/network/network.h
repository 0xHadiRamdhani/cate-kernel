#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Ethernet definitions */
#define ETH_ADDR_LEN        6
#define ETH_TYPE_IP         0x0800
#define ETH_TYPE_ARP        0x0806
#define ETH_TYPE_IPV6       0x86DD
#define ETH_TYPE_VLAN       0x8100
#define ETH_HEADER_SIZE     14
#define ETH_MAX_PAYLOAD     1500
#define ETH_MIN_PAYLOAD     46
#define ETH_MAX_FRAME_SIZE  1518

/* IP definitions */
#define IP_VERSION_4        4
#define IP_VERSION_6        6
#define IP_HEADER_SIZE      20
#define IP_MAX_PACKET_SIZE  65535
#define IP_DEFAULT_TTL      64

/* Protocol numbers */
#define PROTOCOL_ICMP       1
#define PROTOCOL_TCP        6
#define PROTOCOL_UDP        17
#define PROTOCOL_ICMPV6      58

/* Port definitions */
#define PORT_MIN            1
#define PORT_MAX            65535
#define PORT_EPHEMERAL_MIN  49152
#define PORT_EPHEMERAL_MAX  65535

/* Well-known ports for pentesting */
#define PORT_HTTP           80
#define PORT_HTTPS          443
#define PORT_FTP            21
#define PORT_SSH            22
#define PORT_TELNET         23
#define PORT_SMTP           25
#define PORT_DNS            53
#define PORT_DHCP_SERVER    67
#define PORT_DHCP_CLIENT    68
#define PORT_HTTP_ALT       8080
#define PORT_HTTPS_ALT      8443
#define PORT_MYSQL          3306
#define PORT_POSTGRESQL     5432
#define PORT_REDIS          6379
#define PORT_MONGODB        27017

/* Network interface types */
typedef enum {
    NET_IF_TYPE_ETHERNET = 1,
    NET_IF_TYPE_WIFI = 2,
    NET_IF_TYPE_LOOPBACK = 3,
    NET_IF_TYPE_TUNNEL = 4,
    NET_IF_TYPE_VIRTUAL = 5
} net_interface_type_t;

/* Network interface states */
typedef enum {
    NET_IF_STATE_DOWN = 0,
    NET_IF_STATE_UP = 1,
    NET_IF_STATE_TESTING = 2,
    NET_IF_STATE_DORMANT = 3,
    NET_IF_STATE_UNKNOWN = 4
} net_interface_state_t;

/* Network packet types */
typedef enum {
    NET_PACKET_TYPE_UNKNOWN = 0,
    NET_PACKET_TYPE_ARP = 1,
    NET_PACKET_TYPE_IP = 2,
    NET_PACKET_TYPE_ICMP = 3,
    NET_PACKET_TYPE_TCP = 4,
    NET_PACKET_TYPE_UDP = 5,
    NET_PACKET_TYPE_RAW = 6
} net_packet_type_t;

/* Network status codes */
typedef enum {
    NET_STATUS_OK = 0,
    NET_STATUS_ERROR = -1,
    NET_STATUS_TIMEOUT = -2,
    NET_STATUS_INVALID_PARAM = -3,
    NET_STATUS_NO_MEMORY = -4,
    NET_STATUS_NOT_FOUND = -5,
    NET_STATUS_ACCESS_DENIED = -6,
    NET_STATUS_NETWORK_UNREACHABLE = -7,
    NET_STATUS_HOST_UNREACHABLE = -8,
    NET_STATUS_PORT_UNREACHABLE = -9,
    NET_STATUS_PROTOCOL_UNREACHABLE = -10,
    NET_STATUS_CONNECTION_REFUSED = -11,
    NET_STATUS_CONNECTION_RESET = -12,
    NET_STATUS_CONNECTION_CLOSED = -13,
    NET_STATUS_BUFFER_OVERFLOW = -14,
    NET_STATUS_CHECKSUM_ERROR = -15
} net_status_t;

/* Ethernet header */
typedef struct {
    uint8_t dest_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ethertype;
} __attribute__((packed)) eth_header_t;

/* IP header */
typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed)) ip_header_t;

/* TCP header */
typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed)) tcp_header_t;

/* UDP header */
typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) udp_header_t;

/* ICMP header */
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header;
} __attribute__((packed)) icmp_header_t;

/* ARP header */
typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation;
    uint8_t sender_mac[ETH_ADDR_LEN];
    uint32_t sender_ip;
    uint8_t target_mac[ETH_ADDR_LEN];
    uint32_t target_ip;
} __attribute__((packed)) arp_header_t;

/* Network packet structure */
typedef struct net_packet {
    uint8_t* data;
    uint32_t size;
    uint32_t max_size;
    uint32_t header_size;
    net_packet_type_t type;
    uint32_t interface_id;
    uint64_t timestamp;
    uint32_t flags;
    uint32_t checksum;
    uint8_t priority;
    uint8_t ttl;
    struct net_packet* next;
} net_packet_t;

/* Network interface structure */
typedef struct net_interface {
    uint32_t interface_id;
    char name[16];
    net_interface_type_t type;
    net_interface_state_t state;
    uint8_t mac_address[ETH_ADDR_LEN];
    uint32_t ip_address;
    uint32_t subnet_mask;
    uint32_t gateway;
    uint32_t mtu;
    uint32_t speed;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t rx_overruns;
    uint64_t tx_overruns;
    uint64_t collisions;
    uint32_t flags;
    
    /* Interface operations */
    net_status_t (*send)(struct net_interface* iface, net_packet_t* packet);
    net_status_t (*receive)(struct net_interface* iface, net_packet_t** packet);
    net_status_t (*configure)(struct net_interface* iface, uint32_t ip, uint32_t mask, uint32_t gateway);
    net_status_t (*up)(struct net_interface* iface);
    net_status_t (*down)(struct net_interface* iface);
    net_status_t (*reset)(struct net_interface* iface);
    
    /* Pentesting features */
    bool promiscuous_mode;
    bool monitor_mode;
    bool packet_injection;
    bool mac_spoofing;
    bool arp_spoofing;
    bool dhcp_spoofing;
    bool dns_spoofing;
    bool ssl_strip;
    bool packet_capture;
    bool traffic_analysis;
    bool intrusion_detection;
    bool firewall_enabled;
    
    /* Security features */
    bool encrypted;
    uint8_t encryption_key[32];
    uint8_t security_level;
    bool access_control;
    bool authentication_required;
    bool authorization_required;
    
    /* Statistics */
    uint32_t scan_packets_sent;
    uint32_t scan_packets_received;
    uint32_t exploit_packets_sent;
    uint32_t exploit_packets_received;
    uint32_t attack_packets_blocked;
    uint32_t suspicious_packets_detected;
    
    /* Linked list */
    struct net_interface* next;
} net_interface_t;

/* Network socket structure */
typedef struct net_socket {
    uint32_t socket_id;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t local_ip;
    uint32_t remote_ip;
    uint8_t protocol;
    uint8_t state;
    uint8_t flags;
    uint32_t send_buffer_size;
    uint32_t recv_buffer_size;
    uint8_t* send_buffer;
    uint8_t* recv_buffer;
    uint32_t send_head;
    uint32_t send_tail;
    uint32_t recv_head;
    uint32_t recv_tail;
    uint64_t timeout;
    uint32_t max_retries;
    uint32_t retry_count;
    
    /* Socket operations */
    net_status_t (*send)(struct net_socket* socket, const void* data, uint32_t size);
    net_status_t (*receive)(struct net_socket* socket, void* data, uint32_t size, uint32_t* received);
    net_status_t (*close)(struct net_socket* socket);
    net_status_t (*bind)(struct net_socket* socket, uint32_t ip, uint16_t port);
    net_status_t (*connect)(struct net_socket* socket, uint32_t ip, uint16_t port);
    net_status_t (*listen)(struct net_socket* socket, uint32_t backlog);
    net_status_t (*accept)(struct net_socket* socket, struct net_socket** new_socket);
    
    /* Pentesting features */
    bool stealth_mode;
    bool evasion_mode;
    bool fragmentation;
    bool decoy_mode;
    uint32_t decoy_ips[8];
    uint8_t decoy_count;
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t ttl;
    uint8_t tos;
    uint16_t window_size;
    uint8_t tcp_options[40];
    uint8_t tcp_options_len;
    
    /* Security features */
    bool encrypted;
    uint8_t session_key[32];
    uint8_t security_level;
    bool authenticated;
    bool authorized;
    
    /* Linked list */
    struct net_socket* next;
} net_socket_t;

/* Network connection structure */
typedef struct net_connection {
    uint32_t connection_id;
    net_socket_t* socket;
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t protocol;
    uint8_t state;
    uint64_t created_time;
    uint64_t last_activity;
    uint64_t timeout;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t flags;
    
    /* Connection state */
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint16_t window_size;
    uint8_t congestion_window;
    uint8_t slow_start_threshold;
    uint32_t round_trip_time;
    uint32_t round_trip_time_variance;
    uint32_t retransmission_timeout;
    
    /* Security */
    bool encrypted;
    uint8_t session_key[32];
    uint8_t security_level;
    
    /* Pentesting */
    bool scan_detected;
    bool attack_detected;
    bool intrusion_detected;
    uint32_t attack_count;
    uint32_t scan_count;
    
    /* Linked list */
    struct net_connection* next;
} net_connection_t;

/* Network manager structure */
typedef struct {
    net_interface_t* interfaces;
    net_socket_t* sockets;
    net_connection_t* connections;
    uint32_t interface_count;
    uint32_t socket_count;
    uint32_t connection_count;
    bool initialized;
    
    /* Statistics */
    uint64_t total_packets_sent;
    uint64_t total_packets_received;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    uint64_t total_errors;
    uint64_t total_dropped;
    
    /* Security */
    bool firewall_enabled;
    bool intrusion_detection_enabled;
    bool packet_filtering_enabled;
    bool rate_limiting_enabled;
    uint32_t max_packets_per_second;
    uint32_t security_level;
    
    /* Pentesting */
    bool pentest_mode;
    bool stealth_mode;
    bool evasion_mode;
    bool packet_capture_enabled;
    bool traffic_analysis_enabled;
    bool vulnerability_scanning_enabled;
    bool exploit_detection_enabled;
    
    /* Configuration */
    uint32_t default_ttl;
    uint32_t default_window_size;
    uint32_t default_timeout;
    uint32_t max_retransmissions;
    uint32_t buffer_size;
    
    /* Request queue */
    net_packet_t* packet_queue;
    uint32_t queue_size;
    uint32_t queue_head;
    uint32_t queue_tail;
    
} net_manager_t;

/* Network driver functions */
void network_init(void);
void network_shutdown(void);
bool network_is_initialized(void);

/* Interface management */
net_interface_t* network_create_interface(const char* name, net_interface_type_t type);
net_status_t network_destroy_interface(net_interface_t* interface);
net_interface_t* network_get_interface(uint32_t interface_id);
net_interface_t* network_get_interface_by_name(const char* name);
uint32_t network_get_interface_count(void);
net_status_t network_configure_interface(net_interface_t* interface, uint32_t ip, uint32_t mask, uint32_t gateway);
net_status_t network_enable_interface(net_interface_t* interface);
net_status_t network_disable_interface(net_interface_t* interface);

/* Socket management */
net_socket_t* network_create_socket(uint8_t protocol);
net_status_t network_destroy_socket(net_socket_t* socket);
net_socket_t* network_get_socket(uint32_t socket_id);
uint32_t network_get_socket_count(void);
net_status_t network_bind_socket(net_socket_t* socket, uint32_t ip, uint16_t port);
net_status_t network_connect_socket(net_socket_t* socket, uint32_t ip, uint16_t port);
net_status_t network_listen_socket(net_socket_t* socket, uint32_t backlog);
net_status_t network_accept_socket(net_socket_t* socket, net_socket_t** new_socket);
net_status_t network_close_socket(net_socket_t* socket);

/* Packet operations */
net_status_t network_send_packet(net_interface_t* interface, net_packet_t* packet);
net_status_t network_receive_packet(net_interface_t* interface, net_packet_t** packet);
net_status_t network_process_packet(net_packet_t* packet);
net_status_t network_forward_packet(net_packet_t* packet);
net_packet_t* network_create_packet(uint32_t size);
net_status_t network_destroy_packet(net_packet_t* packet);

/* Protocol handlers */
net_status_t network_handle_arp(net_packet_t* packet);
net_status_t network_handle_ip(net_packet_t* packet);
net_status_t network_handle_icmp(net_packet_t* packet);
net_status_t network_handle_tcp(net_packet_t* packet);
net_status_t network_handle_udp(net_packet_t* packet);

/* Pentesting functions */
net_status_t network_start_port_scan(uint32_t target_ip, uint16_t start_port, uint16_t end_port);
net_status_t network_stop_port_scan(void);
net_status_t network_start_vulnerability_scan(uint32_t target_ip);
net_status_t network_stop_vulnerability_scan(void);
net_status_t network_start_packet_capture(const char* filename);
net_status_t network_stop_packet_capture(void);
net_status_t network_start_traffic_analysis(void);
net_status_t network_stop_traffic_analysis(void);
net_status_t network_send_ping(uint32_t target_ip);
net_status_t network_send_tcp_syn(uint32_t target_ip, uint16_t port);
net_status_t network_send_tcp_fin(uint32_t target_ip, uint16_t port);
net_status_t network_send_tcp_xmas(uint32_t target_ip, uint16_t port);
net_status_t network_send_tcp_null(uint32_t target_ip, uint16_t port);
net_status_t network_send_udp_scan(uint32_t target_ip, uint16_t port);
net_status_t network_send_arp_scan(uint32_t target_ip);
net_status_t network_send_arp_spoof(uint32_t target_ip, uint32_t gateway_ip);
net_status_t network_send_dns_spoof(uint32_t target_ip, const char* domain, uint32_t fake_ip);

/* Security functions */
net_status_t network_enable_firewall(void);
net_status_t network_disable_firewall(void);
net_status_t network_enable_intrusion_detection(void);
net_status_t network_disable_intrusion_detection(void);
net_status_t network_enable_packet_filtering(void);
net_status_t network_disable_packet_filtering(void);
net_status_t network_enable_rate_limiting(uint32_t max_packets_per_second);
net_status_t network_disable_rate_limiting(void);
net_status_t network_add_firewall_rule(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port, uint8_t protocol, bool allow);
net_status_t network_remove_firewall_rule(uint32_t rule_id);
bool network_is_firewall_enabled(void);
bool network_is_intrusion_detection_enabled(void);

/* Utility functions */
uint16_t network_checksum(void* data, uint32_t size);
uint32_t network_ip_string_to_int(const char* ip_string);
void network_ip_int_to_string(uint32_t ip_int, char* ip_string);
bool network_is_private_ip(uint32_t ip);
bool network_is_loopback_ip(uint32_t ip);
bool network_is_broadcast_ip(uint32_t ip);
bool network_is_multicast_ip(uint32_t ip);
const char* network_get_status_string(net_status_t status);
const char* network_get_packet_type_string(net_packet_type_t type);

/* Statistics */
void network_get_statistics(uint64_t* packets_sent, uint64_t* packets_received, uint64_t* bytes_sent, uint64_t* bytes_received);
void network_get_interface_statistics(net_interface_t* interface, uint64_t* rx_packets, uint64_t* tx_packets, uint64_t* rx_bytes, uint64_t* tx_bytes);
void network_reset_statistics(void);
void network_reset_interface_statistics(net_interface_t* interface);

/* Advanced features */
net_status_t network_queue_packet(net_packet_t* packet);
net_status_t network_process_queue(void);
net_status_t network_set_promiscuous_mode(net_interface_t* interface, bool enable);
net_status_t network_set_monitor_mode(net_interface_t* interface, bool enable);
net_status_t network_enable_packet_injection(net_interface_t* interface);
net_status_t network_disable_packet_injection(net_interface_t* interface);

/* Global network manager */
extern net_manager_t* global_network_manager;

/* Pentesting specific definitions */
#define NET_SCAN_TYPE_TCP_SYN       1
#define NET_SCAN_TYPE_TCP_FIN       2
#define NET_SCAN_TYPE_TCP_XMAS      3
#define NET_SCAN_TYPE_TCP_NULL      4
#define NET_SCAN_TYPE_UDP           5
#define NET_SCAN_TYPE_ACK           6
#define NET_SCAN_TYPE_WINDOW        7
#define NET_SCAN_TYPE_MAIMON        8

#define NET_ATTACK_TYPE_DOS         1
#define NET_ATTACK_TYPE_DDOS        2
#define NET_ATTACK_TYPE_MITM        3
#define NET_ATTACK_TYPE_SPOOFING    4
#define NET_ATTACK_TYPE_SCANNING    5
#define NET_ATTACK_TYPE_EXPLOIT     6

#define NET_SECURITY_LEVEL_LOW      1
#define NET_SECURITY_LEVEL_MEDIUM   2
#define NET_SECURITY_LEVEL_HIGH     3
#define NET_SECURITY_LEVEL_MAXIMUM  4

/* Network buffer sizes */
#define NET_BUFFER_SIZE         65536
#define NET_MAX_PACKET_SIZE     65535
#define NET_DEFAULT_MTU         1500
#define NET_DEFAULT_TTL         64
#define NET_DEFAULT_WINDOW_SIZE 8192

/* Pentesting buffer sizes */
#define NET_CAPTURE_BUFFER_SIZE 1048576  /* 1MB */
#define NET_SCAN_BUFFER_SIZE    65536
#define NET_ATTACK_BUFFER_SIZE  65536

#endif /* NETWORK_H */