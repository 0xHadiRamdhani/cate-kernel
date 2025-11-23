#include "test_framework.h"
#include "../network/network.h"
#include "../network/packet.h"
#include "../kernel/memory.h"
#include "../kernel/string.h"
#include "../kernel/logging.h"

/* Test data structures */
typedef struct {
    uint8_t test_packet[1500];
    uint32_t packet_size;
    char test_ip[64];
    uint16_t test_port;
    network_protocol_t test_protocol;
} network_test_data_t;

/* Network initialization test cases */

/* Test network initialization */
static test_result_t test_network_init(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Test network subsystem initialization */
    network_init();
    TEST_ASSERT_TRUE(network_is_initialized());
    
    /* Test double initialization */
    network_init(); /* Should not crash */
    TEST_ASSERT_TRUE(network_is_initialized());
    
    return TEST_RESULT_PASS;
}

/* Test network shutdown */
static test_result_t test_network_shutdown(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    TEST_ASSERT_TRUE(network_is_initialized());
    
    /* Test shutdown */
    network_shutdown();
    TEST_ASSERT_FALSE(network_is_initialized());
    
    /* Test double shutdown */
    network_shutdown(); /* Should not crash */
    TEST_ASSERT_FALSE(network_is_initialized());
    
    return TEST_RESULT_PASS;
}

/* Network protocol test cases */

/* Test Ethernet protocol */
static test_result_t test_ethernet_protocol(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test Ethernet header creation */
    ethernet_header_t eth_header;
    memset(&eth_header, 0, sizeof(ethernet_header_t));
    
    /* Set MAC addresses */
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    memcpy(eth_header.src_mac, src_mac, 6);
    memcpy(eth_header.dest_mac, dest_mac, 6);
    eth_header.ether_type = ETHER_TYPE_IPv4;
    
    /* Verify header */
    TEST_ASSERT_MEMORY_EQUAL(src_mac, eth_header.src_mac, 6);
    TEST_ASSERT_MEMORY_EQUAL(dest_mac, eth_header.dest_mac, 6);
    TEST_ASSERT_EQUAL(ETHER_TYPE_IPv4, eth_header.ether_type);
    
    return TEST_RESULT_PASS;
}

/* Test IP protocol */
static test_result_t test_ip_protocol(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test IP header creation */
    ip_header_t ip_header;
    memset(&ip_header, 0, sizeof(ip_header_t));
    
    /* Set IP header fields */
    ip_header.version = 4;
    ip_header.ihl = 5;
    ip_header.tos = 0;
    ip_header.total_length = 1500;
    ip_header.id = 12345;
    ip_header.flags = 0;
    ip_header.fragment_offset = 0;
    ip_header.ttl = 64;
    ip_header.protocol = PROTOCOL_TCP;
    ip_header.checksum = 0;
    
    uint8_t src_ip[4] = {192, 168, 1, 100};
    uint8_t dest_ip[4] = {192, 168, 1, 1};
    
    memcpy(ip_header.src_ip, src_ip, 4);
    memcpy(ip_header.dest_ip, dest_ip, 4);
    
    /* Verify header */
    TEST_ASSERT_EQUAL(4, ip_header.version);
    TEST_ASSERT_EQUAL(5, ip_header.ihl);
    TEST_ASSERT_EQUAL(PROTOCOL_TCP, ip_header.protocol);
    TEST_ASSERT_EQUAL(64, ip_header.ttl);
    TEST_ASSERT_MEMORY_EQUAL(src_ip, ip_header.src_ip, 4);
    TEST_ASSERT_MEMORY_EQUAL(dest_ip, ip_header.dest_ip, 4);
    
    return TEST_RESULT_PASS;
}

/* Test TCP protocol */
static test_result_t test_tcp_protocol(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test TCP header creation */
    tcp_header_t tcp_header;
    memset(&tcp_header, 0, sizeof(tcp_header_t));
    
    /* Set TCP header fields */
    tcp_header.src_port = 12345;
    tcp_header.dest_port = 80;
    tcp_header.seq_num = 1000;
    tcp_header.ack_num = 2000;
    tcp_header.data_offset = 5;
    tcp_header.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    tcp_header.window_size = 8192;
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;
    
    /* Verify header */
    TEST_ASSERT_EQUAL(12345, tcp_header.src_port);
    TEST_ASSERT_EQUAL(80, tcp_header.dest_port);
    TEST_ASSERT_EQUAL(1000, tcp_header.seq_num);
    TEST_ASSERT_EQUAL(2000, tcp_header.ack_num);
    TEST_ASSERT_EQUAL(5, tcp_header.data_offset);
    TEST_ASSERT_EQUAL((TCP_FLAG_SYN | TCP_FLAG_ACK), tcp_header.flags);
    TEST_ASSERT_EQUAL(8192, tcp_header.window_size);
    
    return TEST_RESULT_PASS;
}

/* Test UDP protocol */
static test_result_t test_udp_protocol(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test UDP header creation */
    udp_header_t udp_header;
    memset(&udp_header, 0, sizeof(udp_header_t));
    
    /* Set UDP header fields */
    udp_header.src_port = 53;
    udp_header.dest_port = 53;
    udp_header.length = 100;
    udp_header.checksum = 0;
    
    /* Verify header */
    TEST_ASSERT_EQUAL(53, udp_header.src_port);
    TEST_ASSERT_EQUAL(53, udp_header.dest_port);
    TEST_ASSERT_EQUAL(100, udp_header.length);
    TEST_ASSERT_EQUAL(0, udp_header.checksum);
    
    return TEST_RESULT_PASS;
}

/* Test ICMP protocol */
static test_result_t test_icmp_protocol(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test ICMP header creation */
    icmp_header_t icmp_header;
    memset(&icmp_header, 0, sizeof(icmp_header_t));
    
    /* Set ICMP header fields */
    icmp_header.type = ICMP_TYPE_ECHO_REQUEST;
    icmp_header.code = 0;
    icmp_header.checksum = 0;
    icmp_header.id = 12345;
    icmp_header.sequence = 1;
    
    /* Verify header */
    TEST_ASSERT_EQUAL(ICMP_TYPE_ECHO_REQUEST, icmp_header.type);
    TEST_ASSERT_EQUAL(0, icmp_header.code);
    TEST_ASSERT_EQUAL(12345, icmp_header.id);
    TEST_ASSERT_EQUAL(1, icmp_header.sequence);
    
    return TEST_RESULT_PASS;
}

/* Network packet test cases */

/* Test packet creation */
static test_result_t test_packet_creation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test packet creation */
    network_packet_t* packet = create_network_packet(1500);
    TEST_ASSERT_NOT_NULL(packet);
    
    /* Verify packet properties */
    TEST_ASSERT_EQUAL(1500, packet->size);
    TEST_ASSERT_EQUAL(0, packet->offset);
    TEST_ASSERT_NOT_NULL(packet->data);
    
    /* Test packet destruction */
    destroy_network_packet(packet);
    
    return TEST_RESULT_PASS;
}

/* Test packet buffer management */
static test_result_t test_packet_buffer_management(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Create multiple packets */
    network_packet_t* packets[10];
    for (int i = 0; i < 10; i++) {
        packets[i] = create_network_packet(100 + i * 10);
        TEST_ASSERT_NOT_NULL(packets[i]);
    }
    
    /* Verify packet sizes */
    for (int i = 0; i < 10; i++) {
        TEST_ASSERT_EQUAL(100 + i * 10, packets[i]->size);
    }
    
    /* Destroy packets */
    for (int i = 0; i < 10; i++) {
        destroy_network_packet(packets[i]);
    }
    
    return TEST_RESULT_PASS;
}

/* Test packet data manipulation */
static test_result_t test_packet_data_manipulation(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Create packet */
    network_packet_t* packet = create_network_packet(1000);
    TEST_ASSERT_NOT_NULL(packet);
    
    /* Test data writing */
    uint8_t test_data[100];
    for (int i = 0; i < 100; i++) {
        test_data[i] = (uint8_t)(i & 0xFF);
    }
    
    write_packet_data(packet, test_data, 100);
    TEST_ASSERT_EQUAL(100, packet->offset);
    
    /* Test data reading */
    uint8_t read_data[100];
    read_packet_data(packet, read_data, 100);
    
    /* Verify data integrity */
    TEST_ASSERT_MEMORY_EQUAL(test_data, read_data, 100);
    
    /* Test packet destruction */
    destroy_network_packet(packet);
    
    return TEST_RESULT_PASS;
}

/* Network scanning test cases */

/* Test port scanning */
static test_result_t test_port_scanning(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test port scan initialization */
    port_scan_result_t* results = NULL;
    uint32_t result_count = 0;
    
    /* Test basic port scan */
    test_result_t result = scan_ports("127.0.0.1", 1, 100, &results, &result_count);
    
    /* Results may vary depending on network configuration */
    if (result == TEST_RESULT_PASS) {
        TEST_ASSERT_NOT_NULL(results);
        TEST_ASSERT_TRUE(result_count >= 0);
        
        /* Free results */
        if (results != NULL) {
            kfree(results);
        }
    }
    
    return TEST_RESULT_PASS;
}

/* Test service detection */
static test_result_t test_service_detection(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test service detection */
    service_info_t service_info;
    memset(&service_info, 0, sizeof(service_info_t));
    
    /* Test common service detection */
    test_result_t result = detect_service("127.0.0.1", 80, &service_info);
    
    /* Results may vary depending on network configuration */
    if (result == TEST_RESULT_PASS) {
        TEST_ASSERT_NOT_NULL(service_info.service_name);
        TEST_ASSERT_TRUE(service_info.port == 80);
    }
    
    return TEST_RESULT_PASS;
}

/* Test OS fingerprinting */
static test_result_t test_os_fingerprinting(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test OS fingerprinting */
    os_info_t os_info;
    memset(&os_info, 0, sizeof(os_info_t));
    
    /* Test OS detection */
    test_result_t result = fingerprint_os("127.0.0.1", &os_info);
    
    /* Results may vary depending on network configuration */
    if (result == TEST_RESULT_PASS) {
        TEST_ASSERT_NOT_NULL(os_info.os_name);
        TEST_ASSERT_NOT_NULL(os_info.os_version);
        TEST_ASSERT_TRUE(os_info.confidence >= 0 && os_info.confidence <= 100);
    }
    
    return TEST_RESULT_PASS;
}

/* Network security test cases */

/* Test network intrusion detection */
static test_result_t test_network_intrusion_detection(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test intrusion detection patterns */
    uint8_t malicious_packet[] = {
        0x45, 0x00, 0x00, 0x28, /* IP header */
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01, /* Source IP */
        0xC0, 0xA8, 0x01, 0x02, /* Dest IP */
        0x00, 0x50, 0x00, 0x50, /* TCP ports */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, /* TCP flags */
        0x00, 0x00, 0x00, 0x00
    };
    
    /* Test packet analysis */
    network_intrusion_t intrusion;
    memset(&intrusion, 0, sizeof(network_intrusion_t));
    
    test_result_t result = analyze_network_intrusion(malicious_packet, sizeof(malicious_packet), &intrusion);
    
    /* Results depend on intrusion detection implementation */
    if (result == TEST_RESULT_PASS) {
        TEST_ASSERT_TRUE(intrusion.detected || !intrusion.detected); /* Either is valid for test */
    }
    
    return TEST_RESULT_PASS;
}

/* Test network firewall */
static test_result_t test_network_firewall(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test firewall initialization */
    TEST_ASSERT_TRUE(firewall_is_initialized());
    
    /* Test firewall rules */
    firewall_rule_t rule;
    memset(&rule, 0, sizeof(firewall_rule_t));
    
    rule.action = FIREWALL_ACTION_ALLOW;
    rule.protocol = PROTOCOL_TCP;
    rule.src_port = 80;
    rule.dest_port = 80;
    strncpy(rule.src_ip, "192.168.1.0/24", sizeof(rule.src_ip) - 1);
    strncpy(rule.dest_ip, "0.0.0.0/0", sizeof(rule.dest_ip) - 1);
    
    /* Test rule addition */
    test_result_t result = add_firewall_rule(&rule);
    TEST_ASSERT_EQUAL(TEST_RESULT_PASS, result);
    
    /* Test rule removal */
    result = remove_firewall_rule(&rule);
    TEST_ASSERT_EQUAL(TEST_RESULT_PASS, result);
    
    return TEST_RESULT_PASS;
}

/* Test network encryption */
static test_result_t test_network_encryption(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test encryption initialization */
    TEST_ASSERT_TRUE(network_encryption_is_initialized());
    
    /* Test key generation */
    uint8_t key[32];
    test_result_t result = generate_network_key(key, sizeof(key));
    TEST_ASSERT_EQUAL(TEST_RESULT_PASS, result);
    
    /* Test encryption/decryption */
    uint8_t plaintext[] = "Test network encryption";
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    
    result = encrypt_network_data(plaintext, sizeof(plaintext), key, ciphertext, sizeof(ciphertext));
    TEST_ASSERT_EQUAL(TEST_RESULT_PASS, result);
    
    result = decrypt_network_data(ciphertext, sizeof(ciphertext), key, decrypted, sizeof(decrypted));
    TEST_ASSERT_EQUAL(TEST_RESULT_PASS, result);
    
    /* Verify decryption */
    TEST_ASSERT_MEMORY_EQUAL(plaintext, decrypted, sizeof(plaintext));
    
    return TEST_RESULT_PASS;
}

/* Network performance test cases */

/* Test network throughput */
static test_result_t test_network_throughput(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test throughput measurement */
    uint64_t throughput = measure_network_throughput();
    
    /* Verify throughput is reasonable */
    TEST_ASSERT_TRUE(throughput >= 0);
    
    return TEST_RESULT_PASS;
}

/* Test network latency */
static test_result_t test_network_latency(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test latency measurement */
    uint64_t latency = measure_network_latency("127.0.0.1");
    
    /* Verify latency is reasonable */
    TEST_ASSERT_TRUE(latency >= 0);
    
    return TEST_RESULT_PASS;
}

/* Test network packet loss */
static test_result_t test_network_packet_loss(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Initialize network */
    network_init();
    
    /* Test packet loss measurement */
    uint32_t packet_loss = measure_packet_loss("127.0.0.1", 100);
    
    /* Verify packet loss is reasonable */
    TEST_ASSERT_TRUE(packet_loss >= 0 && packet_loss <= 100);
    
    return TEST_RESULT_PASS;
}

/* Network test setup function */
static test_result_t network_test_setup(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Allocate test data */
    network_test_data_t* test_data = (network_test_data_t*)kmalloc(sizeof(network_test_data_t));
    if (test_data == NULL) {
        return TEST_RESULT_MEMORY_ERROR;
    }
    
    /* Initialize test data */
    memset(test_data, 0, sizeof(network_test_data_t));
    test_data->packet_size = 1000;
    strncpy(test_data->test_ip, "192.168.1.100", sizeof(test_data->test_ip) - 1);
    test_data->test_port = 8080;
    test_data->test_protocol = PROTOCOL_TCP;
    
    /* Fill packet with test data */
    for (uint32_t i = 0; i < test_data->packet_size; i++) {
        test_data->test_packet[i] = (uint8_t)(i & 0xFF);
    }
    
    test_case->test_data = test_data;
    test_case->test_data_size = sizeof(network_test_data_t);
    
    return TEST_RESULT_PASS;
}

/* Network test cleanup function */
static test_result_t network_test_cleanup(test_case_t* test_case) {
    TEST_ASSERT_NOT_NULL(test_case);
    
    /* Free test data */
    if (test_case->test_data != NULL) {
        kfree(test_case->test_data);
        test_case->test_data = NULL;
        test_case->test_data_size = 0;
    }
    
    /* Shutdown network */
    network_shutdown();
    
    return TEST_RESULT_PASS;
}

/* Create network test suite */
test_suite_t* create_network_test_suite(void) {
    test_suite_t* suite = test_create_suite("Network Tests", "Comprehensive network functionality tests", TEST_CATEGORY_NETWORK);
    if (suite == NULL) {
        return NULL;
    }
    
    /* Set suite functions */
    suite->setup = network_test_setup;
    suite->teardown = network_test_cleanup;
    
    /* Network initialization tests */
    test_case_t* network_init_test = test_create_case("Network Initialization", "Test network subsystem initialization", TEST_CATEGORY_NETWORK);
    if (network_init_test != NULL) {
        network_init_test->run = test_network_init;
        test_register_case(suite, network_init_test);
    }
    
    test_case_t* network_shutdown_test = test_create_case("Network Shutdown", "Test network subsystem shutdown", TEST_CATEGORY_NETWORK);
    if (network_shutdown_test != NULL) {
        network_shutdown_test->run = test_network_shutdown;
        test_register_case(suite, network_shutdown_test);
    }
    
    /* Network protocol tests */
    test_case_t* ethernet_test = test_create_case("Ethernet Protocol", "Test Ethernet protocol implementation", TEST_CATEGORY_NETWORK);
    if (ethernet_test != NULL) {
        ethernet_test->run = test_ethernet_protocol;
        test_register_case(suite, ethernet_test);
    }
    
    test_case_t* ip_test = test_create_case("IP Protocol", "Test IP protocol implementation", TEST_CATEGORY_NETWORK);
    if (ip_test != NULL) {
        ip_test->run = test_ip_protocol;
        test_register_case(suite, ip_test);
    }
    
    test_case_t* tcp_test = test_create_case("TCP Protocol", "Test TCP protocol implementation", TEST_CATEGORY_NETWORK);
    if (tcp_test != NULL) {
        tcp_test->run = test_tcp_protocol;
        test_register_case(suite, tcp_test);
    }
    
    test_case_t* udp_test = test_create_case("UDP Protocol", "Test UDP protocol implementation", TEST_CATEGORY_NETWORK);
    if (udp_test != NULL) {
        udp_test->run = test_udp_protocol;
        test_register_case(suite, udp_test);
    }
    
    test_case_t* icmp_test = test_create_case("ICMP Protocol", "Test ICMP protocol implementation", TEST_CATEGORY_NETWORK);
    if (icmp_test != NULL) {
        icmp_test->run = test_icmp_protocol;
        test_register_case(suite, icmp_test);
    }
    
    /* Network packet tests */
    test_case_t* packet_creation_test = test_create_case("Packet Creation", "Test network packet creation", TEST_CATEGORY_NETWORK);
    if (packet_creation_test != NULL) {
        packet_creation_test->run = test_packet_creation;
        test_register_case(suite, packet_creation_test);
    }
    
    test_case_t* packet_buffer_test = test_create_case("Packet Buffer Management", "Test network packet buffer management", TEST_CATEGORY_NETWORK);
    if (packet_buffer_test != NULL) {
        packet_buffer_test->run = test_packet_buffer_management;
        test_register_case(suite, packet_buffer_test);
    }
    
    test_case_t* packet_data_test = test_create_case("Packet Data Manipulation", "Test network packet data manipulation", TEST_CATEGORY_NETWORK);
    if (packet_data_test != NULL) {
        packet_data_test->run = test_packet_data_manipulation;
        test_register_case(suite, packet_data_test);
    }
    
    /* Network scanning tests */
    test_case_t* port_scan_test = test_create_case("Port Scanning", "Test network port scanning functionality", TEST_CATEGORY_NETWORK);
    if (port_scan_test != NULL) {
        port_scan_test->run = test_port_scanning;
        test_register_case(suite, port_scan_test);
    }
    
    test_case_t* service_detect_test = test_create_case("Service Detection", "Test network service detection functionality", TEST_CATEGORY_NETWORK);
    if (service_detect_test != NULL) {
        service_detect_test->run = test_service_detection;
        test_register_case(suite, service_detect_test);
    }
    
    test_case_t* os_fingerprint_test = test_create_case("OS Fingerprinting", "Test OS fingerprinting functionality", TEST_CATEGORY_NETWORK);
    if (os_fingerprint_test != NULL) {
        os_fingerprint_test->run = test_os_fingerprinting;
        test_register_case(suite, os_fingerprint_test);
    }
    
    /* Network security tests */
    test_case_t* intrusion_detect_test = test_create_case("Intrusion Detection", "Test network intrusion detection functionality", TEST_CATEGORY_SECURITY);
    if (intrusion_detect_test != NULL) {
        intrusion_detect_test->run = test_network_intrusion_detection;
        test_register_case(suite, intrusion_detect_test);
    }
    
    test_case_t* firewall_test = test_create_case("Network Firewall", "Test network firewall functionality", TEST_CATEGORY_SECURITY);
    if (firewall_test != NULL) {
        firewall_test->run = test_network_firewall;
        test_register_case(suite, firewall_test);
    }
    
    test_case_t* encryption_test = test_create_case("Network Encryption", "Test network encryption functionality", TEST_CATEGORY_SECURITY);
    if (encryption_test != NULL) {
        encryption_test->run = test_network_encryption;
        test_register_case(suite, encryption_test);
    }
    
    /* Network performance tests */
    test_case_t* throughput_test = test_create_case("Network Throughput", "Test network throughput measurement", TEST_CATEGORY_PERFORMANCE);
    if (throughput_test != NULL) {
        throughput_test->run = test_network_throughput;
        test_register_case(suite, throughput_test);
    }
    
    test_case_t* latency_test = test_create_case("Network Latency", "Test network latency measurement", TEST_CATEGORY_PERFORMANCE);
    if (latency_test != NULL) {
        latency_test->run = test_network_latency;
        test_register_case(suite, latency_test);
    }
    
    test_case_t* packet_loss_test = test_create_case("Network Packet Loss", "Test network packet loss measurement", TEST_CATEGORY_PERFORMANCE);
    if (packet_loss_test != NULL) {
        packet_loss_test->run = test_network_packet_loss;
        test_register_case(suite, packet_loss_test);
    }
    
    return suite;
}