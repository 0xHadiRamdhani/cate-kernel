#include "multiboot2.h"
#include <stdint.h>
#include <stddef.h>

/* EFI system table signatures */
#define EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249ULL  /* "IBI SYST" */
#define EFI_RUNTIME_SERVICES_SIGNATURE 0x54534E52454D5558ULL  /* "XUMER NST" */
#define EFI_BOOT_SERVICES_SIGNATURE 0x5453595320746F4FULL  /* "LOT SYST" */

/* EFI memory types */
#define EFI_RESERVED_TYPE                0
#define EFI_LOADER_CODE                  1
#define EFI_LOADER_DATA                  2
#define EFI_BOOT_SERVICES_CODE           3
#define EFI_BOOT_SERVICES_DATA           4
#define EFI_RUNTIME_SERVICES_CODE        5
#define EFI_RUNTIME_SERVICES_DATA        6
#define EFI_CONVENTIONAL_MEMORY          7
#define EFI_UNUSABLE_MEMORY              8
#define EFI_ACPI_RECLAIM_MEMORY          9
#define EFI_ACPI_MEMORY_NVS               10
#define EFI_MEMORY_MAPPED_IO              11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE   12
#define EFI_PAL_CODE                      13
#define EFI_PERSISTENT_MEMORY              14

/* EFI memory descriptor */
typedef struct {
    uint32_t type;
    uint32_t physical_start;
    uint32_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} __attribute__((packed)) efi_memory_descriptor_32_t;

typedef struct {
    uint32_t type;
    uint32_t physical_start;
    uint32_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} __attribute__((packed)) efi_memory_descriptor_t;

/* EFI table headers */
typedef struct {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} __attribute__((packed)) efi_table_header_t;

/* EFI runtime services */
typedef struct {
    efi_table_header_t header;
    uint64_t get_time;
    uint64_t set_time;
    uint64_t get_wakeup_time;
    uint64_t set_wakeup_time;
    uint64_t set_virtual_address_map;
    uint64_t convert_pointer;
    uint64_t get_variable;
    uint64_t get_next_variable_name;
    uint64_t set_variable;
    uint64_t get_next_high_monotonic_count;
    uint64_t reset_system;
    uint64_t update_capsule;
    uint64_t query_capsule_capabilities;
    uint64_t query_variable_info;
} __attribute__((packed)) efi_runtime_services_t;

/* EFI boot services */
typedef struct {
    efi_table_header_t header;
    uint64_t raise_tpl;
    uint64_t restore_tpl;
    uint64_t allocate_pages;
    uint64_t free_pages;
    uint64_t get_memory_map;
    uint64_t allocate_pool;
    uint64_t free_pool;
    uint64_t create_event;
    uint64_t set_timer;
    uint64_t wait_for_event;
    uint64_t signal_event;
    uint64_t close_event;
    uint64_t check_event;
    uint64_t install_protocol_interface;
    uint64_t reinstall_protocol_interface;
    uint64_t uninstall_protocol_interface;
    uint64_t handle_protocol;
    uint64_t register_protocol_notify;
    uint64_t locate_handle;
    uint64_t locate_device_path;
    uint64_t install_configuration_table;
    uint64_t load_image;
    uint64_t start_image;
    uint64_t exit;
    uint64_t unload_image;
    uint64_t exit_boot_services;
    uint64_t get_next_monotonic_count;
    uint64_t stall;
    uint64_t set_watchdog_timer;
    uint64_t connect_controller;
    uint64_t disconnect_controller;
    uint64_t open_protocol;
    uint64_t close_protocol;
    uint64_t open_protocol_information;
    uint64_t protocols_per_handle;
    uint64_t locate_handle_buffer;
    uint64_t locate_protocol;
    uint64_t install_multiple_protocol_interfaces;
    uint64_t uninstall_multiple_protocol_interfaces;
    uint64_t calculate_crc32;
    uint64_t copy_mem;
    uint64_t set_mem;
    uint64_t create_event_ex;
} __attribute__((packed)) efi_boot_services_t;

/* EFI system table */
typedef struct {
    efi_table_header_t header;
    uint32_t firmware_vendor;
    uint32_t firmware_revision;
    uint32_t console_in_handle;
    uint32_t con_in;
    uint32_t console_out_handle;
    uint32_t con_out;
    uint32_t standard_error_handle;
    uint32_t std_err;
    uint32_t runtime_services;
    uint32_t boot_services;
    uint32_t number_of_table_entries;
    uint32_t configuration_table;
} __attribute__((packed)) efi_system_table_32_t;

typedef struct {
    efi_table_header_t header;
    uint64_t firmware_vendor;
    uint32_t firmware_revision;
    uint32_t console_in_handle;
    uint64_t con_in;
    uint32_t console_out_handle;
    uint64_t con_out;
    uint32_t standard_error_handle;
    uint64_t std_err;
    uint64_t runtime_services;
    uint64_t boot_services;
    uint64_t number_of_table_entries;
    uint64_t configuration_table;
} __attribute__((packed)) efi_system_table_64_t;

/* EFI configuration table entry */
typedef struct {
    uint64_t vendor_guid;
    uint64_t vendor_table;
} __attribute__((packed)) efi_configuration_table_t;

/* Global EFI context */
static struct {
    efi_system_table_64_t* system_table;
    efi_runtime_services_t* runtime_services;
    efi_boot_services_t* boot_services;
    efi_configuration_table_t* config_table;
    uint64_t memory_map;
    uint64_t memory_map_size;
    uint64_t memory_map_descriptor_size;
    uint32_t memory_map_descriptor_version;
    uint8_t efi_enabled;
    uint8_t efi_64bit;
} efi_ctx;

/* Function prototypes */
int efi_init(void* system_table);
int efi_validate_system_table(efi_system_table_64_t* table);
int efi_parse_memory_map(void);
int efi_exit_boot_services(void);
int efi_set_virtual_address_map(void);
void efi_print_info(void);
void efi_get_memory_map(void);
void efi_dump_memory_map(void);
int efi_allocate_pages(uint32_t type, uint32_t memory_type, uint64_t pages, uint64_t* memory);
int efi_free_pages(uint64_t memory, uint64_t pages);
int efi_get_variable(uint16_t* variable_name, uint64_t* vendor_guid, uint32_t* attributes, 
                      uint64_t* data_size, void* data);
int efi_set_variable(uint16_t* variable_name, uint64_t* vendor_guid, uint32_t attributes,
                     uint64_t data_size, void* data);
void efi_reset_system(uint32_t reset_type, uint64_t status, uint64_t data_size, void* reset_data);

/* Initialize EFI subsystem */
int efi_init(void* system_table) {
    if (!system_table) return -1;

    efi_ctx.system_table = (efi_system_table_64_t*)system_table;

    /* Validate system table */
    if (efi_validate_system_table(efi_ctx.system_table) != 0) {
        return -1;
    }

    /* Get runtime services */
    efi_ctx.runtime_services = (efi_runtime_services_t*)efi_ctx.system_table->runtime_services;
    if (!efi_ctx.runtime_services) return -1;

    /* Get boot services */
    efi_ctx.boot_services = (efi_boot_services_t*)efi_ctx.system_table->boot_services;
    if (!efi_ctx.boot_services) return -1;

    /* Get configuration table */
    efi_ctx.config_table = (efi_configuration_table_t*)efi_ctx.system_table->configuration_table;
    if (!efi_ctx.config_table) return -1;

    /* Parse memory map */
    if (efi_parse_memory_map() != 0) {
        return -1;
    }

    /* Print EFI information */
    efi_print_info();

    efi_ctx.efi_enabled = 1;
    efi_ctx.efi_64bit = 1;

    return 0;
}

/* Validate EFI system table */
int efi_validate_system_table(efi_system_table_64_t* table) {
    if (!table) return -1;

    /* Check signature */
    if (table->header.signature != EFI_SYSTEM_TABLE_SIGNATURE) {
        return -1;
    }

    /* Check revision */
    if (table->header.revision < 0x00010000) {
        return -1;
    }

    /* Validate header size */
    if (table->header.header_size < sizeof(efi_table_header_t)) {
        return -1;
    }

    /* Validate CRC32 */
    uint32_t original_crc = table->header.crc32;
    table->header.crc32 = 0;

    /* Calculate CRC32 */
    uint32_t calculated_crc = 0;
    uint8_t* ptr = (uint8_t*)table;
    for (uint32_t i = 0; i < table->header.header_size; i++) {
        calculated_crc ^= ptr[i];
        for (int j = 0; j < 8; j++) {
            if (calculated_crc & 1) {
                calculated_crc = (calculated_crc >> 1) ^ 0xEDB88320;
            } else {
                calculated_crc >>= 1;
            }
        }
    }

    table->header.crc32 = original_crc;

    if (calculated_crc != original_crc) {
        return -1;
    }

    return 0;
}

/* Parse EFI memory map */
int efi_parse_memory_map(void) {
    if (!efi_ctx.boot_services) return -1;

    /* Get memory map size */
    uint64_t memory_map_size = 0;
    uint64_t map_key = 0;
    uint64_t descriptor_size = 0;
    uint32_t descriptor_version = 0;

    /* First call to get size */
    typedef int (*efi_get_memory_map_t)(uint64_t*, void*, uint64_t*, uint64_t*, uint32_t*);
    efi_get_memory_map_t get_memory_map = (efi_get_memory_map_t)efi_ctx.boot_services->get_memory_map;

    /* Allocate buffer for memory map */
    memory_map_size = 4096 * 4; /* 16KB should be enough */
    efi_ctx.memory_map = 0x1000000; /* Allocate at 16MB */
    efi_ctx.memory_map_size = memory_map_size;

    /* Get memory map */
    int status = get_memory_map(&memory_map_size, (void*)efi_ctx.memory_map, 
                                 &map_key, &descriptor_size, &descriptor_version);

    if (status != 0) {
        return -1;
    }

    efi_ctx.memory_map_descriptor_size = descriptor_size;
    efi_ctx.memory_map_descriptor_version = descriptor_version;

    return 0;
}

/* Print EFI information */
void efi_print_info(void) {
    if (!efi_ctx.system_table) return;

    /* Print firmware vendor */
    if (efi_ctx.system_table->firmware_vendor) {
        uint16_t* vendor = (uint16_t*)efi_ctx.system_table->firmware_vendor;
        /* Convert and print Unicode string */
    }

    /* Print firmware revision */
    uint32_t revision = efi_ctx.system_table->firmware_revision;
    uint32_t major = (revision >> 16) & 0xFFFF;
    uint32_t minor = revision & 0xFFFF;

    /* Print system table information */
    /* Print runtime services information */
    /* Print boot services information */
    /* Print memory map information */
}

/* Get EFI memory map */
void efi_get_memory_map(void) {
    if (!efi_ctx.boot_services) return;

    /* Call GetMemoryMap boot service */
    typedef int (*efi_get_memory_map_t)(uint64_t*, void*, uint64_t*, uint64_t*, uint32_t*);
    efi_get_memory_map_t get_memory_map = (efi_get_memory_map_t)efi_ctx.boot_services->get_memory_map;

    uint64_t memory_map_size = efi_ctx.memory_map_size;
    uint64_t map_key = 0;
    uint64_t descriptor_size = 0;
    uint32_t descriptor_version = 0;

    get_memory_map(&memory_map_size, (void*)efi_ctx.memory_map, 
                   &map_key, &descriptor_size, &descriptor_version);
}

/* Dump EFI memory map */
void efi_dump_memory_map(void) {
    if (!efi_ctx.memory_map) return;

    efi_memory_descriptor_t* desc = (efi_memory_descriptor_t*)efi_ctx.memory_map;
    uint64_t entries = efi_ctx.memory_map_size / efi_ctx.memory_map_descriptor_size;

    for (uint64_t i = 0; i < entries; i++) {
        /* Print memory descriptor information */
        desc = (efi_memory_descriptor_t*)((uint8_t*)desc + efi_ctx.memory_map_descriptor_size);
    }
}

/* Exit boot services */
int efi_exit_boot_services(void) {
    if (!efi_ctx.boot_services) return -1;

    /* Get memory map key */
    uint64_t memory_map_size = efi_ctx.memory_map_size;
    uint64_t map_key = 0;
    uint64_t descriptor_size = 0;
    uint32_t descriptor_version = 0;

    typedef int (*efi_get_memory_map_t)(uint64_t*, void*, uint64_t*, uint64_t*, uint32_t*);
    efi_get_memory_map_t get_memory_map = (efi_get_memory_map_t)efi_ctx.boot_services->get_memory_map;

    int status = get_memory_map(&memory_map_size, (void*)efi_ctx.memory_map, 
                                 &map_key, &descriptor_size, &descriptor_version);

    if (status != 0) {
        return -1;
    }

    /* Call ExitBootServices */
    typedef int (*efi_exit_boot_services_t)(uint32_t, uint64_t);
    efi_exit_boot_services_t exit_boot_services = (efi_exit_boot_services_t)efi_ctx.boot_services->exit_boot_services;

    status = exit_boot_services(0, map_key); /* Image handle = 0 */

    if (status != 0) {
        return -1;
    }

    /* Boot services are no longer available */
    efi_ctx.boot_services = NULL;

    return 0;
}

/* Set virtual address map */
int efi_set_virtual_address_map(void) {
    if (!efi_ctx.runtime_services) return -1;

    /* Call SetVirtualAddressMap runtime service */
    typedef int (*efi_set_virtual_address_map_t)(uint64_t, uint64_t, uint32_t, void*);
    efi_set_virtual_address_map_t set_virtual_address_map = 
        (efi_set_virtual_address_map_t)efi_ctx.runtime_services->set_virtual_address_map;

    int status = set_virtual_address_map(efi_ctx.memory_map_size, 
                                          efi_ctx.memory_map_descriptor_size,
                                          efi_ctx.memory_map_descriptor_version,
                                          (void*)efi_ctx.memory_map);

    return status;
}

/* Allocate pages */
int efi_allocate_pages(uint32_t type, uint32_t memory_type, uint64_t pages, uint64_t* memory) {
    if (!efi_ctx.boot_services) return -1;

    typedef int (*efi_allocate_pages_t)(uint32_t, uint32_t, uint64_t, uint64_t*);
    efi_allocate_pages_t allocate_pages = (efi_allocate_pages_t)efi_ctx.boot_services->allocate_pages;

    return allocate_pages(type, memory_type, pages, memory);
}

/* Free pages */
int efi_free_pages(uint64_t memory, uint64_t pages) {
    if (!efi_ctx.boot_services) return -1;

    typedef int (*efi_free_pages_t)(uint64_t, uint64_t);
    efi_free_pages_t free_pages = (efi_free_pages_t)efi_ctx.boot_services->free_pages;

    return free_pages(memory, pages);
}

/* Get variable */
int efi_get_variable(uint16_t* variable_name, uint64_t* vendor_guid, uint32_t* attributes, 
                      uint64_t* data_size, void* data) {
    if (!efi_ctx.runtime_services) return -1;

    typedef int (*efi_get_variable_t)(uint16_t*, uint64_t*, uint32_t*, uint64_t*, void*);
    efi_get_variable_t get_variable = (efi_get_variable_t)efi_ctx.runtime_services->get_variable;

    return get_variable(variable_name, vendor_guid, attributes, data_size, data);
}

/* Set variable */
int efi_set_variable(uint16_t* variable_name, uint64_t* vendor_guid, uint32_t attributes,
                     uint64_t data_size, void* data) {
    if (!efi_ctx.runtime_services) return -1;

    typedef int (*efi_set_variable_t)(uint16_t*, uint64_t*, uint32_t, uint64_t, void*);
    efi_set_variable_t set_variable = (efi_set_variable_t)efi_ctx.runtime_services->set_variable;

    return set_variable(variable_name, vendor_guid, attributes, data_size, data);
}

/* Reset system */
void efi_reset_system(uint32_t reset_type, uint64_t status, uint64_t data_size, void* reset_data) {
    if (!efi_ctx.runtime_services) return;

    typedef void (*efi_reset_system_t)(uint32_t, uint64_t, uint64_t, void*);
    efi_reset_system_t reset_system = (efi_reset_system_t)efi_ctx.runtime_services->reset_system;

    reset_system(reset_type, status, data_size, reset_data);
}