#ifndef MULTIBOOT2_H
#define MULTIBOOT2_H

#include <stdint.h>

/* Multiboot2 header magic numbers */
#define MULTIBOOT2_HEADER_MAGIC 0xE85250D6
#define MULTIBOOT2_BOOTLOADER_MAGIC 0x36D76289

/* Multiboot2 header tags */
#define MULTIBOOT2_HEADER_TAG_INFORMATION_REQUEST 1
#define MULTIBOOT2_HEADER_TAG_ADDRESS 2
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS 3
#define MULTIBOOT2_HEADER_TAG_CONSOLE_FLAGS 4
#define MULTIBOOT2_HEADER_TAG_FRAMEBUFFER 5
#define MULTIBOOT2_HEADER_TAG_MODULE_ALIGN 6
#define MULTIBOOT2_HEADER_TAG_EFI_BS 7
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS_EFI32 8
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS_EFI64 9
#define MULTIBOOT2_HEADER_TAG_RELOCATABLE 10

/* Multiboot2 tag types */
#define MULTIBOOT2_TAG_TYPE_END 0
#define MULTIBOOT2_TAG_TYPE_CMDLINE 1
#define MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME 2
#define MULTIBOOT2_TAG_TYPE_MODULE 3
#define MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO 4
#define MULTIBOOT2_TAG_TYPE_BOOTDEV 5
#define MULTIBOOT2_TAG_TYPE_MMAP 6
#define MULTIBOOT2_TAG_TYPE_VBE 7
#define MULTIBOOT2_TAG_TYPE_FRAMEBUFFER 8
#define MULTIBOOT2_TAG_TYPE_ELF_SECTIONS 9
#define MULTIBOOT2_TAG_TYPE_APM 10
#define MULTIBOOT2_TAG_TYPE_EFI32 11
#define MULTIBOOT2_TAG_TYPE_EFI64 12
#define MULTIBOOT2_TAG_TYPE_SMBIOS 13
#define MULTIBOOT2_TAG_TYPE_ACPI_OLD 14
#define MULTIBOOT2_TAG_TYPE_ACPI_NEW 15
#define MULTIBOOT2_TAG_TYPE_NETWORK 16
#define MULTIBOOT2_TAG_TYPE_EFI_MMAP 17
#define MULTIBOOT2_TAG_TYPE_EFI_BS 18
#define MULTIBOOT2_TAG_TYPE_EFI32_IH 19
#define MULTIBOOT2_TAG_TYPE_EFI64_IH 20
#define MULTIBOOT2_TAG_TYPE_LOAD_BASE_ADDR 21

/* Multiboot2 header flags */
#define MULTIBOOT2_HEADER_TAG_OPTIONAL 1

/* Multiboot2 console flags */
#define MULTIBOOT2_CONSOLE_FLAGS_CONSOLE_REQUIRED 1
#define MULTIBOOT2_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED 2

/* Multiboot2 memory map entry types */
#define MULTIBOOT2_MEMORY_AVAILABLE 1
#define MULTIBOOT2_MEMORY_RESERVED 2
#define MULTIBOOT2_MEMORY_ACPI_RECLAIM 3
#define MULTIBOOT2_MEMORY_NVS 4
#define MULTIBOOT2_MEMORY_BADRAM 5
#define MULTIBOOT2_MEMORY_KERNEL 6
#define MULTIBOOT2_MEMORY_BOOTLOADER 7

/* Multiboot2 header structure */
typedef struct {
    uint32_t magic;
    uint32_t architecture;
    uint32_t header_length;
    uint32_t checksum;
} multiboot2_header_t;

/* Multiboot2 tag header */
typedef struct {
    uint16_t type;
    uint16_t flags;
    uint32_t size;
} multiboot2_tag_t;

/* Multiboot2 information structure */
typedef struct {
    uint32_t total_size;
    uint32_t reserved;
} multiboot2_info_t;

/* Multiboot2 basic memory information */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t mem_lower;
    uint32_t mem_upper;
} multiboot2_tag_basic_meminfo_t;

/* Multiboot2 memory map entry */
typedef struct {
    uint64_t addr;
    uint64_t len;
    uint32_t type;
    uint32_t reserved;
} multiboot2_mmap_entry_t;

/* Multiboot2 memory map */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t entry_size;
    uint32_t entry_version;
    multiboot2_mmap_entry_t entries[];
} multiboot2_tag_mmap_t;

/* Multiboot2 framebuffer information */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t framebuffer_bpp;
    uint8_t framebuffer_type;
    uint8_t reserved;
} multiboot2_tag_framebuffer_t;

/* Multiboot2 module information */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t mod_start;
    uint32_t mod_end;
    char cmdline[];
} multiboot2_tag_module_t;

/* Multiboot2 RSDP (Root System Description Pointer) */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint8_t rsdp[];
} multiboot2_tag_rsdp_t;

/* Multiboot2 EFI system table */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t pointer;
} multiboot2_tag_efi32_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint64_t pointer;
} multiboot2_tag_efi64_t;

/* Multiboot2 EFI memory map */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t descr_size;
    uint32_t descr_version;
    uint8_t efi_mmap[];
} multiboot2_tag_efi_mmap_t;

/* ACPI RSDP structure */
typedef struct {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed)) acpi_rsdp_t;

/* EFI system table */
typedef struct {
    uint64_t header;
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
    uint64_t header;
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

/* Module payload types for pentesting tools */
typedef enum {
    MODULE_TYPE_EXPLOIT = 0x01,
    MODULE_TYPE_SCANNER = 0x02,
    MODULE_TYPE_NETWORK = 0x04,
    MODULE_TYPE_FORENSICS = 0x08,
    MODULE_TYPE_CRYPTO = 0x10,
    MODULE_TYPE_MISC = 0x20
} module_payload_type_t;

/* Module header for dynamic loading */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    uint32_t size;
    uint32_t entry_point;
    uint32_t checksum;
    char name[64];
    char description[128];
    uint32_t dependencies;
    uint32_t reserved;
} __attribute__((packed)) module_header_t;

/* Bootloader context structure */
typedef struct {
    multiboot2_info_t* info;
    multiboot2_tag_mmap_t* mmap;
    multiboot2_tag_framebuffer_t* framebuffer;
    multiboot2_tag_module_t** modules;
    uint32_t module_count;
    acpi_rsdp_t* rsdp;
    void* efi_system_table;
    uint64_t kernel_base;
    uint64_t kernel_size;
    uint64_t stack_base;
    uint32_t stack_size;
    uint32_t flags;
} bootloader_context_t;

/* Function prototypes */
void multiboot2_init(bootloader_context_t* ctx, multiboot2_info_t* info);
void multiboot2_parse_tags(bootloader_context_t* ctx);
void multiboot2_parse_memory_map(bootloader_context_t* ctx, multiboot2_tag_mmap_t* mmap);
void multiboot2_parse_framebuffer(bootloader_context_t* ctx, multiboot2_tag_framebuffer_t* fb);
void multiboot2_parse_modules(bootloader_context_t* ctx, multiboot2_tag_module_t* module);
void multiboot2_parse_acpi(bootloader_context_t* ctx, multiboot2_tag_rsdp_t* rsdp);
void multiboot2_parse_efi(bootloader_context_t* ctx, void* efi_table);
int multiboot2_validate_module(module_header_t* header);
void multiboot2_load_module(bootloader_context_t* ctx, module_header_t* module);
void multiboot2_setup_stack_protection(bootloader_context_t* ctx);
void multiboot2_enable_framebuffer(bootloader_context_t* ctx);

#endif /* MULTIBOOT2_H */