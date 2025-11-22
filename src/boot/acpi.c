#include "multiboot2.h"
#include <stdint.h>
#include <stddef.h>

/* ACPI table signatures */
#define ACPI_RSDP_SIGNATURE 0x2052545020445352ULL  /* "RSD PTR " */
#define ACPI_RSDT_SIGNATURE 0x54445352  /* "RSDT" */
#define ACPI_XSDT_SIGNATURE 0x54445358  /* "XSDT" */
#define ACPI_FADT_SIGNATURE 0x50434146  /* "FACP" */
#define ACPI_MADT_SIGNATURE 0x43495041  /* "APIC" */
#define ACPI_HPET_SIGNATURE 0x54455048  /* "HPET" */
#define ACPI_MCFG_SIGNATURE 0x4746434D  /* "MCFG" */

/* ACPI table header */
typedef struct {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed)) acpi_header_t;

/* RSDP v1 structure */
typedef struct {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
} __attribute__((packed)) acpi_rsdp_v1_t;

/* RSDP v2 structure */
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
} __attribute__((packed)) acpi_rsdp_v2_t;

/* FADT (Fixed ACPI Description Table) */
typedef struct {
    acpi_header_t header;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t reserved1;
    uint8_t preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t pm1_evt_len;
    uint8_t pm1_cnt_len;
    uint8_t pm2_cnt_len;
    uint8_t pm_tmr_len;
    uint8_t gpe0_blk_len;
    uint8_t gpe1_blk_len;
    uint8_t gpe1_base;
    uint8_t cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alrm;
    uint8_t mon_alrm;
    uint8_t century;
    uint16_t iapc_boot_arch;
    uint8_t reserved2;
    uint32_t flags;
    uint32_t reset_reg[3];
    uint8_t reset_value;
    uint8_t reserved3[3];
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
    uint32_t x_pm1a_evt_blk[2];
    uint32_t x_pm1b_evt_blk[2];
    uint32_t x_pm1a_cnt_blk[2];
    uint32_t x_pm1b_cnt_blk[2];
    uint32_t x_pm2_cnt_blk[2];
    uint32_t x_pm_tmr_blk[2];
    uint32_t x_gpe0_blk[2];
    uint32_t x_gpe1_blk[2];
} __attribute__((packed)) acpi_fadt_t;

/* MADT (Multiple APIC Description Table) */
typedef struct {
    acpi_header_t header;
    uint32_t local_apic_address;
    uint32_t flags;
} __attribute__((packed)) acpi_madt_t;

/* HPET (High Precision Event Timer) */
typedef struct {
    acpi_header_t header;
    uint8_t hardware_rev_id;
    uint8_t comparator_count:5;
    uint8_t counter_size:1;
    uint8_t reserved:1;
    uint16_t pci_vendor_id;
    uint32_t address_space_id;
    uint8_t register_bit_width;
    uint8_t register_bit_offset;
    uint8_t reserved2;
    uint64_t address;
    uint8_t hpet_number;
    uint16_t minimum_tick;
    uint8_t page_protection;
} __attribute__((packed)) acpi_hpet_t;

/* MCFG (PCI Express memory mapped configuration space) */
typedef struct {
    acpi_header_t header;
    uint8_t reserved[8];
} __attribute__((packed)) acpi_mcfg_t;

/* MCFG allocation structure */
typedef struct {
    uint64_t address;
    uint16_t pci_segment_group;
    uint8_t start_bus_number;
    uint8_t end_bus_number;
    uint32_t reserved;
} __attribute__((packed)) acpi_mcfg_allocation_t;

/* Global ACPI context */
static struct {
    acpi_rsdp_v2_t* rsdp;
    acpi_fadt_t* fadt;
    acpi_madt_t* madt;
    acpi_hpet_t* hpet;
    acpi_mcfg_t* mcfg;
    uint64_t* xsdt;
    uint32_t* rsdt;
    uint32_t table_count;
    uint8_t revision;
    uint64_t fadt_address;
    uint64_t dsdt_address;
    uint64_t x_dsdt_address;
    uint32_t pm1a_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t smi_cmd;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint32_t local_apic_address;
    uint64_t hpet_address;
    uint64_t mcfg_address;
} acpi_ctx;

/* Function prototypes */
int acpi_init(acpi_rsdp_t* rsdp);
int acpi_validate_rsdp(acpi_rsdp_t* rsdp);
int acpi_validate_table(void* table);
uint32_t acpi_calculate_checksum(void* table, uint32_t length);
void* acpi_find_table(const char* signature);
int acpi_parse_fadt(acpi_fadt_t* fadt);
int acpi_parse_madt(acpi_madt_t* madt);
int acpi_parse_hpet(acpi_hpet_t* hpet);
int acpi_parse_mcfg(acpi_mcfg_t* mcfg);
void acpi_enable(void);
void acpi_disable(void);
uint32_t acpi_read_pm1a_status(void);
void acpi_write_pm1a_status(uint32_t value);
uint32_t acpi_read_pm1a_control(void);
void acpi_write_pm1a_control(uint32_t value);
uint32_t acpi_read_pm_timer(void);
void acpi_enter_sleep_state(uint8_t state);

/* I/O port access functions */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile ("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline uint32_t inl(uint16_t port) {
    uint32_t value;
    __asm__ volatile ("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

/* Initialize ACPI subsystem */
int acpi_init(acpi_rsdp_t* rsdp) {
    if (!rsdp) return -1;

    /* Validate RSDP */
    if (acpi_validate_rsdp(rsdp) != 0) {
        return -1;
    }

    /* Store RSDP */
    acpi_ctx.rsdp = (acpi_rsdp_v2_t*)rsdp;
    acpi_ctx.revision = rsdp->revision;

    /* Find and parse FADT */
    acpi_ctx.fadt = (acpi_fadt_t*)acpi_find_table("FACP");
    if (acpi_ctx.fadt) {
        if (acpi_parse_fadt(acpi_ctx.fadt) != 0) {
            return -1;
        }
    }

    /* Find and parse MADT */
    acpi_ctx.madt = (acpi_madt_t*)acpi_find_table("APIC");
    if (acpi_ctx.madt) {
        if (acpi_parse_madt(acpi_ctx.madt) != 0) {
            return -1;
        }
    }

    /* Find and parse HPET */
    acpi_ctx.hpet = (acpi_hpet_t*)acpi_find_table("HPET");
    if (acpi_ctx.hpet) {
        if (acpi_parse_hpet(acpi_ctx.hpet) != 0) {
            return -1;
        }
    }

    /* Find and parse MCFG */
    acpi_ctx.mcfg = (acpi_mcfg_t*)acpi_find_table("MCFG");
    if (acpi_ctx.mcfg) {
        if (acpi_parse_mcfg(acpi_ctx.mcfg) != 0) {
            return -1;
        }
    }

    return 0;
}

/* Validate RSDP structure */
int acpi_validate_rsdp(acpi_rsdp_t* rsdp) {
    if (!rsdp) return -1;

    /* Check signature */
    if (rsdp->signature[0] != 'R' || rsdp->signature[1] != 'S' ||
        rsdp->signature[2] != 'D' || rsdp->signature[3] != ' ' ||
        rsdp->signature[4] != 'P' || rsdp->signature[5] != 'T' ||
        rsdp->signature[6] != 'R' || rsdp->signature[7] != ' ') {
        return -1;
    }

    /* Validate checksum for RSDP v1 */
    uint8_t sum = 0;
    uint8_t* ptr = (uint8_t*)rsdp;
    for (uint32_t i = 0; i < 20; i++) {
        sum += ptr[i];
    }

    if (sum != 0) return -1;

    /* If RSDP v2, validate extended checksum */
    if (rsdp->revision >= 2) {
        acpi_rsdp_v2_t* rsdp_v2 = (acpi_rsdp_v2_t*)rsdp;
        
        /* Validate length */
        if (rsdp_v2->length < sizeof(acpi_rsdp_v2_t)) {
            return -1;
        }

        /* Validate extended checksum */
        sum = 0;
        for (uint32_t i = 0; i < rsdp_v2->length; i++) {
            sum += ptr[i];
        }

        if (sum != 0) return -1;
    }

    return 0;
}

/* Calculate checksum for ACPI table */
uint32_t acpi_calculate_checksum(void* table, uint32_t length) {
    if (!table || length == 0) return 0;

    uint8_t* ptr = (uint8_t*)table;
    uint8_t sum = 0;

    for (uint32_t i = 0; i < length; i++) {
        sum += ptr[i];
    }

    return sum;
}

/* Validate ACPI table */
int acpi_validate_table(void* table) {
    if (!table) return -1;

    acpi_header_t* header = (acpi_header_t*)table;

    /* Validate signature */
    uint32_t signature = *(uint32_t*)header->signature;

    /* Calculate checksum */
    if (acpi_calculate_checksum(table, header->length) != 0) {
        return -1;
    }

    return 0;
}

/* Find ACPI table by signature */
void* acpi_find_table(const char* signature) {
    if (!signature) return NULL;

    if (acpi_ctx.revision >= 2 && acpi_ctx.xsdt) {
        /* Use XSDT for 64-bit tables */
        uint64_t* entries = (uint64_t*)((uint8_t*)acpi_ctx.xsdt + sizeof(acpi_header_t));
        uint32_t entry_count = (acpi_ctx.xsdt[1] - sizeof(acpi_header_t)) / sizeof(uint64_t);

        for (uint32_t i = 0; i < entry_count; i++) {
            void* table = (void*)entries[i];
            if (table && *(uint32_t*)table == *(uint32_t*)signature) {
                if (acpi_validate_table(table) == 0) {
                    return table;
                }
            }
        }
    } else if (acpi_ctx.rsdt) {
        /* Use RSDT for 32-bit tables */
        uint32_t* entries = (uint32_t*)((uint8_t*)acpi_ctx.rsdt + sizeof(acpi_header_t));
        uint32_t entry_count = (acpi_ctx.rsdt[1] - sizeof(acpi_header_t)) / sizeof(uint32_t);

        for (uint32_t i = 0; i < entry_count; i++) {
            void* table = (void*)(uint64_t)entries[i];
            if (table && *(uint32_t*)table == *(uint32_t*)signature) {
                if (acpi_validate_table(table) == 0) {
                    return table;
                }
            }
        }
    }

    return NULL;
}

/* Parse FADT */
int acpi_parse_fadt(acpi_fadt_t* fadt) {
    if (!fadt) return -1;

    if (acpi_validate_table(fadt) != 0) {
        return -1;
    }

    /* Extract important fields */
    acpi_ctx.fadt_address = (uint64_t)fadt;
    acpi_ctx.dsdt_address = fadt->dsdt;
    acpi_ctx.x_dsdt_address = fadt->x_dsdt;
    acpi_ctx.pm1a_evt_blk = fadt->pm1a_evt_blk;
    acpi_ctx.pm1a_cnt_blk = fadt->pm1a_cnt_blk;
    acpi_ctx.pm_tmr_blk = fadt->pm_tmr_blk;
    acpi_ctx.smi_cmd = fadt->smi_cmd;
    acpi_ctx.acpi_enable = fadt->acpi_enable;
    acpi_ctx.acpi_disable = fadt->acpi_disable;

    return 0;
}

/* Parse MADT */
int acpi_parse_madt(acpi_madt_t* madt) {
    if (!madt) return -1;

    if (acpi_validate_table(madt) != 0) {
        return -1;
    }

    /* Extract local APIC address */
    acpi_ctx.local_apic_address = madt->local_apic_address;

    return 0;
}

/* Parse HPET */
int acpi_parse_hpet(acpi_hpet_t* hpet) {
    if (!hpet) return -1;

    if (acpi_validate_table(hpet) != 0) {
        return -1;
    }

    /* Extract HPET address */
    acpi_ctx.hpet_address = hpet->address;

    return 0;
}

/* Parse MCFG */
int acpi_parse_mcfg(acpi_mcfg_t* mcfg) {
    if (!mcfg) return -1;

    if (acpi_validate_table(mcfg) != 0) {
        return -1;
    }

    /* Extract MCFG address */
    acpi_ctx.mcfg_address = (uint64_t)mcfg;

    return 0;
}

/* Enable ACPI */
void acpi_enable(void) {
    if (!acpi_ctx.fadt) return;

    /* Write ACPI enable command to SMI command port */
    if (acpi_ctx.smi_cmd && acpi_ctx.acpi_enable) {
        outb(acpi_ctx.smi_cmd, acpi_ctx.acpi_enable);
    }
}

/* Disable ACPI */
void acpi_disable(void) {
    if (!acpi_ctx.fadt) return;

    /* Write ACPI disable command to SMI command port */
    if (acpi_ctx.smi_cmd && acpi_ctx.acpi_disable) {
        outb(acpi_ctx.smi_cmd, acpi_ctx.acpi_disable);
    }
}

/* Read PM1A status register */
uint32_t acpi_read_pm1a_status(void) {
    if (acpi_ctx.pm1a_evt_blk == 0) return 0;
    return inl(acpi_ctx.pm1a_evt_blk);
}

/* Write PM1A status register */
void acpi_write_pm1a_status(uint32_t value) {
    if (acpi_ctx.pm1a_evt_blk == 0) return;
    outl(acpi_ctx.pm1a_evt_blk, value);
}

/* Read PM1A control register */
uint32_t acpi_read_pm1a_control(void) {
    if (acpi_ctx.pm1a_cnt_blk == 0) return 0;
    return inl(acpi_ctx.pm1a_cnt_blk);
}

/* Write PM1A control register */
void acpi_write_pm1a_control(uint32_t value) {
    if (acpi_ctx.pm1a_cnt_blk == 0) return;
    outl(acpi_ctx.pm1a_cnt_blk, value);
}

/* Read PM timer */
uint32_t acpi_read_pm_timer(void) {
    if (acpi_ctx.pm_tmr_blk == 0) return 0;
    return inl(acpi_ctx.pm_tmr_blk);
}

/* Enter sleep state */
void acpi_enter_sleep_state(uint8_t state) {
    if (!acpi_ctx.fadt) return;

    uint32_t pm1a_control = acpi_read_pm1a_control();
    pm1a_control &= 0xFFFFFFC3; /* Clear sleep type */
    pm1a_control |= (state << 10); /* Set sleep type */
    acpi_write_pm1a_control(pm1a_control);
}