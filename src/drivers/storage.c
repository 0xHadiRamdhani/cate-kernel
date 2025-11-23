#include "storage.h"
#include "../kernel/memory.h"
#include "../kernel/interrupt.h"
#include "../drivers/vga.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

/* Global storage manager */
storage_manager_t* global_storage_manager = NULL;
bool storage_initialized = false;

/* IDE controller ports */
#define IDE_PRIMARY_IO          0x1F0
#define IDE_PRIMARY_CONTROL     0x3F6
#define IDE_SECONDARY_IO        0x170
#define IDE_SECONDARY_CONTROL   0x376

/* IDE registers */
#define IDE_DATA                0x00
#define IDE_ERROR               0x01
#define IDE_FEATURES            0x01
#define IDE_SECTOR_COUNT        0x02
#define IDE_LBA_LOW             0x03
#define IDE_LBA_MID             0x04
#define IDE_LBA_HIGH            0x05
#define IDE_DRIVE_SELECT        0x06
#define IDE_COMMAND             0x07
#define IDE_STATUS              0x07

/* IDE control registers */
#define IDE_ALT_STATUS          0x00
#define IDE_DEVICE_CONTROL      0x00
#define IDE_DRIVE_ADDRESS       0x01

/* IDE commands */
#define IDE_CMD_READ_SECTORS    0x20
#define IDE_CMD_READ_SECTORS_EXT 0x24
#define IDE_CMD_WRITE_SECTORS   0x30
#define IDE_CMD_WRITE_SECTORS_EXT 0x34
#define IDE_CMD_CACHE_FLUSH     0xE7
#define IDE_CMD_IDENTIFY        0xEC
#define IDE_CMD_SET_FEATURES    0xEF
#define IDE_CMD_SECURITY_SET_PASSWORD 0xF1
#define IDE_CMD_SECURITY_UNLOCK 0xF2
#define IDE_CMD_SECURITY_ERASE_PREPARE 0xF3
#define IDE_CMD_SECURITY_ERASE_UNIT 0xF4
#define IDE_CMD_SECURITY_FREEZE_LOCK 0xF5
#define IDE_CMD_SECURITY_DISABLE 0xF6

/* IDE status bits */
#define IDE_STATUS_BUSY         0x80
#define IDE_STATUS_READY        0x40
#define IDE_STATUS_FAULT        0x20
#define IDE_STATUS_SEEK_COMPLETE 0x10
#define IDE_STATUS_DRQ          0x08
#define IDE_STATUS_CORRECTED    0x04
#define IDE_STATUS_INDEX        0x02
#define IDE_STATUS_ERROR        0x01

/* Initialize storage subsystem */
void storage_init(void) {
    if (storage_initialized) return;
    
    /* Allocate storage manager */
    global_storage_manager = (storage_manager_t*)kmalloc(sizeof(storage_manager_t));
    if (!global_storage_manager) return;
    
    memory_zero(global_storage_manager, sizeof(storage_manager_t));
    
    /* Initialize manager */
    global_storage_manager->initialized = true;
    global_storage_manager->secure_mode = false;
    global_storage_manager->forensics_mode = false;
    global_storage_manager->write_blocking = false;
    global_storage_manager->security_level = STORAGE_SECURITY_NONE;
    global_storage_manager->pentest_mode = false;
    global_storage_manager->evidence_collection = false;
    
    /* Initialize IDE controller */
    ide_init();
    
    /* Detect storage devices */
    storage_detect_devices();
    
    storage_initialized = true;
    
    vga_print_success("Storage subsystem initialized");
}

/* Shutdown storage subsystem */
void storage_shutdown(void) {
    if (!storage_initialized || !global_storage_manager) return;
    
    /* Flush all devices */
    storage_device_t* device = global_storage_manager->devices;
    while (device) {
        storage_flush(device);
        device = device->next;
    }
    
    /* Free resources */
    if (global_storage_manager->request_queue) {
        kfree(global_storage_manager->request_queue);
    }
    
    if (global_storage_manager->cache_buffer) {
        kfree(global_storage_manager->cache_buffer);
    }
    
    kfree(global_storage_manager);
    global_storage_manager = NULL;
    storage_initialized = false;
}

/* Check if initialized */
bool storage_is_initialized(void) {
    return storage_initialized && global_storage_manager && global_storage_manager->initialized;
}

/* Get device by ID */
storage_device_t* storage_get_device(uint32_t device_id) {
    if (!global_storage_manager || !global_storage_manager->initialized) return NULL;
    
    storage_device_t* device = global_storage_manager->devices;
    while (device) {
        if (device->device_id == device_id) {
            return device;
        }
        device = device->next;
    }
    
    return NULL;
}

/* Get device by name */
storage_device_t* storage_get_device_by_name(const char* name) {
    if (!global_storage_manager || !global_storage_manager->initialized || !name) return NULL;
    
    storage_device_t* device = global_storage_manager->devices;
    while (device) {
        if (strcmp(device->name, name) == 0) {
            return device;
        }
        device = device->next;
    }
    
    return NULL;
}

/* Get device count */
uint32_t storage_get_device_count(void) {
    return global_storage_manager ? global_storage_manager->device_count : 0;
}

/* Register device */
storage_status_t storage_register_device(storage_device_t* device) {
    if (!global_storage_manager || !global_storage_manager->initialized || !device) {
        return STORAGE_STATUS_INVALID_PARAM;
    }
    
    /* Add to linked list */
    device->next = global_storage_manager->devices;
    global_storage_manager->devices = device;
    global_storage_manager->device_count++;
    
    return STORAGE_STATUS_OK;
}

/* Unregister device */
storage_status_t storage_unregister_device(uint32_t device_id) {
    if (!global_storage_manager || !global_storage_manager->initialized) {
        return STORAGE_STATUS_INVALID_PARAM;
    }
    
    storage_device_t** current = &global_storage_manager->devices;
    while (*current) {
        if ((*current)->device_id == device_id) {
            storage_device_t* to_remove = *current;
            *current = (*current)->next;
            kfree(to_remove);
            global_storage_manager->device_count--;
            return STORAGE_STATUS_OK;
        }
        current = &(*current)->next;
    }
    
    return STORAGE_STATUS_ERROR;
}

/* Read from device */
storage_status_t storage_read(storage_device_t* device, uint64_t lba, uint32_t count, void* buffer) {
    if (!device || !buffer || count == 0) return STORAGE_STATUS_INVALID_PARAM;
    if (!device->read) return STORAGE_STATUS_ERROR;
    
    /* Security checks */
    if (device->locked) return STORAGE_STATUS_ERROR;
    if (device->forensics_mode && !device->imaging_mode) return STORAGE_STATUS_ERROR;
    
    /* Call device-specific read function */
    storage_status_t status = device->read(device, lba, count, buffer);
    
    /* Update statistics */
    if (status == STORAGE_STATUS_OK) {
        device->total_reads++;
        device->bytes_read += count * device->info.sector_size;
        
        if (global_storage_manager) {
            global_storage_manager->total_reads++;
            global_storage_manager->total_bytes_read += count * device->info.sector_size;
        }
    } else {
        device->error_count++;
        if (global_storage_manager) {
            global_storage_manager->total_errors++;
        }
    }
    
    return status;
}

/* Write to device */
storage_status_t storage_write(storage_device_t* device, uint64_t lba, uint32_t count, const void* buffer) {
    if (!device || !buffer || count == 0) return STORAGE_STATUS_INVALID_PARAM;
    if (!device->write) return STORAGE_STATUS_ERROR;
    
    /* Security checks */
    if (device->locked) return STORAGE_STATUS_ERROR;
    if (device->read_only) return STORAGE_STATUS_WRITE_PROTECTED;
    if (device->write_blocking) return STORAGE_STATUS_ERROR;
    if (device->forensics_mode) return STORAGE_STATUS_ERROR;
    
    /* Call device-specific write function */
    storage_status_t status = device->write(device, lba, count, buffer);
    
    /* Update statistics */
    if (status == STORAGE_STATUS_OK) {
        device->total_writes++;
        device->bytes_written += count * device->info.sector_size;
        
        if (global_storage_manager) {
            global_storage_manager->total_writes++;
            global_storage_manager->total_bytes_written += count * device->info.sector_size;
        }
    } else {
        device->error_count++;
        if (global_storage_manager) {
            global_storage_manager->total_errors++;
        }
    }
    
    return status;
}

/* Flush device */
storage_status_t storage_flush(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    if (!device->flush) return STORAGE_STATUS_OK;
    
    return device->flush(device);
}

/* Trim device */
storage_status_t storage_trim(storage_device_t* device, uint64_t lba, uint32_t count) {
    if (!device || count == 0) return STORAGE_STATUS_INVALID_PARAM;
    if (!device->trim) return STORAGE_STATUS_OK;
    
    return device->trim(device, lba, count);
}

/* Identify device */
storage_status_t storage_identify(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    if (!device->identify) return STORAGE_STATUS_ERROR;
    
    return device->identify(device);
}

/* SMART data */
storage_status_t storage_smart(storage_device_t* device, void* data) {
    if (!device || !data) return STORAGE_STATUS_INVALID_PARAM;
    if (!device->smart) return STORAGE_STATUS_ERROR;
    
    return device->smart(device, data);
}

/* Secure erase */
storage_status_t storage_secure_erase(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    if (!device->secure_erase) return STORAGE_STATUS_ERROR;
    
    /* Security check */
    if (device->forensics_mode) return STORAGE_STATUS_ERROR;
    
    return device->secure_erase(device);
}

/* Read partition */
storage_status_t storage_read_partition(storage_device_t* device, uint32_t partition, uint64_t offset, uint32_t count, void* buffer) {
    if (!device || !buffer || count == 0) return STORAGE_STATUS_INVALID_PARAM;
    if (partition >= device->partition_count) return STORAGE_STATUS_INVALID_PARAM;
    
    partition_info_t* part = &device->partitions[partition];
    if (offset + count > part->size) return STORAGE_STATUS_INVALID_PARAM;
    
    uint64_t device_lba = part->start_lba + offset;
    return storage_read(device, device_lba, count, buffer);
}

/* Write partition */
storage_status_t storage_write_partition(storage_device_t* device, uint32_t partition, uint64_t offset, uint32_t count, const void* buffer) {
    if (!device || !buffer || count == 0) return STORAGE_STATUS_INVALID_PARAM;
    if (partition >= device->partition_count) return STORAGE_STATUS_INVALID_PARAM;
    
    partition_info_t* part = &device->partitions[partition];
    if (offset + count > part->size) return STORAGE_STATUS_INVALID_PARAM;
    
    uint64_t device_lba = part->start_lba + offset;
    return storage_write(device, device_lba, count, buffer);
}

/* Get partition */
partition_info_t* storage_get_partition(storage_device_t* device, uint32_t partition) {
    if (!device || partition >= device->partition_count) return NULL;
    return &device->partitions[partition];
}

/* Get partition count */
uint32_t storage_get_partition_count(storage_device_t* device) {
    return device ? device->partition_count : 0;
}

/* Lock device */
storage_status_t storage_lock_device(storage_device_t* device, const uint8_t* password) {
    if (!device || !password) return STORAGE_STATUS_INVALID_PARAM;
    
    /* Copy password */
    memory_copy(device->password, password, STORAGE_PASSWORD_MAX);
    device->locked = true;
    
    return STORAGE_STATUS_OK;
}

/* Unlock device */
storage_status_t storage_unlock_device(storage_device_t* device, const uint8_t* password) {
    if (!device || !password) return STORAGE_STATUS_INVALID_PARAM;
    
    /* Check password */
    if (memory_compare(device->password, password, STORAGE_PASSWORD_MAX) != 0) {
        return STORAGE_STATUS_ERROR;
    }
    
    device->locked = false;
    return STORAGE_STATUS_OK;
}

/* Set password */
storage_status_t storage_set_password(storage_device_t* device, const uint8_t* password) {
    if (!device || !password) return STORAGE_STATUS_INVALID_PARAM;
    
    memory_copy(device->password, password, STORAGE_PASSWORD_MAX);
    return STORAGE_STATUS_OK;
}

/* Clear password */
storage_status_t storage_clear_password(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    memory_zero(device->password, STORAGE_PASSWORD_MAX);
    device->locked = false;
    return STORAGE_STATUS_OK;
}

/* Check if locked */
bool storage_is_locked(storage_device_t* device) {
    return device ? device->locked : false;
}

/* Check if encrypted */
bool storage_is_encrypted(storage_device_t* device) {
    return device ? device->encrypted : false;
}

/* Start imaging */
storage_status_t storage_start_imaging(storage_device_t* device, const char* image_file) {
    if (!device || !image_file) return STORAGE_STATUS_INVALID_PARAM;
    
    device->imaging_mode = true;
    strncpy(device->evidence_tag, image_file, STORAGE_EVIDENCE_TAG_MAX - 1);
    device->evidence_tag[STORAGE_EVIDENCE_TAG_MAX - 1] = '\0';
    
    vga_printf("Started imaging device %s to %s\n", device->name, image_file);
    return STORAGE_STATUS_OK;
}

/* Stop imaging */
storage_status_t storage_stop_imaging(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    device->imaging_mode = false;
    vga_printf("Stopped imaging device %s\n", device->name);
    return STORAGE_STATUS_OK;
}

/* Start cloning */
storage_status_t storage_start_cloning(storage_device_t* source, storage_device_t* target) {
    if (!source || !target) return STORAGE_STATUS_INVALID_PARAM;
    
    source->cloning_mode = true;
    target->cloning_mode = true;
    
    vga_printf("Started cloning from %s to %s\n", source->name, target->name);
    return STORAGE_STATUS_OK;
}

/* Stop cloning */
storage_status_t storage_stop_cloning(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    device->cloning_mode = false;
    vga_printf("Stopped cloning device %s\n", device->name);
    return STORAGE_STATUS_OK;
}

/* Start analysis */
storage_status_t storage_start_analysis(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    device->analysis_mode = true;
    vga_printf("Started analysis on device %s\n", device->name);
    return STORAGE_STATUS_OK;
}

/* Stop analysis */
storage_status_t storage_stop_analysis(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    device->analysis_mode = false;
    vga_printf("Stopped analysis on device %s\n", device->name);
    return STORAGE_STATUS_OK;
}

/* Mark evidence */
storage_status_t storage_mark_evidence(storage_device_t* device, uint64_t start_lba, uint64_t end_lba, const char* tag) {
    if (!device || !tag) return STORAGE_STATUS_INVALID_PARAM;
    
    device->evidence_mode = true;
    device->evidence_start = start_lba;
    device->evidence_end = end_lba;
    strncpy(device->evidence_tag, tag, STORAGE_EVIDENCE_TAG_MAX - 1);
    device->evidence_tag[STORAGE_EVIDENCE_TAG_MAX - 1] = '\0';
    
    vga_printf("Marked evidence on device %s: LBA %llu-%llu, tag: %s\n", 
               device->name, start_lba, end_lba, tag);
    return STORAGE_STATUS_OK;
}

/* Get evidence info */
storage_status_t storage_get_evidence_info(storage_device_t* device, uint64_t* start_lba, uint64_t* end_lba, char* tag) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    if (start_lba) *start_lba = device->evidence_start;
    if (end_lba) *end_lba = device->evidence_end;
    if (tag) strcpy(tag, device->evidence_tag);
    
    return STORAGE_STATUS_OK;
}

/* Create forensic image */
storage_status_t storage_create_forensic_image(storage_device_t* device, const char* filename) {
    if (!device || !filename) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Creating forensic image of device %s to %s\n", device->name, filename);
    
    /* This would implement the actual imaging logic */
    /* For now, just mark as evidence */
    return storage_mark_evidence(device, 0, device->info.capacity / device->info.sector_size, filename);
}

/* Verify forensic image */
storage_status_t storage_verify_forensic_image(storage_device_t* device, const char* filename) {
    if (!device || !filename) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Verifying forensic image %s against device %s\n", filename, device->name);
    
    /* This would implement the actual verification logic */
    return STORAGE_STATUS_OK;
}

/* Analyze device */
storage_status_t storage_analyze_device(storage_device_t* device, void* analysis_data) {
    if (!device || !analysis_data) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Analyzing device %s\n", device->name);
    
    /* This would implement the actual analysis logic */
    return STORAGE_STATUS_OK;
}

/* Search signatures */
storage_status_t storage_search_signatures(storage_device_t* device, uint64_t start_lba, uint64_t end_lba, void* signatures) {
    if (!device || !signatures) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Searching for signatures on device %s, LBA %llu-%llu\n", device->name, start_lba, end_lba);
    
    /* This would implement the actual signature search logic */
    return STORAGE_STATUS_OK;
}

/* Recover data */
storage_status_t storage_recover_data(storage_device_t* device, uint64_t start_lba, uint64_t end_lba, void* recovery_buffer) {
    if (!device || !recovery_buffer) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Recovering data from device %s, LBA %llu-%llu\n", device->name, start_lba, end_lba);
    
    /* This would implement the actual data recovery logic */
    return STORAGE_STATUS_OK;
}

/* Format device */
storage_status_t storage_format_device(storage_device_t* device, filesystem_type_t fs_type) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Formatting device %s with filesystem %s\n", device->name, storage_get_filesystem_string(fs_type));
    
    /* This would implement the actual formatting logic */
    return STORAGE_STATUS_OK;
}

/* Check device */
storage_status_t storage_check_device(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Checking device %s\n", device->name);
    
    /* This would implement the actual checking logic */
    return STORAGE_STATUS_OK;
}

/* Benchmark device */
storage_status_t storage_benchmark_device(storage_device_t* device, uint32_t* read_speed, uint32_t* write_speed) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    vga_printf("Benchmarking device %s\n", device->name);
    
    /* This would implement the actual benchmarking logic */
    if (read_speed) *read_speed = 100;  /* MB/s */
    if (write_speed) *write_speed = 80; /* MB/s */
    
    return STORAGE_STATUS_OK;
}

/* Get status string */
const char* storage_get_status_string(storage_status_t status) {
    switch (status) {
        case STORAGE_STATUS_OK: return "OK";
        case STORAGE_STATUS_ERROR: return "Error";
        case STORAGE_STATUS_TIMEOUT: return "Timeout";
        case STORAGE_STATUS_NOT_READY: return "Not Ready";
        case STORAGE_STATUS_INVALID_PARAM: return "Invalid Parameter";
        case STORAGE_STATUS_NO_MEDIA: return "No Media";
        case STORAGE_STATUS_WRITE_PROTECTED: return "Write Protected";
        case STORAGE_STATUS_DEVICE_FAULT: return "Device Fault";
        case STORAGE_STATUS_ABORTED: return "Aborted";
        case STORAGE_STATUS_MEDIA_CHANGED: return "Media Changed";
        case STORAGE_STATUS_BUS_RESET: return "Bus Reset";
        default: return "Unknown";
    }
}

/* Get type string */
const char* storage_get_type_string(storage_type_t type) {
    switch (type) {
        case STORAGE_TYPE_IDE: return "IDE";
        case STORAGE_TYPE_SATA: return "SATA";
        case STORAGE_TYPE_NVME: return "NVMe";
        case STORAGE_TYPE_USB: return "USB";
        case STORAGE_TYPE_NETWORK: return "Network";
        case STORAGE_TYPE_RAM_DISK: return "RAM Disk";
        case STORAGE_TYPE_VIRTUAL: return "Virtual";
        default: return "Unknown";
    }
}

/* Get interface string */
const char* storage_get_interface_string(storage_interface_t interface) {
    switch (interface) {
        case STORAGE_INTERFACE_ATA: return "ATA";
        case STORAGE_INTERFACE_ATAPI: return "ATAPI";
        case STORAGE_INTERFACE_SCSI: return "SCSI";
        case STORAGE_INTERFACE_NVME: return "NVMe";
        case STORAGE_INTERFACE_USB: return "USB";
        case STORAGE_INTERFACE_NETWORK: return "Network";
        default: return "Unknown";
    }
}

/* Get filesystem string */
const char* storage_get_filesystem_string(filesystem_type_t fs) {
    switch (fs) {
        case FS_TYPE_FAT32: return "FAT32";
        case FS_TYPE_NTFS: return "NTFS";
        case FS_TYPE_EXT2: return "EXT2";
        case FS_TYPE_EXT3: return "EXT3";
        case FS_TYPE_EXT4: return "EXT4";
        case FS_TYPE_BTRFS: return "BTRFS";
        case FS_TYPE_ZFS: return "ZFS";
        case FS_TYPE_RAW: return "RAW";
        default: return "Unknown";
    }
}

/* Get statistics */
void storage_get_statistics(storage_device_t* device, uint64_t* reads, uint64_t* writes, uint64_t* bytes_read, uint64_t* bytes_written) {
    if (!device) return;
    
    if (reads) *reads = device->total_reads;
    if (writes) *writes = device->total_writes;
    if (bytes_read) *bytes_read = device->bytes_read;
    if (bytes_written) *bytes_written = device->bytes_written;
}

/* Reset statistics */
void storage_reset_statistics(storage_device_t* device) {
    if (!device) return;
    
    device->total_reads = 0;
    device->total_writes = 0;
    device->bytes_read = 0;
    device->bytes_written = 0;
    device->error_count = 0;
    device->timeout_count = 0;
}

/* Get global statistics */
void storage_get_global_statistics(uint64_t* total_reads, uint64_t* total_writes, uint64_t* total_bytes_read, uint64_t* total_bytes_written) {
    if (!global_storage_manager) return;
    
    if (total_reads) *total_reads = global_storage_manager->total_reads;
    if (total_writes) *total_writes = global_storage_manager->total_writes;
    if (total_bytes_read) *total_bytes_read = global_storage_manager->total_bytes_read;
    if (total_bytes_written) *total_bytes_written = global_storage_manager->total_bytes_written;
}

/* Detect storage devices */
void storage_detect_devices(void) {
    if (!global_storage_manager || !global_storage_manager->initialized) return;
    
    /* Detect IDE devices */
    ide_detect_devices();
    
    /* Detect SATA devices */
    ahci_detect_devices();
    
    /* Detect NVMe devices */
    nvme_detect_devices();
    
    vga_printf("Detected %u storage devices\n", global_storage_manager->device_count);
}

/* Queue request */
storage_status_t storage_queue_request(storage_request_t* request) {
    if (!global_storage_manager || !request) return STORAGE_STATUS_INVALID_PARAM;
    
    /* Add to queue */
    /* This would implement actual queueing logic */
    return STORAGE_STATUS_OK;
}

/* Process queue */
storage_status_t storage_process_queue(void) {
    if (!global_storage_manager) return STORAGE_STATUS_INVALID_PARAM;
    
    /* Process queued requests */
    /* This would implement actual queue processing logic */
    return STORAGE_STATUS_OK;
}

/* Cancel request */
storage_status_t storage_cancel_request(uint64_t request_id) {
    if (!global_storage_manager) return STORAGE_STATUS_INVALID_PARAM;
    
    /* Cancel specific request */
    /* This would implement actual cancellation logic */
    return STORAGE_STATUS_OK;
}

/* Wait for request */
storage_status_t storage_wait_for_request(uint64_t request_id, uint32_t timeout) {
    if (!global_storage_manager) return STORAGE_STATUS_INVALID_PARAM;
    
    /* Wait for request completion */
    /* This would implement actual waiting logic */
    return STORAGE_STATUS_OK;
}

/* Initialize IDE controller */
storage_status_t ide_init(void) {
    vga_print_info("Initializing IDE controller");
    
    /* Reset IDE controllers */
    outb(IDE_PRIMARY_CONTROL + IDE_DEVICE_CONTROL, 0x04);  /* Software reset */
    outb(IDE_SECONDARY_CONTROL + IDE_DEVICE_CONTROL, 0x04);
    
    /* Wait for reset */
    for (int i = 0; i < 10000; i++) {
        inb(IDE_PRIMARY_CONTROL + IDE_ALT_STATUS);
    }
    
    /* Clear reset */
    outb(IDE_PRIMARY_CONTROL + IDE_DEVICE_CONTROL, 0x00);
    outb(IDE_SECONDARY_CONTROL + IDE_DEVICE_CONTROL, 0x00);
    
    return STORAGE_STATUS_OK;
}

/* Detect IDE devices */
storage_status_t ide_detect_devices(void) {
    if (!global_storage_manager || !global_storage_manager->initialized) return STORAGE_STATUS_ERROR;
    
    /* Check primary master */
    if (ide_detect_device(0, 0)) {
        vga_print_info("Found IDE primary master");
    }
    
    /* Check primary slave */
    if (ide_detect_device(0, 1)) {
        vga_print_info("Found IDE primary slave");
    }
    
    /* Check secondary master */
    if (ide_detect_device(1, 0)) {
        vga_print_info("Found IDE secondary master");
    }
    
    /* Check secondary slave */
    if (ide_detect_device(1, 1)) {
        vga_print_info("Found IDE secondary slave");
    }
    
    return STORAGE_STATUS_OK;
}

/* Detect individual IDE device */
bool ide_detect_device(uint32_t channel, uint32_t drive) {
    uint16_t io_port = (channel == 0) ? IDE_PRIMARY_IO : IDE_SECONDARY_IO;
    
    /* Select drive */
    outb(io_port + IDE_DRIVE_SELECT, 0xA0 | (drive << 4));
    
    /* Wait for drive to become ready */
    for (int i = 0; i < 10000; i++) {
        uint8_t status = inb(io_port + IDE_STATUS);
        if (!(status & IDE_STATUS_BUSY)) break;
    }
    
    /* Check if device exists */
    uint8_t status = inb(io_port + IDE_STATUS);
    if (status == 0xFF) return false;  /* No device */
    
    /* Send IDENTIFY command */
    outb(io_port + IDE_COMMAND, IDE_CMD_IDENTIFY);
    
    /* Wait for response */
    for (int i = 0; i < 10000; i++) {
        status = inb(io_port + IDE_STATUS);
        if (status & IDE_STATUS_DRQ) break;
        if (status & IDE_STATUS_ERROR) return false;
    }
    
    /* Read identification data */
    uint16_t identify_data[256];
    for (int i = 0; i < 256; i++) {
        identify_data[i] = inw(io_port + IDE_DATA);
    }
    
    /* Create device structure */
    storage_device_t* device = (storage_device_t*)kmalloc(sizeof(storage_device_t));
    if (!device) return false;
    
    memory_zero(device, sizeof(storage_device_t));
    
    /* Fill device information */
    device->device_id = global_storage_manager->device_count;
    sprintf(device->name, "hd%c", 'a' + device->device_id);
    device->type = STORAGE_TYPE_IDE;
    device->interface = STORAGE_INTERFACE_ATA;
    device->initialized = true;
    device->present = true;
    
    /* Parse identification data */
    ide_parse_identify_data(device, identify_data);
    
    /* Set up device operations */
    device->read = ide_read_sectors;
    device->write = ide_write_sectors;
    device->flush = ide_flush_cache;
    device->trim = NULL;
    device->identify = ide_identify_device;
    device->smart = ide_smart_data;
    device->secure_erase = ide_secure_erase;
    
    /* Register device */
    storage_register_device(device);
    
    return true;
}

/* Parse IDE identify data */
void ide_parse_identify_data(storage_device_t* device, uint16_t* data) {
    if (!device || !data) return;
    
    /* Extract model number */
    for (int i = 0; i < 20; i++) {
        device->info.model[i * 2] = (data[27 + i] >> 8) & 0xFF;
        device->info.model[i * 2 + 1] = data[27 + i] & 0xFF;
    }
    device->info.model[40] = '\0';
    
    /* Extract serial number */
    for (int i = 0; i < 10; i++) {
        device->info.serial[i * 2] = (data[10 + i] >> 8) & 0xFF;
        device->info.serial[i * 2 + 1] = data[10 + i] & 0xFF;
    }
    device->info.serial[20] = '\0';
    
    /* Extract firmware revision */
    for (int i = 0; i < 4; i++) {
        device->info.firmware[i * 2] = (data[23 + i] >> 8) & 0xFF;
        device->info.firmware[i * 2 + 1] = data[23 + i] & 0xFF;
    }
    device->info.firmware[8] = '\0';
    
    /* Extract capacity */
    if (data[83] & 0x0400) {  /* LBA48 supported */
        device->info.capacity = ((uint64_t)data[103] << 48) | ((uint64_t)data[102] << 32) |
                               ((uint64_t)data[101] << 16) | data[100];
    } else {
        device->info.capacity = data[61] | ((uint64_t)data[60] << 16);
    }
    
    /* Extract capabilities */
    device->info.sector_size = 512;
    device->info.capabilities = STORAGE_CAP_READ | STORAGE_CAP_WRITE | STORAGE_CAP_FLUSH;
    
    if (data[82] & 0x0001) device->info.capabilities |= STORAGE_CAP_TRIM;
    if (data[82] & 0x0002) device->info.capabilities |= STORAGE_CAP_SMART;
    
    /* Check if solid state */
    device->info.solid_state = (data[217] & 0x0001) ? true : false;
    
    /* Extract temperature */
    if (data[194] != 0) {
        device->info.temperature = data[194] - 273;  /* Convert from Kelvin to Celsius */
    }
}

/* IDE read sectors */
storage_status_t ide_read_sectors(storage_device_t* device, uint64_t lba, uint32_t count, void* buffer) {
    if (!device || !buffer || count == 0) return STORAGE_STATUS_INVALID_PARAM;
    
    uint16_t io_port = (device->device_id < 2) ? IDE_PRIMARY_IO : IDE_SECONDARY_IO;
    uint32_t drive = device->device_id % 2;
    
    /* Select drive */
    outb(io_port + IDE_DRIVE_SELECT, 0xE0 | (drive << 4) | ((lba >> 24) & 0x0F));
    
    /* Wait for device to be ready */
    if (!ide_wait_ready(io_port)) return STORAGE_STATUS_TIMEOUT;
    
    /* Set up transfer */
    outb(io_port + IDE_FEATURES, 0);
    outb(io_port + IDE_SECTOR_COUNT, count);
    outb(io_port + IDE_LBA_LOW, lba & 0xFF);
    outb(io_port + IDE_LBA_MID, (lba >> 8) & 0xFF);
    outb(io_port + IDE_LBA_HIGH, (lba >> 16) & 0xFF);
    
    /* Send read command */
    outb(io_port + IDE_COMMAND, IDE_CMD_READ_SECTORS);
    
    /* Read data */
    uint16_t* word_buffer = (uint16_t*)buffer;
    for (uint32_t sector = 0; sector < count; sector++) {
        /* Wait for data ready */
        if (!ide_wait_drq(io_port)) return STORAGE_STATUS_TIMEOUT;
        
        /* Read sector */
        for (int i = 0; i < 256; i++) {
            word_buffer[sector * 256 + i] = inw(io_port + IDE_DATA);
        }
    }
    
    return STORAGE_STATUS_OK;
}

/* IDE write sectors */
storage_status_t ide_write_sectors(storage_device_t* device, uint64_t lba, uint32_t count, const void* buffer) {
    if (!device || !buffer || count == 0) return STORAGE_STATUS_INVALID_PARAM;
    
    uint16_t io_port = (device->device_id < 2) ? IDE_PRIMARY_IO : IDE_SECONDARY_IO;
    uint32_t drive = device->device_id % 2;
    
    /* Select drive */
    outb(io_port + IDE_DRIVE_SELECT, 0xE0 | (drive << 4) | ((lba >> 24) & 0x0F));
    
    /* Wait for device to be ready */
    if (!ide_wait_ready(io_port)) return STORAGE_STATUS_TIMEOUT;
    
    /* Set up transfer */
    outb(io_port + IDE_FEATURES, 0);
    outb(io_port + IDE_SECTOR_COUNT, count);
    outb(io_port + IDE_LBA_LOW, lba & 0xFF);
    outb(io_port + IDE_LBA_MID, (lba >> 8) & 0xFF);
    outb(io_port + IDE_LBA_HIGH, (lba >> 16) & 0xFF);
    
    /* Send write command */
    outb(io_port + IDE_COMMAND, IDE_CMD_WRITE_SECTORS);
    
    /* Write data */
    const uint16_t* word_buffer = (const uint16_t*)buffer;
    for (uint32_t sector = 0; sector < count; sector++) {
        /* Wait for ready to write */
        if (!ide_wait_drq(io_port)) return STORAGE_STATUS_TIMEOUT;
        
        /* Write sector */
        for (int i = 0; i < 256; i++) {
            outw(io_port + IDE_DATA, word_buffer[sector * 256 + i]);
        }
    }
    
    return STORAGE_STATUS_OK;
}

/* IDE flush cache */
storage_status_t ide_flush_cache(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    uint16_t io_port = (device->device_id < 2) ? IDE_PRIMARY_IO : IDE_SECONDARY_IO;
    
    /* Send flush cache command */
    outb(io_port + IDE_COMMAND, IDE_CMD_CACHE_FLUSH);
    
    /* Wait for completion */
    if (!ide_wait_ready(io_port)) return STORAGE_STATUS_TIMEOUT;
    
    return STORAGE_STATUS_OK;
}

/* IDE identify device */
storage_status_t ide_identify_device(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    uint16_t io_port = (device->device_id < 2) ? IDE_PRIMARY_IO : IDE_SECONDARY_IO;
    uint32_t drive = device->device_id % 2;
    
    /* Select drive */
    outb(io_port + IDE_DRIVE_SELECT, 0xA0 | (drive << 4));
    
    /* Send identify command */
    outb(io_port + IDE_COMMAND, IDE_CMD_IDENTIFY);
    
    /* Wait for response */
    if (!ide_wait_drq(io_port)) return STORAGE_STATUS_TIMEOUT;
    
    /* Read identification data */
    uint16_t identify_data[256];
    for (int i = 0; i < 256; i++) {
        identify_data[i] = inw(io_port + IDE_DATA);
    }
    
    /* Parse data */
    ide_parse_identify_data(device, identify_data);
    
    return STORAGE_STATUS_OK;
}

/* IDE SMART data */
storage_status_t ide_smart_data(storage_device_t* device, void* data) {
    if (!device || !data) return STORAGE_STATUS_INVALID_PARAM;
    
    /* This would implement SMART data retrieval */
    return STORAGE_STATUS_OK;
}

/* IDE secure erase */
storage_status_t ide_secure_erase(storage_device_t* device) {
    if (!device) return STORAGE_STATUS_INVALID_PARAM;
    
    uint16_t io_port = (device->device_id < 2) ? IDE_PRIMARY_IO : IDE_SECONDARY_IO;
    
    /* Send secure erase command */
    outb(io_port + IDE_FEATURES, 0x00);
    outb(io_port + IDE_SECTOR_COUNT, 0x00);
    outb(io_port + IDE_LBA_LOW, 0x00);
    outb(io_port + IDE_LBA_MID, 0x00);
    outb(io_port + IDE_LBA_HIGH, 0x00);
    outb(io_port + IDE_COMMAND, IDE_CMD_SECURITY_ERASE_PREPARE);
    
    /* Wait for completion */
    if (!ide_wait_ready(io_port)) return STORAGE_STATUS_TIMEOUT;
    
    return STORAGE_STATUS_OK;
}

/* Wait for IDE ready */
bool ide_wait_ready(uint16_t io_port) {
    uint32_t timeout = 100000;
    
    while (timeout--) {
        uint8_t status = inb(io_port + IDE_STATUS);
        if (!(status & IDE_STATUS_BUSY)) {
            if (status & IDE_STATUS_ERROR) return false;
            return true;
        }
    }
    
    return false;
}

/* Wait for IDE DRQ */
bool ide_wait_drq(uint16_t io_port) {
    uint32_t timeout = 100000;
    
    while (timeout--) {
        uint8_t status = inb(io_port + IDE_STATUS);
        if (status & IDE_STATUS_DRQ) return true;
        if (status & IDE_STATUS_ERROR) return false;
    }
    
    return false;
}

/* Initialize AHCI */
storage_status_t ahci_init(void) {
    vga_print_info("Initializing AHCI controller");
    /* This would implement AHCI initialization */
    return STORAGE_STATUS_OK;
}

/* Detect SATA devices */
storage_status_t ahci_detect_devices(void) {
    vga_print_info("Detecting SATA devices");
    /* This would implement SATA device detection */
    return STORAGE_STATUS_OK;
}

/* Initialize NVMe */
storage_status_t nvme_init(void) {
    vga_print_info("Initializing NVMe controller");
    /* This would implement NVMe initialization */
    return STORAGE_STATUS_OK;
}

/* Detect NVMe devices */
storage_status_t nvme_detect_devices(void) {
    vga_print_info("Detecting NVMe devices");
    /* This would implement NVMe device detection */
    return STORAGE_STATUS_OK;
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
char* strcpy(char* dest, const char* src) {
    char* original = dest;
    while ((*dest++ = *src++));
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

/* I/O port access functions */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile ("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint16_t inw(uint16_t port) {
    uint16_t value;
    __asm__ volatile ("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}