#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Storage device types */
typedef enum {
    STORAGE_TYPE_NONE = 0,
    STORAGE_TYPE_IDE = 1,
    STORAGE_TYPE_SATA = 2,
    STORAGE_TYPE_NVME = 3,
    STORAGE_TYPE_USB = 4,
    STORAGE_TYPE_NETWORK = 5,
    STORAGE_TYPE_RAM_DISK = 6,
    STORAGE_TYPE_VIRTUAL = 7
} storage_type_t;

/* Storage interface types */
typedef enum {
    STORAGE_INTERFACE_NONE = 0,
    STORAGE_INTERFACE_ATA = 1,
    STORAGE_INTERFACE_ATAPI = 2,
    STORAGE_INTERFACE_SCSI = 3,
    STORAGE_INTERFACE_NVME = 4,
    STORAGE_INTERFACE_USB = 5,
    STORAGE_INTERFACE_NETWORK = 6
} storage_interface_t;

/* Storage command types */
typedef enum {
    STORAGE_CMD_READ = 1,
    STORAGE_CMD_WRITE = 2,
    STORAGE_CMD_FLUSH = 3,
    STORAGE_CMD_TRIM = 4,
    STORAGE_CMD_SECURE_ERASE = 5,
    STORAGE_CMD_SELF_TEST = 6,
    STORAGE_CMD_IDENTIFY = 7,
    STORAGE_CMD_SMART = 8
} storage_command_t;

/* Storage status codes */
typedef enum {
    STORAGE_STATUS_OK = 0,
    STORAGE_STATUS_ERROR = -1,
    STORAGE_STATUS_TIMEOUT = -2,
    STORAGE_STATUS_NOT_READY = -3,
    STORAGE_STATUS_INVALID_PARAM = -4,
    STORAGE_STATUS_NO_MEDIA = -5,
    STORAGE_STATUS_WRITE_PROTECTED = -6,
    STORAGE_STATUS_DEVICE_FAULT = -7,
    STORAGE_STATUS_ABORTED = -8,
    STORAGE_STATUS_MEDIA_CHANGED = -9,
    STORAGE_STATUS_BUS_RESET = -10
} storage_status_t;

/* Storage device capabilities */
typedef enum {
    STORAGE_CAP_READ = 0x01,
    STORAGE_CAP_WRITE = 0x02,
    STORAGE_CAP_FLUSH = 0x04,
    STORAGE_CAP_TRIM = 0x08,
    STORAGE_CAP_SECURE_ERASE = 0x10,
    STORAGE_CAP_SMART = 0x20,
    STORAGE_CAP_HOTPLUG = 0x40,
    STORAGE_CAP_REMOVABLE = 0x80
} storage_capability_t;

/* Partition types */
typedef enum {
    PARTITION_TYPE_NONE = 0,
    PARTITION_TYPE_MBR = 1,
    PARTITION_TYPE_GPT = 2,
    PARTITION_TYPE_RAW = 3
} partition_type_t;

/* File system types */
typedef enum {
    FS_TYPE_NONE = 0,
    FS_TYPE_FAT32 = 1,
    FS_TYPE_NTFS = 2,
    FS_TYPE_EXT2 = 3,
    FS_TYPE_EXT3 = 4,
    FS_TYPE_EXT4 = 5,
    FS_TYPE_BTRFS = 6,
    FS_TYPE_ZFS = 7,
    FS_TYPE_RAW = 8
} filesystem_type_t;

/* Storage device information */
typedef struct {
    char model[41];
    char serial[21];
    char firmware[9];
    uint64_t capacity;
    uint32_t sector_size;
    uint32_t physical_sector_size;
    uint32_t alignment;
    uint32_t max_transfer_size;
    uint32_t queue_depth;
    uint32_t rotation_rate;
    bool solid_state;
    bool removable;
    bool hotplug_capable;
    storage_type_t type;
    storage_interface_t interface;
    uint32_t capabilities;
    uint32_t temperature;
    uint32_t power_cycles;
    uint32_t power_on_hours;
    uint32_t reallocated_sectors;
    uint32_t pending_sectors;
    uint32_t uncorrectable_sectors;
    uint32_t wear_leveling_count;
    uint32_t spare_blocks;
    uint8_t smart_status;
    bool encrypted;
    bool locked;
    uint8_t security_level;
} storage_device_info_t;

/* Partition information */
typedef struct {
    uint64_t start_lba;
    uint64_t end_lba;
    uint64_t size;
    uint8_t type;
    uint8_t status;
    char name[36];
    filesystem_type_t filesystem;
    bool bootable;
    bool hidden;
    uint32_t partition_id;
} partition_info_t;

/* Storage request structure */
typedef struct {
    storage_command_t command;
    uint64_t lba;
    uint32_t sector_count;
    void* buffer;
    size_t buffer_size;
    uint32_t flags;
    uint32_t timeout;
    void* callback;
    void* context;
    uint64_t request_id;
    uint32_t priority;
    bool async;
} storage_request_t;

/* Storage device structure */
typedef struct storage_device {
    uint32_t device_id;
    char name[16];
    storage_type_t type;
    storage_interface_t interface;
    storage_device_info_t info;
    partition_info_t partitions[16];
    uint32_t partition_count;
    
    /* Device operations */
    storage_status_t (*read)(struct storage_device* dev, uint64_t lba, uint32_t count, void* buffer);
    storage_status_t (*write)(struct storage_device* dev, uint64_t lba, uint32_t count, const void* buffer);
    storage_status_t (*flush)(struct storage_device* dev);
    storage_status_t (*trim)(struct storage_device* dev, uint64_t lba, uint32_t count);
    storage_status_t (*identify)(struct storage_device* dev);
    storage_status_t (*smart)(struct storage_device* dev, void* data);
    storage_status_t (*secure_erase)(struct storage_device* dev);
    
    /* Device state */
    bool initialized;
    bool present;
    bool busy;
    uint32_t error_count;
    uint32_t timeout_count;
    uint64_t total_reads;
    uint64_t total_writes;
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint32_t queue_depth;
    uint32_t max_queue_depth;
    
    /* Security features */
    bool encrypted;
    bool locked;
    uint8_t security_level;
    uint8_t password[32];
    bool secure_mode;
    bool forensics_mode;
    bool write_blocking;
    bool read_only;
    
    /* Pentesting features */
    bool imaging_mode;
    bool cloning_mode;
    bool analysis_mode;
    bool evidence_mode;
    char evidence_tag[64];
    uint64_t evidence_start;
    uint64_t evidence_end;
    
    /* Performance monitoring */
    uint32_t avg_read_time;
    uint32_t avg_write_time;
    uint32_t max_read_time;
    uint32_t max_write_time;
    uint32_t cache_hits;
    uint32_t cache_misses;
    
    /* Linked list */
    struct storage_device* next;
} storage_device_t;

/* Storage manager */
typedef struct {
    storage_device_t* devices;
    uint32_t device_count;
    uint32_t max_devices;
    bool initialized;
    
    /* Statistics */
    uint64_t total_reads;
    uint64_t total_writes;
    uint64_t total_bytes_read;
    uint64_t total_bytes_written;
    uint32_t total_errors;
    uint32_t total_timeouts;
    
    /* Security */
    bool secure_mode;
    bool forensics_mode;
    bool write_blocking;
    uint32_t security_level;
    
    /* Pentesting */
    bool pentest_mode;
    bool evidence_collection;
    char case_id[64];
    char investigator[64];
    
    /* Performance */
    uint32_t cache_size;
    void* cache_buffer;
    uint32_t cache_hits;
    uint32_t cache_misses;
    
    /* Request queue */
    storage_request_t* request_queue;
    uint32_t queue_size;
    uint32_t queue_head;
    uint32_t queue_tail;
    
} storage_manager_t;

/* Storage driver functions */
void storage_init(void);
void storage_shutdown(void);
bool storage_is_initialized(void);

/* Device management */
storage_device_t* storage_get_device(uint32_t device_id);
storage_device_t* storage_get_device_by_name(const char* name);
uint32_t storage_get_device_count(void);
storage_status_t storage_register_device(storage_device_t* device);
storage_status_t storage_unregister_device(uint32_t device_id);

/* Device operations */
storage_status_t storage_read(storage_device_t* device, uint64_t lba, uint32_t count, void* buffer);
storage_status_t storage_write(storage_device_t* device, uint64_t lba, uint32_t count, const void* buffer);
storage_status_t storage_flush(storage_device_t* device);
storage_status_t storage_trim(storage_device_t* device, uint64_t lba, uint32_t count);
storage_status_t storage_identify(storage_device_t* device);
storage_status_t storage_smart(storage_device_t* device, void* data);
storage_status_t storage_secure_erase(storage_device_t* device);

/* Partition operations */
storage_status_t storage_read_partition(storage_device_t* device, uint32_t partition, uint64_t offset, uint32_t count, void* buffer);
storage_status_t storage_write_partition(storage_device_t* device, uint32_t partition, uint64_t offset, uint32_t count, const void* buffer);
partition_info_t* storage_get_partition(storage_device_t* device, uint32_t partition);
uint32_t storage_get_partition_count(storage_device_t* device);

/* Security functions */
storage_status_t storage_lock_device(storage_device_t* device, const uint8_t* password);
storage_status_t storage_unlock_device(storage_device_t* device, const uint8_t* password);
storage_status_t storage_set_password(storage_device_t* device, const uint8_t* password);
storage_status_t storage_clear_password(storage_device_t* device);
bool storage_is_locked(storage_device_t* device);
bool storage_is_encrypted(storage_device_t* device);

/* Pentesting functions */
storage_status_t storage_start_imaging(storage_device_t* device, const char* image_file);
storage_status_t storage_stop_imaging(storage_device_t* device);
storage_status_t storage_start_cloning(storage_device_t* source, storage_device_t* target);
storage_status_t storage_stop_cloning(storage_device_t* device);
storage_status_t storage_start_analysis(storage_device_t* device);
storage_status_t storage_stop_analysis(storage_device_t* device);
storage_status_t storage_mark_evidence(storage_device_t* device, uint64_t start_lba, uint64_t end_lba, const char* tag);
storage_status_t storage_get_evidence_info(storage_device_t* device, uint64_t* start_lba, uint64_t* end_lba, char* tag);

/* Forensics functions */
storage_status_t storage_create_forensic_image(storage_device_t* device, const char* filename);
storage_status_t storage_verify_forensic_image(storage_device_t* device, const char* filename);
storage_status_t storage_analyze_device(storage_device_t* device, void* analysis_data);
storage_status_t storage_search_signatures(storage_device_t* device, uint64_t start_lba, uint64_t end_lba, void* signatures);
storage_status_t storage_recover_data(storage_device_t* device, uint64_t start_lba, uint64_t end_lba, void* recovery_buffer);

/* Utility functions */
storage_status_t storage_format_device(storage_device_t* device, filesystem_type_t fs_type);
storage_status_t storage_check_device(storage_device_t* device);
storage_status_t storage_benchmark_device(storage_device_t* device, uint32_t* read_speed, uint32_t* write_speed);
const char* storage_get_status_string(storage_status_t status);
const char* storage_get_type_string(storage_type_t type);
const char* storage_get_interface_string(storage_interface_t interface);
const char* storage_get_filesystem_string(filesystem_type_t fs);

/* Statistics */
void storage_get_statistics(storage_device_t* device, uint64_t* reads, uint64_t* writes, uint64_t* bytes_read, uint64_t* bytes_written);
void storage_reset_statistics(storage_device_t* device);
void storage_get_global_statistics(uint64_t* total_reads, uint64_t* total_writes, uint64_t* total_bytes_read, uint64_t* total_bytes_written);

/* Advanced features */
storage_status_t storage_queue_request(storage_request_t* request);
storage_status_t storage_process_queue(void);
storage_status_t storage_cancel_request(uint64_t request_id);
storage_status_t storage_wait_for_request(uint64_t request_id, uint32_t timeout);

/* IDE/ATA specific functions */
storage_status_t ide_init(void);
storage_status_t ide_detect_devices(void);
storage_device_t* ide_get_device(uint32_t channel, uint32_t drive);

/* SATA/AHCI specific functions */
storage_status_t ahci_init(void);
storage_status_t ahci_detect_devices(void);
storage_device_t* ahci_get_device(uint32_t port);

/* NVMe specific functions */
storage_status_t nvme_init(void);
storage_status_t nvme_detect_devices(void);
storage_device_t* nvme_get_device(uint32_t namespace);

/* Global storage manager */
extern storage_manager_t* global_storage_manager;

/* Pentesting specific definitions */
#define STORAGE_EVIDENCE_TAG_MAX    64
#define STORAGE_PASSWORD_MAX        32
#define STORAGE_CASE_ID_MAX         64
#define STORAGE_INVESTIGATOR_MAX    64

/* Forensics signatures */
#define STORAGE_SIGNATURE_MBR       0x55AA
#define STORAGE_SIGNATURE_GPT       0x5452415020494645ULL  /* "EFI PART" */
#define STORAGE_SIGNATURE_NTFS      0x4E54465320202020ULL  /* "NTFS    " */
#define STORAGE_SIGNATURE_EXT       0xEF53
#define STORAGE_SIGNATURE_FAT32     0x28

/* Security levels */
#define STORAGE_SECURITY_NONE       0
#define STORAGE_SECURITY_LOW        1
#define STORAGE_SECURITY_MEDIUM     2
#define STORAGE_SECURITY_HIGH       3
#define STORAGE_SECURITY_MAXIMUM    4

/* Pentesting modes */
#define STORAGE_MODE_NORMAL         0
#define STORAGE_MODE_FORENSICS      1
#define STORAGE_MODE_PENTEST        2
#define STORAGE_MODE_EVIDENCE       3

#endif /* STORAGE_H */