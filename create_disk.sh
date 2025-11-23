#!/bin/bash

# CATE-Kernel Disk Image Creation Script
# Creates a bootable disk image for the kernel

set -e

echo "Creating CATE-Kernel disk image..."

# Configuration
BUILD_DIR="build"
DISK_NAME="cate-kernel.img"
DISK_SIZE="100M"  # 100MB disk image
MOUNT_DIR="mnt"

# Create disk image
echo "Creating ${DISK_SIZE} disk image..."
dd if=/dev/zero of=${BUILD_DIR}/${DISK_NAME} bs=1M count=100 status=progress

# Create partition table
echo "Creating partition table..."
parted -s ${BUILD_DIR}/${DISK_NAME} mklabel msdos

# Create boot partition (50MB)
echo "Creating boot partition..."
parted -s ${BUILD_DIR}/${DISK_NAME} mkpart primary ext2 1MiB 51MiB
parted -s ${BUILD_DIR}/${DISK_NAME} set 1 boot on

# Create data partition (remaining space)
echo "Creating data partition..."
parted -s ${BUILD_DIR}/${DISK_NAME} mkpart primary ext2 51MiB 100%

# Setup loop device
echo "Setting up loop device..."
LOOP_DEVICE=$(sudo losetup -f --show -P ${BUILD_DIR}/${DISK_NAME})
if [ -z "$LOOP_DEVICE" ]; then
    echo "Error: Failed to setup loop device"
    exit 1
fi

# Wait for partition devices to appear
sleep 2

# Format partitions
echo "Formatting partitions..."
sudo mkfs.ext2 -F -L "CATE_BOOT" ${LOOP_DEVICE}p1
sudo mkfs.ext2 -F -L "CATE_DATA" ${LOOP_DEVICE}p2

# Create mount directories
mkdir -p ${MOUNT_DIR}/boot
mkdir -p ${MOUNT_DIR}/data

# Mount partitions
echo "Mounting partitions..."
sudo mount ${LOOP_DEVICE}p1 ${MOUNT_DIR}/boot
sudo mount ${LOOP_DEVICE}p2 ${MOUNT_DIR}/data

# Install GRUB
echo "Installing GRUB..."
sudo grub-install \
    --target=i386-pc \
    --boot-directory=${MOUNT_DIR}/boot \
    --modules="biosdisk part_msdos ext2" \
    --no-floppy \
    ${LOOP_DEVICE}

# Copy kernel files
echo "Copying kernel files..."
if [ -f "${BUILD_DIR}/kernel.elf" ]; then
    sudo cp ${BUILD_DIR}/kernel.elf ${MOUNT_DIR}/boot/kernel/
else
    echo "Error: kernel.elf not found in ${BUILD_DIR}"
    sudo umount ${MOUNT_DIR}/boot ${MOUNT_DIR}/data
    sudo losetup -d ${LOOP_DEVICE}
    exit 1
fi

# Copy GRUB configuration
echo "Copying GRUB configuration..."
if [ -f "src/boot/grub.cfg" ]; then
    sudo cp src/boot/grub.cfg ${MOUNT_DIR}/boot/grub/grub.cfg
else
    echo "Error: grub.cfg not found"
    sudo umount ${MOUNT_DIR}/boot ${MOUNT_DIR}/data
    sudo losetup -d ${LOOP_DEVICE}
    exit 1
fi

# Create kernel modules directory
echo "Creating kernel modules directory..."
sudo mkdir -p ${MOUNT_DIR}/boot/kernel/modules

# Create pentest tools directory
echo "Creating pentest tools directory..."
sudo mkdir -p ${MOUNT_DIR}/data/tools
sudo mkdir -p ${MOUNT_DIR}/data/exploits
sudo mkdir -p ${MOUNT_DIR}/data/payloads
sudo mkdir -p ${MOUNT_DIR}/data/wordlists
sudo mkdir -p ${MOUNT_DIR}/data/reports

# Create forensics data directory
echo "Creating forensics data directory..."
sudo mkdir -p ${MOUNT_DIR}/data/forensics
sudo mkdir -p ${MOUNT_DIR}/data/evidence
sudo mkdir -p ${MOUNT_DIR}/data/analysis

# Create configuration directory
echo "Creating configuration directory..."
sudo mkdir -p ${MOUNT_DIR}/data/config

# Create log directory
echo "Creating log directory..."
sudo mkdir -p ${MOUNT_DIR}/data/logs

# Create temporary directory
echo "Creating temporary directory..."
sudo mkdir -p ${MOUNT_DIR}/data/tmp

# Set permissions
echo "Setting permissions..."
sudo chmod 755 ${MOUNT_DIR}/boot
sudo chmod 755 ${MOUNT_DIR}/data
sudo chmod 644 ${MOUNT_DIR}/boot/kernel/kernel.elf
sudo chmod 644 ${MOUNT_DIR}/boot/grub/grub.cfg

# Create system configuration
cat > /tmp/kernel.conf << 'EOF'
# CATE-Kernel Configuration
KERNEL_VERSION=1.0.0
KERNEL_BUILD_DATE=$(date)
KERNEL_SECURITY_LEVEL=HIGH
KERNEL_DEBUG_MODE=ENABLED
KERNEL_AUDITING=ENABLED
KERNEL_PROFILING=DISABLED
KERNEL_TRACING=DISABLED
EOF

sudo cp /tmp/kernel.conf ${MOUNT_DIR}/data/config/kernel.conf
rm -f /tmp/kernel.conf

# Create pentest configuration
cat > /tmp/pentest.conf << 'EOF'
# CATE-Kernel Pentest Configuration
PENTEST_MODE=STEALTH
PENTEST_TIMEOUT=3600
PENTEST_MAX_THREADS=100
PENTEST_RATE_LIMIT=1000
PENTEST_USER_AGENT="CATE-Kernel-Scanner/1.0"
PENTEST_DELAY=100
EOF

sudo cp /tmp/pentest.conf ${MOUNT_DIR}/data/config/pentest.conf
rm -f /tmp/pentest.conf

# Create forensics configuration
cat > /tmp/forensics.conf << 'EOF'
# CATE-Kernel Forensics Configuration
FORENSICS_MODE=SAFE
FORENSICS_HASH_ALGORITHM=SHA256
FORENSICS_SIGNATURE_DB=/data/signatures.db
FORENSICS_EVIDENCE_DIR=/data/evidence
FORENSICS_REPORT_FORMAT=JSON
FORENSICS_CHAIN_OF_CUSTODY=ENABLED
EOF

sudo cp /tmp/forensics.conf ${MOUNT_DIR}/data/config/forensics.conf
rm -f /tmp/forensics.conf

# Create network configuration
cat > /tmp/network.conf << 'EOF'
# CATE-Kernel Network Configuration
NETWORK_INTERFACE=eth0
NETWORK_IP=192.168.1.100
NETWORK_NETMASK=255.255.255.0
NETWORK_GATEWAY=192.168.1.1
NETWORK_DNS=8.8.8.8
NETWORK_SCAN_TIMEOUT=30
NETWORK_CAPTURE_BUFFER=10485760
EOF

sudo cp /tmp/network.conf ${MOUNT_DIR}/data/config/network.conf
rm -f /tmp/network.conf

# Create sample wordlist
cat > /tmp/wordlist.txt << 'EOF'
admin
password
123456
root
toor
guest
user
test
default
EOF

sudo cp /tmp/wordlist.txt ${MOUNT_DIR}/data/wordlists/common.txt
rm -f /tmp/wordlist.txt

# Unmount partitions
echo "Unmounting partitions..."
sudo umount ${MOUNT_DIR}/boot
sudo umount ${MOUNT_DIR}/data

# Detach loop device
echo "Detaching loop device..."
sudo losetup -d ${LOOP_DEVICE}

# Cleanup
echo "Cleaning up..."
rmdir ${MOUNT_DIR}/boot ${MOUNT_DIR}/data ${MOUNT_DIR}

# Verify disk image
echo "Verifying disk image..."
if [ -f "${BUILD_DIR}/${DISK_NAME}" ]; then
    DISK_SIZE=$(stat -c%s "${BUILD_DIR}/${DISK_NAME}")
    echo "Disk image created successfully: ${BUILD_DIR}/${DISK_NAME}"
    echo "Size: $((DISK_SIZE / 1024 / 1024)) MB"
    
    # Show partition information
    echo "Partition information:"
    parted -s ${BUILD_DIR}/${DISK_NAME} print
    
    # Create disk info file
    cat > ${BUILD_DIR}/disk_info.txt << EOF
CATE-Kernel Disk Image Information
===============================
Build Date: $(date)
Disk Name: ${DISK_NAME}
Disk Size: $((DISK_SIZE / 1024 / 1024)) MB
Partition Table: MS-DOS
Partitions:
  - Boot partition: 50MB, ext2, bootable
  - Data partition: 49MB, ext2
File Systems:
  - Boot: ext2, label=CATE_BOOT
  - Data: ext2, label=CATE_DATA
Boot Loader: GRUB2 (i386-pc)
Kernel: kernel.elf
Configuration Files:
  - kernel.conf
  - pentest.conf
  - forensics.conf
  - network.conf
Directories:
  - /boot/kernel/ (kernel files)
  - /boot/grub/ (GRUB configuration)
  - /data/tools/ (pentest tools)
  - /data/exploits/ (exploits)
  - /data/payloads/ (payloads)
  - /data/wordlists/ (wordlists)
  - /data/reports/ (reports)
  - /data/forensics/ (forensics data)
  - /data/evidence/ (evidence)
  - /data/analysis/ (analysis results)
  - /data/config/ (configuration)
  - /data/logs/ (logs)
  - /data/tmp/ (temporary files)
EOF
else
    echo "Error: Disk image creation failed"
    exit 1
fi

echo "Disk image creation completed successfully!"
echo "Disk file: ${BUILD_DIR}/${DISK_NAME}"
echo "Use 'qemu-system-x86_64 -hda ${BUILD_DIR}/${DISK_NAME}' to test the disk image"