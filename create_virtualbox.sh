#!/bin/bash

# CATE-Kernel VirtualBox VM Creation Script
# Creates a VirtualBox VM for the kernel

set -e

echo "Creating CATE-Kernel VirtualBox VM..."

# Configuration
VM_NAME="CATE-Kernel-OS"
VM_TYPE="Linux_64"
VM_MEMORY=512
VM_CPUS=2
VM_DISK_SIZE=2048  # 2GB
ISO_FILE="build/cate-kernel.iso"
DISK_FILE="build/cate-kernel.vdi"

# Check if VirtualBox is installed
if ! command -v VBoxManage &> /dev/null; then
    echo "Error: VirtualBox is not installed"
    echo "Please install VirtualBox and try again"
    exit 1
fi

# Check if ISO file exists
if [ ! -f "${ISO_FILE}" ]; then
    echo "Error: ISO file not found: ${ISO_FILE}"
    echo "Please run 'make iso' first"
    exit 1
fi

# Check if VM already exists
if VBoxManage list vms | grep -q "\"${VM_NAME}\""; then
    echo "Warning: VM '${VM_NAME}' already exists"
    read -p "Do you want to delete the existing VM? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting existing VM..."
        VBoxManage unregistervm "${VM_NAME}" --delete
    else
        echo "Operation cancelled"
        exit 1
    fi
fi

# Create VM
echo "Creating VirtualBox VM: ${VM_NAME}"
VBoxManage createvm \
    --name "${VM_NAME}" \
    --ostype "${VM_TYPE}" \
    --register

# Configure VM
echo "Configuring VM settings..."
VBoxManage modifyvm "${VM_NAME}" \
    --memory ${VM_MEMORY} \
    --cpus ${VM_CPUS} \
    --vram 16 \
    --acpi on \
    --ioapic on \
    --hwvirtex on \
    --nestedpaging on \
    --largepages on \
    --firmware bios \
    --boot1 dvd \
    --boot2 disk \
    --boot3 none \
    --boot4 none \
    --nic1 nat \
    --nictype1 82540EM \
    --cableconnected1 on \
    --audio none \
    --clipboard disabled \
    --draganddrop disabled \
    --usb off \
    --usbehci off \
    --usbxhci off \
    --rtcuseutc on \
    --pae on \
    --longmode on \
    --cpuexecutioncap 100

# Create storage controller
echo "Creating storage controller..."
VBoxManage storagectl "${VM_NAME}" \
    --name "SATA Controller" \
    --add sata \
    --controller IntelAhci \
    --portcount 2 \
    --hostiocache on \
    --bootable on

# Create hard disk
echo "Creating hard disk..."
VBoxManage createhd \
    --filename "${DISK_FILE}" \
    --size ${VM_DISK_SIZE} \
    --format VDI \
    --variant Standard

# Attach hard disk
echo "Attaching hard disk..."
VBoxManage storageattach "${VM_NAME}" \
    --storagectl "SATA Controller" \
    --port 0 \
    --device 0 \
    --type hdd \
    --medium "${DISK_FILE}"

# Attach ISO
echo "Attaching ISO..."
VBoxManage storageattach "${VM_NAME}" \
    --storagectl "SATA Controller" \
    --port 1 \
    --device 0 \
    --type dvddrive \
    --medium "${ISO_FILE}"

# Configure network
echo "Configuring network..."
VBoxManage modifyvm "${VM_NAME}" \
    --nic1 nat \
    --nictype1 82540EM \
    --cableconnected1 on

# Configure serial port for debugging
echo "Configuring serial port..."
VBoxManage modifyvm "${VM_NAME}" \
    --uart1 0x3F8 4 \
    --uartmode1 file "${VM_NAME}-serial.log"

# Configure shared folders (optional)
# VBoxManage sharedfolder add "${VM_NAME}" --name "shared" --hostpath "$(pwd)/shared" --automount

# Configure VM description
echo "Setting VM description..."
VBoxManage modifyvm "${VM_NAME}" \
    --description "CATE-Kernel OS Pentest - A specialized operating system for penetration testing and security research. \
This VM includes a custom kernel with built-in security tools, network scanning capabilities, forensics analysis, and exploit development framework. \
Kernel Version: 1.0.0 \
Build Date: $(date) \
Architecture: x86_64 \
Memory: ${VM_MEMORY}MB \
CPUs: ${VM_CPUS} \
Disk: ${VM_DISK_SIZE}MB"

# Create VM configuration file
cat > "${VM_NAME}.vbox-config" << EOF
# CATE-Kernel VirtualBox Configuration
VM_NAME=${VM_NAME}
VM_TYPE=${VM_TYPE}
VM_MEMORY=${VM_MEMORY}
VM_CPUS=${VM_CPUS}
VM_DISK_SIZE=${VM_DISK_SIZE}
ISO_FILE=${ISO_FILE}
DISK_FILE=${DISK_FILE}
CREATED_DATE=$(date)
KERNEL_VERSION=1.0.0
EOF

# Display VM information
echo
echo "VirtualBox VM created successfully!"
echo "=================================="
echo "VM Name: ${VM_NAME}"
echo "VM Type: ${VM_TYPE}"
echo "Memory: ${VM_MEMORY} MB"
echo "CPUs: ${VM_CPUS}"
echo "Disk Size: ${VM_DISK_SIZE} MB"
echo "ISO File: ${ISO_FILE}"
echo "Disk File: ${DISK_FILE}"
echo "Serial Log: ${VM_NAME}-serial.log"
echo "=================================="
echo

# Display usage instructions
echo "Usage Instructions:"
echo "1. Start the VM: VBoxManage startvm \"${VM_NAME}\""
echo "2. Start with GUI: VirtualBox --startvm \"${VM_NAME}\""
echo "3. Stop the VM: VBoxManage controlvm \"${VM_NAME}\" poweroff"
echo "4. Delete the VM: VBoxManage unregistervm \"${VM_NAME}\" --delete"
echo "5. View serial log: tail -f ${VM_NAME}-serial.log"
echo

# Optional: Start the VM
read -p "Do you want to start the VM now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting VirtualBox VM..."
    VBoxManage startvm "${VM_NAME}"
    echo "VM started. Check VirtualBox GUI for console output."
else
    echo "VM created but not started. Use 'VBoxManage startvm \"${VM_NAME}\"' to start it."
fi

echo
echo "VirtualBox VM creation completed!"