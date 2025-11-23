#!/bin/bash

# CATE-Kernel VMware VM Creation Script
# Creates a VMware VM for the kernel

set -e

echo "Creating CATE-Kernel VMware VM..."

# Configuration
VM_NAME="CATE-Kernel-OS"
VM_MEMORY=512
VM_CPUS=2
VM_DISK_SIZE=2048  # 2GB
ISO_FILE="build/cate-kernel.iso"
VMX_FILE="build/${VM_NAME}.vmx"
VMDK_FILE="build/${VM_NAME}.vmdk"

# Check if VMware is installed
if ! command -v vmrun &> /dev/null; then
    echo "Error: VMware is not installed"
    echo "Please install VMware Workstation or VMware Player and try again"
    exit 1
fi

# Check if ISO file exists
if [ ! -f "${ISO_FILE}" ]; then
    echo "Error: ISO file not found: ${ISO_FILE}"
    echo "Please run 'make iso' first"
    exit 1
fi

# Check if VM directory exists
VM_DIR="build/vmware"
if [ -d "${VM_DIR}" ]; then
    echo "Warning: VM directory '${VM_DIR}' already exists"
    read -p "Do you want to delete the existing VM? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting existing VM..."
        rm -rf "${VM_DIR}"
    else
        echo "Operation cancelled"
        exit 1
    fi
fi

# Create VM directory
echo "Creating VM directory..."
mkdir -p "${VM_DIR}"

# Create virtual disk
echo "Creating virtual disk..."
vmware-vdiskmanager -c -s ${VM_DISK_SIZE}MB -a lsilogic -t 0 "${VMDK_FILE}" || {
    echo "Error: Failed to create virtual disk"
    echo "Trying alternative method..."
    
    # Alternative: create disk manually
    dd if=/dev/zero of="${VMDK_FILE}" bs=1M count=${VM_DISK_SIZE}
}

# Create VMX configuration file
echo "Creating VMX configuration file..."
cat > "${VMX_FILE}" << EOF
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "14"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
displayName = "${VM_NAME}"
guestOS = "other3xlinux-64"
nvram = "${VM_NAME}.nvram"
virtualHW.productCompatibility = "hosted"
powerType.powerOff = "soft"
powerType.powerOn = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"
tools.upgrade.policy = "useGlobal"
firmware = "bios"
mks.enable3d = "FALSE"
svga.present = "TRUE"
svga.vramSize = "16777216"
memsize = "${VM_MEMORY}"
mem.hotadd = "TRUE"
vcpu.hotadd = "TRUE"
numvcpus = "${VM_CPUS}"
cpuid.coresPerSocket = "1"
sched.cpu.units = "mhz"
sched.cpu.affinity = "all"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000"
ethernet0.wakeOnPcktRcv = "FALSE"
ethernet0.addressType = "generated"
usb.present = "FALSE"
ehci.present = "FALSE"
sound.present = "FALSE"
serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "${VM_NAME}-serial.log"
serial0.tryNoRxLoss = "FALSE"
floppy0.present = "FALSE"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.fileName = "${VMDK_FILE##*/}"
sata0:0.deviceType = "disk"
sata0:0.mode = "persistent"
sata0:1.present = "TRUE"
sata0:1.fileName = "${ISO_FILE##*/}"
sata0:1.deviceType = "cdrom-raw"
sata0:1.mode = "persistent"
sata0:1.startConnected = "TRUE"
checkpoint.vmState = ""
cleanShutdown = "TRUE"
softPowerOff = "TRUE"
EOF

# Copy ISO and disk files to VM directory
echo "Copying files to VM directory..."
cp "${ISO_FILE}" "${VM_DIR}/"
cp "${VMDK_FILE}" "${VM_DIR}/"
cp "${VMX_FILE}" "${VM_DIR}/"

# Create VMware VM configuration
cat > "${VM_DIR}/${VM_NAME}.vmx" << EOF
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "14"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
displayName = "${VM_NAME}"
guestOS = "other3xlinux-64"
nvram = "${VM_NAME}.nvram"
virtualHW.productCompatibility = "hosted"
powerType.powerOff = "soft"
powerType.powerOn = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"
tools.upgrade.policy = "useGlobal"
firmware = "bios"
mks.enable3d = "FALSE"
svga.present = "TRUE"
svga.vramSize = "16777216"
memsize = "${VM_MEMORY}"
mem.hotadd = "TRUE"
vcpu.hotadd = "TRUE"
numvcpus = "${VM_CPUS}"
cpuid.coresPerSocket = "1"
sched.cpu.units = "mhz"
sched.cpu.affinity = "all"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000"
ethernet0.wakeOnPcktRcv = "FALSE"
ethernet0.addressType = "generated"
usb.present = "FALSE"
ehci.present = "FALSE"
sound.present = "FALSE"
serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "${VM_NAME}-serial.log"
serial0.tryNoRxLoss = "FALSE"
floppy0.present = "FALSE"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.fileName = "${VM_NAME}.vmdk"
sata0:0.deviceType = "disk"
sata0:0.mode = "persistent"
sata0:1.present = "TRUE"
sata0:1.fileName = "cate-kernel.iso"
sata0:1.deviceType = "cdrom-raw"
sata0:1.mode = "persistent"
sata0:1.startConnected = "TRUE"
checkpoint.vmState = ""
cleanShutdown = "TRUE"
softPowerOff = "TRUE"
EOF

# Create VMware VM configuration file
cat > "${VM_DIR}/README.txt" << EOF
CATE-Kernel VMware VM
====================

This directory contains the VMware VM files for CATE-Kernel OS.

Files:
- ${VM_NAME}.vmx     - VMware VM configuration
- ${VM_NAME}.vmdk    - Virtual disk
- cate-kernel.iso    - Bootable ISO image
- README.txt         - This file

Usage:
1. Open VMware Workstation or VMware Player
2. Select "Open a Virtual Machine"
3. Browse to this directory and select ${VM_NAME}.vmx
4. Start the VM

VM Configuration:
- Name: ${VM_NAME}
- Memory: ${VM_MEMORY} MB
- CPUs: ${VM_CPUS}
- Disk: ${VM_DISK_SIZE} MB
- Network: NAT
- Serial: File logging enabled

Serial Output:
- Serial output will be logged to ${VM_NAME}-serial.log
- Use 'tail -f ${VM_NAME}-serial.log' to monitor

Kernel Features:
- Custom x86_64 kernel with pentesting tools
- Network scanning and analysis
- Forensics capabilities
- Security auditing
- Exploit development framework

For more information, see the project documentation.
EOF

# Create VMware VM configuration
cat > "${VM_DIR}/vmware_config.txt" << EOF
# CATE-Kernel VMware Configuration
VM_NAME=${VM_NAME}
VM_MEMORY=${VM_MEMORY}
VM_CPUS=${VM_CPUS}
VM_DISK_SIZE=${VM_DISK_SIZE}
ISO_FILE=${ISO_FILE}
VMDK_FILE=${VM_DIR}/${VM_NAME}.vmdk
VMX_FILE=${VM_DIR}/${VM_NAME}.vmx
CREATED_DATE=$(date)
KERNEL_VERSION=1.0.0
EOF

# Display VM information
echo
echo "VMware VM created successfully!"
echo "================================"
echo "VM Name: ${VM_NAME}"
echo "VM Directory: ${VM_DIR}"
echo "Memory: ${VM_MEMORY} MB"
echo "CPUs: ${VM_CPUS}"
echo "Disk Size: ${VM_DISK_SIZE} MB"
echo "ISO File: ${ISO_FILE}"
echo "VMX File: ${VM_DIR}/${VM_NAME}.vmx"
echo "VMDK File: ${VM_DIR}/${VM_NAME}.vmdk"
echo "Serial Log: ${VM_NAME}-serial.log"
echo "================================"
echo

# Display usage instructions
echo "Usage Instructions:"
echo "1. Open VMware Workstation or VMware Player"
echo "2. Select 'Open a Virtual Machine'"
echo "3. Browse to ${VM_DIR}"
echo "4. Select ${VM_NAME}.vmx"
echo "5. Start the VM"
echo
echo "Alternatively, you can start the VM from command line:"
echo "vmrun start '${VM_DIR}/${VM_NAME}.vmx'"
echo
echo "To monitor serial output:"
echo "tail -f ${VM_NAME}-serial.log"
echo

# Optional: Start the VM
read -p "Do you want to start the VM now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting VMware VM..."
    vmrun start "${VM_DIR}/${VM_NAME}.vmx"
    echo "VM started. Check VMware console for output."
else
    echo "VM created but not started."
    echo "Use 'vmrun start \"${VM_DIR}/${VM_NAME}.vmx\"' to start it."
fi

echo
echo "VMware VM creation completed!"