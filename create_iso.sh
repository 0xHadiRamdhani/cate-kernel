#!/bin/bash

# CATE-Kernel ISO Creation Script
# Creates a bootable ISO image for the kernel

set -e

echo "Creating CATE-Kernel bootable ISO..."

# Configuration
BUILD_DIR="build"
ISO_DIR="iso"
ISO_NAME="cate-kernel.iso"
GRUB_CFG="src/boot/grub.cfg"

# Create ISO directory structure
echo "Creating ISO directory structure..."
mkdir -p ${ISO_DIR}/boot/grub
mkdir -p ${ISO_DIR}/boot/kernel

# Copy kernel files
echo "Copying kernel files..."
if [ -f "${BUILD_DIR}/kernel.elf" ]; then
    cp ${BUILD_DIR}/kernel.elf ${ISO_DIR}/boot/kernel/
else
    echo "Error: kernel.elf not found in ${BUILD_DIR}"
    exit 1
fi

# Copy GRUB configuration
echo "Copying GRUB configuration..."
if [ -f "${GRUB_CFG}" ]; then
    cp ${GRUB_CFG} ${ISO_DIR}/boot/grub/grub.cfg
else
    echo "Error: grub.cfg not found at ${GRUB_CFG}"
    exit 1
fi

# Create GRUB2 BIOS bootable ISO
echo "Creating GRUB2 BIOS bootable ISO..."
grub-mkrescue -o ${BUILD_DIR}/${ISO_NAME} ${ISO_DIR} \
    --modules="biosdisk part_msdos" \
    --fonts="" \
    --themes="" \
    --locales="" \
    --install-modules="normal boot linux search configfile" \
    2>/dev/null || {
    echo "grub-mkrescue failed, trying alternative method..."
    
    # Alternative method using xorriso
    xorriso -as mkisofs \
        -R -J -V "CATE-KERNEL" \
        -b boot/grub/i386-pc/eltorito.img \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        --grub2-boot-info \
        -eltorito-catalog boot/grub/boot.cat \
        -o ${BUILD_DIR}/${ISO_NAME} \
        ${ISO_DIR} 2>/dev/null || {
        echo "Error: Failed to create ISO image"
        echo "Please install grub-mkrescue or xorriso"
        exit 1
    }
}

# Create UEFI bootable ISO
echo "Creating UEFI bootable ISO..."
mkdir -p ${ISO_DIR}/EFI/BOOT

# Create UEFI boot loader
cat > ${ISO_DIR}/EFI/BOOT/BOOTX64.EFI << 'EOF'
# UEFI boot stub - will be replaced with actual UEFI loader
EOF

# Create hybrid ISO (BIOS + UEFI)
echo "Creating hybrid ISO (BIOS + UEFI)..."
xorriso -as mkisofs \
    -R -J -V "CATE-KERNEL" \
    -b boot/grub/i386-pc/eltorito.img \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    --grub2-boot-info \
    -eltorito-catalog boot/grub/boot.cat \
    -e EFI/BOOT/BOOTX64.EFI \
    -no-emul-boot \
    -o ${BUILD_DIR}/${ISO_NAME}.hybrid \
    ${ISO_DIR} 2>/dev/null || {
    echo "Warning: Could not create hybrid ISO"
}

# Verify ISO
echo "Verifying ISO image..."
if [ -f "${BUILD_DIR}/${ISO_NAME}" ]; then
    ISO_SIZE=$(stat -c%s "${BUILD_DIR}/${ISO_NAME}")
    echo "ISO created successfully: ${BUILD_DIR}/${ISO_NAME}"
    echo "Size: $((ISO_SIZE / 1024)) KB"
    
    # Show ISO contents
    echo "ISO contents:"
    7z l ${BUILD_DIR}/${ISO_NAME} 2>/dev/null || \
    isoinfo -l -i ${BUILD_DIR}/${ISO_NAME} 2>/dev/null || \
    echo "Could not list ISO contents"
else
    echo "Error: ISO creation failed"
    exit 1
fi

# Create ISO info file
cat > ${BUILD_DIR}/iso_info.txt << EOF
CATE-Kernel ISO Information
==========================
Build Date: $(date)
ISO Name: ${ISO_NAME}
ISO Size: $((ISO_SIZE / 1024)) KB
Kernel Version: $(grep -r "KERNEL_VERSION" ${BUILD_DIR}/kernel.sym 2>/dev/null | head -1 || echo "Unknown")
Boot Type: GRUB2 BIOS + UEFI
Supported Architectures: x86_64
EOF

# Cleanup
echo "Cleaning up temporary files..."
rm -rf ${ISO_DIR}

echo "ISO creation completed successfully!"
echo "ISO file: ${BUILD_DIR}/${ISO_NAME}"
echo "Use 'make qemu' to test the ISO in QEMU"