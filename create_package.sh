#!/bin/bash

# CATE-Kernel Distribution Package Creation Script
# Creates a distribution package for the kernel

set -e

echo "Creating CATE-Kernel distribution package..."

# Configuration
PACKAGE_NAME="cate-kernel"
PACKAGE_VERSION="1.0.0"
PACKAGE_DIR="${PACKAGE_NAME}-${PACKAGE_VERSION}"
BUILD_DIR="build"
DIST_DIR="dist"
ISO_FILE="${BUILD_DIR}/cate-kernel.iso"
DISK_FILE="${BUILD_DIR}/cate-kernel.img"

# Create distribution directory
echo "Creating distribution directory..."
mkdir -p ${DIST_DIR}
rm -rf ${DIST_DIR}/${PACKAGE_DIR}
mkdir -p ${DIST_DIR}/${PACKAGE_DIR}

# Create package structure
echo "Creating package structure..."
mkdir -p ${DIST_DIR}/${PACKAGE_DIR}/{kernel,docs,tools,scripts,examples,tests,licenses}

# Copy kernel files
echo "Copying kernel files..."
if [ -f "${BUILD_DIR}/kernel.elf" ]; then
    cp ${BUILD_DIR}/kernel.elf ${DIST_DIR}/${PACKAGE_DIR}/kernel/
else
    echo "Warning: kernel.elf not found"
fi

if [ -f "${BUILD_DIR}/kernel.sym" ]; then
    cp ${BUILD_DIR}/kernel.sym ${DIST_DIR}/${PACKAGE_DIR}/kernel/
fi

if [ -f "${BUILD_DIR}/kernel.dis" ]; then
    cp ${BUILD_DIR}/kernel.dis ${DIST_DIR}/${PACKAGE_DIR}/kernel/
fi

# Copy ISO and disk images
echo "Copying disk images..."
if [ -f "${ISO_FILE}" ]; then
    cp ${ISO_FILE} ${DIST_DIR}/${PACKAGE_DIR}/
fi

if [ -f "${DISK_FILE}" ]; then
    cp ${DISK_FILE} ${DIST_DIR}/${PACKAGE_DIR}/
fi

# Copy documentation
echo "Copying documentation..."
cp README.md ${DIST_DIR}/${PACKAGE_DIR}/
cp LICENSE ${DIST_DIR}/${PACKAGE_DIR}/
cp project-roadmap.md ${DIST_DIR}/${PACKAGE_DIR}/docs/
cp kernel-os-pentest-architecture.md ${DIST_DIR}/${PACKAGE_DIR}/docs/
cp development-setup-guide.md ${DIST_DIR}/${PACKAGE_DIR}/docs/
cp learning-resources.md ${DIST_DIR}/${PACKAGE_DIR}/docs/
cp diagram.png ${DIST_DIR}/${PACKAGE_DIR}/docs/

# Copy source code
echo "Copying source code..."
cp -r src ${DIST_DIR}/${PACKAGE_DIR}/
rm -f ${DIST_DIR}/${PACKAGE_DIR}/src/*/.depend
rm -f ${DIST_DIR}/${PACKAGE_DIR}/src/*/*.o
rm -f ${DIST_DIR}/${PACKAGE_DIR}/src/*/*.elf
rm -f ${DIST_DIR}/${PACKAGE_DIR}/src/*/*.sym

# Copy build scripts
echo "Copying build scripts..."
cp Makefile ${DIST_DIR}/${PACKAGE_DIR}/
cp create_iso.sh ${DIST_DIR}/${PACKAGE_DIR}/
cp create_disk.sh ${DIST_DIR}/${PACKAGE_DIR}/
cp create_virtualbox.sh ${DIST_DIR}/${PACKAGE_DIR}/
cp create_vmware.sh ${DIST_DIR}/${PACKAGE_DIR}/

# Copy configuration files
echo "Copying configuration files..."
cp src/boot/grub.cfg ${DIST_DIR}/${PACKAGE_DIR}/kernel/
cp src/kernel/kernel.ld ${DIST_DIR}/${PACKAGE_DIR}/kernel/

# Copy examples
echo "Copying examples..."
mkdir -p ${DIST_DIR}/${PACKAGE_DIR}/examples/{pentest,forensics,network,security}

cat > ${DIST_DIR}/${PACKAGE_DIR}/examples/pentest/scan_network.sh << 'EOF'
#!/bin/bash
# Example network scanning script

echo "Starting network scan..."
# This would use the kernel's network scanning syscalls
# SYSCALL_SCAN_NETWORK("192.168.1.0/24", 30000, 0)
echo "Network scan completed"
EOF

cat > ${DIST_DIR}/${PACKAGE_DIR}/examples/forensics/analyze_disk.sh << 'EOF'
#!/bin/bash
# Example disk forensics analysis

echo "Starting disk forensics analysis..."
# This would use the kernel's forensics syscalls
# SYSCALL_FORENSICS_ANALYZE("/dev/sda", "disk", 0)
echo "Forensics analysis completed"
EOF

cat > ${DIST_DIR}/${PACKAGE_DIR}/examples/network/capture_traffic.sh << 'EOF'
#!/bin/bash
# Example network traffic capture

echo "Starting network traffic capture..."
# This would use the kernel's packet capture syscalls
# SYSCALL_CAPTURE_PACKET(buffer, buffer_size, 60000, 0)
echo "Traffic capture completed"
EOF

cat > ${DIST_DIR}/${PACKAGE_DIR}/examples/security/audit_system.sh << 'EOF'
#!/bin/bash
# Example security audit

echo "Starting security audit..."
# This would use the kernel's security audit syscalls
# SYSCALL_SECURITY_AUDIT("system", "full", 0)
echo "Security audit completed"
EOF

# Copy test files
echo "Copying test files..."
cp -r src/testing ${DIST_DIR}/${PACKAGE_DIR}/tests/

# Copy license files
echo "Copying license files..."
cp LICENSE ${DIST_DIR}/${PACKAGE_DIR}/licenses/
cat > ${DIST_DIR}/${PACKAGE_DIR}/licenses/THIRD_PARTY << 'EOF'
Third Party Licenses
===================

This software may include third-party components with their own licenses:
- GRUB2 (GPL v3)
- GCC (GPL v3)
- Various open source tools and libraries

See individual component directories for specific license information.
EOF

# Create installation script
echo "Creating installation script..."
cat > ${DIST_DIR}/${PACKAGE_DIR}/install.sh << 'EOF'
#!/bin/bash

# CATE-Kernel Installation Script

set -e

echo "CATE-Kernel Installation Script"
echo "==============================="

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/cate-kernel"
KERNEL_DIR="/boot"
BIN_DIR="/usr/local/bin"

# Create installation directory
echo "Creating installation directory..."
mkdir -p ${INSTALL_DIR}
mkdir -p ${INSTALL_DIR}/{kernel,tools,docs,examples,tests}

# Copy files
echo "Copying kernel files..."
cp kernel/kernel.elf ${INSTALL_DIR}/kernel/
cp kernel/kernel.sym ${INSTALL_DIR}/kernel/
cp kernel/grub.cfg ${INSTALL_DIR}/kernel/
cp kernel/kernel.ld ${INSTALL_DIR}/kernel/

# Copy tools
echo "Copying tools..."
cp -r tools/* ${INSTALL_DIR}/tools/

# Copy documentation
echo "Copying documentation..."
cp -r docs/* ${INSTALL_DIR}/docs/

# Copy examples
echo "Copying examples..."
cp -r examples/* ${INSTALL_DIR}/examples/

# Copy tests
echo "Copying tests..."
cp -r tests/* ${INSTALL_DIR}/tests/

# Create symbolic links
echo "Creating symbolic links..."
ln -sf ${INSTALL_DIR}/kernel/kernel.elf ${KERNEL_DIR}/cate-kernel.elf
ln -sf ${INSTALL_DIR}/tools/* ${BIN_DIR}/

# Create configuration
echo "Creating configuration..."
mkdir -p /etc/cate-kernel
cat > /etc/cate-kernel/config.conf << 'CONFIG'
# CATE-Kernel System Configuration
KERNEL_PATH=/opt/cate-kernel/kernel/kernel.elf
TOOLS_PATH=/opt/cate-kernel/tools
LOG_PATH=/var/log/cate-kernel
TEMP_PATH=/tmp/cate-kernel
CONFIG_PATH=/etc/cate-kernel
CONFIG

# Create log directory
echo "Creating log directory..."
mkdir -p /var/log/cate-kernel
chmod 755 /var/log/cate-kernel

# Create temporary directory
echo "Creating temporary directory..."
mkdir -p /tmp/cate-kernel
chmod 777 /tmp/cate-kernel

# Create systemd service (if systemd is available)
if [ -d "/etc/systemd/system" ]; then
    echo "Creating systemd service..."
    cat > /etc/systemd/system/cate-kernel.service << 'SERVICE'
[Unit]
Description=CATE-Kernel OS Service
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/cate-kernel-start
ExecStop=/usr/local/bin/cate-kernel-stop
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable cate-kernel.service
fi

# Create start/stop scripts
cat > /usr/local/bin/cate-kernel-start << 'START'
#!/bin/bash
# CATE-Kernel start script
echo "Starting CATE-Kernel..."
# Add start logic here
START

cat > /usr/local/bin/cate-kernel-stop << 'STOP'
#!/bin/bash
# CATE-Kernel stop script
echo "Stopping CATE-Kernel..."
# Add stop logic here
STOP

chmod +x /usr/local/bin/cate-kernel-start
chmod +x /usr/local/bin/cate-kernel-stop

echo
echo "Installation completed successfully!"
echo "CATE-Kernel has been installed to ${INSTALL_DIR}"
echo "Configuration file: /etc/cate-kernel/config.conf"
echo "Log directory: /var/log/cate-kernel"
echo
echo "To start CATE-Kernel:"
echo "  systemctl start cate-kernel"
echo "or"
echo "  /usr/local/bin/cate-kernel-start"
EOF

chmod +x ${DIST_DIR}/${PACKAGE_DIR}/install.sh

# Create uninstall script
echo "Creating uninstall script..."
cat > ${DIST_DIR}/${PACKAGE_DIR}/uninstall.sh << 'EOF'
#!/bin/bash

# CATE-Kernel Uninstallation Script

set -e

echo "CATE-Kernel Uninstallation Script"
echo "================================="

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/cate-kernel"
KERNEL_LINK="/boot/cate-kernel.elf"
CONFIG_DIR="/etc/cate-kernel"
LOG_DIR="/var/log/cate-kernel"
TEMP_DIR="/tmp/cate-kernel"
BIN_DIR="/usr/local/bin"

# Stop service
echo "Stopping CATE-Kernel service..."
systemctl stop cate-kernel.service 2>/dev/null || true
systemctl disable cate-kernel.service 2>/dev/null || true

# Remove files
echo "Removing files..."
rm -rf ${INSTALL_DIR}
rm -f ${KERNEL_LINK}
rm -rf ${CONFIG_DIR}
rm -rf ${LOG_DIR}
rm -rf ${TEMP_DIR}

# Remove systemd service
if [ -f "/etc/systemd/system/cate-kernel.service" ]; then
    echo "Removing systemd service..."
    rm -f /etc/systemd/system/cate-kernel.service
    systemctl daemon-reload
fi

# Remove scripts
echo "Removing scripts..."
rm -f ${BIN_DIR}/cate-kernel-start
rm -f ${BIN_DIR}/cate-kernel-stop

echo
echo "Uninstallation completed successfully!"
echo "CATE-Kernel has been removed from your system"
EOF

chmod +x ${DIST_DIR}/${PACKAGE_DIR}/uninstall.sh

# Create package info
echo "Creating package info..."
cat > ${DIST_DIR}/${PACKAGE_DIR}/PACKAGE_INFO << EOF
CATE-Kernel Package Information
============================
Package Name: ${PACKAGE_NAME}
Package Version: ${PACKAGE_VERSION}
Build Date: $(date)
Build System: $(uname -s)
Build Architecture: $(uname -m)
Kernel Version: 1.0.0
Supported Architectures: x86_64
Minimum Memory: 512 MB
Recommended Memory: 1024 MB
Minimum Disk Space: 100 MB
Recommended Disk Space: 2 GB

Package Contents:
- Kernel binary (kernel.elf)
- Bootable ISO image (cate-kernel.iso)
- Bootable disk image (cate-kernel.img)
- Source code (src/)
- Documentation (docs/)
- Examples (examples/)
- Tests (tests/)
- Build scripts (create_*.sh)
- Installation scripts (install.sh, uninstall.sh)

Installation:
  ./install.sh

Uninstallation:
  ./uninstall.sh

Testing:
  make test

Documentation:
  See docs/ directory

Support:
  See README.md for support information
EOF

# Create checksums
echo "Creating checksums..."
cd ${DIST_DIR}
find ${PACKAGE_DIR} -type f -exec sha256sum {} \; > ${PACKAGE_DIR}.sha256
find ${PACKAGE_DIR} -type f -exec md5sum {} \; > ${PACKAGE_DIR}.md5

# Create compressed archives
echo "Creating compressed archives..."
tar -czf ${PACKAGE_DIR}.tar.gz ${PACKAGE_DIR}
tar -cjf ${PACKAGE_DIR}.tar.bz2 ${PACKAGE_DIR}
zip -r ${PACKAGE_DIR}.zip ${PACKAGE_DIR}

# Calculate sizes
PACKAGE_SIZE=$(du -sh ${PACKAGE_DIR} | cut -f1)
TAR_GZ_SIZE=$(du -sh ${PACKAGE_DIR}.tar.gz | cut -f1)
TAR_BZ2_SIZE=$(du -sh ${PACKAGE_DIR}.tar.bz2 | cut -f1)
ZIP_SIZE=$(du -sh ${PACKAGE_DIR}.zip | cut -f1)

# Create distribution info
cat > ${PACKAGE_DIR}.info << EOF
CATE-Kernel Distribution Package
===============================
Package: ${PACKAGE_DIR}
Version: ${PACKAGE_VERSION}
Build Date: $(date)
Package Size: ${PACKAGE_SIZE}
Compressed Sizes:
  tar.gz: ${TAR_GZ_SIZE}
  tar.bz2: ${TAR_BZ2_SIZE}
  zip: ${ZIP_SIZE}

Checksums:
  SHA256: $(sha256sum ${PACKAGE_DIR}.tar.gz | cut -d' ' -f1)
  MD5: $(md5sum ${PACKAGE_DIR}.tar.gz | cut -d' ' -f1)

Files:
$(ls -la ${PACKAGE_DIR}.*)

Installation:
  tar -xzf ${PACKAGE_DIR}.tar.gz
  cd ${PACKAGE_DIR}
  ./install.sh
EOF

# Display summary
echo
echo "Package creation completed successfully!"
echo "======================================"
echo "Package: ${PACKAGE_DIR}"
echo "Version: ${PACKAGE_VERSION}"
echo "Size: ${PACKAGE_SIZE}"
echo "Compressed archives:"
echo "  - ${PACKAGE_DIR}.tar.gz (${TAR_GZ_SIZE})"
echo "  - ${PACKAGE_DIR}.tar.bz2 (${TAR_BZ2_SIZE})"
echo "  - ${PACKAGE_DIR}.zip (${ZIP_SIZE})"
echo "Checksums:"
echo "  - SHA256: $(sha256sum ${PACKAGE_DIR}.tar.gz | cut -d' ' -f1)"
echo "  - MD5: $(md5sum ${PACKAGE_DIR}.tar.gz | cut -d' ' -f1)"
echo "======================================"
echo "Distribution files are ready in: ${DIST_DIR}"
echo