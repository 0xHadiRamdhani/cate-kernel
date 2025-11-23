# CATE-Kernel Master Makefile
# Top-level Makefile for building the entire kernel

# Subdirectories
SUBDIRS = boot kernel drivers network security tools forensics testing

# Build directory
BUILD_DIR = ../build

# Default target
all: $(BUILD_DIR) build-all

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build all subdirectories
build-all:
	@for dir in $(SUBDIRS); do \
		echo "Building $$dir..."; \
		$(MAKE) -C $$dir || exit 1; \
	done
	@echo "All components built successfully!"

# Clean all
clean:
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir..."; \
		$(MAKE) -C $$dir clean || exit 1; \
	done
	rm -rf $(BUILD_DIR)
	@echo "All components cleaned!"

# Install all
install: build-all
	@for dir in $(SUBDIRS); do \
		echo "Installing $$dir..."; \
		$(MAKE) -C $$dir install || exit 1; \
	done
	@echo "All components installed!"

# Test all
test:
	@for dir in $(SUBDIRS); do \
		echo "Testing $$dir..."; \
		$(MAKE) -C $$dir test || exit 1; \
	done
	@echo "All tests completed!"

# Create ISO image
iso: build-all
	@echo "Creating bootable ISO image..."
	./create_iso.sh
	@echo "ISO image created successfully!"

# Create disk image
disk: build-all
	@echo "Creating disk image..."
	./create_disk.sh
	@echo "Disk image created successfully!"

# Run in QEMU
qemu: iso
	@echo "Running in QEMU..."
	qemu-system-x86_64 -cdrom $(BUILD_DIR)/cate-kernel.iso -m 512 -enable-kvm

# Run in QEMU with debugging
qemu-debug: iso
	@echo "Running in QEMU with debugging..."
	qemu-system-x86_64 -cdrom $(BUILD_DIR)/cate-kernel.iso -m 512 -enable-kvm \
		-serial stdio -s -S

# Run in VirtualBox
virtualbox: iso
	@echo "Creating VirtualBox VM..."
	./create_virtualbox.sh
	@echo "VirtualBox VM created!"

# Run in VMware
vmware: iso
	@echo "Creating VMware VM..."
	./create_vmware.sh
	@echo "VMware VM created!"

# Package for distribution
package: build-all
	@echo "Creating distribution package..."
	./create_package.sh
	@echo "Distribution package created!"

# Generate documentation
docs:
	@echo "Generating documentation..."
	doxygen Doxyfile
	@echo "Documentation generated!"

# Run static analysis
analyze:
	@echo "Running static analysis..."
	./run_static_analysis.sh
	@echo "Static analysis completed!"

# Run security audit
audit:
	@echo "Running security audit..."
	./run_security_audit.sh
	@echo "Security audit completed!"

# Performance profiling
profile:
	@echo "Running performance profiling..."
	./run_profile.sh
	@echo "Performance profiling completed!"

# Memory leak detection
leakcheck:
	@echo "Running memory leak detection..."
	./run_leakcheck.sh
	@echo "Memory leak detection completed!"

# Code coverage
coverage:
	@echo "Running code coverage analysis..."
	./run_coverage.sh
	@echo "Code coverage analysis completed!"

# Format code
format:
	@echo "Formatting code..."
	./format_code.sh
	@echo "Code formatting completed!"

# Lint code
lint:
	@echo "Linting code..."
	./lint_code.sh
	@echo "Code linting completed!"

# Dependencies
depend:
	@for dir in $(SUBDIRS); do \
		echo "Generating dependencies for $$dir..."; \
		$(MAKE) -C $$dir depend || exit 1; \
	done
	@echo "Dependencies generated!"

# Help
help:
	@echo "CATE-Kernel Build System"
	@echo "Available targets:"
	@echo "  all         - Build all components"
	@echo "  clean       - Clean all build files"
	@echo "  install     - Install all components"
	@echo "  test        - Run all tests"
	@echo "  iso         - Create bootable ISO image"
	@echo "  disk        - Create disk image"
	@echo "  qemu        - Run in QEMU"
	@echo "  qemu-debug  - Run in QEMU with debugging"
	@echo "  virtualbox  - Create VirtualBox VM"
	@echo "  vmware      - Create VMware VM"
	@echo "  package     - Create distribution package"
	@echo "  docs        - Generate documentation"
	@echo "  analyze     - Run static analysis"
	@echo "  audit       - Run security audit"
	@echo "  profile     - Run performance profiling"
	@echo "  leakcheck   - Run memory leak detection"
	@echo "  coverage    - Run code coverage analysis"
	@echo "  format      - Format code"
	@echo "  lint        - Lint code"
	@echo "  depend      - Generate dependencies"
	@echo "  help        - Show this help message"

# Phony targets
.PHONY: all clean install test iso disk qemu qemu-debug virtualbox vmware \
        package docs analyze audit profile leakcheck coverage format lint \
        depend help build-all

# Default target
.DEFAULT_GOAL := all