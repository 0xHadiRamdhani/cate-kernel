# Development Setup Guide - Kernel OS Pentester

## Prerequisites
- Linux development environment (Ubuntu/Debian recommended)
- Basic C programming knowledge
- Understanding of x86_64 architecture
- Terminal/command line familiarity

## Step 1: Install Development Tools

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential development tools
sudo apt install -y build-essential git vim qemu gdb make cmake

# Install cross-compilation tools
sudo apt install -y gcc make binutils libc6-dev-i386

# Install additional tools
sudo apt install -y nasm xorriso mtools grub-pc-bin
```

## Step 2: Build Cross-Compiler Toolchain

```bash
# Create working directory
mkdir -p ~/kernel-dev
cd ~/kernel-dev

# Download and build binutils
wget https://ftp.gnu.org/gnu/binutils/binutils-2.40.tar.xz
tar xf binutils-2.40.tar.xz
mkdir build-binutils
cd build-binutils
../binutils-2.40/configure --target=x86_64-elf --prefix="$HOME/kernel-dev/cross" --with-sysroot --disable-nls --disable-werror
make -j$(nproc)
make install
cd ..

# Download and build GCC
wget https://ftp.gnu.org/gnu/gcc/gcc-13.2.0/gcc-13.2.0.tar.xz
tar xf gcc-13.2.0.tar.xz
mkdir build-gcc
cd build-gcc
../gcc-13.2.0/configure --target=x86_64-elf --prefix="$HOME/kernel-dev/cross" --disable-nls --enable-languages=c,c++ --without-headers
make -j$(nproc) all-gcc
make -j$(nproc) all-target-libgcc
make install-gcc
make install-target-libgcc
cd ..
```

## Step 3: Setup Project Structure

```bash
# Create project directory
mkdir -p kernel-os-pentest
cd kernel-os-pentest

# Create directory structure
mkdir -p src/{kernel,boot,drivers,lib,net,fs}
mkdir -p include/{kernel,drivers,lib,net,fs}
mkdir -p build
mkdir -p tools
mkdir -p docs
mkdir -p iso/boot/grub

# Create initial files
touch src/kernel/main.c
touch src/boot/boot.asm
touch Makefile
touch README.md
```

## Step 4: Configure Environment Variables

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
# Kernel development environment
export PATH="$HOME/kernel-dev/cross/bin:$PATH"
export PREFIX="$HOME/kernel-dev/cross"
export TARGET=x86_64-elf
export PATH="$PREFIX/bin:$PATH"
```

Then reload your shell:
```bash
source ~/.bashrc
```

## Step 5: Verify Installation

```bash
# Check cross-compiler
x86_64-elf-gcc --version
x86_64-elf-ld --version

# Check QEMU
qemu-system-x86_64 --version

# Check GDB
gdb --version
```

## Step 6: Basic Makefile Template

Create `Makefile` in project root:

```makefile
# Cross-compiler
CC = x86_64-elf-gcc
AS = nasm
LD = x86_64-elf-ld

# Flags
CFLAGS = -mcmodel=large -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -ffreestanding -fno-stack-protector -nostdlib -Wall -Wextra -O2
ASFLAGS = -f elf64
LDFLAGS = -nostdlib

# Directories
SRCDIR = src
BUILDDIR = build
ISODIR = iso

# Source files
BOOT_SRC = $(SRCDIR)/boot/boot.asm
KERNEL_SRC = $(wildcard $(SRCDIR)/kernel/*.c)
KERNEL_OBJ = $(KERNEL_SRC:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)

# Target
TARGET = $(BUILDDIR)/kernel.bin
ISO = $(ISODIR)/boot/kernel.bin

all: $(TARGET)

$(BUILDDIR)/boot/boot.o: $(BOOT_SRC)
	@mkdir -p $(BUILDDIR)/boot
	$(AS) $(ASFLAGS) $< -o $@

$(BUILDDIR)/kernel/%.o: $(SRCDIR)/kernel/%.c
	@mkdir -p $(BUILDDIR)/kernel
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(BUILDDIR)/boot/boot.o $(KERNEL_OBJ)
	$(LD) $(LDFLAGS) -T linker.ld -o $@ $^

iso: $(TARGET)
	cp $(TARGET) $(ISO)
	grub-mkrescue -o kernel.iso $(ISODIR)

clean:
	rm -rf $(BUILDDIR) *.iso

run: iso
	qemu-system-x86_64 -cdrom kernel.iso -m 256M

debug: iso
	qemu-system-x86_64 -cdrom kernel.iso -m 256M -s -S
```

## Step 7: Testing Environment

```bash
# Create test script
cat > test.sh << 'EOF'
#!/bin/bash
echo "Building kernel..."
make clean && make

echo "Creating ISO..."
make iso

echo "Running in QEMU..."
make run
EOF

chmod +x test.sh
```

## Next Steps
1. Create basic bootloader (boot.asm)
2. Implement kernel main function
3. Setup basic memory management
4. Implement text output to screen
5. Test with QEMU emulator

## Troubleshooting
- If cross-compiler build fails, check dependencies
- For permission issues, use sudo appropriately
- Check QEMU supports x86_64 emulation
- Ensure sufficient disk space for toolchain (~2GB)