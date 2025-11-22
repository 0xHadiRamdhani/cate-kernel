# Makefile for kernel components

# Cross-compiler settings
CC = x86_64-elf-gcc
AS = nasm
LD = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
OBJDUMP = x86_64-elf-objdump

# Compiler flags
CFLAGS = -mcmodel=large -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
         -ffreestanding -fno-stack-protector -nostdlib -Wall -Wextra -O2 \
         -I../include -I. -fno-pic -fno-pie -fno-omit-frame-pointer \
         -DKERNEL_VERSION_STRING=\"1.0.0\" -DKERNEL_VERSION_MAJOR=1 \
         -DKERNEL_VERSION_MINOR=0 -DKERNEL_VERSION_PATCH=0

# Assembler flags
ASFLAGS = -f elf64

# Linker flags
LDFLAGS = -nostdlib -static -T kernel.ld

# Source files
C_SOURCES = main.c memory.c interrupt.c syscall.c
ASM_SOURCES = interrupt.asm

# Object files
C_OBJECTS = $(C_SOURCES:.c=.o)
ASM_OBJECTS = $(ASM_SOURCES:.asm=.o)
OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

# Target files
TARGET = kernel.elf
BINARY = kernel.bin
ISO = kernel.iso

# Default target
all: $(BINARY)

# Compile C files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile assembly files
%.o: %.asm
	$(AS) $(ASFLAGS) $< -o $@

# Link kernel
$(TARGET): $(OBJECTS) kernel.ld
	$(LD) $(LDFLAGS) -T kernel.ld -o $@ $(OBJECTS)

# Create binary
$(BINARY): $(TARGET)
	$(OBJCOPY) -O binary $< $@

# Create ISO image
$(ISO): $(BINARY) ../boot/bootloader.bin
	mkdir -p iso/boot/grub
	cp ../boot/bootloader.bin iso/boot/
	cp $(BINARY) iso/boot/kernel.bin
	cp ../boot/grub.cfg iso/boot/grub/
	grub-mkrescue -o $@ iso

# Disassembly
disasm: $(TARGET)
	$(OBJDUMP) -d $< > kernel.dis

# Size information
size: $(TARGET)
	$(OBJDUMP) -h $<
	size $(TARGET)

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET) $(BINARY) $(ISO)
	rm -rf iso/
	rm -f kernel.dis

# Test with QEMU
test: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio

# Debug with QEMU
debug: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio -s -S

# Memory test
memtest: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio -d int

# Security test
sectest: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio -d guest_errors

# Performance test
perftest: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio -enable-kvm

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y build-essential nasm qemu-system-x86 grub-pc-bin xorriso mtools

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Build kernel binary"
	@echo "  iso        - Create bootable ISO image"
	@echo "  test       - Test with QEMU"
	@echo "  debug      - Debug with QEMU and GDB"
	@echo "  memtest    - Memory test with QEMU"
	@echo "  sectest    - Security test with QEMU"
	@echo "  perftest   - Performance test with QEMU"
	@echo "  clean      - Clean build artifacts"
	@echo "  install-deps - Install required dependencies"
	@echo "  help       - Show this help"

.PHONY: all clean test debug memtest sectest perftest help install-deps iso

# Dependencies
main.o: main.c ../boot/multiboot2.h memory.h interrupt.h syscall.h
memory.o: memory.c memory.h ../boot/multiboot2.h
interrupt.o: interrupt.c interrupt.h memory.h
interrupt.o: interrupt.asm interrupt.h
syscall.o: syscall.c syscall.h memory.h interrupt.h

# Include bootloader dependency
$(ISO): ../boot/bootloader.bin