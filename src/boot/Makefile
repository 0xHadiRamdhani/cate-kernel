# Makefile for bootloader components

# Cross-compiler settings
CC = x86_64-elf-gcc
AS = nasm
LD = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
OBJDUMP = x86_64-elf-objdump

# Compiler flags
CFLAGS = -mcmodel=large -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
         -ffreestanding -fno-stack-protector -nostdlib -Wall -Wextra -O2 \
         -I../include -I. -fno-pic -fno-pie -fno-omit-frame-pointer

# Assembler flags
ASFLAGS = -f elf64

# Linker flags
LDFLAGS = -nostdlib -static -T linker.ld

# Source files
C_SOURCES = boot.c acpi.c efi.c module_loader.c security.c
ASM_SOURCES = boot.asm

# Object files
C_OBJECTS = $(C_SOURCES:.c=.o)
ASM_OBJECTS = $(ASM_SOURCES:.asm=.o)
OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

# Target files
TARGET = bootloader.elf
BINARY = bootloader.bin
ISO = bootloader.iso

# Default target
all: $(BINARY)

# Compile C files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile assembly files
%.o: %.asm
	$(AS) $(ASFLAGS) $< -o $@

# Link bootloader
$(TARGET): $(OBJECTS) linker.ld
	$(LD) $(LDFLAGS) -T linker.ld -o $@ $(OBJECTS)

# Create binary
$(BINARY): $(TARGET)
	$(OBJCOPY) -O binary $< $@

# Create ISO image
$(ISO): $(BINARY) grub.cfg
	mkdir -p iso/boot/grub
	cp $(BINARY) iso/boot/
	cp grub.cfg iso/boot/grub/
	grub-mkrescue -o $@ iso

# Disassembly
disasm: $(TARGET)
	$(OBJDUMP) -d $< > bootloader.dis

# Size information
size: $(TARGET)
	$(OBJDUMP) -h $<
	size $(TARGET)

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET) $(BINARY) $(ISO)
	rm -rf iso/
	rm -f bootloader.dis

# Test with QEMU
test: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio

# Debug with QEMU
debug: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio -s -S

# Memory test
memtest: $(ISO)
	qemu-system-x86_64 -cdrom $(ISO) -m 256M -serial stdio -d int

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y build-essential nasm qemu-system-x86 grub-pc-bin xorriso mtools

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Build bootloader binary"
	@echo "  iso        - Create bootable ISO image"
	@echo "  test       - Test with QEMU"
	@echo "  debug      - Debug with QEMU and GDB"
	@echo "  clean      - Clean build artifacts"
	@echo "  install-deps - Install required dependencies"
	@echo "  help       - Show this help"

.PHONY: all clean test debug disasm size help install-deps memtest iso

# Dependencies
boot.o: boot.c multiboot2.h
acpi.o: acpi.c multiboot2.h
efi.o: efi.c multiboot2.h
module_loader.o: module_loader.c multiboot2.h
security.o: security.c multiboot2.h