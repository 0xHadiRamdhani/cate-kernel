# CATE-Kernel Makefile
# Makefile for building the kernel

# Compiler and tools
CC = x86_64-elf-gcc
AS = x86_64-elf-as
LD = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
OBJDUMP = x86_64-elf-objdump
NM = x86_64-elf-nm

# Compiler flags
CFLAGS = -std=c11 -ffreestanding -O2 -Wall -Wextra -Werror \
         -nostdlib -nostartfiles -nodefaultlibs \
         -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
         -fno-builtin -fno-stack-protector -fno-pic \
         -I../include -I. -DKERNEL_BUILD

# Assembly flags
ASFLAGS = -64

# Linker flags
LDFLAGS = -nostdlib -lgcc -T kernel.ld

# Source files
C_SOURCES = main.c kernel.c memory.c interrupt.c syscall.c syscall_handlers.c \
            debug.c logging.c string.c

ASM_SOURCES = interrupt.asm

# Object files
C_OBJECTS = $(C_SOURCES:.c=.o)
ASM_OBJECTS = $(ASM_SOURCES:.asm=.o)
OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

# Target
TARGET = kernel.elf

# Default target
all: $(TARGET)

# Build C files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build assembly files
%.o: %.asm
	$(AS) $(ASFLAGS) $< -o $@

# Link kernel
$(TARGET): $(OBJECTS) kernel.ld
	$(LD) $(LDFLAGS) $(OBJECTS) -o $@
	$(OBJCOPY) --only-keep-debug $(TARGET) $(TARGET:.elf=.sym)
	$(OBJCOPY) --strip-debug $(TARGET)

# Create symbol file
symbols: $(TARGET)
	$(NM) -n $(TARGET) > kernel.sym

# Disassemble kernel
disasm: $(TARGET)
	$(OBJDUMP) -d $(TARGET) > kernel.dis

# Size information
size: $(TARGET)
	$(SIZE) $(TARGET)

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET) $(TARGET:.elf=.sym) kernel.dis

# Install
install: $(TARGET)
	cp $(TARGET) ../../build/

# Dependencies
depend:
	$(CC) -MM $(CFLAGS) $(C_SOURCES) > .depend

# Include dependencies
include .depend

# Phony targets
.PHONY: all clean install symbols disasm size depend

# Help
help:
	@echo "CATE-Kernel Build System"
	@echo "Available targets:"
	@echo "  all      - Build the kernel"
	@echo "  clean    - Clean build files"
	@echo "  install  - Install kernel to build directory"
	@echo "  symbols  - Generate symbol file"
	@echo "  disasm   - Disassemble kernel"
	@echo "  size     - Show kernel size information"
	@echo "  depend   - Generate dependencies"
	@echo "  help     - Show this help message"