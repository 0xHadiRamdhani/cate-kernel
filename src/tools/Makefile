# Tools Makefile for Pentesting Kernel OS

# Compiler and flags
CC = x86_64-elf-gcc
AS = x86_64-elf-as
LD = x86_64-elf-ld

# Flags
CFLAGS = -m64 -mno-red-zone -mcmodel=kernel -fno-builtin -fno-stack-protector \
         -nostdlib -nostdinc -fno-pic -fno-asynchronous-unwind-tables \
         -I../kernel -I../drivers -I../network -I../security -I. -std=c99 -O2 -Wall -Wextra -Werror

ASFLAGS = -64
LDFLAGS = -nostdlib -lgcc

# Source files
TOOLS_SRCS = pentest.c
TOOLS_OBJS = $(TOOLS_SRCS:.c=.o)

# Assembly files
ASM_SRCS = 
ASM_OBJS = $(ASM_SRCS:.asm=.o)

# All objects
OBJS = $(TOOLS_OBJS) $(ASM_OBJS)

# Target library
TARGET = libtools.a

# Default target
all: $(TARGET)

# Create static library
$(TARGET): $(OBJS)
	@echo "Building tools library..."
	x86_64-elf-ar rcs $@ $^
	@echo "Tools library built successfully"

# Compile C files
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Compile assembly files
%.o: %.asm
	@echo "Assembling $<..."
	$(AS) $(ASFLAGS) $< -o $@

# Clean
clean:
	@echo "Cleaning tools objects..."
	rm -f $(OBJS) $(TARGET)
	@echo "Tools objects cleaned"

# Install
install: $(TARGET)
	@echo "Installing tools library..."
	cp $(TARGET) ../kernel/
	@echo "Tools library installed"

# Dependencies
pentest.o: pentest.h ../kernel/memory.h ../kernel/interrupt.h ../drivers/vga.h ../network/network.h ../security/security.h

# Phony targets
.PHONY: all clean install

# Help
help:
	@echo "Tools Makefile for Pentesting Kernel OS"
	@echo "Available targets:"
	@echo "  all      - Build the tools library"
	@echo "  clean    - Clean build artifacts"
	@echo "  install  - Install tools library to kernel directory"
	@echo "  help     - Show this help message"