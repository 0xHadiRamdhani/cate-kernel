# Network Makefile for Pentesting Kernel OS

# Compiler and flags
CC = x86_64-elf-gcc
AS = x86_64-elf-as
LD = x86_64-elf-ld

# Flags
CFLAGS = -m64 -mno-red-zone -mcmodel=kernel -fno-builtin -fno-stack-protector \
         -nostdlib -nostdinc -fno-pic -fno-asynchronous-unwind-tables \
         -I../kernel -I../drivers -I. -std=c99 -O2 -Wall -Wextra -Werror

ASFLAGS = -64
LDFLAGS = -nostdlib -lgcc

# Source files
NETWORK_SRCS = network.c
NETWORK_OBJS = $(NETWORK_SRCS:.c=.o)

# Assembly files
ASM_SRCS = 
ASM_OBJS = $(ASM_SRCS:.asm=.o)

# All objects
OBJS = $(NETWORK_OBJS) $(ASM_OBJS)

# Target library
TARGET = libnetwork.a

# Default target
all: $(TARGET)

# Create static library
$(TARGET): $(OBJS)
	@echo "Building network library..."
	x86_64-elf-ar rcs $@ $^
	@echo "Network library built successfully"

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
	@echo "Cleaning network objects..."
	rm -f $(OBJS) $(TARGET)
	@echo "Network objects cleaned"

# Install
install: $(TARGET)
	@echo "Installing network library..."
	cp $(TARGET) ../kernel/
	@echo "Network library installed"

# Dependencies
network.o: network.h ../kernel/memory.h ../kernel/interrupt.h ../drivers/vga.h

# Phony targets
.PHONY: all clean install

# Help
help:
	@echo "Network Makefile for Pentesting Kernel OS"
	@echo "Available targets:"
	@echo "  all      - Build the network library"
	@echo "  clean    - Clean build artifacts"
	@echo "  install  - Install network library to kernel directory"
	@echo "  help     - Show this help message"