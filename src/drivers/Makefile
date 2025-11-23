# Drivers Makefile for Pentesting Kernel OS

# Compiler and flags
CC = x86_64-elf-gcc
AS = x86_64-elf-as
LD = x86_64-elf-ld

# Flags
CFLAGS = -m64 -mno-red-zone -mcmodel=kernel -fno-builtin -fno-stack-protector \
         -nostdlib -nostdinc -fno-pic -fno-asynchronous-unwind-tables \
         -I../kernel -I. -std=c99 -O2 -Wall -Wextra -Werror

ASFLAGS = -64
LDFLAGS = -nostdlib -lgcc

# Source files
DRIVER_SRCS = vga.c keyboard.c storage.c
DRIVER_OBJS = $(DRIVER_SRCS:.c=.o)

# Assembly files
ASM_SRCS = 
ASM_OBJS = $(ASM_SRCS:.asm=.o)

# All objects
OBJS = $(DRIVER_OBJS) $(ASM_OBJS)

# Target library
TARGET = libdrivers.a

# Default target
all: $(TARGET)

# Create static library
$(TARGET): $(OBJS)
	@echo "Building driver library..."
	x86_64-elf-ar rcs $@ $^
	@echo "Driver library built successfully"

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
	@echo "Cleaning driver objects..."
	rm -f $(OBJS) $(TARGET)
	@echo "Driver objects cleaned"

# Install
install: $(TARGET)
	@echo "Installing driver library..."
	cp $(TARGET) ../kernel/
	@echo "Driver library installed"

# Dependencies
vga.o: vga.h ../kernel/memory.h
keyboard.o: keyboard.h ../kernel/memory.h ../kernel/interrupt.h vga.h
storage.o: storage.h ../kernel/memory.h ../kernel/interrupt.h vga.h

# Phony targets
.PHONY: all clean install

# Help
help:
	@echo "Driver Makefile for Pentesting Kernel OS"
	@echo "Available targets:"
	@echo "  all      - Build the driver library"
	@echo "  clean    - Clean build artifacts"
	@echo "  install  - Install driver library to kernel directory"
	@echo "  help     - Show this help message"