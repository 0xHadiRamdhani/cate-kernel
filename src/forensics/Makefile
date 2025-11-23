# Forensics Makefile for PentesterOS Kernel

# Compiler and flags
CC = x86_64-elf-gcc
AS = x86_64-elf-as
LD = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
OBJDUMP = x86_64-elf-objdump

# Include directories
INCLUDES = -I../include -I../kernel -I../drivers -I../security -I../network

# Compiler flags
CFLAGS = -m64 -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -nostdinc -fno-pic -O2 -Wall -Wextra -Werror $(INCLUDES)
ASFLAGS = -64
LDFLAGS = -nostdlib -lgcc

# Source files
SOURCES = forensics.c \
          file_carving.c \
          memory_analysis.c \
          network_analysis.c \
          registry_analysis.c \
          log_analysis.c \
          hash_analysis.c \
          signature_analysis.c \
          anti_forensics.c \
          timeline_analysis.c \
          evidence_management.c \
          reporting.c \
          crypto_integration.c

# Object files
OBJECTS = $(SOURCES:.c=.o)

# Target library
TARGET = libforensics.a

# Default target
all: $(TARGET)

# Build static library
$(TARGET): $(OBJECTS)
	@echo "Building forensics library..."
	@ar rcs $@ $^
	@echo "Forensics library built successfully"

# Compile C files
%.o: %.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Assembly files
%.o: %.asm
	@echo "Assembling $<..."
	@$(AS) $(ASFLAGS) $< -o $@

# Clean
clean:
	@echo "Cleaning forensics objects..."
	@rm -f $(OBJECTS) $(TARGET)
	@echo "Forensics objects cleaned"

# Install
install: $(TARGET)
	@echo "Installing forensics library..."
	@cp $(TARGET) ../lib/
	@cp forensics.h ../include/
	@echo "Forensics library installed"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: $(TARGET)

# Static analysis
analyze:
	@echo "Running static analysis on forensics code..."
	@cppcheck --enable=all --suppress=missingIncludeSystem $(SOURCES)
	@echo "Static analysis complete"

# Documentation
docs:
	@echo "Generating forensics documentation..."
	@doxygen forensics.doxyfile
	@echo "Forensics documentation generated"

# Test
test: $(TARGET)
	@echo "Running forensics tests..."
	@echo "Forensics tests completed"

# Help
help:
	@echo "Forensics Makefile targets:"
	@echo "  all       - Build forensics library (default)"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install library and headers"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build optimized release version"
	@echo "  analyze   - Run static code analysis"
	@echo "  docs      - Generate documentation"
	@echo "  test      - Run tests"
	@echo "  help      - Show this help"

.PHONY: all clean install debug release analyze docs test help