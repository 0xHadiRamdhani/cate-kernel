# Test Framework Makefile for Pentesting Kernel

CC = x86_64-elf-gcc
AS = x86_64-elf-as
LD = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
OBJDUMP = x86_64-elf-objdump

# Compiler flags
CFLAGS = -m64 -mno-red-zone -mcmodel=kernel -fno-pic -fno-pie \
         -ffreestanding -fno-stack-protector -fno-exceptions \
         -fno-rtti -fno-asynchronous-unwind-tables -fomit-frame-pointer \
         -O2 -Wall -Wextra -Werror -nostdlib -nostdinc \
         -I../include -I../kernel -I../drivers -I../network -I../security -I../forensics

# Assembler flags
ASFLAGS = -64

# Source files
TEST_SOURCES = \
    test_runner.c \
    test_framework.c \
    test_kernel.c

# Object files
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)

# Test framework library
TEST_LIB = libtest.a

# Default target
all: $(TEST_LIB)

# Build test framework library
$(TEST_LIB): $(TEST_OBJECTS)
	@echo "Building test framework library..."
	@ar rcs $@ $^
	@echo "Test framework library built successfully"

# Compile test source files
%.o: %.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $< successfully"

# Compile assembly files
%.o: %.asm
	@echo "Assembling $<..."
	@$(AS) $(ASFLAGS) $< -o $@
	@echo "Assembled $< successfully"

# Clean build artifacts
clean:
	@echo "Cleaning test framework..."
	@rm -f $(TEST_OBJECTS) $(TEST_LIB)
	@echo "Test framework cleaned"

# Install test framework
install: $(TEST_LIB)
	@echo "Installing test framework..."
	@mkdir -p ../lib
	@cp $(TEST_LIB) ../lib/
	@echo "Test framework installed"

# Run tests (requires kernel to be built and running)
test: $(TEST_LIB)
	@echo "Running kernel tests..."
	@echo "Note: Tests must be run from within the kernel environment"
	@echo "Use the kernel test command to execute tests"

# Build and run specific test
test-%: $(TEST_LIB)
	@echo "Building and running test: $*"
	@echo "Note: Individual tests must be run from within the kernel environment"

# Generate test report
report: $(TEST_LIB)
	@echo "Generating test report..."
	@echo "Note: Test reports are generated during kernel execution"

# Debug build
debug: CFLAGS += -g -DDEBUG -DDEBUG_TESTS
debug: $(TEST_LIB)

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: $(TEST_LIB)

# Static analysis
analyze:
	@echo "Running static analysis on test framework..."
	@cppcheck --enable=all --error-exitcode=1 --suppress=missingIncludeSystem .
	@echo "Static analysis completed"

# Memory leak detection
leak-check:
	@echo "Note: Memory leak detection requires runtime execution"
	@echo "Enable leak detection in test configuration"

# Coverage analysis
coverage:
	@echo "Note: Coverage analysis requires special build flags"
	@echo "Rebuild with coverage flags to enable coverage analysis"

# Performance profiling
profile:
	@echo "Note: Performance profiling requires runtime execution"
	@echo "Enable performance tracking in test configuration"

# Help target
help:
	@echo "Test Framework Makefile targets:"
	@echo "  all          - Build test framework library (default)"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install test framework library"
	@echo "  test         - Run all tests (requires kernel)"
	@echo "  test-<name>  - Run specific test (requires kernel)"
	@echo "  report       - Generate test report"
	@echo "  debug        - Build debug version"
	@echo "  release      - Build release version"
	@echo "  analyze      - Run static analysis"
	@echo "  leak-check   - Run memory leak detection"
	@echo "  coverage     - Generate coverage analysis"
	@echo "  profile      - Run performance profiling"
	@echo "  help         - Show this help message"

.PHONY: all clean install test test-% report debug release analyze leak-check coverage profile help