# Learning Resources - Kernel Development for Pentester OS

## Essential C Programming for Kernel Development

### Memory Management
- Pointers and memory addresses
- Dynamic memory allocation
- Memory alignment
- Stack vs heap
- Memory-mapped I/O

### Low-Level Programming
- Bit manipulation
- Inline assembly
- Volatile keyword
- Memory barriers
- Atomic operations

### System Programming
- System calls
- File descriptors
- Process management
- Signal handling
- Inter-process communication

## x86_64 Architecture Fundamentals

### CPU Modes
- Real mode (16-bit)
- Protected mode (32-bit)
- Long mode (64-bit)
- System vs user mode
- Privilege levels (Ring 0-3)

### Memory Management
- Virtual memory
- Paging mechanism
- Page tables
- Translation Lookaside Buffer (TLB)
- Memory segmentation

### Interrupts and Exceptions
- Interrupt Vector Table (IVT)
- Interrupt Descriptor Table (IDT)
- Exception handling
- System calls via interrupts
- IRQ (Interrupt Request) handling

### Registers
- General purpose registers (RAX, RBX, RCX, RDX)
- Index registers (RSI, RDI, RBP, RSP)
- Instruction pointer (RIP)
- Flags register (RFLAGS)
- Control registers (CR0, CR2, CR3, CR4)

## Boot Process

### BIOS/UEFI Boot
1. Power-on self-test (POST)
2. BIOS initialization
3. Boot device selection
4. Master Boot Record (MBR) loading
5. Bootloader execution

### Bootloader Responsibilities
1. Switch CPU to protected mode
2. Enable long mode (64-bit)
3. Setup basic memory management
4. Load kernel into memory
5. Jump to kernel entry point

## Kernel Development Concepts

### Memory Management
```c
// Example: Page table entry structure
typedef struct {
    uint64_t present    : 1;
    uint64_t writable   : 1;
    uint64_t user       : 1;
    uint64_t writethrough : 1;
    uint64_t cache_disabled : 1;
    uint64_t accessed   : 1;
    uint64_t dirty      : 1;
    uint64_t pagesize   : 1;
    uint64_t global     : 1;
    uint64_t available  : 3;
    uint64_t address    : 40;
    uint64_t reserved   : 11;
    uint64_t nx         : 1;
} page_table_entry_t;
```

### Interrupt Handling
```c
// Example: Interrupt handler registration
typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed)) idt_entry_t;

void register_interrupt_handler(uint8_t vector, void* handler) {
    idt_entry_t* entry = &idt[vector];
    uint64_t handler_addr = (uint64_t)handler;
    
    entry->offset_low = handler_addr & 0xFFFF;
    entry->offset_mid = (handler_addr >> 16) & 0xFFFF;
    entry->offset_high = (handler_addr >> 32) & 0xFFFFFFFF;
    entry->selector = 0x08; // Kernel code segment
    entry->type_attr = 0x8E; // Present, ring 0, 64-bit interrupt gate
}
```

### System Calls
```c
// Example: System call interface
typedef struct {
    uint64_t rax; // System call number
    uint64_t rdi; // Argument 1
    uint64_t rsi; // Argument 2
    uint64_t rdx; // Argument 3
    uint64_t r10; // Argument 4
    uint64_t r8;  // Argument 5
    uint64_t r9;  // Argument 6
} syscall_args_t;

uint64_t handle_syscall(syscall_args_t* args) {
    switch(args->rax) {
        case SYS_WRITE:
            return sys_write(args->rdi, (void*)args->rsi, args->rdx);
        case SYS_READ:
            return sys_read(args->rdi, (void*)args->rsi, args->rdx);
        case SYS_EXIT:
            sys_exit(args->rdi);
            return 0;
        default:
            return -ENOSYS;
    }
}
```

## Pentesting-Specific Kernel Features

### Network Packet Injection
```c
// Raw socket for packet injection
int create_raw_socket() {
    return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
}

int inject_packet(int sock, uint8_t* packet, size_t len) {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    sll.sll_protocol = htons(ETH_P_ALL);
    
    return sendto(sock, packet, len, 0, 
                  (struct sockaddr*)&sll, sizeof(sll));
}
```

### Memory Forensics
```c
// Memory analysis structure
typedef struct {
    uint64_t physical_addr;
    uint64_t virtual_addr;
    size_t size;
    uint32_t pid;
    uint32_t flags;
    char process_name[256];
} memory_region_t;

int analyze_memory_region(memory_region_t* region) {
    // Implement memory forensics analysis
    // Check for suspicious patterns, injected code, etc.
    return 0;
}
```

## Recommended Learning Path

### Week 1-2: C Programming Refresher
- Pointers and memory management
- Structs and unions
- Bit operations
- Function pointers

### Week 3-4: Assembly Language
- x86_64 assembly basics
- Calling conventions
- Stack operations
- System call interface

### Week 5-6: Computer Architecture
- CPU modes and privilege levels
- Memory management unit (MMU)
- Interrupt handling
- I/O operations

### Week 7-8: OS Concepts
- Process management
- Memory management
- File systems
- Device drivers

### Week 9-10: Kernel Development
- Boot process
- Kernel initialization
- Memory mapping
- System calls

### Week 11-12: Advanced Topics
- Multitasking
- Synchronization
- Security features
- Performance optimization

## Practice Projects

1. **Boot Sector**: Write a bootloader that prints "Hello Kernel!"
2. **Memory Manager**: Implement basic paging
3. **Interrupt Handler**: Handle keyboard interrupts
4. **System Call**: Implement basic read/write syscalls
5. **Driver**: Write a simple VGA text driver
6. **Network**: Implement basic packet transmission

## Debugging Techniques

### QEMU Debugging
```bash
# Start QEMU with GDB server
qemu-system-x86_64 -s -S -cdrom kernel.iso

# Connect with GDB
gdb kernel.elf
(gdb) target remote localhost:1234
(gdb) break kernel_main
(gdb) continue
```

### Serial Output Debugging
```c
// Serial port debugging
void serial_write_char(char c) {
    while (!(inb(0x3F8 + 5) & 0x20));
    outb(0x3F8, c);
}

void debug_print(const char* str) {
    while (*str) {
        serial_write_char(*str++);
    }
}
```

## Resources

### Books
- "Operating Systems: Design and Implementation" - Tanenbaum
- "Linux Kernel Development" - Robert Love
- "Understanding the Linux Kernel" - Bovet & Cesati
- "x86-64 Assembly Language Programming" - Seyfarth

### Online Resources
- OSDev Wiki: https://wiki.osdev.org/
- Intel Manuals: https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html
- x86-64.org: https://www.x86-64.org/documentation/
- Linux Kernel Archives: https://www.kernel.org/

### Communities
- OSDev Forums: https://forum.osdev.org/
- Reddit r/osdev: https://www.reddit.com/r/osdev/
- Stack Overflow: OS development tags
- Kernel newbies mailing list