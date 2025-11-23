#include "vga.h"
#include "../kernel/memory.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

/* Global VGA state */
vga_state_t* global_vga_state = NULL;
vga_graphics_state_t* global_vga_graphics_state = NULL;
bool vga_initialized = false;

/* Current color scheme */
static uint32_t current_color_scheme = VGA_COLOR_SCHEME_DEFAULT;

/* Color schemes for pentesting */
static vga_color_t color_schemes[5][16] = {
    /* Default scheme */
    {
        {VGA_COLOR_WHITE, VGA_COLOR_BLACK},      /* 0: Normal */
        {VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK}, /* 1: Success */
        {VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK},   /* 2: Error */
        {VGA_COLOR_LIGHT_YELLOW, VGA_COLOR_BLACK}, /* 3: Warning */
        {VGA_COLOR_LIGHT_BLUE, VGA_COLOR_BLACK},  /* 4: Info */
        {VGA_COLOR_LIGHT_MAGENTA, VGA_COLOR_BLACK}, /* 5: Debug */
        {VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLACK},  /* 6: Highlight */
        {VGA_COLOR_WHITE, VGA_COLOR_BLACK}        /* 7: White */
    },
    /* Pentest scheme */
    {
        {VGA_COLOR_GREEN, VGA_COLOR_BLACK},      /* 0: Normal */
        {VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK}, /* 1: Success/Exploit */
        {VGA_COLOR_RED, VGA_COLOR_BLACK},         /* 2: Error/Vulnerability */
        {VGA_COLOR_YELLOW, VGA_COLOR_BLACK},    /* 3: Warning/Scan */
        {VGA_COLOR_CYAN, VGA_COLOR_BLACK},        /* 4: Info/Network */
        {VGA_COLOR_MAGENTA, VGA_COLOR_BLACK},     /* 5: Debug/Crypto */
        {VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLACK},  /* 6: Highlight */
        {VGA_COLOR_WHITE, VGA_COLOR_BLACK}        /* 7: White */
    },
    /* Security scheme */
    {
        {VGA_COLOR_LIGHT_GREY, VGA_COLOR_BLACK},  /* 0: Normal */
        {VGA_COLOR_GREEN, VGA_COLOR_BLACK},       /* 1: Secure */
        {VGA_COLOR_RED, VGA_COLOR_BLACK},         /* 2: Insecure */
        {VGA_COLOR_YELLOW, VGA_COLOR_BLACK},      /* 3: Warning */
        {VGA_COLOR_BLUE, VGA_COLOR_BLACK},        /* 4: Info */
        {VGA_COLOR_MAGENTA, VGA_COLOR_BLACK},     /* 5: Alert */
        {VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK}, /* 6: Success */
        {VGA_COLOR_WHITE, VGA_COLOR_BLACK}        /* 7: Critical */
    },
    /* Debug scheme */
    {
        {VGA_COLOR_LIGHT_GREY, VGA_COLOR_BLACK},  /* 0: Normal */
        {VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK}, /* 1: Success */
        {VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK},   /* 2: Error */
        {VGA_COLOR_LIGHT_YELLOW, VGA_COLOR_BLACK}, /* 3: Warning */
        {VGA_COLOR_LIGHT_BLUE, VGA_COLOR_BLACK},  /* 4: Info */
        {VGA_COLOR_LIGHT_MAGENTA, VGA_COLOR_BLACK}, /* 5: Debug */
        {VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLACK},  /* 6: Highlight */
        {VGA_COLOR_WHITE, VGA_COLOR_BLACK}        /* 7: White */
    },
    /* Forensics scheme */
    {
        {VGA_COLOR_WHITE, VGA_COLOR_BLUE},        /* 0: Normal */
        {VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLUE},  /* 1: Evidence */
        {VGA_COLOR_LIGHT_RED, VGA_COLOR_BLUE},    /* 2: Suspicious */
        {VGA_COLOR_LIGHT_YELLOW, VGA_COLOR_BLUE}, /* 3: Warning */
        {VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLUE},   /* 4: Info */
        {VGA_COLOR_LIGHT_MAGENTA, VGA_COLOR_BLUE}, /* 5: Analysis */
        {VGA_COLOR_WHITE, VGA_COLOR_BLUE},        /* 6: Highlight */
        {VGA_COLOR_WHITE, VGA_COLOR_BLUE}         /* 7: White */
    }
};

/* Initialize VGA driver */
void vga_init(void) {
    if (vga_initialized) return;
    
    /* Allocate VGA state */
    global_vga_state = (vga_state_t*)kmalloc(sizeof(vga_state_t));
    if (!global_vga_state) return;
    
    memory_zero(global_vga_state, sizeof(vga_state_t));
    
    /* Setup VGA text mode */
    vga_init_text_mode();
    
    /* Initialize color schemes */
    vga_init_color_schemes();
    
    vga_initialized = true;
}

/* Initialize text mode */
void vga_init_text_mode(void) {
    if (!global_vga_state) return;
    
    /* Map VGA memory */
    global_vga_state->buffer = (uint16_t*)VGA_TEXT_MODE_MEMORY;
    global_vga_state->width = VGA_TEXT_MODE_WIDTH;
    global_vga_state->height = VGA_TEXT_MODE_HEIGHT;
    global_vga_state->cursor_x = 0;
    global_vga_state->cursor_y = 0;
    global_vga_state->current_color.foreground = VGA_COLOR_WHITE;
    global_vga_state->current_color.background = VGA_COLOR_BLACK;
    global_vga_state->cursor_enabled = true;
    global_vga_state->scrolling_enabled = true;
    global_vga_state->scroll_start = 0;
    global_vga_state->scroll_end = VGA_TEXT_MODE_HEIGHT - 1;
    
    /* Clear screen */
    vga_clear_screen();
    
    /* Enable cursor */
    vga_enable_cursor(true);
}

/* Initialize color schemes */
void vga_init_color_schemes(void) {
    /* Set default color scheme */
    current_color_scheme = VGA_COLOR_SCHEME_PENTEST;
}

/* Clear screen */
void vga_clear_screen(void) {
    if (!global_vga_state || !global_vga_state->buffer) return;
    
    uint16_t blank = (global_vga_state->current_color.background << 4) | 
                      global_vga_state->current_color.foreground;
    blank = blank << 8;
    
    for (uint32_t i = 0; i < global_vga_state->width * global_vga_state->height; i++) {
        global_vga_state->buffer[i] = blank;
    }
    
    global_vga_state->cursor_x = 0;
    global_vga_state->cursor_y = 0;
    vga_set_cursor(0, 0);
}

/* Scroll screen */
void vga_scroll(void) {
    if (!global_vga_state || !global_vga_state->buffer || !global_vga_state->scrolling_enabled) return;
    
    uint16_t blank = (global_vga_state->current_color.background << 4) | 
                      global_vga_state->current_color.foreground;
    blank = blank << 8;
    
    /* Move all lines up */
    for (uint32_t y = 0; y < global_vga_state->height - 1; y++) {
        for (uint32_t x = 0; x < global_vga_state->width; x++) {
            global_vga_state->buffer[y * global_vga_state->width + x] = 
                global_vga_state->buffer[(y + 1) * global_vga_state->width + x];
        }
    }
    
    /* Clear last line */
    for (uint32_t x = 0; x < global_vga_state->width; x++) {
        global_vga_state->buffer[(global_vga_state->height - 1) * global_vga_state->width + x] = blank;
    }
    
    global_vga_state->cursor_y = global_vga_state->height - 1;
}

/* Put character */
void vga_put_char(char c) {
    if (!global_vga_state || !global_vga_state->buffer) return;
    
    switch (c) {
        case '\n':
            global_vga_state->cursor_x = 0;
            global_vga_state->cursor_y++;
            break;
        case '\r':
            global_vga_state->cursor_x = 0;
            break;
        case '\t':
            global_vga_state->cursor_x = (global_vga_state->cursor_x + 8) & ~7;
            break;
        case '\b':
            if (global_vga_state->cursor_x > 0) {
                global_vga_state->cursor_x--;
                vga_put_char_at(' ', global_vga_state->cursor_x, global_vga_state->cursor_y);
            }
            break;
        default:
            if (c >= ' ' && c <= '~') {
                vga_put_char_at(c, global_vga_state->cursor_x, global_vga_state->cursor_y);
                global_vga_state->cursor_x++;
            }
            break;
    }
    
    /* Handle cursor wrapping */
    if (global_vga_state->cursor_x >= global_vga_state->width) {
        global_vga_state->cursor_x = 0;
        global_vga_state->cursor_y++;
    }
    
    /* Handle cursor scrolling */
    if (global_vga_state->cursor_y >= global_vga_state->height) {
        if (global_vga_state->scrolling_enabled) {
            vga_scroll();
            global_vga_state->cursor_y = global_vga_state->height - 1;
        } else {
            global_vga_state->cursor_y = 0;
        }
    }
    
    /* Update cursor position */
    vga_set_cursor(global_vga_state->cursor_x, global_vga_state->cursor_y);
}

/* Put string */
void vga_put_string(const char* str) {
    if (!str) return;
    
    while (*str) {
        vga_put_char(*str++);
    }
}

/* Put character at specific position */
void vga_put_char_at(char c, uint32_t x, uint32_t y) {
    if (!global_vga_state || !global_vga_state->buffer) return;
    if (x >= global_vga_state->width || y >= global_vga_state->height) return;
    
    uint16_t entry = (global_vga_state->current_color.background << 12) |
                     (global_vga_state->current_color.foreground << 8) |
                     (uint8_t)c;
    
    global_vga_state->buffer[y * global_vga_state->width + x] = entry;
}

/* Put string at specific position */
void vga_put_string_at(const char* str, uint32_t x, uint32_t y) {
    if (!str || !global_vga_state || !global_vga_state->buffer) return;
    if (x >= global_vga_state->width || y >= global_vga_state->height) return;
    
    uint32_t current_x = x;
    uint32_t current_y = y;
    
    while (*str && current_y < global_vga_state->height) {
        if (*str == '\n') {
            current_x = x;
            current_y++;
        } else if (current_x < global_vga_state->width) {
            vga_put_char_at(*str, current_x, current_y);
            current_x++;
        }
        str++;
    }
}

/* Set color */
void vga_set_color(uint8_t foreground, uint8_t background) {
    if (!global_vga_state) return;
    
    global_vga_state->current_color.foreground = foreground & 0x0F;
    global_vga_state->current_color.background = background & 0x0F;
}

/* Set cursor position */
void vga_set_cursor(uint32_t x, uint32_t y) {
    if (!global_vga_state) return;
    if (x >= global_vga_state->width) x = global_vga_state->width - 1;
    if (y >= global_vga_state->height) y = global_vga_state->height - 1;
    
    global_vga_state->cursor_x = x;
    global_vga_state->cursor_y = y;
    
    /* Update hardware cursor */
    uint16_t pos = y * global_vga_state->width + x;
    
    /* Write to VGA registers */
    vga_write_crt(VGA_CURSOR_LOCATION_HIGH, (pos >> 8) & 0xFF);
    vga_write_crt(VGA_CURSOR_LOCATION_LOW, pos & 0xFF);
}

/* Get cursor position */
void vga_get_cursor(uint32_t* x, uint32_t* y) {
    if (!global_vga_state || !x || !y) return;
    
    *x = global_vga_state->cursor_x;
    *y = global_vga_state->cursor_y;
}

/* Enable/disable cursor */
void vga_enable_cursor(bool enable) {
    if (!global_vga_state) return;
    
    global_vga_state->cursor_enabled = enable;
    
    if (enable) {
        vga_write_crt(VGA_CURSOR_START, 0x0E);
        vga_write_crt(VGA_CURSOR_END, 0x0F);
    } else {
        vga_write_crt(VGA_CURSOR_START, 0x20);
    }
}

/* Enable/disable scrolling */
void vga_enable_scrolling(bool enable) {
    if (!global_vga_state) return;
    
    global_vga_state->scrolling_enabled = enable;
}

/* Set scroll region */
void vga_set_scroll_region(uint32_t start, uint32_t end) {
    if (!global_vga_state) return;
    if (start >= global_vga_state->height || end >= global_vga_state->height) return;
    if (start > end) return;
    
    global_vga_state->scroll_start = start;
    global_vga_state->scroll_end = end;
}

/* Move cursor */
void vga_move_cursor(uint32_t x, uint32_t y) {
    vga_set_cursor(x, y);
}

/* Clear line */
void vga_clear_line(uint32_t line) {
    if (!global_vga_state || !global_vga_state->buffer) return;
    if (line >= global_vga_state->height) return;
    
    uint16_t blank = (global_vga_state->current_color.background << 4) | 
                      global_vga_state->current_color.foreground;
    blank = blank << 8;
    
    for (uint32_t x = 0; x < global_vga_state->width; x++) {
        global_vga_state->buffer[line * global_vga_state->width + x] = blank;
    }
}

/* Clear region */
void vga_clear_region(uint32_t start_x, uint32_t start_y, uint32_t end_x, uint32_t end_y) {
    if (!global_vga_state || !global_vga_state->buffer) return;
    
    if (start_x >= global_vga_state->width) start_x = global_vga_state->width - 1;
    if (start_y >= global_vga_state->height) start_y = global_vga_state->height - 1;
    if (end_x >= global_vga_state->width) end_x = global_vga_state->width - 1;
    if (end_y >= global_vga_state->height) end_y = global_vga_state->height - 1;
    
    if (start_x > end_x) return;
    if (start_y > end_y) return;
    
    uint16_t blank = (global_vga_state->current_color.background << 4) | 
                      global_vga_state->current_color.foreground;
    blank = blank << 8;
    
    for (uint32_t y = start_y; y <= end_y; y++) {
        for (uint32_t x = start_x; x <= end_x; x++) {
            global_vga_state->buffer[y * global_vga_state->width + x] = blank;
        }
    }
}

/* Draw box */
void vga_draw_box(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint8_t color) {
    if (!global_vga_state || !global_vga_state->buffer) return;
    
    vga_color_t old_color = global_vga_state->current_color;
    vga_set_color(color, global_vga_state->current_color.background);
    
    /* Draw top and bottom borders */
    for (uint32_t i = 0; i < width; i++) {
        if (x + i < global_vga_state->width) {
            if (y < global_vga_state->height) {
                vga_put_char_at('-', x + i, y);
            }
            if (y + height - 1 < global_vga_state->height) {
                vga_put_char_at('-', x + i, y + height - 1);
            }
        }
    }
    
    /* Draw left and right borders */
    for (uint32_t i = 0; i < height; i++) {
        if (y + i < global_vga_state->height) {
            if (x < global_vga_state->width) {
                vga_put_char_at('|', x, y + i);
            }
            if (x + width - 1 < global_vga_state->width) {
                vga_put_char_at('|', x + width - 1, y + i);
            }
        }
    }
    
    /* Draw corners */
    if (x < global_vga_state->width && y < global_vga_state->height) {
        vga_put_char_at('+', x, y);
    }
    if (x + width - 1 < global_vga_state->width && y < global_vga_state->height) {
        vga_put_char_at('+', x + width - 1, y);
    }
    if (x < global_vga_state->width && y + height - 1 < global_vga_state->height) {
        vga_put_char_at('+', x, y + height - 1);
    }
    if (x + width - 1 < global_vga_state->width && y + height - 1 < global_vga_state->height) {
        vga_put_char_at('+', x + width - 1, y + height - 1);
    }
    
    global_vga_state->current_color = old_color;
}

/* Print hexadecimal value */
void vga_print_hex(uint64_t value) {
    char buffer[17];
    const char* hex_digits = "0123456789ABCDEF";
    
    buffer[16] = '\0';
    for (int i = 15; i >= 0; i--) {
        buffer[i] = hex_digits[value & 0xF];
        value >>= 4;
    }
    
    vga_put_string("0x");
    vga_put_string(buffer);
}

/* Print decimal value */
void vga_print_dec(uint64_t value) {
    char buffer[21];
    int i = 19;
    
    if (value == 0) {
        vga_put_char('0');
        return;
    }
    
    buffer[20] = '\0';
    while (value > 0 && i >= 0) {
        buffer[i--] = '0' + (value % 10);
        value /= 10;
    }
    
    vga_put_string(&buffer[i + 1]);
}

/* Print binary value */
void vga_print_bin(uint64_t value) {
    char buffer[65];
    int i = 63;
    
    if (value == 0) {
        vga_put_string("0b0");
        return;
    }
    
    buffer[64] = '\0';
    while (value > 0 && i >= 0) {
        buffer[i--] = (value & 1) ? '1' : '0';
        value >>= 1;
    }
    
    vga_put_string("0b");
    vga_put_string(&buffer[i + 1]);
}

/* Simple printf implementation */
void vga_printf(const char* format, ...) {
    if (!format) return;
    
    va_list args;
    va_start(args, format);
    
    while (*format) {
        if (*format == '%' && *(format + 1)) {
            format++;
            switch (*format) {
                case 'd':
                case 'i': {
                    int value = va_arg(args, int);
                    vga_print_dec((uint64_t)value);
                    break;
                }
                case 'u': {
                    unsigned int value = va_arg(args, unsigned int);
                    vga_print_dec((uint64_t)value);
                    break;
                }
                case 'x':
                case 'X': {
                    unsigned int value = va_arg(args, unsigned int);
                    vga_print_hex((uint64_t)value);
                    break;
                }
                case 'p': {
                    void* ptr = va_arg(args, void*);
                    vga_print_hex((uint64_t)ptr);
                    break;
                }
                case 's': {
                    char* str = va_arg(args, char*);
                    vga_put_string(str);
                    break;
                }
                case 'c': {
                    int c = va_arg(args, int);
                    vga_put_char((char)c);
                    break;
                }
                case '%':
                    vga_put_char('%');
                    break;
                default:
                    vga_put_char('%');
                    vga_put_char(*format);
                    break;
            }
        } else {
            vga_put_char(*format);
        }
        format++;
    }
    
    va_end(args);
}

/* Dump memory */
void vga_dump_memory(uint8_t* memory, uint32_t size, uint32_t x, uint32_t y) {
    if (!memory) return;
    
    for (uint32_t i = 0; i < size && i < 256; i += 16) {
        vga_set_cursor(x, y + (i / 16));
        vga_print_hex((uint64_t)(memory + i));
        vga_put_string(": ");
        
        for (uint32_t j = 0; j < 16 && (i + j) < size; j++) {
            vga_print_hex(memory[i + j]);
            vga_put_char(' ');
        }
        
        vga_put_string(" | ");
        
        for (uint32_t j = 0; j < 16 && (i + j) < size; j++) {
            char c = memory[i + j];
            if (c >= 32 && c <= 126) {
                vga_put_char(c);
            } else {
                vga_put_char('.');
            }
        }
    }
}

/* VGA register access functions */
void vga_write_register(uint16_t port, uint8_t index, uint8_t value) {
    outb(port, index);
    outb(port + 1, value);
}

uint8_t vga_read_register(uint16_t port, uint8_t index) {
    outb(port, index);
    return inb(port + 1);
}

void vga_write_seq(uint8_t index, uint8_t value) {
    vga_write_register(VGA_SEQ_ADDRESS, index, value);
}

uint8_t vga_read_seq(uint8_t index) {
    return vga_read_register(VGA_SEQ_ADDRESS, index);
}

void vga_write_crt(uint8_t index, uint8_t value) {
    vga_write_register(VGA_CRT_ADDRESS, index, value);
}

uint8_t vga_read_crt(uint8_t index) {
    return vga_read_register(VGA_CRT_ADDRESS, index);
}

void vga_write_gfx(uint8_t index, uint8_t value) {
    vga_write_register(VGA_GFX_ADDRESS, index, value);
}

uint8_t vga_read_gfx(uint8_t index) {
    return vga_read_register(VGA_GFX_ADDRESS, index);
}

void vga_write_attr(uint8_t index, uint8_t value) {
    /* Reset flip-flop */
    inb(VGA_ATTR_READ);
    outb(VGA_ATTR_ADDRESS, index);
    outb(VGA_ATTR_DATA, value);
}

uint8_t vga_read_attr(uint8_t index) {
    /* Reset flip-flop */
    inb(VGA_ATTR_READ);
    outb(VGA_ATTR_ADDRESS, index);
    return inb(VGA_ATTR_READ);
}

/* Pentesting specific functions */
void vga_print_exploit_info(const char* exploit_name, const char* target) {
    vga_set_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK);
    vga_put_string("[EXPLOIT] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(exploit_name);
    vga_put_string(" -> ");
    vga_put_string(target);
    vga_put_char('\n');
}

void vga_print_scan_results(const char* target, uint32_t open_ports) {
    vga_set_color(VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLACK);
    vga_put_string("[SCAN] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string("Target: ");
    vga_put_string(target);
    vga_put_string(" - Open ports: ");
    vga_print_dec(open_ports);
    vga_put_char('\n');
}

void vga_print_packet_info(const char* protocol, uint32_t size) {
    vga_set_color(VGA_COLOR_LIGHT_BLUE, VGA_COLOR_BLACK);
    vga_put_string("[PACKET] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(protocol);
    vga_put_string(" - Size: ");
    vga_print_dec(size);
    vga_put_string(" bytes\n");
}

void vga_print_crypto_info(const char* algorithm, const char* status) {
    vga_set_color(VGA_COLOR_LIGHT_MAGENTA, VGA_COLOR_BLACK);
    vga_put_string("[CRYPTO] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(algorithm);
    vga_put_string(" - ");
    vga_put_string(status);
    vga_put_char('\n');
}

void vga_print_forensics_info(const char* file, const char* analysis) {
    vga_set_color(VGA_COLOR_YELLOW, VGA_COLOR_BLACK);
    vga_put_string("[FORENSICS] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(file);
    vga_put_string(" - ");
    vga_put_string(analysis);
    vga_put_char('\n');
}

void vga_print_privilege_info(const char* user, const char* privilege) {
    vga_set_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK);
    vga_put_string("[PRIVILEGE] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(user);
    vga_put_string(" - ");
    vga_put_string(privilege);
    vga_put_char('\n');
}

void vga_print_security_alert(const char* alert) {
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_RED);
    vga_put_string("[SECURITY ALERT] ");
    vga_set_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK);
    vga_put_string(alert);
    vga_put_char('\n');
}

void vga_print_vulnerability(const char* vuln, const char* severity) {
    vga_set_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK);
    vga_put_string("[VULNERABILITY] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(vuln);
    vga_put_string(" - Severity: ");
    
    if (severity[0] == 'C' || severity[0] == 'c') { /* Critical */
        vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_RED);
    } else if (severity[0] == 'H' || severity[0] == 'h') { /* High */
        vga_set_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK);
    } else if (severity[0] == 'M' || severity[0] == 'm') { /* Medium */
        vga_set_color(VGA_COLOR_YELLOW, VGA_COLOR_BLACK);
    } else { /* Low */
        vga_set_color(VGA_COLOR_GREEN, VGA_COLOR_BLACK);
    }
    
    vga_put_string(severity);
    vga_put_char('\n');
}

/* Print banner */
void vga_print_banner(const char* title) {
    vga_set_color(VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLACK);
    vga_put_string("╔═══════════════════════════════════════════════════════════════════════╗\n");
    vga_put_string("║ ");
    
    /* Calculate padding */
    int title_len = 0;
    const char* p = title;
    while (*p++) title_len++;
    
    int padding = (69 - title_len) / 2;
    for (int i = 0; i < padding; i++) vga_put_char(' ');
    vga_put_string(title);
    for (int i = 0; i < padding; i++) vga_put_char(' ');
    
    vga_put_string(" ║\n");
    vga_put_string("╚═══════════════════════════════════════════════════════════════════════╝\n");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
}

/* Print separator */
void vga_print_separator(void) {
    vga_set_color(VGA_COLOR_DARK_GREY, VGA_COLOR_BLACK);
    vga_put_string("─────────────────────────────────────────────────────────────────────────\n");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
}

/* Print header */
void vga_print_header(const char* text) {
    vga_set_color(VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLACK);
    vga_put_string("=== ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(text);
    vga_set_color(VGA_COLOR_LIGHT_CYAN, VGA_COLOR_BLACK);
    vga_put_string(" ===\n");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
}

/* Print error */
void vga_print_error(const char* message) {
    vga_set_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK);
    vga_put_string("[ERROR] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(message);
    vga_put_char('\n');
}

/* Print warning */
void vga_print_warning(const char* message) {
    vga_set_color(VGA_COLOR_YELLOW, VGA_COLOR_BLACK);
    vga_put_string("[WARNING] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(message);
    vga_put_char('\n');
}

/* Print success */
void vga_print_success(const char* message) {
    vga_set_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK);
    vga_put_string("[SUCCESS] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(message);
    vga_put_char('\n');
}

/* Print info */
void vga_print_info(const char* message) {
    vga_set_color(VGA_COLOR_LIGHT_BLUE, VGA_COLOR_BLACK);
    vga_put_string("[INFO] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(message);
    vga_put_char('\n');
}

/* Print debug */
void vga_print_debug(const char* message) {
    vga_set_color(VGA_COLOR_LIGHT_MAGENTA, VGA_COLOR_BLACK);
    vga_put_string("[DEBUG] ");
    vga_set_color(VGA_COLOR_WHITE, VGA_COLOR_BLACK);
    vga_put_string(message);
    vga_put_char('\n');
}

/* Set color scheme */
void vga_set_color_scheme(uint32_t scheme) {
    if (scheme < 5) {
        current_color_scheme = scheme;
    }
}

/* Get color scheme */
uint32_t vga_get_color_scheme(void) {
    return current_color_scheme;
}

/* I/O port access functions */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}