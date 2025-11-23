#ifndef VGA_H
#define VGA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* VGA text mode constants */
#define VGA_TEXT_MODE_WIDTH     80
#define VGA_TEXT_MODE_HEIGHT    25
#define VGA_TEXT_MODE_SIZE      (VGA_TEXT_MODE_WIDTH * VGA_TEXT_MODE_HEIGHT)
#define VGA_TEXT_MODE_MEMORY    0xB8000

/* VGA color constants */
#define VGA_COLOR_BLACK         0
#define VGA_COLOR_BLUE          1
#define VGA_COLOR_GREEN         2
#define VGA_COLOR_CYAN          3
#define VGA_COLOR_RED           4
#define VGA_COLOR_MAGENTA       5
#define VGA_COLOR_BROWN         6
#define VGA_COLOR_LIGHT_GREY    7
#define VGA_COLOR_DARK_GREY       8
#define VGA_COLOR_LIGHT_BLUE      9
#define VGA_COLOR_LIGHT_GREEN     10
#define VGA_COLOR_LIGHT_CYAN      11
#define VGA_COLOR_LIGHT_RED       12
#define VGA_COLOR_LIGHT_MAGENTA   13
#define VGA_COLOR_LIGHT_BROWN     14
#define VGA_COLOR_WHITE           15

/* VGA graphics mode constants */
#define VGA_GRAPHICS_MODE_320x200  0x13
#define VGA_GRAPHICS_MODE_640x480  0x12
#define VGA_GRAPHICS_MODE_800x600  0x6A
#define VGA_GRAPHICS_MODE_1024x768 0x6B

/* VGA register ports */
#define VGA_MISC_WRITE          0x3C2
#define VGA_MISC_READ           0x3CC
#define VGA_SEQ_ADDRESS         0x3C4
#define VGA_SEQ_DATA            0x3C5
#define VGA_CRT_ADDRESS         0x3D4
#define VGA_CRT_DATA            0x3D5
#define VGA_GFX_ADDRESS         0x3CE
#define VGA_GFX_DATA            0x3CF
#define VGA_ATTR_ADDRESS        0x3C0
#define VGA_ATTR_DATA           0x3C1
#define VGA_ATTR_READ           0x3C1

/* VGA cursor constants */
#define VGA_CURSOR_START        0x0A
#define VGA_CURSOR_END          0x0B
#define VGA_CURSOR_LOCATION_HIGH 0x0E
#define VGA_CURSOR_LOCATION_LOW 0x0F

/* VGA character structure */
typedef struct {
    uint8_t character;
    uint8_t color;
} vga_char_t;

/* VGA color structure */
typedef struct {
    uint8_t foreground;
    uint8_t background;
} vga_color_t;

/* VGA state structure */
typedef struct {
    uint16_t* buffer;
    uint32_t width;
    uint32_t height;
    uint32_t cursor_x;
    uint32_t cursor_y;
    vga_color_t current_color;
    bool cursor_enabled;
    bool scrolling_enabled;
    uint32_t scroll_start;
    uint32_t scroll_end;
} vga_state_t;

/* VGA graphics state */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t pitch;
    uint8_t* framebuffer;
    uint32_t framebuffer_size;
    uint32_t current_mode;
    bool graphics_enabled;
} vga_graphics_state_t;

/* Function prototypes */
void vga_init(void);
void vga_init_text_mode(void);
void vga_init_graphics_mode(uint32_t mode);
void vga_clear_screen(void);
void vga_scroll(void);
void vga_put_char(char c);
void vga_put_string(const char* str);
void vga_put_char_at(char c, uint32_t x, uint32_t y);
void vga_put_string_at(const char* str, uint32_t x, uint32_t y);
void vga_set_color(uint8_t foreground, uint8_t background);
void vga_set_cursor(uint32_t x, uint32_t y);
void vga_get_cursor(uint32_t* x, uint32_t* y);
void vga_enable_cursor(bool enable);
void vga_enable_scrolling(bool enable);
void vga_set_scroll_region(uint32_t start, uint32_t end);
void vga_move_cursor(uint32_t x, uint32_t y);
void vga_clear_line(uint32_t line);
void vga_clear_region(uint32_t start_x, uint32_t start_y, uint32_t end_x, uint32_t end_y);
void vga_draw_box(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint8_t color);
void vga_draw_line(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint8_t color);
void vga_draw_pixel(uint32_t x, uint32_t y, uint32_t color);
uint32_t vga_get_pixel(uint32_t x, uint32_t y);
void vga_fill_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t color);
void vga_copy_rect(uint32_t src_x, uint32_t src_y, uint32_t dst_x, uint32_t dst_y, 
                   uint32_t width, uint32_t height);
void vga_print_hex(uint64_t value);
void vga_print_dec(uint64_t value);
void vga_print_bin(uint64_t value);
void vga_printf(const char* format, ...);
void vga_dump_memory(uint8_t* memory, uint32_t size, uint32_t x, uint32_t y);
void vga_dump_registers(void);
void vga_dump_stack(uint64_t* stack, uint32_t size);

/* VGA register access */
void vga_write_register(uint16_t port, uint8_t index, uint8_t value);
uint8_t vga_read_register(uint16_t port, uint8_t index);
void vga_write_seq(uint8_t index, uint8_t value);
uint8_t vga_read_seq(uint8_t index);
void vga_write_crt(uint8_t index, uint8_t value);
uint8_t vga_read_crt(uint8_t index);
void vga_write_gfx(uint8_t index, uint8_t value);
uint8_t vga_read_gfx(uint8_t index);
void vga_write_attr(uint8_t index, uint8_t value);
uint8_t vga_read_attr(uint8_t index);

/* VGA mode switching */
void vga_set_mode(uint32_t mode);
uint32_t vga_get_mode(void);
bool vga_is_text_mode(void);
bool vga_is_graphics_mode(void);
void vga_save_state(void);
void vga_restore_state(void);

/* VGA text utilities */
void vga_print_banner(const char* title);
void vga_print_separator(void);
void vga_print_header(const char* text);
void vga_print_error(const char* message);
void vga_print_warning(const char* message);
void vga_print_success(const char* message);
void vga_print_info(const char* message);
void vga_print_debug(const char* message);

/* VGA graphics utilities */
void vga_draw_logo(uint32_t x, uint32_t y);
void vga_draw_progress_bar(uint32_t x, uint32_t y, uint32_t width, uint32_t percent);
void vga_draw_menu(uint32_t x, uint32_t y, const char** items, uint32_t count);
void vga_draw_status_bar(const char* status);
void vga_draw_memory_map(void);
void vga_draw_cpu_info(void);
void vga_draw_network_status(void);

/* VGA pentesting features */
void vga_print_exploit_info(const char* exploit_name, const char* target);
void vga_print_scan_results(const char* target, uint32_t open_ports);
void vga_print_packet_info(const char* protocol, uint32_t size);
void vga_print_crypto_info(const char* algorithm, const char* status);
void vga_print_forensics_info(const char* file, const char* analysis);
void vga_print_privilege_info(const char* user, const char* privilege);
void vga_print_security_alert(const char* alert);
void vga_print_vulnerability(const char* vuln, const char* severity);

/* VGA debugging features */
void vga_enable_debug_mode(void);
void vga_disable_debug_mode(void);
bool vga_is_debug_mode(void);
void vga_dump_idt(void);
void vga_dump_gdt(void);
void vga_dump_page_tables(void);
void vga_dump_memory_map(void);
void vga_dump_interrupt_stats(void);
void vga_dump_syscall_stats(void);

/* Global variables */
extern vga_state_t* global_vga_state;
extern vga_graphics_state_t* global_vga_graphics_state;
extern bool vga_initialized;

/* Color schemes for pentesting */
#define VGA_COLOR_SCHEME_DEFAULT    0
#define VGA_COLOR_SCHEME_PENTEST    1
#define VGA_COLOR_SCHEME_SECURITY   2
#define VGA_COLOR_SCHEME_DEBUG      3
#define VGA_COLOR_SCHEME_FORENSICS  4

void vga_set_color_scheme(uint32_t scheme);
uint32_t vga_get_color_scheme(void);
void vga_init_color_schemes(void);

#endif /* VGA_H */